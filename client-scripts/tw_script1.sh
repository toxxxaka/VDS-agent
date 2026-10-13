#!/usr/bin/env python3
"""
diag.py — диагностический снапшот сервера (только stdout).

Использование:
    sudo ./diag.py                     # всё, в конце спросит домен для поиска vhost/логов
    sudo ./diag.py --only network,vpn  # только выбранные секции
    sudo ./diag.py --list              # показать список доступных секций
    sudo ./diag.py --timeout 5         # свой таймаут на команду (по умолчанию 10с)
    sudo ./diag.py --no-vhost          # без интерактивного запроса домена в конце
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

DEFAULT_TIMEOUT = 10

# Каждая секция: (тег, заголовок, команда, требует_root)
COMMANDS = [
    # --- базовое ---
    ("general", "UPTIME / LOAD", "uptime", False),
    ("general", "MEMORY", "free -h", False),
    ("general", "SYSTEM RESOURCES", "lsblk && echo && nproc", False),

    # --- диск ---
    ("disk", "DISK SPACE + INODES", "df -h && echo && df -i", False),
    ("disk", "TOP-10 LARGEST DIRS in /var", "du -xh --max-depth=3 /var 2>/dev/null | sort -rh | head -10", False),
    ("disk", "TOP-10 LARGEST DIRS in /home", "du -xh --max-depth=3 /home 2>/dev/null | sort -rh | head -10", False),

    # --- процессы ---
    ("proc", "TOP CPU PROCESSES", "ps aux --sort=-%cpu | head -15", False),
    ("proc", "TOP MEMORY PROCESSES", "ps aux --sort=-%mem | head -15", False),
    ("proc", "ZOMBIE PROCESSES", "ps aux | awk '$8 ~ /^Z/'", False),

    # --- systemd / journal ---
    ("systemd", "FAILED UNITS", "systemctl --failed --no-pager", False),
    ("systemd", "JOURNAL: LAST ERRORS (priority err+)", "journalctl -p err -n 50 --no-pager", True),
    ("systemd", "OOM KILLER EVENTS", "journalctl -k --no-pager 2>/dev/null | grep -i 'out of memory' | tail -20", True),

    # --- сеть ---
    ("network", "ALL LISTENING SOCKETS", "ss -tulpn", True),
    ("network", "WEB PORTS 80/443", "ss -tulpn | grep -E ':80|:443' || true", True),
    ("network", "SSH LISTENING", "ss -tulpn | grep sshd || true", True),
    ("network", "ESTABLISHED CONNECTIONS (top remote IPs)",
     "ss -tn state established | awk 'NR>1{print $5}' | sed -E 's/:[0-9]+$//' | sort | uniq -c | sort -rn | head -15", False),
    ("network", "NETWORK INTERFACES", "ip -brief addr", False),

    # --- ssh ---
    ("ssh", "SSHD EFFECTIVE CONFIG (key options)",
     "sshd -T 2>&1 | grep -E 'passwordauthentication|kbdinteractiveauthentication|"
     "challengeresponseauthentication|^port|permitrootlogin|pubkeyauthentication'", True),
    ("ssh", "RECENT AUTH ACTIVITY (fail/accepted)",
     "journalctl -u ssh -u sshd -n 200 --no-pager 2>/dev/null | grep -Ei 'fail|accepted|invalid' | tail -30", True),

    # --- firewall ---
    ("fw", "UFW STATUS", "ufw status verbose", True),
    ("fw", "IPTABLES INPUT CHAIN", "iptables -L INPUT -n -v --line-numbers", True),
    ("fw", "FAIL2BAN STATUS", "fail2ban-client status", True),
    ("fw", "FAIL2BAN JAILS DETAIL", "fail2ban-client status | grep 'Jail list' | sed 's/.*://' | tr ',' '\\n' | "
     "xargs -I{} sh -c 'echo ---{}---; fail2ban-client status {}'", True),

    # --- vpn / proxy (актуально для твоего стека) ---
    ("vpn", "VPN/PROXY LISTENING SERVICES",
     "ss -tulpn | egrep -i 'xray|x2ray|vray|openvpn|wireguard|wg|x-ui|3x-ui' || echo '(ничего не найдено)'", True),
    ("vpn", "WIREGUARD STATUS", "wg show 2>/dev/null || echo '(wg не установлен или нет прав)'", True),
    ("vpn", "X-UI / 3X-UI SERVICE STATUS",
     "systemctl status x-ui --no-pager 2>/dev/null || systemctl status 3x-ui --no-pager 2>/dev/null || "
     "echo '(x-ui сервис не найден)'", True),

    # --- веб / БД ---
    ("web", "NGINX ERROR LOG (last 50)", "tail -n 50 /var/log/nginx/error.log 2>/dev/null || echo '(нет файла)'", True),
    ("web", "APACHE ERROR LOG (last 50)", "tail -n 50 /var/log/apache2/error.log 2>/dev/null || echo '(нет файла)'", True),
    ("web", "PHP-FPM ERROR LOG (last 50)", "tail -n 50 /var/log/php*-fpm.log 2>/dev/null || echo '(нет файла)'", True),
    ("db", "MYSQL PROCESSLIST", "mysql -e 'SHOW FULL PROCESSLIST;' 2>/dev/null || echo '(нет доступа/не запущен)'", False),
    ("db", "MYSQL STATUS", "mysqladmin status 2>/dev/null || echo '(нет доступа/не запущен)'", False),

    # --- docker ---
    ("docker", "DOCKER CONTAINERS", "docker ps --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'", True),
    ("docker", "DOCKER CONTAINERS (ALL, включая остановленные)", "docker ps -a", True),
    ("docker", "DOCKER STOPPED/RESTARTING", "docker ps -a --filter status=exited --filter status=restarting "
     "--format 'table {{.Names}}\\t{{.Status}}'", True),
    ("docker", "DOCKER DISK USAGE", "docker system df", True),

    # --- почта ---
    ("mail", "EXIM QUEUE SIZE", "exim -bpc 2>/dev/null || echo '(exim не установлен)'", True),
    ("mail", "POSTFIX QUEUE SIZE", "postqueue -p 2>/dev/null | tail -1 || echo '(postfix не установлен)'", True),
]

SECTION_NAMES = {
    "general": "Общее", "disk": "Диск", "proc": "Процессы", "systemd": "Systemd/журнал",
    "network": "Сеть", "ssh": "SSH", "fw": "Файрвол", "vpn": "VPN/прокси",
    "web": "Веб-сервер", "db": "БД", "docker": "Docker", "mail": "Почта",
    "vhost": "Поиск vhost/логов по домену (интерактивно, в самом конце)",
}


def print_help_panel():
    """Печатается всегда в начале вывода — краткая справка по параметрам запуска."""
    print("Параметры запуска:")
    print("  --only <секции>   выполнить только перечисленные через запятую секции")
    print("                    например: --only network,vpn,fw")
    print("  --timeout <сек>   таймаут на одну команду, по умолчанию", DEFAULT_TIMEOUT)
    print("  --slow <сек>      порог, после которого команда помечается как медленная (по умолчанию 2.0)")
    print("  --list            показать список доступных секций и выйти")
    print("  --no-vhost        пропустить интерактивный поиск vhost/логов по домену в конце")
    print("  -h, --help        стандартная справка argparse")
    print()
    print("Доступные секции: " + ", ".join(SECTION_NAMES.keys()))


def run_command(command, timeout):
    try:
        result = subprocess.run(
            command, shell=True, executable="/bin/bash", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
        )
        return result.stdout.strip(), None
    except subprocess.TimeoutExpired:
        return None, f"(превышен таймаут {timeout}с — команда могла зависнуть, это тоже диагностический сигнал)"
    except Exception as e:
        return None, f"(ошибка запуска: {e})"


def has(cmd):
    return shutil.which(cmd) is not None


# Где искать конфиги виртуальных хостов
NGINX_VHOST_DIRS = ["/etc/nginx/sites-enabled", "/etc/nginx/sites-available", "/etc/nginx/conf.d"]
APACHE_VHOST_DIRS = ["/etc/apache2/sites-enabled", "/etc/apache2/sites-available",
                     "/etc/httpd/conf.d", "/etc/httpd/sites-enabled"]


def find_vhost_files(domain, dirs, patterns):
    """Ищет конфиг-файлы, где встречается домен рядом с одним из паттернов
    (server_name / ServerName / ServerAlias). Возвращает список найденных путей."""
    existing_dirs = [d for d in dirs if os.path.isdir(d)]
    if not existing_dirs:
        return []
    pattern_re = "|".join(patterns)
    cmd = (
        f"grep -lRiE '({pattern_re}).*{domain}' " + " ".join(existing_dirs) + " 2>/dev/null"
    )
    output, err = run_command(cmd, timeout=10)
    if err or not output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def extract_log_paths(vhost_file):
    """Достаёт из конфига пути access_log/error_log. Только путь, без tail содержимого."""
    cmd = (
        f"grep -Ei 'access_log|error_log|ErrorLog|CustomLog' {vhost_file} 2>/dev/null"
    )
    output, err = run_command(cmd, timeout=10)
    if err or not output:
        return []
    paths = []
    for line in output.splitlines():
        line = line.strip().rstrip(";")
        # апаче использует переменную ${APACHE_LOG_DIR}, подставляем типовое значение
        line = line.replace("${APACHE_LOG_DIR}", "/var/log/apache2")
        parts = line.split()
        # берём первый токен после директивы, похожий на путь
        for token in parts[1:]:
            if token.startswith("/"):
                paths.append(token)
                break
    # убираем дубликаты, сохраняя порядок
    seen = set()
    result = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


def interactive_vhost_search():
    """Запускается последним. Спрашивает домен и ищет:
    1) конфиг виртуального хоста (nginx/apache), где он упомянут;
    2) пути (только пути, без содержимого) к его access_log и error_log.
    Пустой ввод — пропустить."""
    print(f"\n{'=' * 20} [vhost] ПОИСК VHOST И ЛОГОВ ПО ДОМЕНУ {'=' * 20}")
    try:
        domain = input("Введите домен для поиска (Enter — пропустить): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n(ввод недоступен или прерван — секция пропущена)")
        return

    if not domain:
        print("(пропущено пользователем)")
        return

    print(f"\n-- Поиск конфигов nginx для '{domain}' --")
    nginx_files = find_vhost_files(domain, NGINX_VHOST_DIRS, ["server_name"])
    if nginx_files:
        for f in nginx_files:
            print(f"  найден vhost: {f}")
    else:
        print("  (не найдено)")

    print(f"\n-- Поиск конфигов apache для '{domain}' --")
    apache_files = find_vhost_files(domain, APACHE_VHOST_DIRS, ["ServerName", "ServerAlias"])
    if apache_files:
        for f in apache_files:
            print(f"  найден vhost: {f}")
    else:
        print("  (не найдено)")

    all_files = nginx_files + apache_files
    if not all_files:
        print("\n(vhost не найден — пути логов определить не удалось)")
        return

    print(f"\n-- Пути access_log / error_log для '{domain}' (только путь, без содержимого) --")
    any_paths = False
    for f in all_files:
        for path in extract_log_paths(f):
            print(f"  {path}   (из {f})")
            any_paths = True
    if not any_paths:
        print("  (директивы лога в найденных конфигах не обнаружены)")


def main():
    parser = argparse.ArgumentParser(description="Диагностический снапшот сервера")
    parser.add_argument("--only", help="запустить только указанные секции через запятую, "
                                        "например: network,vpn,disk")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                         help=f"таймаут на команду в секундах (по умолчанию {DEFAULT_TIMEOUT})")
    parser.add_argument("--list", action="store_true", help="показать список доступных секций и выйти")
    parser.add_argument("--slow", type=float, default=2.0,
                         help="помечать команды, выполнявшиеся дольше N секунд (по умолчанию 2.0)")
    parser.add_argument("--no-vhost", action="store_true",
                         help="пропустить интерактивный поиск vhost/логов по домену в конце")
    args = parser.parse_args()

    if args.list:
        print("Доступные секции:")
        for tag, name in SECTION_NAMES.items():
            print(f"  {tag:10s} — {name}")
        return

    is_root = os.geteuid() == 0
    wanted = set(args.only.split(",")) if args.only else None

    print("=" * 70)
    print("SERVER DIAGNOSTICS")
    print("=" * 70)
    print_help_panel()
    print("=" * 70)
    if not is_root:
        print("ВНИМАНИЕ: запущено без root — часть секций (ss -p, journalctl, sshd -T,")
        print("iptables, docker) может выдать пустой/неполный вывод из-за прав доступа.")
    print("=" * 70)

    for tag, title, command, needs_root in COMMANDS:
        if wanted and tag not in wanted:
            continue

        # пропускаем секции, если нужной команды нет в системе (без лишнего шума)
        binary = command.split()[0].lstrip("(")
        if not has(binary) and binary not in ("systemctl", "ss"):  # эти двое почти всегда есть
            continue

        print(f"\n{'=' * 20} [{tag}] {title} {'=' * 20}")
        print(f"$ {command}\n")

        t0 = time.monotonic()
        output, err = run_command(command, args.timeout)
        elapsed = time.monotonic() - t0

        if err:
            print(err)
        elif output:
            print(output)
        else:
            print("(no output)")

        if elapsed > args.slow:
            print(f"[выполнялось {elapsed:.1f}с]")

    # Интерактивный поиск vhost/логов по домену — всегда последним,
    # т.к. требует ввода от пользователя и не должен блокировать автоматические секции.
    if not args.no_vhost and (wanted is None or "vhost" in wanted):
        interactive_vhost_search()

    print("\n" + "=" * 70)
    print("DIAGNOSTICS FINISHED")
    print("=" * 70)

import os
import sys

def cleanup():
    script = os.path.abspath(sys.argv[0])

    print("\nCleaning up...")

    # Очистка history в дочернем shell (скорее формальность)
    try:
        subprocess.run(
            "history -c && history -w",
            shell=True,
            executable="/bin/bash",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

    # Очистка файла истории
    try:
        histfiles = [
            os.environ.get("HISTFILE"),
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
        ]

        for histfile in histfiles:
            if histfile and os.path.isfile(histfile):
                open(histfile, "w").close()
                print(f"Cleared: {histfile}")

    except Exception as e:
        print(f"History cleanup error: {e}")

    # Удаляем сам скрипт последним
    try:
        os.remove(script)
        print(f"Removed: {script}")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Cannot remove script: {e}")


if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
