#!/usr/bin/env bash
# Короткий снимок нагрузки, веб/БД/SSH и последних проблем ядра.
set -u
section() { printf '\n== %s ==\n' "$1"; }
section 'RESOURCES'; lsblk 2>/dev/null; free -h 2>/dev/null; printf 'CPU cores: '; nproc
section 'TOP CPU'; ps aux --sort=-%cpu | head -n 15
section 'TOP MEMORY'; ps aux --sort=-%mem | head -n 15
section 'WEB LISTENERS'; ss -ltnp 2>/dev/null | awk 'NR==1 || $4 ~ /:(80|443)$/'
section 'OOM AND DISK KERNEL EVENTS'
journalctl -k -b -p warning -n 300 --no-pager 2>/dev/null \
  | grep -Ei 'oom|out of memory|killed process|i/o error|nvme|ext4.*error|xfs.*error' | tail -n 20 || true
section 'SSH CONFIGURATION'
if command -v sshd >/dev/null; then
  sshd -T 2>/dev/null | grep -E '^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|port|permitrootlogin|pubkeyauthentication) ' || true
fi
section 'SSH ERRORS'; journalctl -u ssh -u sshd -p warning -n 30 --no-pager 2>/dev/null || true
section 'NGINX BUILD OPTIONS'
if command -v nginx >/dev/null; then nginx -V 2>&1 | tr ' ' '\n' | grep '^--with' | head -n 30 || true; fi
section 'MYSQL MEMORY / CONNECTION SETTINGS'
if command -v mysql >/dev/null; then
  mysql --batch --skip-column-names -e "SHOW VARIABLES WHERE Variable_name IN ('innodb_buffer_pool_size','key_buffer_size','max_connections','query_cache_size','tmp_table_size','max_heap_table_size','innodb_log_buffer_size')" 2>/dev/null || true
fi
