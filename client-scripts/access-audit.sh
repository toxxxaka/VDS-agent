#!/usr/bin/env bash
# Отчёт об SSH и привилегированных доступах, без изменения конфигурации.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
printf 'ACCESS AUDIT — %s\n\n' "$(hostname)"
echo 'USERS WITH LOGIN SHELLS'
awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ {print $1 " (uid=" $3 ", shell=" $7 ")"}' /etc/passwd
printf '\nSUDO MEMBERS\n'
getent group sudo 2>/dev/null || true
getent group wheel 2>/dev/null || true
printf '\nSSH EFFECTIVE SETTINGS\n'
if command -v sshd >/dev/null; then
  sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|allowgroups|maxauthtries) ' || true
fi
printf '\nAUTHORIZED KEYS\n'
find /root /home -xdev -type f -name authorized_keys -printf '%p (%s bytes)\n' 2>/dev/null
printf '\nRECENT SSH LOGINS\n'
last -Fiw | head -n 20 || true
printf '\nRECENT FAILED SSH ATTEMPTS\n'
journalctl -u ssh -u sshd --since '7 days ago' --no-pager -o short-iso 2>/dev/null | grep -Ei 'failed password|invalid user|authentication failure' | tail -n 30 || true
printf '\nFAIL2BAN\n'
if command -v fail2ban-client >/dev/null; then fail2ban-client status 2>/dev/null || true; else echo 'not installed'; fi
