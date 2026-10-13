#!/usr/bin/env bash
# Статус критичных сервисов, открытые порты и последние ошибки.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
services=(nginx apache2 caddy php8.1-fpm php8.2-fpm php8.3-fpm mysql mariadb exim4 redis-server docker ihttpd)
printf 'SERVICE CHECK — %s\n' "$(date -Is)"
printf '%-18s %-12s %s\n' SERVICE STATE 'RECENT ERRORS'
for service in "${services[@]}"; do
  systemctl list-unit-files "$service.service" --no-legend 2>/dev/null | grep -q "^$service.service" || continue
  state=$(systemctl is-active "$service" 2>/dev/null || true)
  errors=$(journalctl -u "$service" -p warning -n 1 --no-pager -o cat 2>/dev/null | tr '\n' ' ')
  printf '%-18s %-12s %.100s\n' "$service" "${state:-unknown}" "${errors:--}"
done
printf '\nFAILED UNITS\n'
systemctl --failed --no-pager --no-legend || true
printf '\nLISTENING PORTS (web/mail/db)\n'
ss -ltnp 2>/dev/null | awk 'NR==1 || /:(80|443|25|465|587|3306|5432|6379) /'
printf '\nCONFIGURATION TESTS\n'
for spec in 'nginx:nginx -t' 'apache2:apache2ctl configtest' 'caddy:caddy validate --config /etc/caddy/Caddyfile'; do
  name=${spec%%:*}; cmd=${spec#*:}
  command -v "${cmd%% *}" >/dev/null || continue
  if eval "$cmd" >/dev/null 2>&1; then echo "OK   $name"; else echo "FAIL $name"; fi
done
