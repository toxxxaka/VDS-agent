#!/usr/bin/env bash
# Проверка одного домена: DNS, HTTP(S), TLS, vhost и журналы ошибок.
set -Eeuo pipefail

usage() { echo "Usage: $0 DOMAIN [--no-ipv6]"; }
domain=${1:-}
[[ -n $domain && $domain != -* ]] || { usage >&2; exit 2; }
ipv6=1
case ${2:-} in
  '') ;;
  --no-ipv6) ipv6=0 ;;
  *) usage >&2; exit 2 ;;
esac
[[ $# -le 2 ]] || { usage >&2; exit 2; }
[[ $domain =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && $domain != *..* ]] || { echo "Invalid domain" >&2; exit 2; }

red=$'\033[31m'; green=$'\033[32m'; yellow=$'\033[33m'; reset=$'\033[0m'
[[ -t 1 && -z ${NO_COLOR:-} ]] || red=green=yellow=reset=''
ok() { printf '%sOK%s  %s\n' "$green" "$reset" "$*"; }
warn() { printf '%sWARN%s %s\n' "$yellow" "$reset" "$*"; }
bad() { printf '%sFAIL%s %s\n' "$red" "$reset" "$*"; }
title() { printf '\n%s\n' "$1"; }

title "SITE CHECK: $domain"
title "DNS"
if command -v dig >/dev/null; then
  a=$(dig +short A "$domain" | paste -sd, -); aaaa=$(dig +short AAAA "$domain" | paste -sd, -)
else
  a=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, -)
  aaaa=$(getent ahostsv6 "$domain" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, -)
fi
[[ -n $a ]] && ok "A: $a" || warn "No A record found"
(( ipv6 )) && { [[ -n $aaaa ]] && ok "AAAA: $aaaa" || warn "No AAAA record found"; }

title "HTTP"
if command -v curl >/dev/null; then
  for scheme in http https; do
    output=$(curl -sSIL --max-redirs 8 --connect-timeout 5 --max-time 15 -o /dev/null -w '%{http_code} %{url_effective} %{remote_ip}' "$scheme://$domain/" 2>&1) || { bad "$scheme: $output"; continue; }
    ok "$scheme: $output"
  done
else warn "curl is not installed"; fi

title "TLS"
if command -v openssl >/dev/null; then
  cert=$(timeout 12 openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -enddate 2>/dev/null) || cert=''
  [[ -n $cert ]] && ok "$cert" || warn "Could not obtain TLS certificate"
else warn "openssl is not installed"; fi

title "VHOST"
found=0
for root in /etc/nginx /etc/apache2 /etc/caddy /usr/local/fastpanel2; do
  [[ -d $root ]] || continue
  matches=$(grep -RIl --include='*.conf' --include='Caddyfile' --include='*.caddy' -F -- "$domain" "$root" 2>/dev/null | head -n 15 || true)
  if [[ -n $matches ]]; then printf '%s\n' "$matches"; found=1; fi
done
(( found )) || warn "No vhost configuration containing the exact domain was found"

title "RECENT RELATED ERRORS"
shown=0
for log in /var/log/nginx/error.log /var/log/apache2/error.log /var/log/caddy/*.log; do
  [[ -f $log ]] || continue
  lines=$(tail -n 500 -- "$log" 2>/dev/null | grep -Fi -- "$domain" | tail -n 10 || true)
  [[ -z $lines ]] || { printf '%s\n' "$log:" "$lines"; shown=1; }
done
(( shown )) || echo "No domain-specific errors found in the standard logs."
