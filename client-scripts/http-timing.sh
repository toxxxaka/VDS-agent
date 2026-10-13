#!/usr/bin/env bash
# DNS/TCP/TLS/TTFB для указанного URL.
set -euo pipefail
usage() { echo "Usage: $0 URL [--repeat N]"; }
url=${1:-}; [[ $url == http://* || $url == https://* ]] || { usage >&2; exit 2; }
shift
repeat=1
while (($#)); do
  case $1 in
    --repeat) (($# >= 2)) || { usage >&2; exit 2; }; repeat=$2; shift 2 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ $repeat =~ ^[0-9]+$ ]] && ((repeat >= 1 && repeat <= 20)) || { echo 'Repeat must be 1..20' >&2; exit 2; }
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 1; }
for ((i=1;i<=repeat;i++)); do
  printf 'Request %d/%d: %s\n' "$i" "$repeat" "$url"
  curl -sS -L -o /dev/null --connect-timeout 5 --max-time 30 \
    -w $'DNS: %{time_namelookup}s\nTCP: %{time_connect}s\nTLS: %{time_appconnect}s\nTTFB: %{time_starttransfer}s\nTotal: %{time_total}s\nHTTP: %{http_code}\nRemote IP: %{remote_ip}\n' "$url"
done
