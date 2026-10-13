#!/usr/bin/env bash
# Быстрая диагностика интерфейса, маршрута и внешней связности.
set -u
usage() { echo "Usage: $0 [--interface IFACE] [--url HTTPS_URL]"; }
iface=''; url='https://www.google.com/'
while (($#)); do
  case $1 in
    --interface) (($# >= 2)) || { usage >&2; exit 2; }; iface=$2; shift 2 ;;
    --url) (($# >= 2)) || { usage >&2; exit 2; }; url=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ $url == https://* || $url == http://* ]] || { echo 'URL must start with http:// or https://' >&2; exit 2; }
command -v ip >/dev/null || { echo 'iproute2 is required' >&2; exit 1; }
route=$(ip -4 route show default 2>/dev/null | head -n 1)
if [[ -z $iface ]]; then iface=$(awk '{for(i=1;i<NF;i++) if($i=="dev") {print $(i+1); exit}}' <<< "$route"); fi
[[ -n $iface ]] || { echo 'No default IPv4 interface. Supply --interface.' >&2; exit 1; }
ip link show dev "$iface" >/dev/null 2>&1 || { echo "Unknown interface: $iface" >&2; exit 2; }
route=$(ip -4 route show default dev "$iface" 2>/dev/null | head -n 1)
gateway=$(awk '{for(i=1;i<NF;i++) if($i=="via") {print $(i+1); exit}}' <<< "$route")
printf 'INTERFACE: %s\nDEFAULT ROUTE: %s\n\nIP ADDRESSES\n' "$iface" "${route:-none}"
ip -br address show dev "$iface"
printf '\nNEIGHBORS\n'; ip neigh show dev "$iface" | head -n 30
if [[ -n $gateway ]]; then
  printf '\nGATEWAY PING (%s)\n' "$gateway"; ping -c 1 -W 2 "$gateway" 2>&1 | tail -n 3 || true
fi
printf '\nPUBLIC IP PING (8.8.8.8)\n'; ping -c 1 -W 2 8.8.8.8 2>&1 | tail -n 3 || true
if command -v curl >/dev/null; then
  printf '\nHTTP CHECK (%s)\n' "$url"
  curl -sS -L -I --connect-timeout 5 --max-time 12 -o /dev/null \
    -w 'HTTP %{http_code}; remote IP %{remote_ip}; total %{time_total}s\n' "$url" || true
fi
printf '\nWEB LISTENERS\n'; ss -ltnp 2>/dev/null | awk 'NR==1 || $4 ~ /:(80|443)$/'
