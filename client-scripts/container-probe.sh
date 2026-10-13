#!/usr/bin/env bash
# HTTP-проверка из указанного Docker-контейнера.
set -euo pipefail
usage() { echo "Usage: $0 CONTAINER [URL]  (default: http://127.0.0.1:3000/)"; }
container=${1:-}; url=${2:-http://127.0.0.1:3000/}
[[ $# -ge 1 && $# -le 2 && -n $container && $container != -* ]] || { usage >&2; exit 2; }
[[ $url == http://* || $url == https://* ]] || { usage >&2; exit 2; }
command -v docker >/dev/null || { echo 'docker is required' >&2; exit 1; }
docker inspect "$container" >/dev/null 2>&1 || { echo "Unknown container: $container" >&2; exit 1; }
printf 'HTTP probe inside %s: %s\n' "$container" "$url"
if docker exec "$container" wget -S --spider -T 8 "$url"; then exit 0; fi
if docker exec "$container" curl -fsSI --connect-timeout 5 --max-time 10 "$url"; then exit 0; fi
echo 'Probe failed; ensure wget or curl is present inside the container' >&2
exit 1
