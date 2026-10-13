#!/usr/bin/env bash
# Состояние Docker без удаления образов, контейнеров или журналов.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
command -v docker >/dev/null || { echo 'Docker is not installed' >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo 'Docker daemon is unavailable' >&2; exit 1; }
printf 'DOCKER HEALTH\n\nCONTAINERS\n'
docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.RunningFor}}\t{{.Ports}}'
printf '\nUNHEALTHY / RESTARTING\n'
docker ps -a --filter health=unhealthy --format '{{.Names}} {{.Status}}' || true
docker ps -a --filter status=restarting --format '{{.Names}} {{.Status}}' || true
printf '\nRESTART COUNTS\n'
docker ps -aq | while read -r id; do
  [[ -n $id ]] || continue
  docker inspect --format '{{.Name}} restarts={{.RestartCount}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$id"
done | sed 's#^/##' | sort -t= -k2,2nr
printf '\nDISK USAGE\n'
docker system df
printf '\nLARGEST CONTAINER LOGS\n'
find /var/lib/docker/containers -xdev -type f -name '*-json.log' -printf '%s %p\n' 2>/dev/null | sort -nr | head -n 20 | numfmt --field=1 --to=iec --suffix=B 2>/dev/null || true
printf '\nRECENT DOCKER ERRORS\n'
journalctl -u docker -p warning -n 30 --no-pager 2>/dev/null || true
