#!/usr/bin/env bash
# Сводка по access log в формате combined: коды, IP, URL, User-Agent.
set -euo pipefail
usage() { echo "Usage: $0 LOG_FILE [--top N] [--exclude-ip PREFIX[,PREFIX...]]"; }
log=''; top=20; excludes=''
while (($#)); do
  case $1 in
    --top) (($# >= 2)) || { usage >&2; exit 2; }; top=$2; shift 2 ;;
    --exclude-ip) (($# >= 2)) || { usage >&2; exit 2; }; excludes=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *) [[ -z $log ]] || { usage >&2; exit 2; }; log=$1; shift ;;
  esac
done
if [[ -z $log && -t 0 ]]; then read -r -p 'Access log path: ' log; fi
[[ -f $log && -r $log ]] || { usage >&2; echo 'Log file is missing or unreadable' >&2; exit 2; }
[[ $top =~ ^[0-9]+$ ]] && ((top>=1 && top<=100)) || { usage >&2; exit 2; }
tmp=$(mktemp -d); trap 'rm -rf -- "$tmp"' EXIT
# Разбираем обычный combined log. Для нестандартного log_format точность полей не гарантируется.
awk -F'"' -v exclusions="$excludes" '
  BEGIN {n=split(exclusions,excluded,",")}
  NF>=6 {
    split($1,pre," "); ip=pre[1]; skip=0
    for(i=1;i<=n;i++) if(excluded[i]!="" && index(ip,excluded[i])==1) skip=1
    if(skip) next
    split($3,post," "); code=post[1]
    split($2,request," "); path=request[2]
    if(code !~ /^[1-5][0-9][0-9]$/) next
    print code >> status; print ip >> ips; print path >> paths; print $6 >> agents
    count++
  }
  END {printf "Parsed requests: %d\n",count > "/dev/stderr"}
' status="$tmp/status" ips="$tmp/ips" paths="$tmp/paths" agents="$tmp/agents" "$log"
for kind in status ips paths agents; do
  printf '\nTOP %s %s\n' "$top" "${kind^^}"
  [[ -f $tmp/$kind ]] || { echo '(no entries)'; continue; }
  sort "$tmp/$kind" | uniq -c | sort -nr | head -n "$top"
done
