#!/usr/bin/env bash
# Инвентаризация резервных копий: размер, возраст и свободное место.
set -Eeuo pipefail
usage() { echo "Usage: $0 [--days N]"; }
days=7
if [[ ${1:-} == --days ]]; then days=${2:-}; shift 2; fi
[[ $# -eq 0 && $days =~ ^[0-9]+$ ]] || { usage >&2; exit 2; }
roots=(/var/backups /var/lib/backup /usr/local/mgr5/var/backup /usr/local/fastpanel2/backups /home /var/www /opt)
printf 'BACKUP AUDIT — stale threshold: %s days\n\n' "$days"
printf '%-10s %-8s %-10s %s\n' 'SIZE' 'AGE' 'NEWEST' 'PATH'
printf '%-10s %-8s %-10s %s\n' '----' '---' '------' '----'
declare -A seen=()
while IFS= read -r -d '' path; do
  [[ -n ${seen[$path]:-} ]] && continue; seen[$path]=1
  size=$(du -shx -- "$path" 2>/dev/null | awk '{print $1}')
  newest=$(find "$path" -xdev -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 || true)
  if [[ -n $newest ]]; then
    ts=${newest%% *}; file=${newest#* }; age=$(( ($(date +%s) - ${ts%.*}) / 86400 ))
    printf '%-10s %-8s %-10s %s\n' "${size:-?}" "${age}d" "$(basename -- "$file")" "$path"
  else
    printf '%-10s %-8s %-10s %s\n' "${size:-?}" 'empty' '-' "$path"
  fi
done < <(for root in "${roots[@]}"; do
  [[ -d $root ]] || continue
  find "$root" -xdev -maxdepth 6 -type d \( -iname backup -o -iname backups -o -iname backup* \) -print0 2>/dev/null
done)
printf '\nFilesystem free space:\n'
df -hP / /var /home 2>/dev/null | awk '!seen[$1]++'
echo 'Review retention and test restoration separately; this script does not modify backups.'
