#!/usr/bin/env bash
# Крупнейшие файлы в выбранном дереве без перехода на другие файловые системы.
set -euo pipefail
usage() { echo "Usage: $0 [DIRECTORY] [--top N] [--min-mib N]"; }
root=''; top=50; min=100
while (($#)); do
  case $1 in
    --top) (($# >= 2)) || { usage >&2; exit 2; }; top=$2; shift 2 ;;
    --min-mib) (($# >= 2)) || { usage >&2; exit 2; }; min=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *) [[ -z $root ]] || { usage >&2; exit 2; }; root=$1; shift ;;
  esac
done
if [[ -z $root ]]; then
  if [[ -t 0 ]]; then read -r -p 'Directory to scan [/var]: ' root; fi
  root=${root:-/var}
fi
[[ -d $root && $root != / ]] || { echo 'Choose an existing directory below /' >&2; exit 2; }
[[ $top =~ ^[0-9]+$ && $min =~ ^[0-9]+$ ]] && ((top>=1 && top<=500)) || { usage >&2; exit 2; }
printf 'Largest files under %s (same filesystem, >= %s MiB):\n' "$root" "$min"
find "$root" -xdev -type f -size +"${min}"M -printf '%s\t%p\n' 2>/dev/null \
  | sort -nr | head -n "$top" | numfmt --field=1 --to=iec --suffix=B 2>/dev/null || true
