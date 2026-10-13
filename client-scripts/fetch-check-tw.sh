#!/usr/bin/env bash
# Скачать внешний check_tw; выполнять только после сверки SHA-256.
set -euo pipefail
usage() { echo "Usage: $0 [--sha256 HEX] [--run]"; }
expected=''; run=0
while (($#)); do
  case $1 in
    --sha256) (($# >= 2)) || { usage >&2; exit 2; }; expected=$2; shift 2 ;;
    --run) run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -z $expected || $expected =~ ^[[:xdigit:]]{64}$ ]] || { echo 'SHA-256 must have 64 hex digits' >&2; exit 2; }
(( !run )) || [[ -n $expected ]] || { echo '--run requires --sha256' >&2; exit 2; }
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 1; }
temp=$(mktemp); trap 'rm -f -- "$temp"' EXIT
url='https://raw.githubusercontent.com/toxxxaka/tools/main/check_tw'
curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 -o "$temp" "$url"
actual=$(sha256sum "$temp" | awk '{print $1}')
printf 'Source: %s\nSHA-256: %s\n' "$url" "$actual"
if [[ -n $expected && ${expected,,} != $actual ]]; then echo 'Checksum mismatch' >&2; exit 1; fi
if ((run)); then
  echo 'Checksum verified. Running downloaded script.' >&2
  bash "$temp"
else
  echo 'Preview (first 40 lines):'
  sed -n '1,40p' "$temp"
  echo 'No downloaded code was executed.'
fi
