#!/usr/bin/env bash
# Сведения о PID и открытых им сетевых соединениях.
set -euo pipefail
usage() { echo "Usage: $0 PID"; }
pid=${1:-}; [[ $# -eq 1 && $pid =~ ^[1-9][0-9]*$ ]] || { usage >&2; exit 2; }
[[ -d /proc/$pid ]] || { echo "PID $pid does not exist" >&2; exit 1; }
printf 'PROCESS\n'; ps -fp "$pid"
printf '\nEXECUTABLE\n'; readlink -f -- "/proc/$pid/exe" || true
printf '\nWORKING DIRECTORY\n'; readlink -f -- "/proc/$pid/cwd" || true
printf '\nNETWORK FILES\n'
if command -v lsof >/dev/null; then lsof -Pan -p "$pid" -i 2>/dev/null || true; else echo 'lsof is not installed'; fi
