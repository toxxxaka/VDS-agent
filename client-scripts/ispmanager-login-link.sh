#!/usr/bin/env bash
# Одноразовая ссылка входа ISPmanager. Печатать только в личном терминале.
set -euo pipefail
usage() { echo "Usage: sudo $0 [--host IP_OR_DOMAIN] [--user USER]"; }
host=''; user='root'
while (($#)); do
  case $1 in
    --host) (($# >= 2)) || { usage >&2; exit 2; }; host=$2; shift 2 ;;
    --user) (($# >= 2)) || { usage >&2; exit 2; }; user=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ -t 1 ]] || { echo 'A private terminal is required to display the login link' >&2; exit 1; }
[[ $user =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || { echo 'Invalid username' >&2; exit 2; }
mgrctl=/usr/local/mgr5/sbin/mgrctl
[[ -x $mgrctl ]] || { echo "ISPmanager mgrctl not found: $mgrctl" >&2; exit 1; }
command -v openssl >/dev/null || { echo 'openssl is required' >&2; exit 1; }
if [[ -z $host ]]; then
  host=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") {print $(i+1); exit}}')
fi
[[ $host =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ && $host != *..* ]] || { echo 'Invalid host; use --host' >&2; exit 2; }
key=$(openssl rand -hex 24)
PANEL_LOGIN_KEY=$key "$mgrctl" -m ispmgr session.newkey "username=$user" -e 'key=$PANEL_LOGIN_KEY' >/dev/null
printf 'Private login URL for %s:\nhttps://%s:1500/ispmgr?func=auth&key=%s\n' "$user" "$host" "$key"
echo 'Treat this URL as a password and avoid pasting it into tickets or chat.' >&2
