#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 077
usage() { echo "Usage: $0 [--dry-run] OLD_IP NEW_IP"; }
dry=0; old=''; new=''
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *) if [[ -z $old ]]; then old=$arg; elif [[ -z $new ]]; then new=$arg; else usage >&2; exit 2; fi ;;
  esac
done
[[ -n $old && -n $new ]] || { usage >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
python3 - "$old" "$new" <<'PY'
import ipaddress, sys
try:
    a, b = (ipaddress.IPv4Address(x) for x in sys.argv[1:])
    if a == b or not (a.is_global and b.is_global):
        raise ValueError("addresses must be distinct public IPv4")
except ValueError as exc:
    sys.exit(str(exc))
PY
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  green=$'\033[32m'; yellow=$'\033[33m'; red=$'\033[31m'; reset=$'\033[0m'
else green=''; yellow=''; red=''; reset=''; fi
say() { printf '%s\n' "$*"; }
warn() { printf '%s%s%s\n' "$yellow" "$*" "$reset"; }
bad() { printf '%s%s%s\n' "$red" "$*" "$reset"; }
ok() { printf '%s%s%s\n' "$green" "$*" "$reset"; }
panel='none'
[[ -f /usr/local/mgr5/etc/ihttpd.conf ]] && panel='ISPmanager'
if [[ -d /usr/local/fastpanel2 || -d /etc/fastpanel || -d /etc/fastpanel2 ]]; then
  [[ $panel == none ]] && panel='FASTPANEL' || panel='ISPmanager + FASTPANEL'
fi
say "Detected panel: $panel"
[[ $panel != none ]] || { bad "No supported panel detected"; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
manifest=$tmp/manifest
: > "$manifest"
old_re=$(printf '%s' "$old" | sed 's/\./\\./g')
roots=(/usr/local/mgr5/etc /usr/local/fastpanel2/etc /usr/local/fastpanel2/conf
       /etc/fastpanel /etc/fastpanel2 /etc/nginx /etc/apache2 /etc/caddy
       /etc/exim4 /etc/mysql)
for root in "${roots[@]}"; do
  [[ -d $root ]] || continue
  while IFS= read -r -d '' file; do
    if grep -Iq . "$file" && grep -Eq "(^|[^0-9.])$old_re($|[^0-9.])" "$file"; then
      case "$file" in
        /usr/local/mgr5/etc/ihttpd.conf) group=ihttpd ;;
        /usr/local/mgr5/*) group=panel ;;
        /usr/local/fastpanel2/*|/etc/fastpanel/*|/etc/fastpanel2/*) group=fastpanel ;;
        /etc/nginx/*) group=nginx ;;
        /etc/apache2/*) group=apache2 ;;
        /etc/caddy/*) group=caddy ;;
        /etc/exim4/*) group=exim4 ;;
        /etc/mysql/*) group=mysql ;;
        *) group=other ;;
      esac
      printf '%s\t%s\n' "$group" "$file" >> "$manifest"
    fi
  done < <(find "$root" -xdev -maxdepth 8 -type f -size -2048k -print0 2>/dev/null)
done
sort -u "$manifest" -o "$manifest"
if [[ ! -s $manifest ]]; then ok "No exact OLD_IP occurrences in selected text configuration files."; exit 0; fi
say "Files to change:"
cat "$manifest"
if (( dry )); then warn "DRY RUN: no files changed and no services reloaded."; exit 0; fi
backup=/var/backups/change-ip-$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir -m 700 -- "$backup"
say "Backup: $backup"
rollback() {
  trap - ERR
  bad "Unexpected error: restoring all files from backup"
  while IFS=$'\t' read -r group file; do
    if [[ -f $backup$file ]]; then cp -a -- "$backup$file" "$file"; fi
  done < "$manifest"
  return 0
}
while IFS=$'\t' read -r group file; do
  if [[ $(stat -c %h -- "$file") -ne 1 ]]; then
    bad "Hard-linked file cannot be changed safely: $file"
    exit 1
  fi
  cp -a --parents -- "$file" "$backup"
done < "$manifest"
trap rollback ERR
while IFS=$'\t' read -r group file; do
  python3 - "$file" "$old" "$new" <<'PY'
import os, re, shutil, sys, tempfile
path, old, new = sys.argv[1:]
pattern = re.compile(rb'(?<![0-9.])' + re.escape(old.encode()) + rb'(?![0-9.])')
with open(path, 'rb') as stream:
    data = stream.read()
updated = pattern.sub(new.encode(), data)
if updated == data:
    sys.exit(0)
fd, temp = tempfile.mkstemp(prefix='.change-ip-', dir=os.path.dirname(path))
try:
    with os.fdopen(fd, 'wb') as stream:
        stream.write(updated)
        stream.flush()
        os.fsync(stream.fileno())
    st = os.stat(path)
    os.chown(temp, st.st_uid, st.st_gid)
    shutil.copystat(path, temp)
    os.replace(temp, path)
except BaseException:
    if os.path.exists(temp): os.unlink(temp)
    raise
PY
done < "$manifest"
trap - ERR
say "Residual OLD_IP matches:"
residual=0
while IFS=$'\t' read -r group file; do
  if grep -Eq "(^|[^0-9.])$old_re($|[^0-9.])" "$file"; then bad "$file"; residual=1; fi
done < "$manifest"
(( residual == 0 )) && ok "None in modified files."
declare -A checked=()
declare -A changed=()
while IFS=$'\t' read -r group file; do changed[$group]=1; done < "$manifest"
validate() {
  local group=$1; shift
  [[ -n ${changed[$group]:-} ]] || return 0
  if ! command -v "$1" >/dev/null 2>&1; then
    warn "$group: validation tool unavailable; service untouched"; checked[$group]=skip; return
  fi
  if "$@" >"$tmp/$group.check" 2>&1; then
    ok "$group: configuration valid"; checked[$group]=ok
  else
    bad "$group: invalid configuration; restoring its changed files"
    sed -n '1,12p' "$tmp/$group.check"
    while IFS=$'\t' read -r g file; do
      [[ $g == "$group" && -f $backup$file ]] && cp -a -- "$backup$file" "$file"
    done < "$manifest"
    checked[$group]=failed
  fi
}
validate nginx nginx -t
validate apache2 apache2ctl configtest
validate caddy caddy validate --config /etc/caddy/Caddyfile
validate exim4 exim4 -bV
if command -v mysqld >/dev/null 2>&1; then
  validate mysql mysqld --validate-config
elif command -v mariadbd >/dev/null 2>&1; then
  validate mysql mariadbd --validate-config
else
  [[ -z ${changed[mysql]:-} ]] || { warn "mysql: no validator; service untouched"; checked[mysql]=skip; }
fi
for group in panel fastpanel ihttpd; do
  if [[ -n ${changed[$group]:-} && -z ${checked[$group]:-} ]]; then
    warn "$group: no documented reliable validator; service untouched; restart manually after review"; checked[$group]=skip
  fi
done
say "Service reload/restart:"
fail=0
for group in nginx apache2 caddy exim4 mysql ihttpd panel fastpanel; do
  [[ ${checked[$group]:-} == failed || ${checked[$group]:-} == skip ]] && fail=1
done
for group in nginx apache2 caddy exim4 mysql ihttpd; do
  [[ ${checked[$group]:-} == ok ]] || continue
  service=$group
  [[ $group == mysql ]] && { systemctl list-unit-files mariadb.service --no-legend 2>/dev/null | grep -q '^mariadb.service' && service=mariadb || service=mysql; }
  if ! systemctl list-unit-files "$service.service" --no-legend 2>/dev/null | grep -q "^$service.service"; then
    warn "$service: unit not installed"; continue
  fi
  if ! systemctl is-active --quiet "$service"; then warn "$service: inactive; not started automatically"; continue; fi
  if systemctl reload-or-restart "$service" && systemctl is-active --quiet "$service"; then
    ok "$service: active after reload/restart"
  else bad "$service: reload/restart failed"; fail=1; fi
done
if systemctl is-active --quiet systemd-resolved && command -v resolvectl >/dev/null; then
  resolvectl flush-caches && ok "systemd-resolved DNS cache flushed"
fi
say "Failed units:"
systemctl --failed --no-pager --no-legend || true
if [[ $panel == *ISPmanager* ]]; then
  warn "Check IP assignments in ISPmanager: DNS, Sites, DB servers, Mail domains."
  warn "Alternative DB instances managed by ISPmanager require separate migration/backup."
fi
say "Backup retained: $backup"
(( residual == 0 && fail == 0 )) && ok "Finished" || { bad "Finished with issues"; exit 1; }
