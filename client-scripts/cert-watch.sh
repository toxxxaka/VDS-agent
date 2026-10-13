#!/usr/bin/env bash
# Поиск локальных сертификатов и предупреждение об истечении срока.
set -Eeuo pipefail
usage() { echo "Usage: $0 [--days N]"; }
days=30
if [[ ${1:-} == --days ]]; then days=${2:-}; shift 2; fi
[[ $# -eq 0 && $days =~ ^[0-9]+$ ]] || { usage >&2; exit 2; }
command -v openssl >/dev/null || { echo 'openssl is required' >&2; exit 1; }
now=$(date +%s); count=0; alerts=0
printf 'CERTIFICATE WATCH — warning threshold: %s days\n\n' "$days"
printf '%-7s %-8s %-28s %s\n' 'DAYS' 'STATUS' 'SUBJECT' 'FILE'
while IFS= read -r -d '' cert; do
  end=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2-) || continue
  end_ts=$(date -d "$end" +%s 2>/dev/null) || continue
  left=$(( (end_ts-now)/86400 )); subject=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/^subject= *//')
  status=OK; (( left < 0 )) && status=EXPIRED || (( left <= days )) && status=EXPIRING
  printf '%-7s %-8s %-28.28s %s\n' "$left" "$status" "$subject" "$cert"
  [[ $status == OK ]] || alerts=$((alerts+1)); count=$((count+1))
done < <(find /etc/letsencrypt /etc/ssl /usr/local/mgr5/etc -xdev -type f \( -name '*.pem' -o -name '*.crt' \) -print0 2>/dev/null)
echo "\nCertificates inspected: $count; expiring or expired: $alerts"
exit "$(( alerts > 0 ))"
