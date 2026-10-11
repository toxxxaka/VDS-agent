#!/usr/bin/env bash
# Low-rate owner-operated external baseline check. It intentionally targets only
# the two VDS-Agent domains unless VDS_AGENT_ALLOWED_DOMAINS is changed in source.
set -euo pipefail

readonly ALLOWED_DOMAINS=("0x870x4k3r.tech" "monitoring.0x870x4k3r.tech")
readonly REPORT_DIR="${1:-docs/baseline}"
mkdir -p "$REPORT_DIR"
report="$REPORT_DIR/external-$(date -u +%F).md"

{
  echo "# External check — $(date -u +%F)"
  echo
  echo "Run from: $(hostname -s). This script performs low-rate checks only."
  for host in "${ALLOWED_DOMAINS[@]}"; do
    echo
    echo "## $host"
    echo
    echo '```text'
    curl --noproxy '*' -sS -I --connect-timeout 8 "https://$host/" || true
    echo "TRACE:"
    curl --noproxy '*' -sS -o /dev/null -w '%{http_code}\n' -X TRACE --connect-timeout 8 "https://$host/" || true
    echo "TLS 1.2:"
    printf '' | openssl s_client -connect "$host:443" -servername "$host" -tls1_2 2>/dev/null | awk '/Protocol|Cipher|Verify return code/' || true
    echo '```'
  done
  echo
  echo '## Optional tools'
  echo
  echo 'Run these manually from an owner-controlled external host if installed:'
  echo
  echo '```text'
  echo 'nmap -sT -sU --top-ports 100 0x870x4k3r.tech'
  echo 'ssh-audit 0x870x4k3r.tech'
  echo 'testssl.sh --quiet monitoring.0x870x4k3r.tech'
  echo '```'
} >"$report"
printf 'Wrote %s\n' "$report"
