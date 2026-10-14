#!/usr/bin/env bash
# Installs only the independent Sentinel onto its own host. It never touches nginx,
# firewall, SSH, Docker, or VDS Agent files on the monitored server.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh --config /secure/path/sentinel.json [--check] [--plan] [--yes]

--check  Validate prerequisites and configuration without changing the host.
--plan   Print the exact managed paths without changing the host.
--yes    Confirm installation without an interactive prompt.
EOF
}

config=""
check_only=0
plan_only=0
assume_yes=0
while (($#)); do
  case "$1" in
    --config) config=${2:?"--config requires a path"}; shift 2 ;;
    --check) check_only=1; shift ;;
    --plan) plan_only=1; shift ;;
    --yes) assume_yes=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run this installer as root" >&2; exit 1; }
[[ -n "$config" && -f "$config" ]] || { echo "--config must name an existing private JSON file" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
python3 "$root/vds_agent_sentinel.py" --config "$config" --check-config

if (( ! check_only && ! plan_only && ! assume_yes )); then
  if [[ ! -t 0 ]]; then
    echo "non-interactive installation requires --yes" >&2
    exit 2
  fi
  cat <<'EOF'
External Sentinel runs on this separate host and observes a different VDS.
It is optional: without it, VDS Agent keeps all local monitoring, WebUI and
Telegram features, but cannot alert you when the monitored host itself, its
network, DNS or power becomes unavailable. Sentinel has no SSH, WebUI, TOTP,
provider, firewall or action access to that monitored host.
EOF
  read -r -p "Install External Sentinel on this host? [y/N] " answer
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]] || { echo "Sentinel installation cancelled; no files changed."; exit 0; }
fi

cat <<'EOF'
Sentinel-managed paths:
  /usr/local/lib/vds-agent-sentinel/vds-agent-sentinel.py
  /etc/vds-agent-sentinel/sentinel.json
  /etc/systemd/system/vds-agent-sentinel.service
  /etc/systemd/system/vds-agent-sentinel.timer
  /var/lib/vds-agent-sentinel/state.json
It will create the non-login system user vds-sentinel if absent.
It will not modify nginx, SSH, Docker, firewall rules, or any monitored-host files.
EOF
((check_only || plan_only)) && exit 0

if ! getent passwd vds-sentinel >/dev/null; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin --user-group vds-sentinel
fi
install -d -o root -g root -m 0755 /usr/local/lib/vds-agent-sentinel
install -d -o root -g vds-sentinel -m 0750 /etc/vds-agent-sentinel
install -d -o vds-sentinel -g vds-sentinel -m 0750 /var/lib/vds-agent-sentinel
install -o root -g root -m 0755 "$root/vds_agent_sentinel.py" /usr/local/lib/vds-agent-sentinel/vds-agent-sentinel.py
if [[ ! -e /etc/vds-agent-sentinel/sentinel.json ]]; then
  install -o root -g vds-sentinel -m 0640 "$config" /etc/vds-agent-sentinel/sentinel.json
else
  echo "refusing to overwrite existing /etc/vds-agent-sentinel/sentinel.json" >&2
  echo "review it manually, then rerun with a new host or replace it explicitly." >&2
  exit 1
fi
install -o root -g root -m 0644 "$root/vds-agent-sentinel.service" /etc/systemd/system/vds-agent-sentinel.service
install -o root -g root -m 0644 "$root/vds-agent-sentinel.timer" /etc/systemd/system/vds-agent-sentinel.timer
systemd-analyze verify /etc/systemd/system/vds-agent-sentinel.service /etc/systemd/system/vds-agent-sentinel.timer
systemctl daemon-reload
systemctl enable --now vds-agent-sentinel.timer
systemctl start vds-agent-sentinel.service
systemctl --no-pager --full status vds-agent-sentinel.service
