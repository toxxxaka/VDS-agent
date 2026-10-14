# External Sentinel

VDS Agent on a failed host cannot report a total host, network, power or provider outage: its WebUI, Telegram worker and monitoring services fail with that host. Sentinel is a small independent observer installed on a different machine and trust domain.

It makes outbound DNS, TCP, TLS and HTTPS checks only. It has no inbound listener, SSH key, VDS Agent session, TOTP secret, provider API token or ability to restart the monitored server. A `DOWN` alert means that the configured endpoint is unreachable from the Sentinel host; it does not prove that the server is powered off.

## Why it is optional

Choose Sentinel when an independent alert about total server unavailability is useful. It must run on another host, region, home machine, or managed uptime platform; installing it beside VDS Agent defeats its purpose.

Choosing not to install it does not remove any VDS Agent feature. Local metrics, incidents, WebUI, Telegram, MCP and local alerts work normally while the monitored host is reachable. The only missing capability is an external notification when that host, its network, DNS, or power is completely unavailable.

The Sentinel installer asks for confirmation before it changes its host. It is not part of the monitored-server deployment and does not connect to that server over SSH. For automated installation, pass `--yes` after reviewing `--check` and `--plan`.

## AMS configuration

For the current deployment, configure these two independent HTTPS targets:

| Name | URL |
| --- | --- |
| VDS Agent release | `https://vds-agent.0x870x4k3r.tech/` |
| VDS Agent beta | `https://betatest.0x870x4k3r.tech/` |

Copy `sentinel/sentinel.json.example` to a root-readable private file on AMS and replace only the two Telegram placeholders. Use a separate alert-only bot where possible. Its token is kept on AMS in `/etc/vds-agent-sentinel/sentinel.json`, never in this repository or on the monitored host.

```bash
sudo install -d -m 0700 /root/vds-agent-sentinel
sudo cp sentinel/sentinel.json.example /root/vds-agent-sentinel/sentinel.json
sudoedit /root/vds-agent-sentinel/sentinel.json
sudo ./sentinel/install.sh --config /root/vds-agent-sentinel/sentinel.json --check
sudo ./sentinel/install.sh --config /root/vds-agent-sentinel/sentinel.json --plan
sudo ./sentinel/install.sh --config /root/vds-agent-sentinel/sentinel.json
# For a reviewed non-interactive provisioner only:
# sudo ./sentinel/install.sh --config /root/vds-agent-sentinel/sentinel.json --yes
```

The installer creates only the non-login `vds-sentinel` account and the following paths on AMS:

```text
/usr/local/lib/vds-agent-sentinel/
/etc/vds-agent-sentinel/
/var/lib/vds-agent-sentinel/
/etc/systemd/system/vds-agent-sentinel.service
/etc/systemd/system/vds-agent-sentinel.timer
```

It does not alter nginx, SSH, Docker, firewall rules, default vhost or any files on the monitored VDS. It validates the private configuration and runs `systemd-analyze verify` before enabling the timer. Existing Sentinel configuration is never overwritten.

## Alert semantics

A probe runs every minute with a small random delay. A target sends one `DOWN` alert after three consecutive failures. It sends one recovery alert after two consecutive successes. The saved state is local to AMS and contains only target state, timestamps and diagnostics; it contains no Telegram token.

The failure notification identifies the first failed layer: `dns`, `tcp`, `tls`, or `https`. This avoids treating a generic HTTP error as a host-power failure.

## Operations

```bash
sudo systemctl status vds-agent-sentinel.timer
sudo systemctl status vds-agent-sentinel.service
sudo journalctl -u vds-agent-sentinel.service -n 100 --no-pager
sudo cat /var/lib/vds-agent-sentinel/state.json
sudo systemctl start vds-agent-sentinel.service  # one immediate probe
```

To temporarily suppress expected maintenance alerts, stop the timer before the maintenance window and start it afterwards:

```bash
sudo systemctl stop vds-agent-sentinel.timer
sudo systemctl start vds-agent-sentinel.timer
```

The first successful probe establishes baseline state and sends no alert. A notification-delivery failure is logged on the Sentinel host; it must not be confused with the probe result.
