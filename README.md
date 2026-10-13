# VDS Agent

[![CI](https://github.com/toxxxaka/VDS-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/toxxxaka/VDS-agent/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

VDS Agent is a private, self-hosted monitoring and operations console for a single Ubuntu or Debian server. It combines Telegram alerts and commands, an authenticated HTTPS WebUI, lightweight local metrics, incident history, and a strictly allow-listed diagnostics backend shared by the WebUI, Telegram AI and MCP.

It is intended for personal infrastructure. It is not a public shell, a multi-tenant monitoring platform, or a replacement for a full observability stack.

## Features

### Monitoring and incidents

- Tracks CPU, load average, RAM, cache, swap, filesystem capacity and inodes, Linux PSI pressure, network throughput, packet rates, TCP states, SYN-RECV and disk I/O.
- Detects OOM-killer events and external SSH logins.
- Stores local SQLite telemetry for 30 days and exposes 1h, 6h, 24h, 7d and 30d charts. Raw points are retained for short ranges; bounded 5-minute and hourly rollups serve long ranges without hiding peaks or sending excessive data to the browser.
- Opens one incident per active condition, records later observations, then closes it automatically after recovery. Recovery timestamps and diagnostic snapshots remain available.
- Can persist Telegram deliveries in a bounded SQLite outbox, so a temporary Telegram failure cannot stop monitoring or silently discard an alert. This feature is disabled by default.
- Separates ICMP diagnostics from availability: repeated TCP/HTTP checks determine `UP`, `DEGRADED`, `DOWN` or `UNKNOWN`; an ICMP timeout alone never means a server is down.

### Telegram bot and AI diagnostics

The Telegram bot covers status, CPU/RAM/disk/load, uptime, daily reporting, remote checks, SSH sessions, recent logins, controlled session termination and power actions. Sensitive actions use explicit confirmation.

`/ai` runs only bounded local diagnostic tools and can use an optional private OpenAI-compatible Timeweb Agent for interpretation:

```text
/ai help
/ai processes
/ai cpu
/ai memory
/ai disk
/ai network
/ai services
/ai logs
/ai incidents
/ai Почему сервер тормозит? Проверь процессы, память, диск и последние ошибки.
```

The default answer is concise and evidence-first. It identifies measured processes with PID, user, CPU, RSS, command and uptime where relevant. If the AI provider is unavailable, the bot returns a clearly labelled local diagnostic result rather than inventing an explanation.

### WebUI

The mobile-first HTTPS interface works in a regular browser and Telegram Mini App.

- **Dashboard** — current CPU, memory, disk, network, active problems, monitored services and recent diagnostics.
- **Metrics** — live local charts for CPU, memory, RX/TX and disk I/O.
- **AI** — a server-side streaming proxy to the optional private Timeweb Agent. The browser never receives its token.
- **Tools** — incidents, activity/audit, diagnostics, backups, client script library, firewall, TLS/password/network tools, SSH and power actions.

Tools also includes **Safe Console**, a Linux-shell-shaped read-only console. It offers history, completions and contextual help for fixed diagnostics such as `processes cpu`, `services failed`, `logs nginx.service`, `network sockets` and `metrics 24h`. It rejects shell syntax, arbitrary paths and unrecognised arguments; it never executes user-entered shell commands.

### MCP

An optional Streamable HTTP MCP service exposes the same bounded **read-only** diagnostic backend to ChatGPT. It supports current status, load/process/service diagnostics, redacted journals, metrics, incidents, availability and self-monitoring. Administrative actions are intentionally unavailable through MCP.

See [MCP and Telegram AI](docs/MCP.md) for connection settings and tools.

## Architecture

```text
Telegram bot (v3.py)                     HTTPS browser / Telegram Mini App
      │                                              │
      ├── alerts, commands, auth                      └── v4/webapp.py
      └── Telegram /ai                                       │
                                                               ├── static v4/ui/
Health and OOM monitors ──► incidents + snapshots ──► SQLite WAL
Snapshot timer ───────────► local metric samples             │
                                                               ├── agent_tools.py
ChatGPT MCP ─────────────────────────────────────────────────┤
                                                               └── restricted helpers
                                                                        │
                                                                  operating system
```

Metric samples and incident snapshots are separate data sets: inexpensive periodic telemetry is retained for charts, while snapshots are created only around incidents.

### Reliability controls

The application uses SQLite WAL for telemetry, incident history, audit data and bounded background work. Diagnostic tasks have explicit lifecycle events, idempotency keys, cancellation requests and conservative retry rules: only read-only diagnostics may be recovered after a worker restart. Controlled operations and backups are never replayed automatically.

Optional controls in `config/monitoringbot.json` keep new behaviour reviewable:

- **Flight Recorder** retains a small in-memory window of recent telemetry and writes it only when an incident is opened.
- **Adaptive baseline** calculates an hourly local baseline in shadow mode. It records potential anomalies but never changes alert delivery or thresholds automatically.
- **Telegram outbox** retries failed notification delivery with bounded backoff and deduplication.
- **Incident Intelligence** detects failed service units, captures bounded forensics and runs listener/IOC checks in detect-only mode.
- **Recovery Studio** loads tracked YAML runbooks for dry-runs and audited approval workflows; YAML never executes shell commands.

All optional controls are disabled by default. Validate a prospective non-secret configuration before deployment:

```bash
python3 -m v4.cli check-config
```

## Security model

- HTTPS and reverse-proxy IP allow-lists for direct browser access.
- Telegram Mini App `initData` validation, Telegram user allow-list and TOTP.
- Server-side sessions with secure cookie attributes and expiry.
- A distinct bearer token for MCP.
- Narrow root-owned helpers for privileged operations.
- Short-lived, caller-bound confirmations for destructive operations.
- SQLite audit records for authentication, diagnostics and actions.
- No arbitrary shell, filesystem, `sudo`, `nft` or root endpoint in the WebUI, Telegram AI or MCP.
- Optional AIDE integrity checking; keep it disabled while actively changing
  the host, then create and review a trusted baseline before enabling it.

Secrets must stay outside the repository. Never commit Telegram tokens, TOTP secrets, MCP/AI tokens, private keys, session/runtime databases or private allow-lists. See [SECURITY.md](SECURITY.md).

## Requirements

- Ubuntu 24.04 LTS or a compatible Debian-based system
- Python 3.11+ and systemd
- SQLite, nftables and nginx (or an equivalent HTTPS reverse proxy)
- A Telegram bot for Telegram functionality
- Optional: an OpenAI-compatible private AI endpoint and an MCP client

Python dependencies are declared in `requirements.txt`: `psutil`, `requests`, `mcp` and `uvicorn`.

## Installation and configuration

Keep source, private configuration and runtime state separate:

```text
/opt/monitoringbot/          deployed application code
/etc/monitoringbot-main/     private configuration and secrets
/etc/monitoringbot/          private allow-lists
/var/lib/monitoringbot/      SQLite and runtime state
```

1. Clone the repository into a reviewable source checkout and create a Python virtual environment for deployment.
2. Install `requirements.txt` into that environment.
3. Copy only required `config/*.example` files to the private configuration directories. Replace placeholders there, never in the source checkout.
4. Install and review the relevant units, root helpers, sudoers examples and nginx virtual hosts from `systemd/`.
5. Validate unit files and nginx before enabling or reloading anything.
6. Run the tests and use the health-gated procedure in [docs/OPERATIONS.md](docs/OPERATIONS.md).

Private files commonly include:

```text
/etc/monitoringbot-main/telegram.env
/etc/monitoringbot-main/auth.json
/etc/monitoringbot-main/health.json
/etc/monitoringbot-main/servers.json
/etc/monitoringbot-main/timeweb-ai.env       # optional
/etc/monitoringbot-main/mcp.env              # optional
/etc/monitoringbot/ssh-allowlist.json
```

Set restrictive ownership and permissions. Tracked examples contain placeholders only.

### Metrics and availability

The snapshot timer records a cheap local point once per minute. The collector uses a one-second CPU sample and counter deltas, clamps counter resets to zero, and retains 30 days. Charts use bounded downsampling while preserving meaningful peaks.

Configure remote hosts in private `servers.json` from `config/servers.json.example`. Define TCP ports and optional HTTP endpoints for availability decisions; ICMP remains a separate diagnostic signal.

### Optional Timeweb AI

Copy `config/timeweb-ai.env.example` outside the repository and configure:

Required environment variable names are `TIMEWEB_AI_OPENAI_URL`,
`TIMEWEB_AI_API_TOKEN` and `TIMEWEB_AI_MODEL`. Copy the tracked example to a
private environment file and replace its placeholders there.

The backend streams this endpoint only after existing WebUI or Telegram authentication. The browser, MCP client and audit log never receive the AI token. No live server context is sent automatically.

### Optional MCP

Copy `config/mcp.env.example` outside the repository and generate a separate random `MONITORINGBOT_MCP_TOKEN`. Configure the dedicated localhost service and reverse-proxy route. In ChatGPT, connect with the published `/mcp` URL and this Bearer token. Do not reuse Telegram, TOTP or AI credentials as an MCP token.

## Development, testing and release

Development happens on `dev`; `prod` is the reviewed release branch. Publishing source is separate from deploying it to `/opt/monitoringbot`.

```bash
python3 -m py_compile v3.py health_monitor.py oom_monitor.py v4/*.py tests/*.py
PYTHONPATH=. python3 -m unittest discover -v
node --check v4/ui/app.js
git diff --check
```

GitHub Actions installs dependencies, compiles Python, runs the unit suite, checks browser JavaScript and rejects recognisable credentials. Use the atomic, health-gated process in [docs/OPERATIONS.md](docs/OPERATIONS.md) for a deployment.

## Troubleshooting

| Symptom | First checks |
| --- | --- |
| Metrics are stale | Check `monitorbot-snapshot.timer`, the latest SQLite sample and collector journal. |
| WebUI login fails | Verify the reverse-proxy IP allow-list, Telegram `initData` path, TOTP clock and server-side session state. |
| AI provider unavailable | Check the private AI environment file, endpoint reachability and `monitorbot-web`/Telegram logs. A local diagnostic fallback remains available. |
| MCP returns `401` | Supply the separate MCP Bearer token; WebUI/Telegram credentials do not authenticate MCP. |
| Availability is `UNKNOWN` | Add valid TCP or HTTP checks in private `servers.json`; ICMP alone is diagnostic. |
| Controlled action does not run | Repeat it using the unexpired confirmation created for the same authenticated caller. |

### Project nginx logs

Project requests are separated from the normal `/var/log/nginx/` files:

- `/var/log/nginx/site/` — public site;
- `/var/log/nginx/vds-agent/` — Monitoring WebUI and MCP;
- `/var/log/nginx/x-agent/` — X-Agent MCP and the public chat proxy.

They rotate daily with 14 compressed generations. The deployment snippets,
permissions and validation commands are in [Project nginx logs](docs/LOGGING.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [MCP and Telegram AI](docs/MCP.md)
- [Firewall model](docs/FIREWALL.md)
- [Operations and release procedure](docs/OPERATIONS.md)
- [Project nginx logs](docs/LOGGING.md)
- [Recovery runbooks](runbooks/)
- [Security policy](SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
