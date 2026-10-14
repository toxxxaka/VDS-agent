# VDS-Agent — AS-IS Technical Review

**Review date:** 2026-10-14 UTC
**Repository:** `toxxxaka/VDS-agent`
**Source checkout:** `/home/ai/monitoringbot` (`dev`, `b8e0b0b`)
**Deployed code:** `/opt/monitoringbot`
**Scope:** source, deployed code, private configuration shape, systemd, nginx, local storage, listeners and runtime state. This document deliberately omits credentials, token values, TOTP material, Telegram identifiers, and private allow-list addresses.

## 1. Executive overview

VDS-Agent is a single-server Ubuntu/Debian operations console. It combines a Telegram long-polling bot, an authenticated WebUI/Mini App, a local SQLite monitoring store, bounded diagnostics, incident history, an optional Timeweb-compatible AI interpreter, and an MCP server for read-only ChatGPT diagnostics.

The project is deliberately not a general shell or a multi-tenant monitoring platform. Browser, Telegram AI and MCP requests reach a common allow-listed tools layer. Privileged work is split into narrow local root bridges and short-lived confirmations.

The currently deployed VDS-Agent components are running. The source `dev` branch is ahead of `prod` and contains later intelligence, recovery, service-pack, logging and UI work. The deployed code agrees with `dev` for the operational v4 modules inspected; it lacks some later repository documentation and nginx/logrotate templates. The live nginx configuration has already been manually configured for separated project logs.

## 2. Inventory

### 2.1 Source checkout

`/home/ai/monitoringbot` contains 143 tracked files. Main groups:

| Area | Files / role |
|---|---|
| Legacy bot and monitors | `v3.py`, `health_monitor.py`, `oom_monitor.py` |
| Web/backend | `v4/webapp.py`, `v4/ui/index.html`, `app.js`, `app.css`, `favicon.svg` |
| Shared diagnostics | `v4/agent_tools.py`, `console.py`, `availability.py`, `external_tools.py` |
| Data/metrics | `storage.py`, `metrics.py`, `snapshots.py`, `incidents.py`, `tasks.py`, `outbox.py` |
| Intelligence/recovery | `intelligence.py`, `stage78.py`, `runbooks.py`, `rbac.py`, `baseline.py`, `flight_recorder.py`, `alerting.py` |
| Integrations | `ai.py`, `telegram_ai.py`, `mcp_http.py`, `backups.py`, `firewall.py`, `library.py` |
| Deployment templates | `systemd/`, `config/*.example`, `config/nginx/`, `config/logrotate/` |
| Tests | `test_v3.py`, `tests/test_agent_tools.py`, `tests/test_v4_metrics.py`, `tests/test_v4_web_auth.py`, `tests/test_v4_web_security.py`, `tests/test_stage3_foundations.py`, `tests/test_stage456_foundations.py`, `tests/test_infrad.py` |
| Documentation | README, SECURITY, CHANGELOG, architecture, operations, MCP, firewall, logging, code map, security/phase/roadmap documents |
| User client scripts | `client-scripts/` and `client-scripts/COMMANDS.md` |

Ignored local runtime material includes bytecode caches and a local SSH allow-list file. It is not tracked and is not described here by value.

### 2.2 Deployment and private state

| Path | AS-IS purpose |
|---|---|
| `/opt/monitoringbot` | deployed application source and MCP virtual environment |
| `/etc/monitoringbot-main` | private environment and JSON configuration: Telegram, auth, health thresholds, monitored servers, AI, MCP, feature settings |
| `/etc/monitoringbot` | private allow-list and compatibility configuration |
| `/var/lib/monitoringbot` | SQLite database and JSON state cache; private modes are in effect |
| `/var/lib/monitorbot-oom` | root-owned OOM watcher cursor/state |
| `/run/monitorbot` | Unix sockets for root backup and infrastructure bridges |
| `/usr/local/libexec/monitorbot-*` | installed constrained helpers/bridges |
| `/var/log/nginx/site` | public site logs |
| `/var/log/nginx/vds-agent` | WebUI and VDS MCP logs |
| `/var/log/nginx/x-agent` | separate X-Agent logs; not a VDS-Agent component |
| `/var/log/atop` | atop history controlled independently from VDS-Agent |

Private configuration contains one permitted Telegram user, a finite browser IP allow-list, one-hour session lifetime, TOTP replay/lockout controls, health thresholds and two monitored remote-server definitions. Values are intentionally excluded.

## 3. History and branch state

The repository started as a Telegram server monitor (`v3.py`). It evolved in layers:

1. **Core monitoring:** resource reports, Telegram commands, remote availability, SSH-login detection, health/OOM monitors.
2. **WebUI and SQLite:** TOTP-backed Mini App/browser UI, local telemetry, incidents, audit, metrics history.
3. **Secure diagnostic plane:** shared `agent_tools`, Safe Console, bearer-protected Streamable HTTP MCP, Timeweb-compatible server-side AI proxy.
4. **Hardening:** auth replay protection, default nginx deny vhost, rate controls, state-file permissions, constrained helpers.
5. **Operational foundations:** task records, outbox, adaptive-baseline shadow mode, metric rollups/migrations.
6. **Incident/recovery:** intelligence snapshots, runbooks, RBAC/four-eyes data model.
7. **Service packs and replay:** timeline, weekly report, maintenance records and synthetic demonstrations.
8. **Current source additions:** client-script library and segregated nginx log templates.

`dev` is at `b8e0b0b`; `prod` is at `02f1bd0`. `dev` contains the changes listed above that are absent from `prod`, including the intelligence/recovery/service-pack work, telemetry foundations, client-script library and logging templates. There are no Git tags. The working tree was clean before this requested review file was created.

## 4. Architecture and interaction chains

```text
Telegram client ──HTTPS Telegram Bot API──► v3.py (long polling)
                                              │
                                              ├── v4.telegram_ai ──► v4.agent_tools
                                              ├── alerts/incidents ─► SQLite WAL
                                              └── Telegram delivery

Browser / Telegram Mini App ─► nginx TLS/IP gate ─► v4.webapp :8787 loopback
                                                        │
                              static UI ◄───────────────┤
                                                        ├── SQLite / v4 metrics, incidents, tasks
                                                        ├── Safe Console ─► v4.console ─► agent_tools
                                                        ├── Timeweb-compatible AI proxy
                                                        ├── backup/infrastructure Unix bridges
                                                        └── constrained sudo helpers for explicit actions

ChatGPT MCP client ─► nginx TLS ─► v4.mcp_http :8793 loopback ─► agent_tools

snapshot timer ─► snapshots.record_metric ─► metrics + SQLite + cached self-monitoring
health daemon ─► alert policy ─► snapshots/incidents ─► Telegram
OOM daemon ─► kernel journal ─► snapshots/incidents ─► Telegram
```

The process is Python 3. The WebUI uses Python standard-library `ThreadingHTTPServer`, not Flask/Django/FastAPI. MCP uses FastMCP/Starlette/Uvicorn. The frontend is plain HTML/CSS/ES JavaScript without a bundler, node package tree or framework build step. Runtime dependencies are `psutil`, `requests`, `mcp`, `uvicorn`, and `PyYAML`.

### Key request chains

* **Metric point:** systemd timer → `snapshots.record_metric()` → one-second CPU measurement plus cheap psutil/proc counters → `metric_samples`, current rollup buckets and self-monitoring cache.
* **Alert:** `monitorbot-health` samples every configured 10 seconds → debounce policy → incident snapshot → `incidents.observe()` → Telegram open/recovery message. Optional intelligence runs in the same health process only when its flags are enabled.
* **Safe Console:** browser POST → authenticated `webapp.Handler` → `console.parse()` rejects shell syntax → fixed tool/function call → bounded subprocess or psutil/SQLite read → JSON response rendered as escaped `<pre>`.
* **Controlled operation:** step-up TOTP → short-lived caller-bound record in `pending_actions` → second confirmation → fixed root helper/systemctl path. No browser text is passed to a shell.

## 5. Frontend, backend and HTTP API

### 5.1 Frontend implementation

`v4/ui/index.html` loads `/static/app.css`, `/static/app.js` and the local SVG favicon. `app.js` keeps page/range/timer state in memory and language choice in browser local storage. It calls same-origin endpoints with credentials and attaches Telegram `initData` when present.

The chart implementation is custom Canvas, not Grafana/Chart.js. It sizes for touch/desktop, formats binary byte values, draws a single hover/touch cursor and tooltip, and does not poll while the document is hidden. On visibility return it reloads the Metrics page. This explains why a chart needs at least two verified stored samples before drawing.

### 5.2 Authentication middleware behavior

The root HTML and static assets are served by the app without app-level session validation; nginx supplies the browser-IP perimeter for the Monitoring host. API calls require either valid signed Telegram Mini App `initData` or an approved browser IP principal. All non-login API calls then require a matching server-side TOTP session cookie.

`POST /api/totp` validates a six-digit TOTP, rejects used Telegram initData and used TOTP time steps, creates a server-side session record, and returns an `HttpOnly`, `Secure`, `SameSite=None` cookie. The session is not a signed bearer cookie: the browser holds only a numeric lookup key. Logout deletes the matching record. Recent TOTP (60 seconds) is required for high-risk routes.

### 5.3 Complete API catalogue

All JSON responses set `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Unless stated, listed routes require the authenticated session described above.

| Method and route | Handler / result |
|---|---|
| `GET /` | WebUI HTML |
| `GET /static/{app.css,app.js,favicon.svg}` | static assets only from a fixed allow-list |
| `GET /download/<token>` | expiring client-script download; token syntax constrained |
| `GET /api/session` | whether the caller has a current TOTP session |
| `POST /api/totp` | creates a session after replay-protected TOTP authentication |
| `POST /api/logout` | deletes session and expires cookie |
| `GET /api/dashboard` | overview, active incidents, counts, latest task runs and cached self-monitoring |
| `GET /api/metrics?range=1h|6h|24h|7d|30d` | bounded metric chart points and latest sample timestamp |
| `POST /api/ai/chat` | SSE proxy to configured private AI endpoint; body `messages`, 1–20 user/assistant entries, 4k characters per item |
| `GET /api/incidents?status=all|open|closed` | latest 100 incident records |
| `GET /api/incidents/<id>` | incident, 100 events, saved snapshot when present |
| `POST /api/incidents/<id>/investigate` | fresh bounded intelligence evidence |
| `GET /api/incidents/<id>/forensics` | anonymised JSON evidence bundle |
| `POST /api/incidents/close-all` | manually closes active records; next unhealthy sample may reopen |
| `POST /api/incidents/<id>/ack|close` | legacy-compatible acknowledge/close endpoint; acknowledge is not in normal UI |
| `GET /api/audit`, `/api/runs`, `/api/runs/<uuid>` | last 100 audit entries, task runs, or one run |
| `POST /api/runs`, `/api/runs/<uuid>/cancel` | queued predefined UI diagnostic task or cancellation request |
| `POST /api/commands/<name>` | legacy command endpoint for fixed `status/daily/ping/cpu/ram/disk/load/uptime/sshlogins/sessions` |
| `POST /api/console` | Safe Console command, max 1 KiB request body |
| `GET /api/self-monitoring`, `/api/patch-status` | cached health / update state |
| `GET /api/timeline?...` | lazy timeline: `last`, `day`, `week`, or custom timestamp interval up to 31 days |
| `GET/POST /api/maintenance` | list/create future maintenance windows |
| `GET /api/report/weekly` | generated HTML report embedded in JSON |
| `GET /api/runbooks`; `POST /api/runbooks/<id>/{dry-run,request,decision}` | declarative Recovery Studio data and approval flow |
| `POST /api/packs` | read-only container/network/web/backup packs |
| `POST /api/demo` | synthetic preview for OOM, SSH anomaly, failed unit or disk exhaustion |
| `GET /api/backups`, `/api/backups/destinations`; `POST /api/backups` | task history/destinations/start backup through root bridge; start requires fresh TOTP |
| `GET /api/library`, `/api/library/<slug>`; `POST /api/library/<slug>/link` | script catalogue/content and expiring download link |
| `POST /api/tools/password|ssl|checkhost|cheburcheck` | local password, SSL and external lookup helpers |
| `GET /api/firewall`; `POST /api/firewall/{preview,request,confirm,keep,rollback}` | constrained firewall bridge. All state-changing paths need fresh TOTP |
| `POST /api/actions/ssh`, `/api/actions/power`, `/api/actions/confirm/<id>` | SSH termination/reboot/poweroff confirmation workflow; fresh TOTP |
| `GET /api/settings` | non-secret settings summary and task specs |

Input bodies have size bounds (normally 4 KiB; AI 32 KiB), route-specific validation and audit events. A malformed action returns 400/403/404 rather than executing a fallback command.

## 6. WebUI function catalogue

### Dashboard

Shows hostname, CPU %, three load averages, RAM availability, filesystem usage, boot-cumulative received network bytes, active incidents, selected service states and recent diagnostic tasks. CPU/RAM/disk/network cards are buttons opening Safe Console commands `diagnose cpu`, `diagnose memory`, `disk usage`, `network summary`. Each service card opens `service <unit>.service`.

The CPU figure uses a nonblocking delta between CPU-time reads. Its first request falls back to the latest persisted one-second metric. Therefore it does not block one second like the collector, but can legitimately differ slightly from a full one-second chart sample.

Services intentionally appear only if systemd reports `active`, `inactive` or `failed`; missing unit names are omitted. The currently selected list is monitoring bot, WebUI, MCP, health, OOM, infrastructure bridge, nginx, SSH, Docker and fail2ban.

### Metrics

Four Canvas charts: CPU (fixed 0–100, tooltip includes load1), memory used/cache/available, RX/TX rates, disk read/write rates. Range controls are 1h/6h/24h/7d/30d. It shows “LIVE” only while the newest persisted sample is within two collection periods; otherwise it marks the series stale. The timer tracks a 60-second collector cycle and requests again just after the expected next point.

Raw points are used for 1h/6h/24h; 7d consumes five-minute rollups and 30d hourly rollups when sufficient. A query returns at most 720 rendered buckets. Each downsample bucket preserves maximum CPU/load/rates and last memory/disk state. Counter reset/reboot deltas are clamped at zero.

### AI

A local chat UI with client-only current-chat history, New chat, Stop via `AbortController`, loading/error state and streamed display. It talks only to `/api/ai/chat`; it cannot see API tokens, current telemetry or secrets automatically. A new browser refresh loses its chat history. It accepts at most 4,000 characters per message and at most 20 exchanged roles in the backend.

### Tools

* **Server events:** all/open/closed incident filters, incident detail, current investigation, and downloadable anonymised forensics JSON. “Close all” warns that real unhealthy conditions may reopen.
* **Activity:** latest task runs and audit rows.
* **Recovery Studio:** lists YAML runbooks. “Dry run” only collects fixed evidence. “Request approval” creates an approval record and may require another approver according to configuration. It does not execute arbitrary YAML or shell.
* **Incident Intelligence / service packs:** manual read-only container, network, web and backup diagnostic packs; patch status, timeline and synthetic demo cards are implemented by `stage78.py`.
* **Timeline:** intentionally lazy. It fetches nothing until the operator selects Last 10, 24 hours, week or a custom start/end range.
* **Backups:** lists backup task history/destinations and asks the root backup bridge to create a validated rsync backup. The work is a non-retryable task.
* **Client Script Library:** shows tracked script contents and creates temporary download links.
* **External tools:** password generation, TLS check, Check-Host and Cheburcheck URL. These are not used by the normal metric collector.
* **Firewall:** `none`, `standard`, `hard` profiles. Preview/request/confirm/keep/rollback call only the infrastructure socket. Hard mode is designed to auto-rollback unless kept.
* **Safe Shell:** described in the next section.
* **SSH/power task views:** list bounded existing session data and submit separate, expiring confirmation requests. No direct button starts `sudo` without the second confirmation.

### Safe Console complete reference

The visual shell is not a terminal. It accepts up to 160 characters, parses with `shlex`, rejects `| ; & \` $ > < \\`, paths and unrecognised arguments, and maps the result to a fixed `agent_tools` function. Every accepted run is audited as `web_console`.

| Group | Syntax and meaning |
|---|---|
| Basics | `help [network|diagnose|security|disk|monitoring|services|logs]`; `status`; `cpu`; `memory`; `disk`; `network`; `load`; `uptime`; `health` |
| Processes | `processes [cpu|memory|io]`; `process PID`; `sockets [port|name]` |
| Telemetry | `metrics [1h|6h|24h|7d|30d]`; `compare cpu 1h 24h`; `report 24h` |
| Diagnosis | `diagnose cpu|memory|io|server|nginx|docker`; `pressure`; `oom history` |
| Network | `network summary|top|interfaces|errors|connections|listen|syn|dns|routes` |
| Services/logs | `services [failed|restart-count]`; `service <allowed-unit>`; `logs [allowed-unit|errors|kernel|ssh]`; `timers`; `boot analyze` |
| Security | `security overview|ssh|fail2ban|firewall|ports|updates` |
| Storage | `disk usage|inodes|health|growth`; `backup status|verify` |
| Monitoring/events | `monitoring health|collectors|alerts`; `incidents [active|closed|all|recent]`; `changes 24h` |

Allowed service/log unit names are: `monitoringbot.service`, `monitorbot-web.service`, `monitorbot-mcp.service`, `monitorbot-health.service`, `monitorbot-oom.service`, `monitorbot-snapshot.service`, `monitorbot-infrad.service`, `monitorbot-backupd.service`, `nginx.service`, `ssh.service`, `docker.service`, `fail2ban.service`.

Missing arguments return usage text and available alternatives. `help <topic>` has the same vocabulary. Some aliases are intentionally coarse: bare `cpu`, `memory`, `disk`, `load` call the shared load diagnostic, while `disk usage` selects filesystem facts.

Tool implementation uses psutil, `/proc`, limited `systemctl`, fixed `journalctl`, `ip route`, `ss`, `fail2ban-client`, `apt`, and `smartctl --scan-open` calls with 4–15 second timeouts and generally 3–10 KiB output caps. Journal direct reading is enabled only in `monitorbot-web` by `MONITORINGBOT_JOURNAL_DIRECT=1`; the same Console command through another process reports journal unavailable.

## 7. Native Telegram bot

`v3.py` implements long polling through Telegram `getUpdates` (50-second long poll, network timeout 65 seconds). It registers a 22-item native command menu at startup. It accepts only private chats where the message sender and chat match, then checks the configured user allow-list.

### Authentication and sessions

`/start` explains login. `/login <6-digit TOTP>` validates a current code, deletes the original login message where Telegram permits, records the session in private JSON state, and expires it after the configured interval. `/logout` clears it. High-risk Telegram actions additionally need a TOTP logged in during the most recent 60 seconds.

### All registered commands

| Command | Behavior |
|---|---|
| `/start`, `/login code`, `/logout`, `/help` | session lifecycle and compact HTML help |
| `/status`, `/daily` | legacy full status/daily report builders |
| `/ping` | configured remote availability. ICMP is informational; repeated TCP/HTTP results determine UP/DEGRADED/DOWN/UNKNOWN |
| `/cpu`, `/ram`, `/disk`, `/load`, `/uptime` | current resource/status reads; disk also asks legacy SMART helper |
| `/sessions`, `/sshlogins` | active SSH sessions via root helper; successful untrusted logins from private state |
| `/killssh PID`, `/killssh confirm PID token` | caller-bound 60-second confirmation then SSH helper termination |
| `/incidents`, `/incident ID`, `/ack ID`, `/close ID` | recent incident list/details and compatibility acknowledge/close mutations |
| `/reboot`, `/shutdown`, `/reboot confirm token`, `/shutdown confirm token` | fixed system power workflow with confirmation and fresh TOTP |
| `/ai`, `/ai help`, `/ai …` | AI diagnostics, detailed below |

There are no separate hidden Telegram slash commands in the code. There are callback-only operations: `ai-query:processes`, `ai-query:logs`, `ai-query:explain`, `ai-confirm:<id>`, and `ai-cancel`. Callback handling repeats private-chat and authenticated-user checks before action.

### Telegram AI agent

`v4.telegram_ai` has a 30-minute in-memory context per Telegram user (last six messages). It is lost on bot restart and is not saved into SQLite. `/ai help` documents:

* `cpu`, `processes`, `memory`, `disk`, `network`, `services`, `logs`, `incidents`, `incident ID`, `patch`, `explain`;
* natural language after `/ai`; and
* `/ai action <allowed-action>` for the controlled action confirmation path.

Each recognised request builds a deterministic small plan of shared tools. Natural-language matching is keyword based, not an autonomous tool-planning agent. Evidence is recursively size-capped and sanitised before it crosses to the AI provider. The instruction asks the provider to answer Russian, begin with a conclusion, use 2–5 evidence lines, at most two safe recommendations, avoid Markdown and not invent facts. It identifies at most five processes with PID/user/CPU/RSS/command/uptime.

There are two upstream attempts (the second after 0.5 seconds). If no response arrives, the bot emits a measured local fallback and buttons for two relevant follow-up diagnostics. This is why “external AI did not respond” can appear: it means the private upstream failed, timed out, or yielded no usable content; it does not mean local diagnostics failed. The source logs only the error class/short reason, not token values.

Telegram text is sent in approximately 3,900-character chunks as HTML. Provider output is stripped of Markdown-like characters and escaped. The fallback itself is preformatted HTML. The `/help` text does not mention `/ai incident ID`, `/ai patch`, or `/ai action`; the dedicated `/ai help` does. `/help` also omits `/login`, `/start`, `/incident`, `/ack` and `/close` despite all being available. This is a documentation/UI discrepancy.

## 8. AI and MCP

### Private AI endpoint

`v4.ai` reads only server-side `TIMEWEB_AI_OPENAI_URL`, `TIMEWEB_AI_API_TOKEN`, and `TIMEWEB_AI_MODEL`. URL must be HTTPS; a missing `/chat/completions` suffix is appended. It uses a bearer Authorization request, connection/read timeout `(10, 180)`, and supports OpenAI SSE delta responses plus a non-streaming JSON completion returned despite `stream=true`.

It sends only caller chat messages. It has no built-in system prompt beyond what Telegram AI supplies as a user message, and the WebUI deliberately does not pass system metrics or secrets. This avoids duplicating a provider-side agent prompt but means WebUI AI is a general chat, not an automatic server investigator.

### MCP

`v4.mcp_http` starts FastMCP on `127.0.0.1:8793`, Streamable HTTP `/mcp`, stateless mode. Nginx exposes it at the dedicated Monitoring MCP hostname over TLS. A separate `MONITORINGBOT_MCP_TOKEN` bearer value is checked with constant-time comparison. `/healthz` is locally unauthenticated but nginx externally returns 404 for it.

MCP tools are read-only: `server_status`, `diagnose_load`, `process_inspect`, `socket_inspect`, `service_status`, `service_logs`, `metrics_query`, `incidents_query`, `network_diagnostics`, `monitoring_health`, `service_pack`, `weekly_report`, `incident_investigate`, `forensics_export`, `patch_status`, `security_detect`, and `historical_query`. Administrative action is explicitly denied when the actor begins with `mcp`.

`network_diagnostics` validates a public host and port, resolves it, then performs bounded DNS/TCP/optional HTTPS/optional ICMP checks. It must not be treated as an unrestricted port scanner.

## 9. Systemd, nginx, network and infrastructure

### 9.1 Installed services and timers

| Unit | Actual command/user | Status and controls |
|---|---|---|
| `monitoringbot.service` | `monitorbot` → `/opt/monitoringbot/v3.py` | active; restart always/10s; state dir 0750; private tmp, read-only system except app state. Less hardened than newer units: no `NoNewPrivileges`, `ProtectHome`, or device restriction. |
| `monitorbot-web.service` | `monitorbot` + `adm` → `python -m v4.webapp` | active; loopback 8787; restart always/5s; no-new-privileges, private tmp, ProtectSystem=full, ProtectHome=yes. `adm` allows allow-listed journal reads. |
| `monitorbot-mcp.service` | `monitorbot` → venv `python -m v4.mcp_http` | active; loopback 8793; restart on failure/5s; strict filesystem, devices private, address-family bound, 384 MiB/50% CPU limits. |
| `monitorbot-health.service` | `monitorbot` → `health_monitor.py` | active; 10s configured loop; hardened, 256 MiB/35% CPU. |
| `monitorbot-oom.service` | `root` → `oom_monitor.py` | active; scans kernel journal every 5s; hardened, 256 MiB/25% CPU. |
| `monitorbot-backupd.service` | `root` → installed backup bridge | active; Unix socket service with constrained writable backup/media/socket paths. |
| `monitorbot-infrad.service` | `root` → installed infrastructure bridge | active; firewall bridge; strict sandbox, AF_UNIX/NETLINK. |
| `monitorbot-snapshot.service` | `monitorbot` → `snapshots.record_metric()` | one-shot. Triggered every minute by active persistent `monitorbot-snapshot.timer`. |
| `monitoringbot-daily.service` | `monitorbot` → `v3.py --daily-report` | one-shot daily at 06:00 UTC via active persistent timer. It has weaker hardening than current units. |
| `monitoringbot-ssh-login.service` | `ai` → source checkout `v3.py --check-ssh-logins` | one-shot every minute via active timer. This is a real source/deploy divergence: it uses `/home/ai/monitoringbot`, `/etc/monitoringbot/telegram.env` and `/var/lib/monitoringbot-ssh`, unlike the source template that points at `/opt` and the main config/state. |
| `vds-aide-check.service` | `root` → AIDE check | static/inactive. `vds-aide-check.timer` is disabled/inactive intentionally while host/project changes are frequent. |

`systemctl --failed` was empty during review. The active status of a oneshot service is normally `inactive (dead)` between timer runs and is not an error.

### 9.2 nginx

Nginx owns public `80/443` on IPv4/IPv6 and TLS termination. It has:

* a public static `0x870x4k3r.tech` vhost, including a separate proxy path to a non-VDS X-Agent AI proxy and selected health bridge endpoints;
* `monitoring.0x870x4k3r.tech` → WebUI loopback `8787`, protected by a fixed nginx IPv4/loopback allow-list plus app auth/TOTP;
* `monitoring-mcp.0x870x4k3r.tech/mcp` → loopback `8793`, bearer-token protected by MCP;
* unrelated X-Agent vhost(s) under a separate hostname/path; and
* default port 80 `444`, default TLS `ssl_reject_handshake on`, preventing hostless direct-IP content delivery.

Headers include HSTS, nosniff, referrer policy and permissions policy. Monitoring uses CSP **Report-Only** with Telegram frame ancestors and without `X-Frame-Options`, deliberately preserving Mini App embedding while observing policy violations. The public site retains `X-Frame-Options: SAMEORIGIN`.

The public static site has a 20 request/sec per-IP zone, burst 40 and maximum 30 connections. Listed search crawler identities receive 2 request/sec / burst 10. The bot-control snippet is presently **observe-only**: unwanted crawler identities are logged, not blocked. This makes it reversible but provides no active bot protection yet.

Project logs route as listed in section 2. Daily logrotate keeps 14 compressed generations, creates files `0640 www-data:adm`, and signals nginx to reopen. `nginx -T` remains valid, but emits duplicate TLS protocol-option warnings in pre-existing 443 server configuration; that is configuration debt, not a failed reload.

### 9.3 Network and firewall

Public listeners are nginx HTTP/HTTPS, SSH, a Zabbix agent port, and existing Docker-published VPN-related UDP/TCP ports. VDS-Agent application listeners are loopback-only: WebUI `8787`, MCP `8793`; several other loopback listeners belong to non-VDS projects/services.

Current nftables tables include IPv4 and IPv6 raw/filter/nat tables. Docker owns published ports, including an IPv6-published port. The VDS firewall bridge is designed to manipulate only Monitoring-managed rules rather than Docker’s tables. No firewall changes were made in this review.

## 10. Metrics, monitoring, alerts and incidents

### Telemetry

The minute timer calls `metrics.collect()`:

* CPU: `psutil.cpu_percent(interval=1.0)`;
* load1: `os.getloadavg()`;
* virtual memory: used/cached/available;
* root filesystem: used/total;
* NIC cumulative RX/TX counters;
* disk cumulative read/write counters;
* `/proc/pressure` avg10 for CPU/memory/I/O; and root inode counts.

It deliberately does not probe services, remote HTTP or external tools per metric point. Current SQLite contains 14,282 raw points and 663 rollup records. Raw range spans approximately 11.2 days at review time, so the configured 30-day maximum retention is not yet fully populated.

Retention deletes raw samples older than configured 30 days, five-minute rollups older than seven days, and hourly rollups older than 30 days. The database has a 256 MiB configured soft health limit. SQLite `auto_vacuum` is off; `incremental_vacuum` therefore does not reclaim pages in this existing DB. WAL mode and foreign keys are on.

### Health alerts

`health_monitor.py` reads `health.json` each cycle. Configured thresholds include CPU, load, per-core load, incoming Mbps/packets, SYN-RECV and TCP connection count. Each condition uses a consecutive-sample policy (currently three), recovery count, optional reminder and optional quiet hours. It writes its JSON state atomically with mode 0600.

The monitor opens/updates one active incident per condition. On recovery it marks the record `closed`, writes a recovery event/timestamps, and sends recovery notification unless quiet hours suppress delivery. The storage startup migration converts historical `recovered` status to `closed`.

`oom_monitor.py` reads only kernel journal records after its saved cursor and opens critical OOM incidents. **It does not contain a matching recovery condition**, so an OOM incident remains active until manual close or future logic changes. This conflicts with the broader automatic-recovery model.

Remote availability is `availability.py` via configured ICMP/TCP/HTTP checks, previous-state thresholds and status machine. ICMP failure alone is diagnostic and cannot declare DOWN. The bot and legacy web command clearly state that repeated configured TCP/HTTP failures are required.

### Self-monitoring

The snapshot process calls `self_monitoring.collect()` best-effort and stores a 0600 cache. It checks selected unit states, failed units, metric freshness (180 seconds), SQLite quick check/size, task failures in the past 24h, backup freshness (seven days if configured), and WebUI unit status. UI reads cached data and does not rerun all checks unless cache is missing.

## 11. Storage, caches and lifecycle

### SQLite schema

`/var/lib/monitoringbot/monitoring.db` is private, WAL-enabled and about 11 MiB before its current WAL. Tables:

| Table | Data |
|---|---|
| `metric_samples`, `metric_rollups` | raw telemetry and 5m/1h JSON rollups |
| `incidents`, `incident_events`, `snapshots` | lifecycle, event history, incident evidence and legacy state capture |
| `audit_log`, `pending_actions` | security/activity audit; session, confirmation and expiring state |
| `web_auth_replays`, `web_totp_steps` | Mini App and TOTP replay prevention |
| `command_runs`, `task_events` | durable UI task lifecycle/cancellation/idempotency |
| `notification_outbox` | optional Telegram delivery retry queue |
| `intelligence_baselines`, `log_patterns` | listener/IOC baseline and grouped journal pattern state |
| `recovery_runs`, `recovery_approvals` | Recovery Studio dry-runs/decisions |
| `maintenance_windows` | scheduled mute/intention metadata |

Indexes cover sample time, incident status/time, events, snapshots, audit, expiry, task status/time, patterns, recovery runs, rollups and due outbox work. Migrations occur lazily in `storage.connect()` through additive columns/indexes and legacy JSON snapshot import. This is simple but means application startup has schema-change authority.

### Other runtime files

| File/category | Producer | Lifecycle |
|---|---|---|
| `health_state.json` | health daemon | persistent debounce/network state, atomically rewritten 0600 |
| `self_monitoring.json` | snapshot collector | cached health, max desired age 180 seconds |
| `server_status.json` | availability | remote availability prior state |
| `ssh_login_state.json`, `telegram_auth_state.json` | legacy bot/timer | SSH and Telegram auth/session state |
| OOM `state.json` | root OOM daemon | journal cursor, atomically rewritten 0600 |
| nginx project logs | nginx/logrotate | daily, 14 compressed generations |
| system journal | journald | max 512 MiB, max 14 days, max file age one day |
| atop logs | atop | 14 generations in `/var/log/atop`; currently a substantial separate disk consumer |

No Redis, Prometheus, Grafana, InfluxDB, remote database or message broker is used.

## 12. Logging, audit, backups and recovery

Python process logs go to journald through systemd. The bot logs Telegram API method status and authenticated command name; health/OOM log exception classes; MCP/Uvicorn logs server events; WebUI overrides `BaseHTTPRequestHandler.log_message`, so ordinary access logs are nginx’s responsibility.

`audit_log` records authentication, tool execution, console access, runbooks, firewall requests, SSH/power confirmations and actions. It stores actor/action/target/result/details as JSON but no explicit retention pruning is implemented for audit, incidents, snapshots, task history or runbooks. This is a long-term storage-growth concern outside telemetry retention.

Backup initiation uses `v4.backups` over `/run/monitorbot/backup.sock` to a root bridge and stores work in `command_runs`. It validates types/lengths and is never automatically retried because writing a destination is not idempotent. Backup freshness is checked, but sandbox restore testing is explicitly “not configured.”

Recovery Studio YAML is parsed with PyYAML, accepts only a fixed diagnostic-tool allow-list and three fixed intended actions (`restart_monitoringbot`, `restart_web`, `restart_health`). It records dry-runs/approval. `decide()` returns instructions to use the existing action-specific path: it does not itself restart services.

## 13. Authorization and security model

* Telegram user allow-list, private-chat restriction, TOTP and time-limited bot session.
* Browser: nginx IP allow-list plus Telegram signed initData or permitted browser principal, then TOTP, then server-side session.
* Replay controls: stored initData digest for five minutes and one accepted TOTP time step per user.
* Web cookies: Secure, HttpOnly, SameSite=None required for embedded Telegram usage.
* MCP: separate bearer token, comparison with `secrets.compare_digest`; MCP is read-only.
* AI credentials stay only in the service environment; neither browser nor MCP receives them.
* Safe Console/tool layer: validation, fixed argv, timeout/output caps, audit and redaction of some likely secret patterns.
* Privileged actions require a recent TOTP and a second, expiring caller-bound confirmation. Firewall/backup use Unix root bridges; SSH termination uses a specific helper.
* SQLite state and sensitive JSON files use restrictive modes. Services generally have `UMask=0077`.

Security limitations are listed in section 16. In particular, browser authentication has a large trust surface because an allow-listed IP can act as the app principal outside Telegram; it is still gated by TOTP. Also, `monitoringbot.service` and daily/SSH timer units are less sandboxed than the newer units.

## 14. CI, deployment, versioning and rollback

GitHub Actions triggers on every push and PR. It creates Ubuntu/Python 3.12 job, installs `requirements.txt`, compiles Python, runs unittest discovery, syntax-checks `app.js`, checks whitespace, and scans tracked text for common Telegram/AI/MCP key forms and private-key markers.

At the reviewed `dev` head, remote Actions runs had failed at the test stage. The protected job log could not be fetched from this server because Git remote SSH access does **not** grant GitHub REST/Actions log authorization. Local clean Python 3.12 environment runs had passed the 78-test suite repeatedly before this review, but that is not evidence that remote CI is green. This is the current release gate issue.

Source publishing and deployment are separate. `/opt` is not automatically synchronized by a Git push. Normal release procedure is source review/tests → deploy to `/opt` → install/reload only affected units/nginx after validation → health checks → switch/rollback according to `docs/OPERATIONS.md`. This review changed neither code nor deployment.

## 15. Current integrations

| Integration | Method | Role |
|---|---|---|
| Telegram Bot API | HTTPS `requests` long polling/sendMessage | command interface, alerts and AI replies |
| Telegram Mini App | signed `initData` header | browser identity path |
| Timeweb/private OpenAI-compatible agent | server-side HTTPS streaming | optional AI conversation/interpretation |
| ChatGPT/MCP clients | Streamable HTTP via TLS reverse proxy | bounded read-only diagnostics |
| systemd/journald | fixed subprocesses | unit state and journal evidence |
| psutil/proc/sysfs | local reads | metrics/process/network facts |
| nginx | reverse proxy/TLS/IP/rate policies | public perimeter |
| root backup/infrastructure bridges | Unix sockets | constrained backup/firewall actions |
| Check-Host/Cheburcheck | explicit operator tool routes | ad hoc external checks |
| Docker/conntrack/atop/smartctl | optional fixed local commands | partial diagnostics only |

## 16. Verified discrepancies, technical debt and risks

### Implemented and working at review time

* Primary VDS-Agent services and all three operational timers were active; no failed unit was reported.
* Local telemetry was writing and SQLite was in WAL mode with current data.
* nginx project log routing is active; journald and atop retention are configured.
* Default nginx vhosts reject direct-IP/unknown-host content.
* WebUI, MCP, health, OOM, backup and infrastructure bridge listeners are correctly loopback/internal where expected.

### Implemented but limited / needs accurate operator expectation

1. **Recovery Studio is an approval recorder, not an executor.** It creates evidence and approval state; the returned execution instruction relies on another confirmation path.
2. **Service packs are partial.** Container pack is unavailable without a separately installed helper. Web pack reports PHP/database monitoring as not configured. Backup pack does not perform a sandbox restore. Optional Prometheus endpoint/SLO/error-budget implementation is absent.
3. **`disk health` only probes `smartctl --scan-open`.** It does not run SMART/NVMe health attributes and virtual disks often cannot expose them.
4. **`network top` ranks TCP connection counts by peer, not byte traffic.** It is not a per-IP bandwidth meter.
5. **`processes io` and intelligence I/O ranks are cumulative process bytes**, not current I/O rate.
6. **WebUI AI has no persistence and no automatic server context.** Telegram AI context is in memory only for 30 minutes.
7. **Timeline is only partially historical.** Systemd/SSH/kernel entries respect its requested window, but the `dpkg.log` contribution takes its last 400 lines without filtering timestamps. Event time for journal text is stored as `None`, so sorting/precision are limited. It no longer eagerly loads on page entry, which fixes the original slow initial view.
8. **Maintenance windows are stored and displayed but are not consulted by `health_monitor` to suppress incidents/notifications.**
9. **Demo mode is synthetic preview only**, with no state injection or alert delivery.
10. **Outbox, adaptive baseline, flight recorder, failed-unit intelligence, port-baseline and IOC checks are feature-flagged.** Their availability in code does not prove they are enabled in the private config.

### Defects / security or operability debt

1. **OOM incident lifecycle:** OOM watcher opens critical incident but never closes it automatically. This contradicts the stated general recovery model.
2. **Source/deployment split for SSH login timer:** live `monitoringbot-ssh-login.service` runs `/home/ai/monitoringbot/v3.py` as `ai` and uses a different config/state path than its tracked template. Future source/deploy releases can diverge unexpectedly.
3. **Partial unit hardening:** `monitoringbot.service`, daily reporting and SSH-login units lack the stronger `NoNewPrivileges`, `ProtectHome`, device and resource constraints applied to newer units. This is not proof of compromise; it is inconsistent hardening.
4. **MCP perimeter:** external MCP hostname has bearer auth but no nginx IP allow-list. This is appropriate for remote ChatGPT usage, but token rotation, request rate limit and endpoint audit review matter.
5. **CSP is Report-Only.** This is intentional compatibility protection for Telegram Mini App, but does not actively block policy violations. No retained CSP report analytics exists; endpoint merely accepts/replies.
6. **Nginx bot controls are observe-only.** Identified unwanted crawlers are logged rather than blocked. Claimed anti-bot protection is not active enforcement.
7. **Audit/snapshot/task retention absent.** Metric retention is bounded; several other SQLite tables can grow forever. `auto_vacuum=0` means deletion does not necessarily shrink file size.
8. **AIDE disabled.** This is intentional during rapid change, but host integrity checking is currently not running.
9. **CI status unresolved.** Remote GitHub Actions failure needs direct log/API inspection and a rerun before merge/deploy confidence.
10. **Nginx duplicate TLS option warnings** should be normalized; current config tests pass but warning-free validation is not achieved.
11. **Source documentation overstates some UI options:** README describes Safe Console `network sockets`; parser actually provides `network listen` and standalone `sockets`. README’s “all optional controls disabled by default” is true by code default but live flags were not disclosed in this report.
12. **Legacy and modern pathways coexist:** v3 direct JSON state/Telegram, v4 SQLite task/incident tools, and legacy WebUI command routes. This is manageable but creates duplicated formatting/auth/action behavior.

## 17. Dependency map

| User capability | Web/Telegram/MCP entry | Core module | Data / OS dependency | Service |
|---|---|---|---|---|
| Dashboard | `/api/dashboard` | `snapshots.overview`, `webapp` | psutil, `systemctl`, SQLite incidents/tasks/cache | web |
| Charts | `/api/metrics` | `metrics` | psutil, `/proc`, SQLite | snapshot timer |
| Alerts | Telegram messages | `health_monitor`, `alerting`, `incidents` | psutil, `/proc/net`, SQLite, Telegram | health |
| OOM alert | Telegram | `oom_monitor`, `incidents` | kernel journal, SQLite | OOM |
| Server availability | `/ping`, legacy route | `availability` | configured network checks/state JSON | bot |
| Web/Telegram AI | AI route or `/ai` | `ai`, `telegram_ai` | AI env, requests, agent tools | web/bot |
| MCP | `/mcp` | `mcp_http`, `agent_tools` | MCP env, uvicorn | MCP |
| Safe Shell | `/api/console` | `console`, `agent_tools` | psutil, fixed OS commands, SQLite audit | web |
| Incidents/evidence | events views/MCP | `incidents`, `intelligence`, `snapshots` | SQLite, journal, `/proc`, systemctl | health/web |
| Firewall | tools routes | `firewall` | infrastructure Unix socket / nft helper | infrad |
| Backup | tools routes | `backups`, `tasks` | backup Unix socket / rsync bridge | backupd |
| SSH actions | bot/web | `v3`, `webapp` | privileged session helper, pending action state | bot/web |
| Scripts | library view | `library` | tracked `client-scripts`, temporary links | web |

## 18. Configuration, endpoint and timer reference

### Non-secret configuration names

* `MONITORINGBOT_AUTH_CONFIG`, `MONITORINGBOT_SERVERS_CONFIG`, `MONITORINGBOT_HEALTH_CONFIG`, `MONITORINGBOT_STATE_DIR`, `MONITORINGBOT_DB`.
* `MONITORINGBOT_WEB_PORT` (current WebUI loopback port), `MONITORINGBOT_MCP_PORT` (current MCP loopback port), `MONITORINGBOT_JOURNAL_DIRECT`.
* `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`; `TIMEWEB_AI_OPENAI_URL`, `TIMEWEB_AI_API_TOKEN`, `TIMEWEB_AI_MODEL`; `MONITORINGBOT_MCP_TOKEN`.
* Telemetry: `raw_retention_days`, `rollup_5m_retention_days`, `rollup_1h_retention_days`, `database_soft_limit_mib`, `flight_recorder_*`.
* Feature flags: `adaptive_baseline`, `telegram_outbox`, `external_heartbeat`, `incident_intelligence`, `port_baseline_detection`, `ioc_detect_only`.
* Health: interval, consecutive/recovery samples, reminder, CPU/load/network/SYN/TCP thresholds, optional quiet hours.

### Timers

* Snapshot: boot + every minute, persistent.
* SSH-login monitor: boot + every minute, persistent.
* Daily report: 06:00 UTC daily, persistent.
* AIDE: installed but disabled.

### Operational API/listener reference

* WebUI: loopback TCP 8787 through Monitoring nginx vhost.
* MCP: loopback TCP 8793 through Monitoring MCP nginx vhost.
* Root bridges: Unix sockets under `/run/monitorbot`; no browser direct socket access.
* External public server functions beyond nginx/SSH/Docker are outside VDS-Agent scope and should be reviewed independently.

## Conclusion

VDS-Agent is a functioning, deliberately bounded single-host monitoring console with a clear direction: shared read-only diagnostics, local metric storage, incident evidence and explicit escalation for mutations. Its strongest implemented areas are the local telemetry pipeline, WebUI/TOTP perimeter, Safe Console parser, and common tool backend. Its most important next engineering work is to resolve remote CI failures, converge the SSH-login deployment unit with source, give OOM incidents a recovery policy, define retention for non-metric SQLite data, and distinguish implemented service-pack/recovery features from their currently unavailable integrations.
