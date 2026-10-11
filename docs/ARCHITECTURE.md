# Monitoringbot v4 — architecture

## Purpose

VDS Agent is a protected personal monitoring console for one Ubuntu or Debian server. It combines Telegram operations with an HTTPS browser/Mini App console. It is not a multi-tenant monitoring service.

## Components

```text
Telegram bot (v3.py)                     HTTPS / Telegram Mini App
      │                                               │
      ├── commands and notifications                  └── v4/webapp.py
      ├── SSH login monitor                                   │
      └── daily report

Timeweb AI Agent ◄── server-only v4/ai.py ◄── authenticated `/api/ai/chat`                                         ├── v4/ui/ (HTML, CSS, JS)
                                                                  ├── metrics.py
Health monitor ──────► incidents.py ──────► SQLite/WAL ◄───────┤
OOM monitor ─────────► snapshots.py (incident context)         ├── backups/library/firewall/tools
Snapshot timer ──────► metrics.py (one cheap point/minute)     └── restricted helpers
```

The AI proxy uses the configured private OpenAI-compatible endpoint only from the backend. It forwards the current browser chat history as `user` and `assistant` messages and streams OpenAI SSE deltas back to the authenticated browser. It sends no system prompt, server telemetry, incident data, secrets, or browser credentials. It is deliberately structured as a separate module so a later context provider can be introduced without changing the chat UI or authentication route.

The WebUI is intentionally split into a small Python HTTP/API layer and static `v4/ui/index.html`, `app.css`, and `app.js`. This keeps API/security code separate from layout, interaction, Canvas rendering and mobile presentation. No frontend framework is required.

## Authentication and privileges

The server validates Telegram Mini App `initData` using Telegram's HMAC scheme and checks the configured user allow-list and a five-minute `auth_date` window. Direct browser access is allowed only from configured trusted IP networks. Both paths require TOTP before any data API is available. Sessions are server-side SQLite records with a one-hour expiry; cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

All actions are audit logged. Secrets, TOTP values, Telegram credentials, session data and confirmation tokens are excluded from audit records. The browser has no arbitrary shell endpoint. Destructive actions use short-lived confirmations and narrowly scoped root helpers.

## Persistent data

`/var/lib/monitoringbot/monitoring.db` runs in SQLite WAL mode. The Timeweb endpoint and token stay in `/etc/monitoringbot-main/timeweb-ai.env`; they are never stored in this DB.

| Data | Table | Purpose |
| --- | --- | --- |
| Incidents | `incidents`, `incident_events` | Event lifecycle, severity, timestamps and context |
| Incident context | `snapshots` | Lightweight diagnostic snapshot only when an incident occurs |
| Historical metrics | `metric_samples`, `metric_rollups` | Raw local counters plus bounded 5-minute/hourly rollups; independent of incident snapshots |
| Actions | `audit_log`, `command_runs`, `task_events`, `pending_actions` | Audit history, durable diagnostics and short-lived confirmations/sessions |
| Notifications | `notification_outbox` | Opt-in idempotent retry queue; disabled by default |

On first start of this revision, `metric_samples` and its time index are created without deleting `snapshots`. Existing `recovered` incidents are logically migrated to `closed`, keeping `recovered_at` intact.

## Metric collection and chart API

The existing `monitorbot-snapshot.timer` remains the collector cadence: once per minute. CPU is measured across a one-second interval to avoid falsely treating a short scheduler burst as a full-minute 100% load. It reads only local `psutil` counters: CPU percentage/load, RAM/cache/available, filesystem usage, network byte counters and disk read/write counters. It does not run service checks, external requests, or diagnostic commands for each point.

`metrics.record()` retains configurable raw history (30 days by default), writes 5-minute and hourly rollups, and removes expired data during normal collection. Corrected one-second telemetry uses version 2; the short-lived rollout label version 3 is migrated into v2 so chart history remains continuous. `/api/metrics?range=1h|6h|24h|7d|30d` returns bounded visual points. Downsampling preserves per-bucket CPU and rate peaks, and emits the newest gauge values. Counter deltas are clamped to zero after reboot/interface/disk counter resets, so client charts never receive negative rates.

The UI paints Canvas charts for CPU, memory, RX/TX and disk I/O. It supplies axis units, legends, timestamps, hover/touch tooltips and a LIVE indicator derived from the last stored sample timestamp. It schedules the next fetch for the expected collector cycle, marks data stale if no sample appears within two cycles, and refreshes immediately when the document returns from the background.

## Incident lifecycle

A healthy sample does not create an event. An unhealthy condition opens a single `active` incident, with later unhealthy samples updating the same record. Recovery changes it to `closed`, stores both `recovered_at` and `closed_at`, and lets the health monitor send a recovery notification. If the condition returns later, a new incident is created. This preserves complete recovery history without an acknowledgement workflow in the UI.

Tools → Server events offers All, Open and Closed views. **Close all** is an explicit manual action for active records. The UI warns that a condition still detected by the monitor can create another incident later.

## Main UI navigation

- **Dashboard**: compact current CPU, RAM, disk usage, network counters, active problems, primary service state and recent diagnostics.
- **Metrics**: historical charts and live refresh.
- **AI**: private Timeweb Agent chat via the authenticated backend proxy, with New chat, Stop generation, streaming states and local current-chat history.
- **Tools**: Server events, Activity/audit, diagnostics, a safe read-only console, backups, client script library, network/security checks, firewall and power actions.

## Operational health

`v4/self_monitoring.py` is an authenticated operator-facing read model. It performs bounded local checks only and does not expose configuration values, tokens, or database contents. A stale metric indicates collector lag rather than an attempt to infer host availability.


## MCP and Telegram AI

`v4/agent_tools.py` is the only diagnostic/action backend used by both `v4/mcp_http.py` and `v4/telegram_ai.py`. It uses fixed argv subprocess calls, typed bounds, timeouts, redaction and audit records. It never provides a shell or a generic filesystem operation. The MCP server is a separate localhost-only Streamable HTTP service protected by a distinct Bearer token.

Telegram `/ai` builds a bounded diagnostic plan from the request, runs these local tools, then sends compact evidence to the already configured private Timeweb Agent for interpretation. Context lives only in process memory for 30 minutes. Controlled actions use a database-backed, caller-bound 90-second confirmation.

Availability state is implemented in `v4/availability.py`. The private server configuration declares TCP ports and optional HTTP endpoints. ICMP is reported as a diagnostic signal and cannot alone mark a server DOWN.

## Safe console and runtime safeguards

The Tools console is intentionally a terminal-shaped user interface, not a remote
shell. It accepts a short fixed vocabulary such as `processes cpu`, `sockets
name`, `services`, `logs nginx.service` and `metrics 24h`. The parser rejects
shell operators and paths, maps commands to `agent_tools.execute()`, enforces
output/time bounds, audits each request and returns redacted output. The same
backend is used by Telegram AI and MCP.

Runtime SQLite files are kept owner-only (`0600`) and their directory is private
(`0750`) when opened by the application. Unit templates set `UMask=0077`; the
health, OOM and infrastructure templates also use `NoNewPrivileges`, private
temporary/devices and a strict read-only system view with only their runtime
paths writable.
