# VDS-Agent MCP and Telegram AI

## MCP endpoint

The optional MCP service uses Streamable HTTP and listens only on localhost. nginx publishes it at:

```text
https://monitoring-mcp.0x870x4k3r.tech/mcp
```

ChatGPT connection settings:

- **URL:** `https://monitoring-mcp.0x870x4k3r.tech/mcp`
- **Authentication:** Bearer token
- **Token:** the value of `MONITORINGBOT_MCP_TOKEN` from the private `/etc/monitoringbot-main/mcp.env` file.

The token is never placed in source code, browser JavaScript, audit records or tool output.

## Tools

| Tool | Purpose |
|---|---|
| `server_status` | Current CPU, RAM, disks, uptime and network overview. |
| `diagnose_load` | CPU, RAM, I/O and top process evidence. |
| `process_inspect` | Bounded process details by CPU or RAM. |
| `service_status` | Read state of named systemd services. |
| `service_logs` | Bounded, redacted recent journal excerpt for one service. |
| `metrics_query` | Current telemetry and 1h, 6h, 24h, 7d or 30d history. |
| `incidents_query` | Active or historical incidents. |
| `network_diagnostics` | DNS, TCP and optional HTTPS/ICMP checks of a public host. |
| `monitoring_health` | VDS-Agent self-monitoring state. |
| `admin_action` | Explicit two-step high-risk action workflow. |

MCP has no arbitrary command, filesystem, shell or root tool. Tool arguments are validated and output is bounded and redacted.

## Administrative actions

`admin_action` accepts only `restart_monitoringbot`, `restart_web`, `restart_health`, `reboot` and `poweroff`.

The first invocation returns a one-time `confirmation_id`, bound to the caller and valid for 90 seconds. The caller must repeat the same action with that id. The action then goes through the root-owned allowlist helper. No operation runs until that second call.

## Telegram AI

Use the existing authenticated Telegram bot:

```text
/ai Почему сервер тормозит? Проверь процессы, память, диск и последние ошибки.
/ai Покажи активные инциденты и метрики за час.
/ai action restart_web
```

`/ai` uses the same read-only tools as MCP. It sends bounded diagnostics to the configured private Timeweb Agent for a concise Russian-language interpretation. It stores a short in-memory conversation context per Telegram user for 30 minutes and never stores it in SQLite.

`/ai action …` creates an inline confirmation button. The callback is valid only for the authenticated Telegram user and expires after 90 seconds.

## Availability checks

Remote checks are configured only in `/etc/monitoringbot-main/servers.json`, based on `config/servers.json.example`.

- **UP:** all configured TCP/HTTP health checks succeed.
- **DEGRADED:** at least one configured check succeeds and another fails, or a failure/recovery threshold is still pending.
- **DOWN:** all configured service checks fail for the configured number of consecutive sampling cycles.
- **UNKNOWN:** there is no service check or insufficient data to make a service availability decision.

ICMP is kept as a diagnostic check. Missing ICMP alone can never produce `DOWN`.

## Installation order

1. Install dependencies from `requirements.txt` in the production Python environment.
2. Create private `mcp.env` and `servers.json` from examples with mode `0640`, owned by `root:monitorbot`.
3. Install the reviewed `monitorbot-mcp.service`, helper and sudoers files.
4. Install the dedicated nginx vhost, obtain the certificate, then test nginx before reload.
5. Start the MCP service and validate `GET /healthz` locally and an authenticated `initialize` request through nginx.

The deployment commands are intentionally not embedded here because they modify system services and security configuration; review them before running.

## Rollback

Stop and disable `monitorbot-mcp.service`, remove only the dedicated `monitoring-mcp` nginx vhost, and remove the corresponding sudoers/helper files. Existing Monitoringbot, WebUI, Telegram and X-Agent MCP services remain independent.
