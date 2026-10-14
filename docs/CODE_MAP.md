# VDS Agent code map

This map was produced during Phase 0 on 2026-10-11 from the `prod`-aligned source tree. It names configuration and secret *identifiers* only; it contains no values.

## Entry points and data flows

| Entry point | Component | Authentication / caller | Main flow |
| --- | --- | --- | --- |
| Telegram polling | `v3.py` | Telegram chat allow-list and bot login | Commands, alerts, SSH-login watcher and `/ai` dispatch. |
| WebUI / Mini App | `v4.webapp` on loopback | Valid Telegram `initData` or trusted browser IP, then TOTP session | Static UI, JSON API, task submission and confirmed actions. |
| MCP | `v4.mcp_http` on loopback | Separate Bearer token | FastMCP Streamable HTTP tools call `agent_tools.execute`. |
| Health monitor | `health_monitor.py` | systemd service account | Observes CPU/load/network thresholds and updates incidents. |
| OOM monitor | `oom_monitor.py` | root systemd unit | Polls bounded kernel journal output, opens OOM incidents and sends Telegram alert. |
| Metric collector | `monitorbot-snapshot.timer` → `v4.snapshots.record_metric` | `monitorbot` | Stores one lightweight sample per minute. |
| Infrastructure bridge | `systemd/monitorbot-infrad.py` | root Unix socket peer credential | Owns only `table inet monitoringbot` and implements rollback for that table. |
| External Sentinel | `sentinel/vds_agent_sentinel.py` on another host | root-owned config, unprivileged `vds-sentinel` process | DNS/TCP/TLS/HTTPS availability probes and thresholded Telegram transitions; no control-plane access to VDS Agent. |

## HTTP routes

`v4/webapp.py` serves the static shell and allow-listed assets `app.css`, `app.js` and `favicon.svg`. Its API includes session, TOTP login/logout, dashboard, metrics, incidents, audit/runs, diagnostics, backups, library, network checks, firewall requests and confirmations, Safe Console, authenticated support requests, SSH termination, power confirmation, and the AI chat stream.

The handler reads a bounded JSON body, maps each route to fixed Python functions, and uses server-side records in `pending_actions` for Web sessions and confirmations. There is no route that accepts a shell command or filesystem path.

## Telegram commands

`BOT_COMMANDS` in `v3.py` registers status, daily report, availability, CPU/RAM/disk/load, uptime, SSH sessions/logins, session termination, logout, reboot and shutdown. `/ai` delegates to `v4.telegram_ai`, including `help`, `processes`, `cpu`, `memory`, `disk`, `network`, `services`, `logs`, `incidents` and `explain`.

## MCP and Safe Console vocabulary

MCP tools in `v4/mcp_http.py` are `server_status`, `diagnose_load`, `process_inspect`, `socket_inspect`, `service_status`, `service_logs`, `metrics_query`, `incidents_query`, `network_diagnostics`, `monitoring_health` and `admin_action`.

The Safe Console parser in `v4/console.py` maps fixed words to `agent_tools.console_diagnostic`. It accepts no shell operators, paths or arbitrary executable names. `v4/agent_tools.py` uses fixed argv arrays with timeouts and output limits.

## External outage observer

`sentinel/` is intentionally not installed with the monitored application. Its timer, state and Telegram delivery exist only on an independent host. Its configuration contains only the target URLs and optional alert bot credentials; it must not contain VDS Agent, SSH, TOTP, MCP, AI or provider credentials. Without this optional component, a complete local outage has no independent alert source.

## Privilege boundaries

| Boundary | Location | Purpose |
| --- | --- | --- |
| Telegram power/SSH | `monitoringbot-power.sudoers.example`, SSH session helper | Fixed root operations after confirmation. |
| MCP controlled action | `monitoringbot-admin-helper` and admin sudoers example | Fixed service restart/reboot/poweroff allow-list. |
| Diagnostics | diagnostic helper / `adm` journal membership | Bounded allow-listed journal excerpts. |
| Firewall | root `monitorbot-infrad` Unix socket | Creates, previews and restores only the VDS-Agent nft table. |
| Backup | root `monitorbot-backupd` Unix socket | Constrained rsync backup operation. |

## Persistent data and configuration identifiers

SQLite WAL tables are created in `v4/storage.py`: incidents, incident events, snapshots, audit log, pending actions, metric samples and command runs. Private runtime state is under `/var/lib/monitoringbot`.

Private configuration identifiers: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `MONITORINGBOT_AUTH_CONFIG`, `MONITORINGBOT_SERVERS_CONFIG`, `TIMEWEB_AI_OPENAI_URL`, `TIMEWEB_AI_API_TOKEN`, `TIMEWEB_AI_MODEL`, and `MONITORINGBOT_MCP_TOKEN`. Their values belong outside the repository.
