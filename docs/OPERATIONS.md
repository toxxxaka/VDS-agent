# Operations and release procedure

This document describes how to move a reviewed `dev` revision to the private
production installation. It intentionally separates source review from live
server changes.

## Runtime boundaries

- Source checkout: `/home/ai/monitoringbot`
- Deployed code: `/opt/monitoringbot`
- Private configuration: `/etc/monitoringbot-main` and `/etc/monitoringbot`
- Runtime state: `/var/lib/monitoringbot`
- Privileged helpers: `/usr/local/libexec`

Never copy `*.env`, JSON state, SQLite files or private keys from runtime into
the source checkout.

## Pre-flight

1. On `dev`, run `PYTHONPATH=. python3 -m unittest discover -v`.
2. Run `python3 -m py_compile v3.py health_monitor.py oom_monitor.py v4/*.py`
   and `node --check v4/ui/app.js`.
3. Review `git diff prod...dev`, run the CI workflow, and check the secret
   guard. Do not release while CI is failing.
4. Confirm that `/etc/monitoringbot-main` holds the existing private
   configuration and that `/var/lib/monitoringbot/monitoring.db` is backed up.
5. Validate nginx before changing its configuration: `nginx -t`.

## Atomic application procedure

Deploy a new revision into a new root-owned release directory, verify Python
imports and static assets there, then atomically move the `/opt/monitoringbot`
symlink. Keep the previous release directory until the health gate has passed.
Do not overwrite runtime state or private configuration.

After the symlink move, restart only the VDS-Agent units whose code changed.
Check `systemctl --failed`, the active units, both localhost ports (8787/8793),
metric freshness and an authenticated read-only health request. The nginx
configuration only needs reload after an nginx vhost change and after a
successful `nginx -t`.

## Health-gated rollback

Revert the symlink to the previous release and restart the same VDS-Agent units
if any of these checks fail:

- a VDS-Agent unit fails or repeatedly restarts;
- WebUI or MCP stops listening on its loopback address;
- SQLite `PRAGMA quick_check` is not `ok`;
- a metric sample does not arrive within two collector cycles;
- authenticated WebUI/MCP smoke checks fail.

The firewall is different: VDS Agent owns only `table inet monitoringbot`.
Before changing it, the infrastructure helper writes a private snapshot of the
previous **managed table**. Rollback restores that table; it does not rewrite
Docker, fail2ban or host firewall tables. Always preview and explicitly confirm
firewall changes from a connected trusted IP.

## Privilege model

The safe WebUI console, Telegram AI and MCP diagnostics are read-only and share
the same allow-listed backend. They do not accept arbitrary shell syntax. A
controlled action has a short expiry, a user-bound confirmation, an audit
record, bounded runtime and a root-owned helper. High-risk changes such as
firewall, restart, reboot and shutdown require a separate confirmation.

## Optional stage 1–3 configuration

`config/monitoringbot.json.example` is a non-secret template. Copy it outside
of the checkout as `/etc/monitoringbot-main/config.json` only after reviewing
its values and file ownership. Validate it before a release:

```bash
PYTHONPATH=/opt/monitoringbot /usr/bin/python3 -m v4.cli check-config
```

The Flight Recorder, adaptive baseline, Telegram outbox and external heartbeat
are disabled by default. When `telegram_outbox` is enabled, the bot queues messages
in SQLite and drains retries with exponential backoff during polling. The adaptive baseline runs in shadow mode only; it never
changes the static alert policy without a later reviewed implementation. Enabling a flag is a reviewed configuration change,
not a deployment prerequisite. The recorder keeps at most 512 KiB of process
memory and writes evidence to SQLite only when an incident opens.

## SQLite migration and rollback

This revision uses additive SQLite migrations: new task, outbox and metric
rollup tables are created on first application open; new columns have defaults.
Existing metric samples, incidents and command history are never rewritten.

Before deployment, take the normal runtime database backup. To roll back the
application code, restore the previous release symlink and restart the same
units. The additional tables can remain; older code ignores them. Do not delete
SQLite tables as part of rollback.
