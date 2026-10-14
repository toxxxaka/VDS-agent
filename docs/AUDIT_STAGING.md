# Authenticated audit staging

`v4.audit_webapp` is a separate WebUI entry point for an isolated audit instance. It is not referenced by the normal VDS Agent unit.

## Safety boundary

- Telegram Mini App `initData`, TOTP, session expiry, one-time TOTP steps, recent step-up, and confirmation binding remain active.
- A successful WebUI reboot or shutdown confirmation creates an audit record with `result=simulated`; it never invokes `sudo`, `systemctl`, or a privileged helper.
- Viewer sessions may read data but cannot request or confirm power, SSH, firewall, or backup actions. Admin-only routes return `403` with an audit record.
- TOTP failures are persisted per authenticated principal. After `max_failures`, the endpoint returns `429` and `Retry-After` for `lockout_seconds`. A successful TOTP login clears the counter.

## Isolation requirements

Deploy it with a separate source directory, SQLite database, auth file, Telegram bot token, TOTP secret, loopback port, nginx vhost, runbook directory, and state directory. Do not reuse the main database, bot token, TOTP secret, MCP token, firewall bridge, or runtime directory.

The supplied `systemd/monitorbot-audit-web.service`, `config/audit-staging.env.example`, and `config/auth.audit.json.example` are templates. They do not create or modify a live audit instance by themselves.

## Auditor inputs

The auditor supplies two numeric Telegram IDs, their source IP for reverse-proxy access, and a public staging hostname. Each auditor identity opens the staging Mini App through a dedicated staging bot; Telegram then generates valid `initData`. Do not send raw `initData` in chat because it is short-lived and replay-sensitive.

Share the temporary staging TOTP seed only through a one-time encrypted channel, revoke it after the engagement, and delete the isolated state/database when the audit finishes.
