# Public demo mode

`monitorbot-demo-web.service` runs an isolated public WebUI on `127.0.0.1:8788`.
It has its own SQLite database at `/var/lib/monitoringbot-demo/demo.db`; it does
not reuse normal browser sessions, TOTP records, incident state or audit data.

## Credential flow

1. A visitor requests access from the login page.
2. The browser receives a random request cookie and waits for the owner.
3. The owner-only Telegram bot receives `<request-id>-DD-MM` and can generate,
   share or delete a credential pair through inline buttons.
4. The generated Latin-only login (6–9 characters) and password (9–15
   characters) expire after 24 hours. The password is displayed to the visitor
   once and is stored as an scrypt hash for sign-in verification.

Requests are limited to one per source IP hash every 15 minutes. The public
browser never receives a Telegram ID, TOTP secret or bot token.

## Deliberately unavailable

The demo backend rejects host-changing routes even if called directly:
reboot, shutdown, SSH termination, firewall operations, backup creation,
runbooks, maintenance changes, client-script library and outbound network tools.
Only the dashboard, metrics and allow-listed Safe Shell diagnostics remain.

## Rollback

The normal `monitorbot-web.service` continues on `127.0.0.1:8787`.
To return the public vhost to normal WebUI, change its `proxy_pass` back to
`http://127.0.0.1:8787`, run `nginx -t`, reload nginx, then stop and disable
`monitorbot-demo-web.service`. Remove the `monitoringbot.service.d/demo-access.conf`
drop-in only after demo requests are no longer needed, then daemon-reload and
restart `monitoringbot.service`.
