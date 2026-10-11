# Phase 1 gate — audit remediation

## Completed in source and covered by tests

### S-05: Telegram and browser authentication replay controls

- Telegram Mini App initData now rejects duplicate parameter names, verifies a signed allow-listed numeric user and an age of at most five minutes, and stores only a SHA-256 digest of accepted initData for the freshness window.
- Browser and Telegram bot TOTP flows accept each time step once per principal.
- Firewall, backup, SSH-termination and power routes require TOTP verified within the previous 60 seconds. The WebUI exposes **Re-authenticate** so the user can deliberately obtain the short step-up window.
- A full local suite passed: 52 tests, including forged, stale, unknown-user, reordered and replayed initData, TOTP replay and step-up expiry.

The changes are source-only until a reviewed deployment. Existing live sessions made before deployment have no `totp_at` field and will deliberately require re-authentication after deployment.

## Completed on the host with verification

### S-03: nginx version disclosure and default virtual host

`server_tokens off` is active. A low-rate external follow-up observed `Server: nginx` without a version on both declared HTTPS sites. The default HTTP vhost now returns `444`; the default TLS vhost uses `ssl_reject_handshake on`. TLS 1.2 and the declared hosts continue to work.

### S-08: supporting evidence

- Certificate renewal dry-run returned success.
- `docs/SECURITY_NOTES.md` records the non-findings from the original audit.
- `scripts/external-check.sh` provides repeatable, low-rate owner checks.

## Open items before Phase 2

| Task | State | Reason / next safe step |
| --- | --- | --- |
| S-01 clickjacking | waiting for controlled Telegram Web test | Do not add `X-Frame-Options` to the Mini App entry point. Telegram’s official docs identify the WebApp SDK origin but do not provide a stable finite parent-origin allow-list. Run CSP Report-Only and test native plus Telegram Web before enforcing `frame-ancestors`. |
| S-02 CSP | waiting for 3–7 days of Report-Only observations | The UI needs final removal of dynamic inline style attributes before an enforceable no-`unsafe-inline` policy. A report endpoint, retention and deny-by-default test must be implemented and observed first. |
| S-03 default virtual host | completed | HTTP by raw IP yields no response (`444`); TLS by raw IP rejects the handshake. A five-minute auto-rollback was armed during the change and cancelled only after validation. |
| S-04 main-site rate limits | completed | Main static site uses 20 req/s, burst 40 and 30 concurrent connections per IP. A 100-request, concurrency-20 check yielded 75 × 200 and 25 × 503; both sites remained healthy afterward. |
| S-06 Docker/IPv6 exposure | accepted owner risk, external verification pending | No public AAAA records exist for the two sites. IPv6 input has default drop and allows only 80/443 plus ICMPv6, but `wg-easy` listens on `[::]:51821` and the IPv6 DOCKER-USER chain is empty. A local connection confirms the listener but cannot prove external reachability. The owner previously instructed not to modify firewall or Docker rules. |
| S-07 SSH MACs | blocked by anti-lockout check | A new loopback key-authentication probe could not be completed, so weak MAC removal was not applied. Existing password and forwarding restrictions remain. |
| S-09 external comparison | partial | Follow-up confirms version hiding; remaining S-01–S-07 controls cannot be claimed complete. |

## Rollback

The source S-05 change is rolled back by reverting commit `778a3bb`. The active nginx change can be manually restored with `/root/vds-agent-nginx-rollback-20261011-0015/restore.sh`; it restores the exact previous default and main-site vhosts, removes the two added include files, validates nginx and reloads it. The auto-rollback timer was cancelled after successful validation.

Phase 2 must not start until these unresolved Phase 1 decisions have been reviewed.
