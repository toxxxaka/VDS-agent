# Phase 1 gate — audit remediation

## Completed in source and covered by tests

### S-05: Telegram and browser authentication replay controls

- Telegram Mini App initData now rejects duplicate parameter names, verifies a signed allow-listed numeric user and an age of at most five minutes, and stores only a SHA-256 digest of accepted initData for the freshness window.
- Browser and Telegram bot TOTP flows accept each time step once per principal.
- Firewall, backup, SSH-termination and power routes require TOTP verified within the previous 60 seconds. The WebUI exposes **Re-authenticate** so the user can deliberately obtain the short step-up window.
- A full local suite passed: 52 tests, including forged, stale, unknown-user, reordered and replayed initData, TOTP replay and step-up expiry.

The changes are source-only until a reviewed deployment. Existing live sessions made before deployment have no `totp_at` field and will deliberately require re-authentication after deployment.

## Completed on the host with verification

### S-03 (partial): nginx version disclosure

`server_tokens off` is active. A low-rate external follow-up observed `Server: nginx` without a version on both declared HTTPS sites. TLS 1.2 and the existing security headers still work.

### S-08: supporting evidence

- Certificate renewal dry-run returned success.
- `docs/SECURITY_NOTES.md` records the non-findings from the original audit.
- `scripts/external-check.sh` provides repeatable, low-rate owner checks.

## Open items before Phase 2

| Task | State | Reason / next safe step |
| --- | --- | --- |
| S-01 clickjacking | waiting for controlled Telegram Web test | Do not add `X-Frame-Options` to the Mini App entry point. Telegram’s official docs identify the WebApp SDK origin but do not provide a stable finite parent-origin allow-list. Run CSP Report-Only and test native plus Telegram Web before enforcing `frame-ancestors`. |
| S-02 CSP | waiting for 3–7 days of Report-Only observations | The UI needs final removal of dynamic inline style attributes before an enforceable no-`unsafe-inline` policy. A report endpoint, retention and deny-by-default test must be implemented and observed first. |
| S-03 default virtual host | proposed, not applied | Direct requests to the server IP return the Debian/default site. Replace it with port 80 `return 444` and TLS `ssl_reject_handshake on`, using the SSH/nginx anti-lockout procedure and an automatic five-minute rollback. |
| S-04 main-site rate limits | proposed, not applied | The site is static. The sampled access log shows only 57 recent lines and an observed peak of 10 requests in one second, insufficient to select production thresholds confidently. Prepare a conservative 10 r/s, burst 30, connection 20 policy and observe it before tightening. |
| S-06 Docker/IPv6 exposure | accepted owner risk for this phase | Docker publishes 51821 on IPv6 and no equivalent explicit IPv6 DOCKER-USER restriction was found. The owner previously instructed not to modify firewall or Docker rules. |
| S-07 SSH MACs | blocked by anti-lockout check | A new loopback key-authentication probe could not be completed, so weak MAC removal was not applied. Existing password and forwarding restrictions remain. |
| S-09 external comparison | partial | Follow-up confirms version hiding; remaining S-01–S-07 controls cannot be claimed complete. |

## Rollback

The source S-05 change is rolled back by reverting commit `778a3bb`. For any later nginx deployment: restore the prior vhost/snippet, run `nginx -t`, reload nginx and cancel the pre-created auto-rollback timer only after a fresh external request and a second SSH session succeed.

Phase 2 must not start until these unresolved Phase 1 decisions have been reviewed.
