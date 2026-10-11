# Audit findings and hypothesis validation

Status meanings: **confirmed** is demonstrated by code or baseline evidence; **partial** means the control exists but misses a stated requirement; **not checked** needs a staging/external test. No hypothesis is called a vulnerability solely because it appeared in the planning document.

| ID | Status | Evidence | Severity | Follow-up |
| --- | --- | --- | --- | --- |
| B-01 MCP confirmation can be initiated and consumed in one caller context | confirmed | `v4/agent_tools.py:admin_action` creates and consumes a pending record for the same `actor`; MCP always supplies `actor="mcp"`. | High | SEC-01 |
| B-02 OOM monitor uses follow mode | partial | `oom_monitor.py:journal` calls `journalctl -k` every five seconds with a cursor; it is bounded polling, not `journalctl -f`. | Medium | IMP-05 |
| B-03 sudoers are narrow and helper chain is root-owned | partial | Template `monitoringbot-power.sudoers.example` contains a wildcard terminate argument; actual sudoers need a separate non-secret structure audit. | High | SEC-02 |
| B-04 shell interpolation | not confirmed | Static review found `subprocess.run` fixed argv patterns and no `shell=True` in tracked application Python. This needs a CI assertion. | Medium | SEC-02, SEC-12 |
| B-05 file/journal reads use `O_NOFOLLOW` | confirmed | `Path.read_text` and normal `open` are used in storage/config/log paths; no symlink-safe open wrapper is present. | Medium | SEC-02 |
| B-06 initData validation uses secure comparison and freshness | partial | Source commit `778a3bb` enforces unique parameters, `hmac.compare_digest`, a 300-second age, numeric allow-list and persisted digest replay rejection. It remains source-only pending reviewed deployment. | High | S-05, SEC-12 |
| B-07 TOTP replay and rate limiting | partial | Source commit `778a3bb` persists accepted Telegram and WebUI TOTP time steps and requires a 60-second step-up for sensitive routes. Recovery codes and broader session hardening remain Phase 2 work. | High | SEC-04 |
| B-08 loopback binding and forwarded-IP trust | partial | `v4.mcp_http` binds `127.0.0.1`; WebUI trusts `X-Real-IP` directly in `browser_principal` and requires proxy trust review. | High | SEC-06 |
| B-09 audit log integrity | confirmed | `v4/storage.py:audit` inserts mutable SQLite rows with no hash chain or external checkpoint. | High | SEC-09 |
| B-10 secrets absent from current tree/history | partial | Current tracked-tree credential guard passed; repository history scan still requires gitleaks. | Medium | SEC-10 |
| B-11 dependency locking | confirmed | `requirements.txt` has compatible ranges and no hashes. | Medium | SEC-10 |
| B-12 CI supply-chain controls | partial | CI compiles/tests and has regex credential guard, but no locked action SHAs, pip-audit, gitleaks or explicit workflow permissions. | Medium | SEC-10 |
| B-13 strict CSP compatibility | confirmed | `v4/ui/app.js` contains inline event-associated style attributes and the WebUI has no CSP header. | Medium | S-02 |
| B-14 meaning of unauthenticated `totp:false` | mitigated in source | `v4/webapp.py` returns 401 before `/api/session` to an unauthenticated requester. For an authenticated principal, the field denotes only this browser session’s TOTP state, never global MFA state. | Medium | S-05 |
| B-15 provider-specific AI naming | confirmed | `TIMEWEB_AI_*` appears in source/config and needs provider-neutral aliases before broader AI work. | Low | IMP-08 |
| B-16 MCP least privilege / read-only DB | confirmed | MCP runs as `monitorbot` and imports tools that can create audit/pending-action rows; its database access is not `mode=ro`. | Medium | SEC-03, SEC-05 |

## External baseline findings

- nginx exposes `nginx/1.24.0 (Ubuntu)` in the `Server` header.
- The main site emits `X-Frame-Options`; monitoring does not emit `X-Frame-Options` or CSP.
- Monitoring correctly returns `403` to the unauthorised external baseline request; TRACE returns `405` on both domains.
- IPv6 is enabled. Nginx and the Docker-published WireGuard UI have IPv6 listeners.
- Docker publishes the WireGuard UI on TCP 51821. IPv4 has `DOCKER-USER` filtering; IPv6 lacks equivalent explicit port filtering in the captured baseline.

## Decision records

- **Mini App framing:** official Telegram documentation specifies loading `https://telegram.org/js/telegram-web-app.js` but does not publish a stable finite allow-list of Telegram Web parent origins. Phase 1 must use Report-Only CSP before enforcement and must not add `X-Frame-Options` to the Mini App entry point until Telegram Web behavior is tested.
- **SSH:** password and forwarding are already disabled. Root key login remains enabled by owner decision; no change to this exception is made in Phase 0.
- **Firewall:** no firewall or Docker change is made in Phase 0. Any later change needs a second SSH session and auto-rollback.
