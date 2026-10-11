# External follow-up — 2026-10-11

This was one low-rate, owner-authorised follow-up against the declared domains. It did not use credentials, fuzzing, scanning, or load.

| Check | Main site | Monitoring site |
| --- | --- | --- |
| HTTPS response | 200 | 403 for an unauthorised client |
| `Server` header | `nginx` | `nginx` |
| TRACE | 405 | 405 |
| TLS 1.2 | successful, certificate verified | successful, certificate verified |
| HSTS / nosniff / Referrer / Permissions | present | present |
| CSP | absent | absent |
| Frame policy | `SAMEORIGIN` | absent |

`server_tokens off` is effective: the upstream nginx version is no longer disclosed in either `Server` header. The default virtual host remains open: direct IPv4 HTTP and HTTPS requests returned content. This is a remaining S-03 item, not a completed control.

No external IPv6 probe was available. Local inspection confirms IPv6 listeners for SSH, nginx and Docker-published WireGuard-related ports; firewall changes remain outside this phase by owner decision.
