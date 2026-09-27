# Firewall module

The WebUI never invokes `nft` or `sudo`. A root-owned Unix-socket bridge accepts a fixed protocol from the `monitorbot` account only.

- Rules live solely in `table inet monitoringbot`, leaving Docker and existing tables intact.
- Every change stores the pre-change ruleset.
- `hard` starts an automatic rollback timer. The browser must confirm connectivity before that timer expires.
- Hard mode receives the reverse-proxy verified client IP and asks whether to retain HTTPS from that IP.
- Audit records include profile, trusted IP, and result. They contain neither session nor confirmation tokens.
