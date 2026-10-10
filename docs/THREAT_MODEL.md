# Threat model

## Assets

- Server availability, SSH access and firewall rules.
- Telegram bot, Mini App authorisation, TOTP sessions and MCP credentials.
- SQLite incidents, metrics, audit history and backup metadata.
- Root-owned helpers, systemd units and private configuration.

## Trust boundaries

1. Internet → nginx → loopback WebUI/MCP.
2. Telegram client → signed `initData` → WebUI session and bot command handler.
3. ChatGPT MCP client → bearer gateway → shared tools.
4. Local diagnostics/logs/process command lines → AI provider and Telegram output.
5. Unprivileged monitoring service → narrow root helpers over sudo or Unix sockets.

## Priority threats

| STRIDE category | Threat | Existing controls | Gap / phase |
| --- | --- | --- | --- |
| Spoofing | Replayed Telegram `initData` or TOTP | HMAC, freshness, allow-list, session expiry | Replay record and step-up: S-05, SEC-04 |
| Tampering | Firewall / helper manipulation | Root helpers, separate managed nft table, snapshots | Immutable audit and file integrity: SEC-09 |
| Repudiation | Privileged action denial | SQLite audit | Hash chain and external checkpoint: SEC-09 |
| Information disclosure | Secrets or logs reach browser/AI | env outside Git, partial redaction, auth | unified untrusted-output/redaction policy: SEC-01, SEC-08, SEC-11 |
| Denial of service | nginx abuse, Docker bypass, expensive tools | IP policy, bounded tools, systemd limits | rate limits and Docker/IPv6 parity: S-04, S-06, SEC-06 |
| Elevation | Prompt-injected action / broad sudo | allow-list and confirmation | MCP same-actor confirmation and sudo validation: SEC-01, SEC-02 |

## Non-goals

This project does not provide an arbitrary remote shell. Any future tool remains deny-by-default and must use a fixed allow-list with bounded output, audit and confirmation.
