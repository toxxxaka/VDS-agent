# Remediation progress

| Phase / ID | Status | Date | Notes |
| --- | --- | --- | --- |
| P0-1 Code map | ready for review | 2026-10-11 | `docs/CODE_MAP.md` |
| P0-2 Hypothesis validation | ready for review | 2026-10-11 | `docs/FINDINGS.md` |
| P0-3 Server baseline | ready for review | 2026-10-11 | redacted baseline captured |
| P0-4 External baseline | ready for review | 2026-10-11 | low-rate checks only |
| P0-5 Test baseline | ready for review | 2026-10-11 | current local suite: 50 passing |
| P0-6 Threat model | ready for review | 2026-10-11 | `docs/THREAT_MODEL.md` |
| S-03 nginx version token | ready for review | 2026-10-11 | `server_tokens off` applied after nginx validation and rollback guard |
| S-07 SSH MAC hardening | blocked | 2026-10-11 | key-only acceptance probe unavailable; no SSH change made |
| S-08 supporting audit material | ready for review | 2026-10-11 | renewal dry-run, notes and external-check script |
| S-05 authentication replay protection | ready for review | 2026-10-11 | Browser initData and TOTP time steps are single-use; Telegram bot TOTP steps are also single-use; sensitive WebUI and Telegram actions require a TOTP no older than 60 seconds. Source-only until a reviewed deployment. |
| S-01, S-02, S-04, S-06, S-09 | in progress | — | CSP needs 3–7 day Report-Only observation; firewall deployment remains excluded by prior owner decision |
| SEC-01…SEC-13 | not started | — | requires Phase 2 implementation after Phase 1 gate |
