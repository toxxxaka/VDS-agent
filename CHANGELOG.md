# Changelog

## Unreleased

- Added a shared bounded diagnostics backend for Streamable HTTP MCP and Telegram `/ai`.
- Added bearer-protected MCP transport, deployment templates and dedicated documentation.
- Added Telegram AI multi-step diagnostics using the existing private Timeweb Agent, with short-lived caller-bound action confirmation.
- Reworked remote availability into configurable repeated ICMP/TCP/HTTP checks with `UP`, `DEGRADED`, `DOWN` and `UNKNOWN` states.
- Added regression and integration coverage for MCP auth, Telegram AI, controlled actions and availability failure modes.

All notable changes to VDS Agent will be documented here.

## [Unreleased]

### Changed
- Rebuilt WebUI navigation around Dashboard, Metrics, AI and Tools.
- Moved incident history and Activity into Tools; Dashboard is now a compact current-state overview.
- Replaced inline WebUI markup with maintainable static `v4/ui` assets.
- Recovery now automatically closes incidents while retaining recovery timestamps and history.

### Fixed
- Replaced volatile 100ms CPU sampling with a one-second collector measurement shared by Metrics and Dashboard.
- Versioned telemetry so pre-fix short-window samples remain retained but do not pollute current charts.
- Made Metrics live refresh follow the actual collector timestamp and expose stale collection instead of animating a stale chart.

### Added
- Private Timeweb AI Agent chat with authenticated server-side OpenAI-compatible streaming proxy.
- 30-day Metrics range and API freshness metadata.
- Sanitized `config/timeweb-ai.env.example` and optional systemd environment-file integration.

### Added
- Lightweight local SQLite metric series with 30-day retention and a time index.
- Interactive Canvas charts for CPU, memory, RX/TX and disk I/O with 1h, 6h, 24h and 7d ranges.
- Visibility-aware live refresh, countdown indicator, touch/hover tooltips, legends and unit-aware scales.
- Server events filters and audited bulk close action.
- AI navigation placeholder without an external AI integration.


### Added
- Hardened HTTPS WebUI
- Telegram Mini App authentication
- Incident Engine
- SQLite/WAL storage
- System snapshots and statistics
- Backup management
- Firewall manager with automatic rollback
- External diagnostic tools
- SSH login monitoring
- CPU, load, network and OOM alerts

### Security
- TOTP authentication
- IP allow-list support
- Restricted privileged helpers
- Server-side sessions
- Audit logging

## 2026-10-05 — Reliability hardening

- Added authenticated self-monitoring for service state, telemetry and backup freshness, SQLite/WAL integrity, and recent failed component runs.
- Added CI for compilation, tests, and accidental-secret detection.
- Hardened monitoring unit examples and preserved the active V4 deployment model.
