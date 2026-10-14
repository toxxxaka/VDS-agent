# Product delivery roadmap

## Stage 0 — boundaries and evidence

The supported target is a single Ubuntu or Debian host. `docs/ARCHITECTURE.md`,
`docs/THREAT_MODEL.md`, `docs/CODE_MAP.md`, and `docs/PROGRESS.md` are the
authoritative design, security, integration, and delivery records. New
collectors and integrations require a feature flag, resource budget, tests,
and a documented rollback before release.

## Stage 1 — Operations Core

The shared `v4` package is the common backend for WebUI, Telegram and MCP.
`v3.py` remains the compatible Telegram entry point during migration. Optional
behaviour is declared in `config/monitoringbot.json.example` and validated by
`vds-agent check-config`; secret-bearing environment files remain outside Git.

## Stage 2 — Durable work

Tasks are persisted in SQLite with idempotency keys, lifecycle events,
cancellation requests, bounded retries and recovery after process restart.
Only diagnostic tasks can be automatically retried. Controlled actions always
remain confirmation-bound and are never replayed automatically.

## Stage 3 — telemetry and incidents

Raw minute samples are retained for current charts; 5-minute and hourly
rollups provide bounded long-range queries. A feature-flagged Flight Recorder
stores a small in-memory pre-trigger window and writes it only on an incident.
Alert policies use explicit `for` and recovery windows, hysteresis, severity,
deduplication, quiet hours and backoff.

## Optional external outage observation

Release installation offers an explicit External Sentinel choice. It explains the separate-host requirement and the consequence of declining: the local installation remains fully functional, but cannot independently report its own total outage. The Sentinel bundle is provisioned separately and never grants the primary installer remote access to another host.
