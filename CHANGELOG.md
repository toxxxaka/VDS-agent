# Changelog

All notable changes to VDS Agent are documented here.

## Unreleased

### Added

- Independent dependency-free Sentinel for an external host: DNS/TCP/TLS/HTTPS probes, thresholded Telegram down/recovery alerts, a hardened systemd timer, an interactive opt-in installer, configuration template and operations guide. The installer explains the separate-host requirement and the consequence of declining it.
- Local operator CLI commands `vds-agent status` and `vds-agent doctor`, with human-readable and `--json` output for health checks and automation.
- Desktop Support navigation and an authenticated support request form in the primary WebUI and isolated public demo. Requests are bounded, HTML-escaped for Telegram delivery, and audited.
- Safe Console diagnostics for disk, network and OOM triage, swap capacity/activity, and kernel reclaim/allocation counters.

- Separate, rotating nginx log templates for the public site, VDS Agent and
  X-Agent, with an operational guide that keeps default nginx logs intact.

- Shared bounded diagnostics backend for Telegram AI, Safe Console and Streamable HTTP MCP.
- Bearer-protected MCP service, deployment templates and documentation.
- Telegram `/ai` focused subcommands, bounded multi-step diagnostics, context, owner-bound confirmations and compact evidence-first responses.
- Safe Console with a fixed read-only command vocabulary, suggestions, history and contextual argument help.
- Cached authenticated self-monitoring for unit state, metric freshness, backup freshness, SQLite/WAL integrity and recent internal failures.
- Local SQLite metric series with 30-day retention, a 30-day chart range, downsampling and freshness metadata.
- Server-event filters, audited bulk close action, and regression tests for telemetry, incidents, API contracts, AI streaming, diagnostics, firewall rollback, availability and console parsing.
- CI compilation, test, JavaScript syntax and credential-guard stages.

### Changed

- Documented the intentional temporary pause of the optional AIDE timer while
  the monitored host is under active development.

- Reworked the WebUI around Dashboard, Metrics, AI and Tools, and moved incidents/activity into Tools.
- Split frontend markup, styles and browser behaviour into maintainable static UI assets.
- Made metrics refresh follow the real collector timestamp and pause while the browser tab is in the background.
- Separated periodic metric collection from incident snapshots.
- Reworked remote availability into repeated ICMP/TCP/HTTP observations with `UP`, `DEGRADED`, `DOWN` and `UNKNOWN` states.
- Made recovery automatically close incidents while preserving recovery history.
- Hardened monitoring, OOM, snapshot, WebUI, MCP and infrastructure unit templates and private runtime-state creation.
- Changed managed nftables rollback to restore the exact prior VDS-Agent table without touching Docker, fail2ban or host firewall tables.

### Fixed

- Replaced volatile short CPU sampling with a one-second collector measurement shared by Metrics and Dashboard.
- Excluded legacy inaccurate telemetry from current version-two charts while retaining history.
- Clamped network and disk counter resets so charts never show negative rates.
- Corrected OOM state-directory hardening and preserved the Telegram journal helper path.
- Escaped and bounded AI-provider output for Telegram and handled compatible JSON as well as SSE responses.
- Added an nginx bot-control configuration with `off`, `observe`, and `enforce` modes. The default is `observe`.
