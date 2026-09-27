# VDS Agent

A security-focused, self-hosted monitoring and operations console for Debian servers.

VDS Agent combines a Telegram bot, a hardened HTTPS WebUI, incident tracking, system metrics, controlled administrative actions and isolated privileged helpers.

The project is designed for private infrastructure management — not as a public multi-tenant monitoring platform.

## Features

### Monitoring

- CPU and load average monitoring
- Memory and swap statistics
- Disk usage and system status
- Network throughput and packet-rate monitoring
- TCP connection and SYN-RECV tracking
- Linux OOM killer detection
- SSH login monitoring
- Periodic system snapshots
- Hour, day and week statistics
- Recovery notifications and alert cooldowns

### Incident management

The built-in Incident Engine tracks operational events through their lifecycle:

- active
- recovered
- acknowledged
- closed

Incidents support severity levels, deduplication, hysteresis, cooldowns and links to system snapshots captured around the event.

### Telegram

The Telegram bot provides server status, alerts and controlled administrative operations.

Available functionality includes:

- server status
- CPU, RAM, disk and load statistics
- uptime
- remote server availability checks
- active SSH sessions
- external SSH login alerts
- incident management
- controlled SSH session termination
- reboot and shutdown operations
- daily server reports

Sensitive operations require explicit confirmation.

### WebUI

The mobile-first HTTPS WebUI provides:

- Dashboard
- Incidents
- Activity
- Statistics
- Diagnostics
- Backup management
- Client script library
- Firewall management
- TLS inspection
- Password generation
- External HTTP, TCP, DNS and ping checks

The interface is designed for both desktop browsers and Telegram Mini Apps.

## Security model

Security-sensitive functionality is deliberately separated from the WebUI.

The WebUI does not expose an arbitrary shell and does not directly execute `sudo` or `nft`.

Privileged operations are performed through narrowly scoped, root-owned helpers using fixed protocols and Unix sockets.

Authentication layers include:

- Telegram Mini App `initData` validation
- Telegram user allow-list
- IP allow-list for direct browser access
- TOTP authentication
- server-side sessions
- short-lived confirmation tokens for destructive actions

Sessions are stored server-side and protected with secure cookie attributes.

Administrative actions are written to an audit log. Authentication secrets, Telegram tokens, TOTP secrets and confirmation tokens are not written to the audit trail.

## Firewall manager

VDS Agent manages only its own nftables table:

```text
table inet monitoringbot
```

Existing Docker and system firewall tables are left untouched.

Firewall changes support:

- ruleset preview
- pre-change snapshots
- trusted client IP handling
- standard and hardened profiles
- automatic rollback for connectivity-sensitive changes

The hardened profile must be explicitly confirmed after the change or the previous ruleset is restored automatically.

## Architecture

```text
Telegram
   │
   ▼
v3.py
   │
   ├── alerts
   ├── commands
   ├── authentication
   └── controlled operations

HTTPS / Telegram Mini App
   │
   ▼
v4/webapp.py
   │
   ├── storage.py
   ├── incidents.py
   ├── snapshots.py
   ├── tasks.py
   ├── backups.py
   ├── library.py
   ├── firewall.py
   └── external_tools.py
            │
            ▼
      restricted helpers
            │
            ▼
        Linux system
```

Persistent state is stored in SQLite using WAL mode.

## Repository layout

```text
.
├── v3.py                 # Telegram bot and command handling
├── health_monitor.py     # CPU, load and network monitoring
├── oom_monitor.py        # Kernel OOM event monitoring
├── v4/                   # WebUI and operations backend
├── systemd/              # Service, timer and helper definitions
├── config/               # Safe configuration examples
├── docs/                 # Architecture and deployment documentation
└── test_v3.py            # Core unit tests
```

## Requirements

VDS Agent is intended for Linux servers using:

- Python 3
- systemd
- nftables
- nginx or another HTTPS reverse proxy
- SQLite
- Telegram Bot API

Python dependencies are listed in `requirements.txt`.

## Configuration

Real credentials must never be stored in the repository.

Production configuration is expected outside the source tree, for example:

```text
/etc/monitoringbot-main/telegram.env
/etc/monitoringbot-main/auth.json
/etc/monitoringbot-main/health.json
/etc/monitoringbot/ssh-allowlist.json
```

See the sanitized examples in `config/`.

## Deployment

The recommended production layout separates source code, runtime state and secrets:

```text
/opt/monitoringbot/          application code
/etc/monitoringbot-main/     private configuration
/var/lib/monitoringbot/      persistent runtime state
```

systemd unit examples are available under `systemd/`.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full installation procedure.

## Development workflow

Development happens in the `dev` branch.

The `prod` branch contains the currently deployable version.

Typical workflow:

```text
feature/* → dev → prod
```

Production changes should reach `prod` through reviewed merges rather than direct development.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Firewall model](docs/FIREWALL.md)
- [Security policy](SECURITY.md)

## Project status

VDS Agent is under active development.

Interfaces, configuration formats and deployment procedures may change before the first stable release.

## Security notice

This software can perform privileged server operations including firewall changes, SSH session termination, reboot and shutdown.

Review all service files, helpers, sudo rules and network restrictions before deploying it to a production server.

Never commit real Telegram tokens, TOTP secrets, private keys or production authentication files.
