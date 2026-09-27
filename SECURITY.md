# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities through a public GitHub issue.

Use GitHub Private Vulnerability Reporting for this repository when available, or contact the repository owner privately.

Please include:

- affected component
- reproduction steps
- expected and actual behavior
- potential security impact
- relevant logs or proof-of-concept details

Do not include production credentials, authentication tokens or private infrastructure information.

## Security model

VDS Agent is designed around least-privilege separation.

The WebUI does not provide arbitrary shell execution and must not run unrestricted commands as root.

Privileged operations are delegated to narrowly scoped helpers with explicit inputs and fixed protocols.

Production deployments should use:

- HTTPS
- network allow-lists
- TOTP authentication
- restricted system users
- hardened systemd services
- minimal sudo rules
- isolated runtime state
- external secret/configuration files

## Secrets

Never commit:

- Telegram bot tokens
- TOTP secrets
- private keys
- production authentication files
- session databases
- production allow-lists containing sensitive infrastructure data

If a secret is accidentally committed, consider it compromised even after deleting the file from the latest commit. Rotate the secret and remove it from repository history.

## Deployment responsibility

VDS Agent can perform privileged operations such as firewall changes, SSH session termination, reboot and shutdown.

Review all service definitions, helpers, sudo rules and network restrictions before deploying the project to a production host.
