# Security notes

## Findings that require context

- **nginx package version:** Ubuntu backports security fixes. Assess nginx through the installed package provenance and Ubuntu Security Tracker, not only the visible upstream version string.
- **WireGuard UDP port:** the WireGuard listener is an expected service. Invalid UDP packets receiving no response is normal and is not evidence of an open unauthenticated application protocol.
- **Unauthenticated Monitoring shell:** the public static shell is not the console data plane. API data and actions require the configured browser/Telegram authentication and TOTP session.
- **ICMP:** lack of an ICMP reply alone is a diagnostic signal, not an availability decision.

## Operational requirements

- Keep certificates on automated renewal and alert before their remaining lifetime falls below 21 days.
- Review reverse-proxy and Docker published-port changes together; Docker traffic has its own forwarding path.
- Treat an accidental token, key or private configuration exposure as a rotation incident. Do not place values in tickets, commits or reports.
