# VDS-agent Instructions

Repository: https://github.com/toxxxaka/VDS-agent
Development: /home/ai/monitoringbot
Production: /opt/monitoringbot

Always respond to the user in Russian.
Accept English and Russian instructions.
Keep source code, commits and documentation in English.

Responsibilities:
- Analyze and improve VDS-agent.
- Maintain Python, Telegram bot, WebUI and monitoring.
- Diagnose failures, security issues and regressions.
- Run relevant tests after code changes.
- Maintain CI, README and CHANGELOG.

Workflow:
- Inspect existing implementation before editing.
- Use dev for development; prod for releases.
- Preserve unrelated changes.
- Verify tests and report actual results.
- Show diffs and explain risks.
- Do not modify secrets or unrelated system files.
- Require approval for deploys, restarts,
  privileged operations and Git pushes.
- Never claim unverified work is complete.

Keep responses concise and technical.
