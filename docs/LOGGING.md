# Project nginx logs

VDS Agent keeps the distribution nginx logs in `/var/log/nginx/` and separates
project traffic into three subdirectories:

| Directory | Traffic |
| --- | --- |
| `/var/log/nginx/site/` | `0x870x4k3r.tech`, including its redirects |
| `/var/log/nginx/vds-agent/` | Monitoring WebUI and Monitoring MCP |
| `/var/log/nginx/x-agent/` | X-Agent MCP and the public AI chat proxy |

Each directory has `access.log` and `error.log`. Directories are `root:adm`
with mode `0750`; log files use mode `0640`. Do not put request bodies,
credentials, or private allow-lists in either format.

## Installation

Create the directories before testing nginx:

```bash
sudo install -d -o root -g adm -m 0750 \
  /var/log/nginx/site /var/log/nginx/vds-agent /var/log/nginx/x-agent
```

Include the corresponding file from `config/nginx/` inside every matching
`server {}` block. The public `/api/ai/chat` location is part of the main site
vhost, so add the two directives from `log-x-agent.conf` directly inside that
location to prevent chat requests being mixed with site traffic.

Install `config/logrotate/nginx-project-logs` as
`/etc/logrotate.d/vds-agent-project-logs`. It matches the standard nginx
rotation policy: daily, 14 compressed generations, and a graceful nginx
reopen after rotation.

Validate before applying:

```bash
sudo nginx -t
sudo logrotate -d /etc/logrotate.d/vds-agent-project-logs
sudo systemctl reload nginx
```

## AIDE

The optional AIDE check is intentionally paused on the reference server while
the project changes frequently. Its timer is disabled rather than deleting the
service or integrity database. Re-enable it only after reviewing and creating
a new trusted baseline; do not silently replace a baseline following a failed
check.
