# Safe Shell reference

Safe Shell is a read-only command vocabulary for the authenticated WebUI. It is
not a browser terminal: every accepted phrase maps to a fixed backend operation
with validated arguments, a timeout, bounded output, redaction and an audit
record. Paths, pipes, redirects, substitutions and arbitrary executable names
are refused.

Use `help` for the complete catalogue, `help <topic>` for exact accepted
arguments, and `man <topic>` for purpose, usage and examples. The manual pages
are local text and make no system call.

## Everyday inspection

```text
status | cpu | memory | disk | network | load | uptime
metrics [1h|6h|24h|7d|30d]
processes [cpu|memory|io]
process PID
sockets [port|name]
```

`processes io` reports cumulative per-process read/write bytes since process
start, not an instantaneous I/O rate.

## Diagnosis

```text
diagnose cpu|memory|io|disk|network|oom|server|nginx|docker
pressure
oom history
compare cpu 1h 24h
report 24h
```

Each `diagnose` option returns a different evidence set. It never changes a
service or host configuration.

## Memory and kernel

```text
swap usage|activity|pressure
kernel reclaim|allocfail|hung-tasks|oops
```

`swap pressure` reads memory PSI. Kernel counters are cumulative since boot.
`hung-tasks` and `oops` search the bounded kernel journal window.

## Network and local limits

```text
network summary|top|interfaces|errors|connections|listen|syn|dns|routes
limits fd|conntrack
```

Network results are local counters and current sockets. `network top` groups
current TCP connections by peer; it is not packet capture. `limits conntrack`
returns the local count and configured maximum when the kernel exposes them.

## Services and logs

```text
services [failed|restart-count]
service <unit>
service deps|restarts <unit>
logs [<unit>|errors|kernel|ssh|journal-size|rotate]
timers
boot analyze
```

`<unit>` is limited to VDS Agent and selected core units shown by `help
services`. Dependency and restart views only read systemd metadata.

## Host, access and package state

```text
time sync
apt health|pending-security
fail2ban jails|bans
ssh sessions|last-logins
```

`apt pending-security` lists locally known upgradable packages. It does not
refresh package lists, install updates or claim a CVE classification.

## Existing monitoring, storage and security groups

```text
security overview|ssh|fail2ban|firewall|ports|updates
disk usage|inodes|health|growth
backup status|verify
monitoring health|collectors|alerts
incidents [active|closed|all|recent]
changes 24h
```

## Manual pages

```text
man processes
man diagnose
man network
man services
man security
man system
```

When a required object is absent or invalid, the console returns its exact
accepted syntax and, where relevant, the allow-listed units.
