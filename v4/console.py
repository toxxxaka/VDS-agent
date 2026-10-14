"""Safe read-only command vocabulary for the WebUI console.

The browser never reaches a shell. Familiar command text resolves to one fixed,
audited backend operation with validated arguments.
"""
from __future__ import annotations

import shlex
from typing import Any

from .agent_tools import LOG_UNITS, ToolError, execute

SERVICE_NAMES = "|".join(sorted(LOG_UNITS))
HELP = f"""Safe Shell — read-only, audited diagnostics

Type man <topic> for purpose, safe usage and examples.

BASICS
  help [topic] | man <topic>     command catalogue and manual pages
  status | cpu | memory | disk | network | load | uptime
  processes [cpu|memory|io]      sampled top processes
  process PID                    details for one PID
  sockets [port|name]            listening TCP/UDP sockets
  metrics [1h|6h|24h|7d|30d]     telemetry history

DIAGNOSIS
  diagnose cpu|memory|io|disk|network|oom|server|nginx|docker
  pressure | oom history | compare cpu 1h 24h | report 24h
  swap usage|activity|pressure
  kernel reclaim|allocfail|hung-tasks|oops

NETWORK
  network summary|top|interfaces|errors|connections|listen|syn|dns|routes
  limits fd|conntrack             local resource ceilings and current use

SERVICES, LOGS & HOST
  services [failed|restart-count]
  service <unit>                  allowed unit status
  service deps|restarts <unit>    unit dependencies or restart evidence
  logs [<unit>|errors|kernel|ssh|journal-size|rotate]
  timers | boot analyze | time sync
  apt health|pending-security
  fail2ban jails|bans | ssh sessions|last-logins

SECURITY, STORAGE & MONITORING
  security overview|ssh|fail2ban|firewall|ports|updates
  disk usage|inodes|health|growth
  backup status|verify
  monitoring health|collectors|alerts
  incidents [active|closed|all|recent]
  changes 24h

Shell syntax, paths, pipelines and arbitrary commands are refused. Commands
without required arguments print their accepted arguments."""

TOPIC_HELP = {
    "processes": "processes [cpu|memory|io]\nprocess <PID>\nsockets [port|name]",
    "network": "network <summary|top|interfaces|errors|connections|listen|syn|dns|routes>",
    "diagnose": "diagnose <cpu|memory|io|disk|network|oom|server|nginx|docker>",
    "security": "security <overview|ssh|fail2ban|firewall|ports|updates>",
    "disk": "disk <usage|inodes|health|growth>",
    "monitoring": "monitoring <health|collectors|alerts>",
    "services": "services [failed|restart-count]\nservice <unit>\nservice <deps|restarts> <unit>\nAllowed units: " + SERVICE_NAMES,
    "logs": "logs [<unit>|errors|kernel|ssh|journal-size|rotate]\nAllowed units: " + SERVICE_NAMES,
    "swap": "swap <usage|activity|pressure>",
    "kernel": "kernel <reclaim|allocfail|hung-tasks|oops>",
    "system": "apt <health|pending-security>\ntime sync\nlimits <fd|conntrack>\nfail2ban <jails|bans>\nssh <sessions|last-logins>",
}

MANUAL = {
    "processes": """NAME\n  processes — inspect bounded process and socket evidence\n\nSYNOPSIS\n  processes [cpu|memory|io]\n  process PID\n  sockets [port|name]\n\nDESCRIPTION\n  Samples CPU briefly, then lists at most five processes. `io` means process\n  counters accumulated since that process started; it is not an I/O rate.\n\nEXAMPLES\n  processes memory\n  process 1234\n  sockets port\n\nSAFETY\n  Read-only. PIDs, paths and shell syntax are validated and never executed.""",
    "diagnose": """NAME\n  diagnose — focused local evidence for a common failure mode\n\nSYNOPSIS\n  diagnose <cpu|memory|io|disk|network|oom|server|nginx|docker>\n\nDESCRIPTION\n  Each option gathers a distinct bounded evidence set. It does not restart a\n  service, alter configuration or infer a cause where telemetry is missing.\n\nEXAMPLES\n  diagnose memory\n  diagnose network\n  diagnose nginx\n\nRELATED\n  pressure, oom history, services failed, logs errors""",
    "network": """NAME\n  network — inspect local interfaces, TCP states and resolver settings\n\nSYNOPSIS\n  network <summary|top|interfaces|errors|connections|listen|syn|dns|routes>\n  limits conntrack\n\nDESCRIPTION\n  Reads local counters and socket state. `top` groups current TCP connections\n  by peer. It is an observation, not a traffic capture or a firewall command.\n\nEXAMPLES\n  network errors\n  network syn\n  network routes\n  limits conntrack""",
    "services": """NAME\n  services — inspect allow-listed systemd units\n\nSYNOPSIS\n  services [failed|restart-count]\n  service <unit>\n  service <deps|restarts> <unit>\n\nDESCRIPTION\n  Only VDS Agent and core units accepted by this installation can be queried.\n  Dependency output is informational; no unit is started, stopped or reloaded.\n\nEXAMPLES\n  services failed\n  service nginx.service\n  service restarts monitorbot-web.service""",
    "security": """NAME\n  security — read local security signals without changing the host\n\nSYNOPSIS\n  security <overview|ssh|fail2ban|firewall|ports|updates>\n  fail2ban <jails|bans>\n  ssh <sessions|last-logins>\n  apt <health|pending-security>\n\nDESCRIPTION\n  Reports configured or observed state. Package data is only as current as the\n  local APT catalogue; it does not run an upgrade or vulnerability scan.\n\nEXAMPLES\n  security ports\n  fail2ban bans\n  ssh last-logins\n  apt pending-security""",
    "system": """NAME\n  system — inspect local host health, time and log pressure\n\nSYNOPSIS\n  time sync\n  limits <fd|conntrack>\n  logs <journal-size|rotate>\n  kernel <reclaim|allocfail|hung-tasks|oops>\n  swap <usage|activity|pressure>\n\nDESCRIPTION\n  Uses kernel counters, journald metadata and systemd state. Counters marked\n  "since boot" are cumulative and should be compared across observations.\n\nEXAMPLES\n  swap pressure\n  kernel hung-tasks\n  logs journal-size\n  limits fd""",
}

COMMANDS = {
    "status": ("server_status", {}), "cpu": ("diagnose_load", {"limit": 5}),
    "memory": ("diagnose_load", {"limit": 5}), "disk": ("diagnose_load", {"limit": 5}),
    "network": ("server_status", {}), "load": ("diagnose_load", {"limit": 5}),
    "uptime": ("server_status", {}), "health": ("monitoring_health", {}),
}


def _usage(value: str) -> ToolError:
    return ToolError(f"missing or invalid argument. Usage: {value}")


def parse(command: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(command, str) or len(command) > 160:
        raise ToolError("command is too long (maximum 160 characters)")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ToolError("invalid quoting; type help") from exc
    if not parts:
        raise ToolError("enter a command or type help")
    if any(any(mark in part for mark in ("|", ";", "&", "`", "$", ">", "<", "\\")) for part in parts):
        raise ToolError("shell syntax is not supported; type help for allowed commands")
    name, arguments = parts[0].lower(), [value.lower() for value in parts[1:]]
    if name == "help":
        if len(arguments) > 1 or (arguments and arguments[0] not in TOPIC_HELP):
            raise _usage("help [processes|network|diagnose|security|disk|monitoring|services|logs|swap|kernel|system]")
        return "help", {"topic": arguments[0] if arguments else ""}
    if name == "man":
        if len(arguments) != 1 or arguments[0] not in MANUAL:
            raise _usage("man <processes|network|diagnose|services|security|system>")
        return "manual", {"topic": arguments[0]}
    if name in COMMANDS and not arguments:
        return COMMANDS[name]
    if name in COMMANDS:
        if name in {"disk", "network"}:
            allowed = {"disk": {"usage", "inodes", "health", "growth"}, "network": {"summary", "top", "interfaces", "errors", "connections", "listen", "syn", "dns", "routes"}}[name]
            if len(arguments) != 1 or arguments[0] not in allowed:
                raise _usage(TOPIC_HELP[name])
            return "console_diagnostic", {"topic": name, "option": arguments[0]}
        raise _usage(name)
    if name == "processes":
        if len(arguments) > 1 or (arguments and arguments[0] not in {"cpu", "memory", "io"}): raise _usage("processes [cpu|memory|io]")
        return "process_inspect", {"sort": arguments[0] if arguments else "cpu", "limit": 5}
    if name == "process":
        if len(arguments) != 1 or not arguments[0].isdigit(): raise _usage("process <PID>")
        return "process_inspect", {"pid": int(arguments[0]), "limit": 1, "sort": "cpu"}
    if name == "sockets":
        if len(arguments) > 1 or (arguments and arguments[0] not in {"port", "name"}): raise _usage("sockets [port|name]")
        return "socket_inspect", {"sort": arguments[0] if arguments else "port"}
    if name == "logs":
        if len(arguments) > 1: raise _usage(TOPIC_HELP["logs"])
        option = arguments[0] if arguments else "monitoringbot.service"
        if option in {"errors", "kernel", "ssh", "journal-size", "rotate"}: return "console_diagnostic", {"topic": "logs", "option": option}
        if option not in LOG_UNITS: raise _usage(TOPIC_HELP["logs"])
        return "service_logs", {"unit": option, "lines": 40, "minutes": 60}
    if name == "services":
        if len(arguments) > 1 or (arguments and arguments[0] not in {"failed", "restart-count"}): raise _usage(TOPIC_HELP["services"])
        return ("service_status", {}) if not arguments else ("console_diagnostic", {"topic": "services", "option": arguments[0]})
    if name == "service":
        if len(arguments) == 1 and arguments[0] in LOG_UNITS:
            return "console_diagnostic", {"topic": "service", "option": arguments[0]}
        if len(arguments) == 2 and arguments[0] in {"deps", "restarts"} and arguments[1] in LOG_UNITS:
            return "console_diagnostic", {"topic": "service", "option": f"{arguments[0]}:{arguments[1]}"}
        raise _usage(f"service <unit>\nservice <deps|restarts> <unit>\nAllowed units: {SERVICE_NAMES}")
    if name in {"pressure", "timers"}:
        if arguments: raise _usage(name)
        return "console_diagnostic", {"topic": name, "option": ""}
    if name in {"swap", "kernel"}:
        allowed = {"swap": {"usage", "activity", "pressure"}, "kernel": {"reclaim", "allocfail", "hung-tasks", "oops"}}[name]
        if len(arguments) != 1 or arguments[0] not in allowed: raise _usage(TOPIC_HELP[name])
        return "console_diagnostic", {"topic": name, "option": arguments[0]}
    if name == "oom":
        if arguments != ["history"]: raise _usage("oom history")
        return "console_diagnostic", {"topic": "oom", "option": "history"}
    if name == "boot":
        if arguments != ["analyze"]: raise _usage("boot analyze")
        return "console_diagnostic", {"topic": "boot", "option": "analyze"}
    if name in {"apt", "time", "limits", "fail2ban", "ssh"}:
        accepted = {"apt": {"health", "pending-security"}, "time": {"sync"}, "limits": {"fd", "conntrack"}, "fail2ban": {"jails", "bans"}, "ssh": {"sessions", "last-logins"}}[name]
        if len(arguments) != 1 or arguments[0] not in accepted: raise _usage(TOPIC_HELP["system"])
        return "console_diagnostic", {"topic": name, "option": arguments[0]}
    if name in {"diagnose", "security", "monitoring", "backup"}:
        usage = TOPIC_HELP.get(name, f"{name} <cpu|memory|io|disk|network|oom|server|nginx|docker>")
        allowed = {"diagnose": {"cpu", "memory", "io", "disk", "network", "oom", "server", "nginx", "docker"}, "security": {"overview", "ssh", "fail2ban", "firewall", "ports", "updates"}, "monitoring": {"health", "collectors", "alerts"}, "backup": {"status", "verify"}}[name]
        if len(arguments) != 1 or arguments[0] not in allowed: raise _usage(usage)
        return "console_diagnostic", {"topic": name, "option": arguments[0]}
    if name == "incidents":
        if len(arguments) > 1 or (arguments and arguments[0] not in {"active", "closed", "all", "recent"}): raise _usage("incidents [active|closed|all|recent]")
        if arguments == ["recent"]: return "console_diagnostic", {"topic": "incidents", "option": "recent"}
        return "incidents_query", {"status": arguments[0] if arguments else "active"}
    if name == "metrics":
        if len(arguments) > 1 or (arguments and arguments[0] not in {"1h", "6h", "24h", "7d", "30d"}): raise _usage("metrics [1h|6h|24h|7d|30d]")
        return "metrics_query", {"range": arguments[0] if arguments else "1h"}
    if name == "compare":
        if arguments != ["cpu", "1h", "24h"]: raise _usage("compare cpu 1h 24h")
        return "console_diagnostic", {"topic": "compare", "option": "cpu"}
    if name in {"changes", "report"}:
        if arguments != ["24h"]: raise _usage(f"{name} 24h")
        return "console_diagnostic", {"topic": name, "option": "24h"}
    raise ToolError("unknown command; type help for the allow-listed command list")


def run(command: Any, actor: str) -> dict[str, Any]:
    tool, arguments = parse(command)
    if tool == "help":
        topic = arguments["topic"]
        return {"command": "help", "tool": "help", "read_only": True, "text": TOPIC_HELP[topic] if topic else HELP}
    if tool == "manual":
        return {"command": f"man {arguments['topic']}", "tool": "manual", "read_only": True, "text": MANUAL[arguments["topic"]]}
    result = execute(tool, arguments, actor=actor)
    return {"command": str(command).strip(), "tool": tool, "read_only": True, "result": result}
