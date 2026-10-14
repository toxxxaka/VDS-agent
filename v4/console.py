"""Safe read-only command vocabulary for the WebUI console.

The browser never reaches a shell. Familiar command text resolves to one fixed,
audited backend operation with validated arguments.
"""
from __future__ import annotations

import shlex
from typing import Any

from .agent_tools import LOG_UNITS, ToolError, execute

SERVICE_NAMES = "|".join(sorted(LOG_UNITS))
HELP = f"""Safe console — read-only, audited diagnostics

BASICS
  help [topic]                  full list or one topic
  status | cpu | memory | disk | network | load | uptime
  processes [cpu|memory|io]     sampled top processes
  process PID                   details for one PID
  sockets [port|name]           listening TCP/UDP sockets
  metrics [1h|6h|24h|7d|30d]    telemetry history

DIAGNOSIS
  diagnose cpu|memory|io|disk|network|oom|server|nginx|docker
  pressure                      CPU / memory / I/O PSI
  oom history                   recent OOM killer events
  swap usage|activity           swap capacity and page-in/page-out counters
  kernel reclaim|allocfail      memory-reclaim and allocation-failure counters
  compare cpu 1h 24h            CPU average comparison
  report 24h                    health and incident summary

NETWORK
  network summary|top|interfaces|errors|connections|listen|syn|dns|routes

SERVICES & LOGS
  services [failed|restart-count]
  service <unit>                unit must be one of: {SERVICE_NAMES}
  logs [<unit>|errors|kernel|ssh]
  timers | boot analyze

SECURITY, STORAGE & MONITORING
  security overview|ssh|fail2ban|firewall|ports|updates
  disk usage|inodes|health|growth
  backup status|verify
  monitoring health|collectors|alerts
  incidents [active|closed|all|recent]
  changes 24h

Type a command without required arguments and the console prints its valid
arguments. Shell syntax, paths, pipelines and arbitrary commands are refused."""

TOPIC_HELP = {
    "network": "network <summary|top|interfaces|errors|connections|listen|syn|dns|routes>",
    "diagnose": "diagnose <cpu|memory|io|disk|network|oom|server|nginx|docker>",
    "security": "security <overview|ssh|fail2ban|firewall|ports|updates>",
    "disk": "disk <usage|inodes|health|growth>",
    "monitoring": "monitoring <health|collectors|alerts>",
    "services": "services [failed|restart-count]",
    "logs": f"logs [<unit>|errors|kernel|ssh]\nAllowed units: {SERVICE_NAMES}",
    "swap": "swap <usage|activity>",
    "kernel": "kernel <reclaim|allocfail>",
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
        if len(arguments) > 1: raise _usage("help [network|diagnose|security|disk|monitoring|services|logs|swap|kernel]")
        return "help", {"topic": arguments[0] if arguments else ""}
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
        if option in {"errors", "kernel", "ssh"}: return "console_diagnostic", {"topic": "logs", "option": option}
        if option not in LOG_UNITS: raise _usage(TOPIC_HELP["logs"])
        return "service_logs", {"unit": option, "lines": 40, "minutes": 60}
    if name == "services":
        if len(arguments) > 1 or (arguments and arguments[0] not in {"failed", "restart-count"}): raise _usage(TOPIC_HELP["services"])
        if not arguments:
            return "service_status", {}
        return "console_diagnostic", {"topic": "services", "option": arguments[0]}
    if name == "service":
        if len(arguments) != 1 or arguments[0] not in LOG_UNITS: raise _usage(f"service <unit>\nAllowed units: {SERVICE_NAMES}")
        return "console_diagnostic", {"topic": "service", "option": arguments[0]}
    if name in {"pressure", "timers"}:
        if arguments: raise _usage(name)
        return "console_diagnostic", {"topic": name, "option": ""}
    if name in {"swap", "kernel"}:
        allowed = {"swap": {"usage", "activity"}, "kernel": {"reclaim", "allocfail"}}[name]
        if len(arguments) != 1 or arguments[0] not in allowed: raise _usage(TOPIC_HELP[name])
        return "console_diagnostic", {"topic": name, "option": arguments[0]}
    if name == "oom":
        if arguments != ["history"]: raise _usage("oom history")
        return "console_diagnostic", {"topic": "oom", "option": "history"}
    if name == "boot":
        if arguments != ["analyze"]: raise _usage("boot analyze")
        return "console_diagnostic", {"topic": "boot", "option": "analyze"}
    if name in {"diagnose", "security", "monitoring", "backup"}:
        usage = TOPIC_HELP.get(name, f"{name} <{'cpu|memory|io|disk|network|oom|server|nginx|docker' if name == 'diagnose' else 'status|verify'}>")
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
        if topic and topic not in TOPIC_HELP: raise _usage("help [network|diagnose|security|disk|monitoring|services|logs|swap|kernel]")
        return {"command": "help", "tool": "help", "read_only": True, "text": TOPIC_HELP[topic] if topic else HELP}
    result = execute(tool, arguments, actor=actor)
    return {"command": str(command).strip(), "tool": tool, "read_only": True, "result": result}
