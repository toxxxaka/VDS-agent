"""Safe read-only command vocabulary for the WebUI console.

The browser never reaches a shell.  A familiar command is parsed into one of the
same bounded diagnostic tools used by Telegram and MCP.
"""
from __future__ import annotations

import shlex
from typing import Any

from .agent_tools import ToolError, execute

HELP = """Allowed commands:
  help                         show this list
  status | cpu | memory | disk | network
  processes [cpu|memory|io]    top five sampled processes
  sockets [port|name]          listening TCP/UDP sockets
  services                     core service states
  logs [unit]                  recent journal for an allowed unit
  incidents [active|closed|all]
  metrics [1h|6h|24h|7d|30d]

This console is read-only. It does not run shell commands, pipelines, paths,
or arguments outside this allow-list. Use the dedicated Tools actions for
confirmed administrative operations."""

COMMANDS = {
    "status": ("server_status", {}),
    "cpu": ("diagnose_load", {"limit": 5}),
    "memory": ("diagnose_load", {"limit": 5}),
    "disk": ("diagnose_load", {"limit": 5}),
    "network": ("server_status", {}),
    "services": ("service_status", {}),
}


def parse(command: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(command, str) or len(command) > 160:
        raise ToolError("command is too long")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ToolError("invalid command syntax") from exc
    if not parts:
        raise ToolError("enter a command or type help")
    if any(any(mark in part for mark in ("|", ";", "&", "`", "$", ">", "<", "\\")) for part in parts):
        raise ToolError("shell syntax is not supported")
    name, arguments = parts[0].lower(), parts[1:]
    if name == "help" and not arguments:
        return "help", {}
    if name in COMMANDS and not arguments:
        return COMMANDS[name]
    if name == "processes" and len(arguments) <= 1:
        return "process_inspect", {"sort": arguments[0].lower() if arguments else "cpu", "limit": 5}
    if name == "sockets" and len(arguments) <= 1:
        return "socket_inspect", {"sort": arguments[0].lower() if arguments else "port"}
    if name == "logs" and len(arguments) <= 1:
        return "service_logs", {"unit": arguments[0] if arguments else "monitoringbot.service", "lines": 40, "minutes": 60}
    if name == "incidents" and len(arguments) <= 1:
        return "incidents_query", {"status": arguments[0].lower() if arguments else "active"}
    if name == "metrics" and len(arguments) <= 1:
        return "metrics_query", {"range": arguments[0].lower() if arguments else "1h"}
    raise ToolError("unknown command or arguments; type help")


def run(command: Any, actor: str) -> dict[str, Any]:
    tool, arguments = parse(command)
    if tool == "help":
        return {"command": "help", "tool": "help", "read_only": True, "text": HELP}
    result = execute(tool, arguments, actor=actor)
    return {"command": str(command).strip(), "tool": tool, "read_only": True, "result": result}
