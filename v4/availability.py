"""Remote server availability: ICMP diagnostics plus configured TCP/HTTP health checks."""
from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

CONFIG = Path(os.environ.get("MONITORINGBOT_SERVERS_CONFIG", "/etc/monitoringbot-main/servers.json"))
STATES = {"UP", "DEGRADED", "DOWN", "UNKNOWN"}


def _port(value: Any) -> int:
    try:
        value = int(value)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid TCP port") from error
    if not 1 <= value <= 65535:
        raise ValueError("invalid TCP port")
    return value


def _server(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("server must be an object")
    name, host = value.get("name"), value.get("host")
    if not isinstance(name, str) or not name.strip() or not isinstance(host, str) or not host.strip():
        raise ValueError("server name and host are required")
    ports = [_port(port) for port in value.get("tcp_ports", [])]
    url = value.get("http_url")
    if url is not None:
        parsed = urlparse(str(url))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("http_url must be an absolute HTTP(S) URL")
    return {"name": name.strip(), "host": host.strip(), "tcp_ports": list(dict.fromkeys(ports)), "http_url": url}


def load_config(fallback: dict[str, str] | None = None, path: Path = CONFIG) -> dict[str, Any]:
    defaults = {"attempts": 2, "failure_threshold": 2, "recovery_threshold": 1, "servers": []}
    try:
        raw = json.loads(path.read_text())
        if not isinstance(raw, dict):
            raise ValueError("configuration root must be an object")
        value = {**defaults, **raw}
    except FileNotFoundError:
        value = defaults
        value["servers"] = [{"name": name, "host": host, "tcp_ports": [22]} for name, host in (fallback or {}).items()]
    attempts = int(value["attempts"])
    failure_threshold = int(value["failure_threshold"])
    recovery_threshold = int(value["recovery_threshold"])
    if not 1 <= attempts <= 4 or not 1 <= failure_threshold <= 5 or not 1 <= recovery_threshold <= 5:
        raise ValueError("invalid availability thresholds")
    servers = [_server(item) for item in value.get("servers", [])]
    return {"attempts": attempts, "failure_threshold": failure_threshold, "recovery_threshold": recovery_threshold, "servers": servers}


def _icmp(host: str) -> bool:
    try:
        return subprocess.run(["/usr/bin/ping", "-c", "1", "-W", "2", host], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _tcp(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except ConnectionRefusedError:
        return True  # The peer answered; the service is intentionally closed.
    except OSError:
        return False


def _http(url: str) -> tuple[bool, int | None]:
    try:
        response = requests.get(url, timeout=(3, 5), allow_redirects=True, headers={"User-Agent": "VDS-Agent/1.0"})
        return 200 <= response.status_code < 400, response.status_code
    except requests.RequestException:
        return False, None


def probe(server: dict[str, Any], attempts: int = 2) -> dict[str, Any]:
    """Run bounded checks. ICMP is diagnostic only; services determine availability."""
    icmp = []
    tcp: dict[int, list[bool]] = {port: [] for port in server["tcp_ports"]}
    http: list[tuple[bool, int | None]] = []
    for _ in range(attempts):
        icmp.append(_icmp(server["host"]))
        for port in tcp:
            tcp[port].append(_tcp(server["host"], port))
        if server["http_url"]:
            http.append(_http(server["http_url"]))
    checks = [{"kind": "icmp", "ok": any(icmp), "attempts": len(icmp)}]
    checks.extend({"kind": "tcp", "port": port, "ok": any(values), "attempts": len(values)} for port, values in tcp.items())
    if http:
        checks.append({"kind": "http", "url": server["http_url"], "ok": any(value[0] for value in http), "status": next((value[1] for value in reversed(http) if value[1] is not None), None), "attempts": len(http)})
    service_checks = [item for item in checks if item["kind"] in {"tcp", "http"}]
    if not service_checks:
        candidate = "UP" if any(icmp) else "UNKNOWN"
    elif all(item["ok"] for item in service_checks):
        candidate = "UP"
    elif any(item["ok"] for item in service_checks):
        candidate = "DEGRADED"
    else:
        candidate = "DOWN"
    return {"name": server["name"], "host": server["host"], "candidate": candidate, "checks": checks, "icmp_reachable": any(icmp)}


def _previous(previous: Any) -> dict[str, Any]:
    if isinstance(previous, bool):
        return {"status": "UP" if previous else "UNKNOWN", "failure_streak": 0, "recovery_streak": 0}
    return previous if isinstance(previous, dict) else {}


def stabilise(result: dict[str, Any], previous: Any, failure_threshold: int, recovery_threshold: int) -> dict[str, Any]:
    """Apply failure/recovery thresholds without turning ICMP loss into DOWN."""
    before = _previous(previous)
    candidate = result["candidate"]
    failures = int(before.get("failure_streak", 0))
    recoveries = int(before.get("recovery_streak", 0))
    old_status = before.get("status", "UNKNOWN") if before.get("status") in STATES else "UNKNOWN"
    if candidate == "DOWN":
        failures += 1
        recoveries = 0
        status = "DOWN" if failures >= failure_threshold else "DEGRADED"
    elif candidate == "UP":
        recoveries += 1
        failures = 0
        status = "UP" if old_status != "DOWN" or recoveries >= recovery_threshold else "DEGRADED"
    elif candidate == "DEGRADED":
        status, failures, recoveries = "DEGRADED", 0, 0
    else:
        status, failures, recoveries = "UNKNOWN", 0, 0
    return {**result, "status": status, "failure_streak": failures, "recovery_streak": recoveries, "previous_status": old_status}


def check_all(config: dict[str, Any], previous: dict[str, Any] | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    prior = (previous or {}).get("servers", previous or {})
    output: dict[str, dict[str, Any]] = {}
    for server in config["servers"]:
        result = probe(server, config["attempts"])
        output[server["name"]] = stabilise(result, prior.get(server["name"]), config["failure_threshold"], config["recovery_threshold"])
    state = {"version": 2, "servers": {name: {"status": item["status"], "failure_streak": item["failure_streak"], "recovery_streak": item["recovery_streak"]} for name, item in output.items()}}
    return output, state
