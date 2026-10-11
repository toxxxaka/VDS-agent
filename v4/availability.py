"""Remote availability: ICMP diagnostics plus explicit DNS/TCP/HTTP/TLS checks."""
from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import time
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
    body = value.get("http_body_regex")
    if body is not None:
        if not isinstance(body, str) or len(body) > 256:
            raise ValueError("http_body_regex must be a short string")
        try:
            re.compile(body)
        except re.error as error:
            raise ValueError("invalid http_body_regex") from error
    status = value.get("http_status", [200, 399])
    if not isinstance(status, list) or len(status) != 2 or any(isinstance(item, bool) or not isinstance(item, int) for item in status) or not 100 <= status[0] <= status[1] <= 599:
        raise ValueError("http_status must be [minimum, maximum]")
    tls_warn = value.get("tls_expiry_warning_days", 21)
    if isinstance(tls_warn, bool) or not isinstance(tls_warn, int) or not 1 <= tls_warn <= 365:
        raise ValueError("invalid tls_expiry_warning_days")
    return {"name": name.strip(), "host": host.strip(), "tcp_ports": list(dict.fromkeys(ports)), "http_url": url,
            "http_body_regex": body, "http_status": status, "tls_expiry_warning_days": tls_warn}


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
    attempts, failure_threshold, recovery_threshold = int(value["attempts"]), int(value["failure_threshold"]), int(value["recovery_threshold"])
    if not 1 <= attempts <= 4 or not 1 <= failure_threshold <= 5 or not 1 <= recovery_threshold <= 5:
        raise ValueError("invalid availability thresholds")
    return {"attempts": attempts, "failure_threshold": failure_threshold, "recovery_threshold": recovery_threshold, "servers": [_server(item) for item in value.get("servers", [])]}


def _icmp(host: str) -> bool:
    try:
        return subprocess.run(["/usr/bin/ping", "-c", "1", "-W", "2", host], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _dns(host: str) -> bool:
    try:
        return bool(socket.getaddrinfo(host, None, type=socket.SOCK_STREAM))
    except OSError:
        return False


def _tcp(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except ConnectionRefusedError:
        return True  # The peer answered; a closed optional port is reachable.
    except OSError:
        return False


def _http_detail(url: str, expected: list[int], body_regex: str | None) -> tuple[bool, int | None, float | None]:
    started = time.monotonic()
    try:
        response = requests.get(url, timeout=(3, 5), allow_redirects=True, headers={"User-Agent": "VDS-Agent/1.0"})
        status_ok = expected[0] <= response.status_code <= expected[1]
        body_ok = body_regex is None or re.search(body_regex, response.text[:262144]) is not None
        return status_ok and body_ok, response.status_code, round((time.monotonic() - started) * 1000, 1)
    except requests.RequestException:
        return False, None, round((time.monotonic() - started) * 1000, 1)


def _http(url: str) -> tuple[bool, int | None]:
    """Compatibility wrapper retained for existing callers and tests."""
    ok, status, _elapsed = _http_detail(url, [200, 399], None)
    return ok, status


def _tls_days(url: str) -> int | None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    try:
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=parsed.hostname) as wrapped:
                certificate = wrapped.getpeercert()
        return max(0, int((ssl.cert_time_to_seconds(certificate["notAfter"]) - time.time()) // 86400))
    except (OSError, ssl.SSLError, KeyError, ValueError):
        return None


def probe(server: dict[str, Any], attempts: int = 2) -> dict[str, Any]:
    """ICMP is diagnostic only; repeated configured service checks decide DOWN."""
    server = _server(server)
    icmp, dns = [], []
    tcp: dict[int, list[bool]] = {port: [] for port in server["tcp_ports"]}
    http: list[tuple[bool, int | None, float | None]] = []
    for _ in range(attempts):
        dns.append(_dns(server["host"]))
        icmp.append(_icmp(server["host"]))
        for port in tcp:
            tcp[port].append(_tcp(server["host"], port))
        if server["http_url"]:
            http.append(_http_detail(server["http_url"], server["http_status"], server["http_body_regex"]))
    checks = [{"kind": "dns", "ok": any(dns), "attempts": len(dns)}, {"kind": "icmp", "ok": any(icmp), "attempts": len(icmp)}]
    checks.extend({"kind": "tcp", "port": port, "ok": any(values), "attempts": len(values)} for port, values in tcp.items())
    if http:
        latencies = [entry[2] for entry in http if entry[2] is not None]
        checks.append({"kind": "http", "url": server["http_url"], "ok": any(value[0] for value in http), "status": next((value[1] for value in reversed(http) if value[1] is not None), None), "attempts": len(http), "response_ms": latencies[-1] if latencies else None, "p95_ms": max(latencies) if latencies else None})
        days = _tls_days(server["http_url"])
        if days is not None:
            checks.append({"kind": "tls", "ok": days >= server["tls_expiry_warning_days"], "days_remaining": days, "warning_days": server["tls_expiry_warning_days"]})
    service_checks = [item for item in checks if item["kind"] in {"tcp", "http", "tls"}]
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
    before = _previous(previous)
    candidate = result["candidate"]
    failures, recoveries = int(before.get("failure_streak", 0)), int(before.get("recovery_streak", 0))
    old_status = before.get("status", "UNKNOWN") if before.get("status") in STATES else "UNKNOWN"
    if candidate == "DOWN":
        failures += 1; recoveries = 0; status = "DOWN" if failures >= failure_threshold else "DEGRADED"
    elif candidate == "UP":
        recoveries += 1; failures = 0; status = "UP" if old_status != "DOWN" or recoveries >= recovery_threshold else "DEGRADED"
    elif candidate == "DEGRADED":
        status, failures, recoveries = "DEGRADED", 0, 0
    else:
        status, failures, recoveries = "UNKNOWN", 0, 0
    return {**result, "status": status, "failure_streak": failures, "recovery_streak": recoveries, "previous_status": old_status}


def check_all(config: dict[str, Any], previous: dict[str, Any] | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    prior = (previous or {}).get("servers", previous or {})
    output = {server["name"]: stabilise(probe(server, config["attempts"]), prior.get(server["name"]), config["failure_threshold"], config["recovery_threshold"]) for server in config["servers"]}
    return output, {"version": 3, "servers": {name: {"status": item["status"], "failure_streak": item["failure_streak"], "recovery_streak": item["recovery_streak"]} for name, item in output.items()}}
