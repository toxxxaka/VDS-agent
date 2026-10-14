#!/usr/bin/env python3
"""Small, dependency-free external availability Sentinel for VDS Agent.

The process is intended for a separate host.  It has no control-plane access to
the monitored server; it only performs outbound DNS/TCP/TLS/HTTPS probes and
optionally sends state-transition notifications through Telegram.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT = 8.0
DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_RECOVERY_THRESHOLD = 2


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    stage: str
    detail: str
    status: int | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _as_positive_int(value: Any, field: str, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} must be a positive integer")
    return value


def load_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read configuration: {error}") from error
    if not isinstance(raw, dict):
        raise ValueError("configuration must be a JSON object")
    if raw.get("schema", 1) != 1:
        raise ValueError("unsupported configuration schema")
    targets = raw.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets must be a non-empty array")
    names: set[str] = set()
    validated: list[dict[str, Any]] = []
    for item in targets:
        if not isinstance(item, dict):
            raise ValueError("every target must be an object")
        name, url = item.get("name"), item.get("url")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("target name must be a non-empty string")
        if name in names:
            raise ValueError(f"duplicate target name: {name}")
        names.add(name)
        if not isinstance(url, str):
            raise ValueError(f"target {name}: url must be a string")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError(f"target {name}: only absolute https URLs are allowed")
        expected = item.get("expected_status", [200, 399])
        if not (isinstance(expected, list) and len(expected) == 2 and all(isinstance(v, int) for v in expected)):
            raise ValueError(f"target {name}: expected_status must be [minimum, maximum]")
        if expected[0] < 100 or expected[0] > expected[1] or expected[1] > 599:
            raise ValueError(f"target {name}: invalid expected_status range")
        timeout = item.get("timeout_seconds", DEFAULT_TIMEOUT)
        if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 60:
            raise ValueError(f"target {name}: timeout_seconds must be between 0 and 60")
        validated.append({
            "name": name,
            "url": url,
            "expected_status": expected,
            "timeout_seconds": float(timeout),
        })
    telegram = raw.get("telegram")
    if telegram is not None:
        if not isinstance(telegram, dict):
            raise ValueError("telegram must be an object when configured")
        if not isinstance(telegram.get("bot_token"), str) or not telegram["bot_token"].strip():
            raise ValueError("telegram.bot_token is required when telegram is configured")
        if not isinstance(telegram.get("chat_id"), (str, int)) or not str(telegram["chat_id"]).strip():
            raise ValueError("telegram.chat_id is required when telegram is configured")
    return {
        "schema": 1,
        "targets": validated,
        "failure_threshold": _as_positive_int(raw.get("failure_threshold"), "failure_threshold", DEFAULT_FAILURE_THRESHOLD),
        "recovery_threshold": _as_positive_int(raw.get("recovery_threshold"), "recovery_threshold", DEFAULT_RECOVERY_THRESHOLD),
        "telegram": telegram,
    }


def probe_target(target: dict[str, Any]) -> ProbeResult:
    """Diagnose the first failing layer without accepting redirects implicitly."""
    parsed = urlsplit(target["url"])
    host = parsed.hostname
    assert host is not None
    port = parsed.port or 443
    timeout = target["timeout_seconds"]
    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as error:
        return ProbeResult(False, "dns", str(error))
    try:
        connection = socket.create_connection((host, port), timeout=timeout)
    except OSError as error:
        return ProbeResult(False, "tcp", str(error))
    try:
        context = ssl.create_default_context()
        tls_connection = context.wrap_socket(connection, server_hostname=host)
        tls_connection.close()
    except (OSError, ssl.SSLError) as error:
        connection.close()
        return ProbeResult(False, "tls", str(error))
    path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
    try:
        https_connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
        https_connection.request("GET", path, headers={"Host": host, "User-Agent": "VDS-Agent-Sentinel/1.0"})
        response = https_connection.getresponse()
        response.read(1)
        status = response.status
        https_connection.close()
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        return ProbeResult(False, "https", str(error))
    minimum, maximum = target["expected_status"]
    if minimum <= status <= maximum:
        return ProbeResult(True, "https", f"HTTP {status}", status)
    return ProbeResult(False, "https", f"unexpected HTTP {status}", status)


def _load_state(path: str | os.PathLike[str]) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_state(path: str | os.PathLike[str], value: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def transition(previous: dict[str, Any], result: ProbeResult, failure_threshold: int, recovery_threshold: int, now: str) -> tuple[dict[str, Any], str | None]:
    """Return durable state and one event: down, recovered, or None."""
    state = dict(previous)
    availability = state.get("availability", "unknown")
    state["availability"] = availability
    failures = int(state.get("consecutive_failures", 0))
    successes = int(state.get("consecutive_successes", 0))
    state["last_checked_at"] = now
    state["last_stage"] = result.stage
    state["last_detail"] = result.detail
    state["last_status"] = result.status
    if result.ok:
        successes += 1
        failures = 0
        state["consecutive_successes"] = successes
        state["consecutive_failures"] = 0
        state["last_success_at"] = now
        if availability == "down" and successes >= recovery_threshold:
            state["availability"] = "up"
            return state, "recovered"
        if availability == "unknown":
            state["availability"] = "up"
        return state, None
    failures += 1
    successes = 0
    state["consecutive_failures"] = failures
    state["consecutive_successes"] = 0
    state["last_failure_at"] = now
    if availability != "down" and failures >= failure_threshold:
        state["availability"] = "down"
        return state, "down"
    return state, None


def notification(event: str, target: dict[str, Any], state: dict[str, Any]) -> str:
    if event == "down":
        headline = "⚠️ VDS Agent Sentinel: service unavailable"
        body = f"Failure: {state['last_stage']} — {state['last_detail']}"
    else:
        headline = "✅ VDS Agent Sentinel: service recovered"
        body = f"Recovered after a successful {state['last_stage']} check"
    return "\n".join((headline, f"Target: {target['name']}", f"URL: {target['url']}", body, f"Checked: {state['last_checked_at']}"))


def send_telegram(config: dict[str, Any], message: str) -> None:
    telegram = config.get("telegram")
    if not telegram:
        return
    endpoint = f"https://api.telegram.org/bot{telegram['bot_token']}/sendMessage"
    payload = json.dumps({"chat_id": telegram["chat_id"], "text": message, "disable_web_page_preview": True}).encode()
    request = Request(endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=10) as response:  # nosec B310: URL is a fixed Telegram API origin
        if not 200 <= response.status < 300:
            raise RuntimeError(f"Telegram returned HTTP {response.status}")


def run_once(config: dict[str, Any], state_path: str | os.PathLike[str], probe: Callable[[dict[str, Any]], ProbeResult] = probe_target, notify: Callable[[dict[str, Any], str], None] = send_telegram, now: str | None = None) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    state = _load_state(state_path)
    targets_state = state.get("targets") if isinstance(state.get("targets"), dict) else {}
    updated: dict[str, Any] = {}
    events: list[tuple[str, str]] = []
    checked_at = now or utc_now()
    for target in config["targets"]:
        result = probe(target)
        current, event = transition(targets_state.get(target["name"], {}), result, config["failure_threshold"], config["recovery_threshold"], checked_at)
        updated[target["name"]] = current
        if event:
            events.append((event, target["name"]))
            try:
                notify(config, notification(event, target, current))
            except Exception as error:
                print(f"sentinel notification failed for {target['name']}: {error}", file=sys.stderr)
    final = {"schema": 1, "updated_at": checked_at, "targets": updated}
    _write_state(state_path, final)
    return final, events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independent VDS Agent availability Sentinel")
    parser.add_argument("--config", default="/etc/vds-agent-sentinel/sentinel.json")
    parser.add_argument("--state", default="/var/lib/vds-agent-sentinel/state.json")
    parser.add_argument("--check-config", action="store_true", help="validate configuration without probing or writing state")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.check_config:
            print(f"valid configuration: {len(config['targets'])} target(s)")
            return 0
        _, events = run_once(config, args.state)
        print("checked " + str(len(config["targets"])) + " target(s)" + ("; event(s): " + ", ".join(f"{event}:{name}" for event, name in events) if events else ""))
        return 0
    except Exception as error:
        print(f"sentinel error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
