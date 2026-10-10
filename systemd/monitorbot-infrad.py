#!/usr/bin/env python3
"""Root bridge for VDS-Agent infrastructure operations.

The bridge owns only ``table inet monitoringbot``.  It never replaces the host
ruleset: every managed change stores the previous managed table and rollback
restores that exact table (or removes the table when it did not exist).
"""
from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import secrets
import socket
import struct
import subprocess
import threading
import time
from typing import Any

SOCKET = "/run/monitorbot/infrastructure.sock"
BASE = pathlib.Path("/var/lib/monitoringbot/firewall")
ACTIVE_PREVIOUS = BASE / "active-previous.nft"
ACTIVE_META = BASE / "active-previous.json"
TABLE = ("inet", "monitoringbot")
PENDING: dict[str, dict[str, Any]] = {}
LOCK = threading.Lock()


def run(*args: str, check: bool = True, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=check,
    )


def trusted(connection: socket.socket) -> bool:
    _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return uid == __import__("pwd").getpwnam("monitorbot").pw_uid


def profile(name: str, source_ip: str, keep_webui: bool) -> str:
    address = ipaddress.ip_address(source_ip)
    family = "ip6" if address.version == 6 else "ip"
    ssh = f"{family} saddr {address} tcp dport 22 accept"
    https = f"{family} saddr {address} tcp dport 443 accept"
    if name == "none":
        return ""
    if name == "standard":
        extras = "tcp dport {22,80,443} accept\n"
    elif name == "hard":
        extras = ssh + "\n" + (https + "\n" if keep_webui else "")
    else:
        raise ValueError("unknown profile")
    return (
        "table inet monitoringbot {\n"
        "  chain input {\n"
        "    type filter hook input priority -50; policy drop;\n"
        "    iifname \"lo\" accept\n"
        "    ct state established,related accept\n"
        "    ct state invalid drop\n"
        "    ip protocol icmp accept\n"
        "    ip6 nexthdr ipv6-icmp accept\n"
        f"    {extras}"
        "  }\n"
        "}\n"
    )


def _ensure_base() -> None:
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BASE, 0o700)


def _managed_table() -> str | None:
    result = run("/usr/sbin/nft", "list", "table", *TABLE, check=False)
    return result.stdout if result.returncode == 0 else None


def _write_private(path: pathlib.Path, text: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def save_previous() -> dict[str, Any]:
    """Save only the managed table; an absent table is a valid rollback target."""
    _ensure_base()
    before = _managed_table()
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    backup = BASE / f"{stamp}-previous.nft"
    _write_private(backup, before or "")
    _write_private(ACTIVE_PREVIOUS, before or "")
    metadata = {"created_at": time.time(), "table_existed": before is not None, "backup": str(backup)}
    _write_private(ACTIVE_META, json.dumps(metadata, separators=(",", ":")))
    return metadata


def _delete_managed() -> None:
    run("/usr/sbin/nft", "delete", "table", *TABLE, check=False)


def restore_previous() -> dict[str, Any]:
    """Restore the saved managed table without touching other nftables tables."""
    if not ACTIVE_META.exists() or not ACTIVE_PREVIOUS.exists():
        raise RuntimeError("no managed firewall rollback snapshot is available")
    try:
        metadata = json.loads(ACTIVE_META.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("managed firewall rollback metadata is invalid") from error
    previous = ACTIVE_PREVIOUS.read_text()
    _delete_managed()
    if metadata.get("table_existed"):
        validation = run("/usr/sbin/nft", "-c", "-f", str(ACTIVE_PREVIOUS), check=False)
        if validation.returncode != 0:
            raise RuntimeError("saved managed firewall snapshot failed validation")
        applied = run("/usr/sbin/nft", "-f", str(ACTIVE_PREVIOUS), check=False)
        if applied.returncode != 0:
            raise RuntimeError("saved managed firewall snapshot could not be restored")
    return {"restored": True, "table_existed": bool(metadata.get("table_existed")), "backup": metadata.get("backup")}


def apply(data: dict[str, Any]) -> dict[str, Any]:
    name = str(data["profile"])
    source_ip = str(data["source_ip"])
    keep_webui = bool(data["keep_webui"])
    rules = profile(name, source_ip, keep_webui)
    previous = save_previous()
    try:
        _delete_managed()
        if rules:
            active = BASE / "active.nft"
            _write_private(active, rules)
            validation = run("/usr/sbin/nft", "-c", "-f", str(active), check=False)
            if validation.returncode != 0:
                raise RuntimeError("generated managed firewall rules failed validation")
            applied = run("/usr/sbin/nft", "-f", str(active), check=False)
            if applied.returncode != 0:
                raise RuntimeError("generated managed firewall rules could not be applied")
    except Exception:
        try:
            restore_previous()
        except Exception:
            pass
        raise
    return {"backup": previous["backup"], "profile": name, "rollback_seconds": 120 if name == "hard" else 0}


def expire(token: str) -> None:
    time.sleep(120)
    with LOCK:
        data = PENDING.pop(token, None)
    if data and data.get("rollback"):
        try:
            restore_previous()
        except Exception:
            pass


def state() -> dict[str, Any]:
    """Expose only VDS-Agent's managed table, never the host-wide firewall."""
    managed = _managed_table() or ""
    return {"managed": managed, "rollback_available": ACTIVE_META.exists() and ACTIVE_PREVIOUS.exists()}


def handle(data: dict[str, Any]) -> dict[str, Any]:
    action = data.get("action")
    if action == "firewall_state":
        return {"ok": True, **state()}
    if action == "firewall_preview":
        return {"ok": True, "rules": profile(str(data["profile"]), str(data["source_ip"]), bool(data["keep_webui"]))}
    if action == "firewall_request":
        profile(str(data["profile"]), str(data["source_ip"]), bool(data["keep_webui"]))
        token = secrets.token_urlsafe(32)
        with LOCK:
            PENDING[token] = dict(data)
        return {"ok": True, "token": token, "expires_in": 60}
    if action == "firewall_confirm":
        token = str(data.get("token", ""))
        with LOCK:
            request = PENDING.pop(token, None)
        if not request:
            return {"ok": False, "error": "confirmation expired"}
        result = apply(request)
        if request["profile"] == "hard":
            with LOCK:
                PENDING[token] = {"rollback": True}
            threading.Thread(target=expire, args=(token,), daemon=True).start()
            result["rollback_token"] = token
        return {"ok": True, **result}
    if action == "firewall_keep":
        with LOCK:
            kept = PENDING.pop(str(data.get("token", "")), None)
        return {"ok": bool(kept), "error": "rollback token expired" if not kept else ""}
    if action == "firewall_rollback":
        return {"ok": True, **restore_previous()}
    return {"ok": False, "error": "unsupported action"}


def main() -> None:
    runtime = pathlib.Path("/run/monitorbot")
    runtime.mkdir(mode=0o750, exist_ok=True)
    os.chown(runtime, 0, __import__("grp").getgrnam("monitorbot").gr_gid)
    try:
        os.unlink(SOCKET)
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX)
    server.bind(SOCKET)
    os.chown(SOCKET, 0, __import__("grp").getgrnam("monitorbot").gr_gid)
    os.chmod(SOCKET, 0o660)
    server.listen(16)
    while True:
        connection, _ = server.accept()
        try:
            if not trusted(connection):
                raise PermissionError("peer denied")
            raw = connection.recv(8192)
            output = handle(json.loads(raw.decode()))
        except Exception as error:
            output = {"ok": False, "error": type(error).__name__}
        connection.sendall((json.dumps(output) + "\n").encode())
        connection.close()


if __name__ == "__main__":
    main()
