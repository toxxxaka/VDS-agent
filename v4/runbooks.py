"""Declarative, bounded Recovery Studio runbooks.

YAML describes intent and fixed allow-listed diagnostic tool names. It does not
contain shell, arbitrary paths, inline scripts or credentials. Actions are only
proposed here; their existing privileged bridge and confirmation remain the
sole execution path.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

import yaml

from .agent_tools import ToolError, execute
from .rbac import require
from .storage import audit, connect, rows

RUNBOOK_DIR = Path(os.environ.get("MONITORINGBOT_RUNBOOK_DIR", Path(__file__).parent.parent / "runbooks"))
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,63}")
TOOLS = {"server_status", "diagnose_load", "process_inspect", "service_status", "service_logs", "metrics_query", "incidents_query", "monitoring_health", "incident_investigate", "patch_status", "security_detect"}
ACTIONS = {"restart_monitoringbot", "restart_web", "restart_health"}


def _load(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(f"invalid runbook {path.name}") from error
    if not isinstance(value, dict):
        raise ValueError(f"invalid runbook {path.name}")
    identifier = value.get("id")
    if not isinstance(identifier, str) or not ID_RE.fullmatch(identifier):
        raise ValueError(f"invalid runbook id in {path.name}")
    diagnostics = value.get("diagnostics", [])
    if not isinstance(diagnostics, list) or not all(isinstance(item, dict) and item.get("tool") in TOOLS and isinstance(item.get("arguments", {}), dict) for item in diagnostics):
        raise ValueError(f"invalid diagnostics in {path.name}")
    action = value.get("action")
    if action is not None and action not in ACTIONS:
        raise ValueError(f"invalid action in {path.name}")
    return value


def list_runbooks() -> list[dict[str, Any]]:
    output = []
    try: candidates = sorted(RUNBOOK_DIR.glob("*.yaml"))
    except OSError: candidates = []
    for path in candidates:
        try:
            data = _load(path)
            output.append({key: data.get(key) for key in ("id", "title", "description", "conditions", "cooldown_seconds", "max_attempts", "rollback", "post_check")})
        except ValueError:
            continue
    return output


def get_runbook(identifier: str) -> dict[str, Any]:
    if not isinstance(identifier, str) or not ID_RE.fullmatch(identifier):
        raise ValueError("invalid runbook id")
    path = RUNBOOK_DIR / f"{identifier}.yaml"
    data = _load(path)
    if data["id"] != identifier:
        raise ValueError("runbook id mismatch")
    return data


def _recent_count(identifier: str, seconds: int) -> int:
    cutoff = time.time() - max(1, seconds)
    return int(rows("SELECT COUNT(*) AS n FROM recovery_runs WHERE runbook_id=? AND created_at>=?", (identifier, cutoff))[0]["n"])


def dry_run(identifier: str, actor: str, config: dict | None = None) -> dict[str, Any]:
    require(actor, "operator", config)
    runbook = get_runbook(identifier)
    maximum = max(1, min(int(runbook.get("max_attempts", 1)), 10))
    cooldown = max(0, min(int(runbook.get("cooldown_seconds", 300)), 7 * 86400))
    if _recent_count(identifier, cooldown) >= maximum:
        raise ValueError("runbook cooldown or attempt limit is active")
    evidence = []
    for item in runbook["diagnostics"][:12]:
        try:
            evidence.append({"tool": item["tool"], "result": execute(item["tool"], item.get("arguments", {}), actor=f"runbook:{actor}")})
        except ToolError as error:
            evidence.append({"tool": item["tool"], "available": False, "error": str(error)})
    run_id = str(uuid.uuid4())
    data = {"runbook": identifier, "dry_run": True, "evidence": evidence, "action": runbook.get("action"), "rollback": runbook.get("rollback", "not defined"), "post_check": runbook.get("post_check", [])}
    now = time.time()
    with connect() as connection:
        connection.execute("INSERT INTO recovery_runs(id,runbook_id,actor,status,created_at,updated_at,data) VALUES(?,?,?,?,?,?,?)", (run_id, identifier, actor, "dry_run", now, now, json.dumps(data)))
    audit(actor, "runbook_dry_run", identifier, "ok", {"run_id": run_id})
    return {"id": run_id, "status": "dry_run", **data}


def request(identifier: str, actor: str, config: dict | None = None) -> dict[str, Any]:
    require(actor, "admin", config)
    report = dry_run(identifier, actor, config)
    if not report.get("action"):
        return report | {"status": "diagnostics_completed", "approval_required": False}
    with connect() as connection:
        connection.execute("UPDATE recovery_runs SET status=?,updated_at=? WHERE id=?", ("pending_approval", time.time(), report["id"]))
    audit(actor, "runbook_action_request", identifier, "pending", {"run_id": report["id"], "action": report["action"]})
    return report | {"status": "pending_approval", "approval_required": True, "four_eyes": bool((config or {}).get("four_eyes", False))}


def decide(run_id: str, actor: str, approve: bool, config: dict | None = None) -> dict[str, Any]:
    require(actor, "admin", config)
    current = rows("SELECT * FROM recovery_runs WHERE id=?", (run_id,))
    if not current or current[0]["status"] != "pending_approval":
        raise ValueError("recovery request is not pending")
    run = current[0]
    data = json.loads(run["data"])
    previous = rows("SELECT actor,decision FROM recovery_approvals WHERE recovery_run_id=? ORDER BY id", (run_id,))
    if any(item["actor"] == actor for item in previous):
        raise PermissionError("one approval per administrator")
    with connect() as connection:
        connection.execute("INSERT INTO recovery_approvals(recovery_run_id,actor,decision,time,details) VALUES(?,?,?,?,?)", (run_id, actor, "approved" if approve else "rejected", time.time(), "{}"))
        if not approve:
            status = "rejected"
        elif bool((config or {}).get("four_eyes", False)) and not any(item["decision"] == "approved" and item["actor"] != actor for item in previous):
            status = "awaiting_second_approval"
        else:
            status = "approved"
        connection.execute("UPDATE recovery_runs SET status=?,updated_at=? WHERE id=?", (status, time.time(), run_id))
    audit(actor, "runbook_decision", run["runbook_id"], status, {"run_id": run_id})
    return {"id": run_id, "status": status, "action": data.get("action"), "execution": "Use the existing action-specific confirmation path; this runbook never executes shell input."}


def runs(limit: int = 30) -> list[dict[str, Any]]:
    return rows("SELECT id,runbook_id,actor,status,created_at,updated_at FROM recovery_runs ORDER BY created_at DESC LIMIT ?", (max(1, min(int(limit), 100)),))
