"""Operator-facing, non-privileged VDS Agent commands."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .config import validate
from . import self_monitoring


def _json(value: dict[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _age(value: object) -> str:
    if not isinstance(value, (int, float)):
        return "unavailable"
    seconds = max(0, round(value))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


def _status_text(report: dict[str, Any]) -> str:
    lines = [f"VDS Agent: {'healthy' if report.get('healthy') else 'needs attention'}"]
    metrics = report.get("metrics") or {}
    lines.append(f"Telemetry: {_age(metrics.get('age_seconds'))} old")
    database = report.get("database") or {}
    database_state = "ok" if database.get("ok") else "failed"
    lines.append(f"SQLite: {database_state} · {int(database.get('size_bytes') or 0)} bytes")
    services = report.get("services") or []
    if services:
        lines.append("Services:")
        lines.extend(f"  {item.get('unit', 'unknown')}: {item.get('state', 'unknown')}" for item in services)
    failed = report.get("failed_units") or []
    if failed:
        lines.append("Failed units:")
        lines.extend(f"  {item}" for item in failed)
    failures = report.get("component_failures") or []
    if failures:
        lines.append(f"Recent failed jobs: {len(failures)}")
    return "\n".join(lines)


def status(json_output: bool = False) -> int:
    report = self_monitoring.report()
    if json_output:
        _json(report)
    else:
        print(_status_text(report))
    return 0 if report.get("healthy") else 1


def doctor(json_output: bool = False) -> int:
    checks: list[dict[str, Any]] = []
    try:
        settings = validate()
        checks.append({"name": "configuration", "status": "ok", "details": settings})
    except ValueError as error:
        checks.append({"name": "configuration", "status": "error", "message": str(error)})
    report = self_monitoring.report()
    for name, value in (report.get("checks") or {}).items():
        checks.append({"name": f"health.{name}", "status": "ok" if value else "error"})
    result = {
        "healthy": not any(item["status"] == "error" for item in checks),
        "checks": checks,
        "report": report,
    }
    if json_output:
        _json(result)
    else:
        for item in checks:
            suffix = item.get("message") or ""
            print(f"{item['status'].upper():5} {item['name']}{': ' + suffix if suffix else ''}")
        print(f"\nOverall: {'healthy' if result['healthy'] else 'needs attention'}")
    return 0 if result["healthy"] else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vds-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check-config", help="validate the non-secret VDS Agent configuration")
    check.add_argument("--json", action="store_true", help="print JSON")
    status_parser = sub.add_parser("status", help="show VDS Agent component and telemetry status")
    status_parser.add_argument("--json", action="store_true", help="print JSON")
    doctor_parser = sub.add_parser("doctor", help="run local read-only configuration and health checks")
    doctor_parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)
    if args.command == "check-config":
        try:
            result = validate()
            _json(result) if args.json else print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except ValueError as error:
            print(f"configuration invalid: {error}", file=sys.stderr)
            return 2
    if args.command == "status":
        return status(args.json)
    if args.command == "doctor":
        return doctor(args.json)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
