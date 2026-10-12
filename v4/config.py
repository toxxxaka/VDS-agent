"""Small typed configuration surface for optional VDS Agent capabilities.

Configuration is deliberately stdlib-only: a missing optional dependency must
never prevent monitoring from starting.  Values may be supplied through a JSON
file and overridden by environment variables.  This module never reads secrets.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path


CONFIG_PATH = Path(os.environ.get("MONITORINGBOT_CONFIG", "/etc/monitoringbot-main/config.json"))


@dataclass(frozen=True)
class TelemetryConfig:
    raw_retention_days: int = 30
    rollup_5m_retention_days: int = 7
    rollup_1h_retention_days: int = 30
    database_soft_limit_mib: int = 256
    flight_recorder_enabled: bool = False
    flight_recorder_interval_seconds: int = 5
    flight_recorder_window_seconds: int = 300


@dataclass(frozen=True)
class FeatureFlags:
    adaptive_baseline: bool = False
    telegram_outbox: bool = False
    external_heartbeat: bool = False
    incident_intelligence: bool = False
    port_baseline_detection: bool = False
    ioc_detect_only: bool = False


@dataclass(frozen=True)
class Settings:
    telemetry: TelemetryConfig = TelemetryConfig()
    features: FeatureFlags = FeatureFlags()


def _object(value: object, name: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _positive(value: object, name: str, minimum: int = 1, maximum: int = 3650) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def load(path: Path = CONFIG_PATH) -> Settings:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, PermissionError):
        # The optional non-secret file may not be installed yet. Monitoring
        # keeps its conservative defaults instead of failing its collector.
        raw = {}
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path}: {error.msg}") from error
    raw = _object(raw, "configuration")
    telemetry_raw = _object(raw.get("telemetry"), "telemetry")
    feature_raw = _object(raw.get("features"), "features")
    defaults = TelemetryConfig()
    telemetry = TelemetryConfig(
        raw_retention_days=_positive(telemetry_raw.get("raw_retention_days", defaults.raw_retention_days), "telemetry.raw_retention_days"),
        rollup_5m_retention_days=_positive(telemetry_raw.get("rollup_5m_retention_days", defaults.rollup_5m_retention_days), "telemetry.rollup_5m_retention_days"),
        rollup_1h_retention_days=_positive(telemetry_raw.get("rollup_1h_retention_days", defaults.rollup_1h_retention_days), "telemetry.rollup_1h_retention_days"),
        database_soft_limit_mib=_positive(telemetry_raw.get("database_soft_limit_mib", defaults.database_soft_limit_mib), "telemetry.database_soft_limit_mib", 16, 4096),
        flight_recorder_enabled=_boolean(telemetry_raw.get("flight_recorder_enabled", defaults.flight_recorder_enabled), "telemetry.flight_recorder_enabled"),
        flight_recorder_interval_seconds=_positive(telemetry_raw.get("flight_recorder_interval_seconds", defaults.flight_recorder_interval_seconds), "telemetry.flight_recorder_interval_seconds", 1, 60),
        flight_recorder_window_seconds=_positive(telemetry_raw.get("flight_recorder_window_seconds", defaults.flight_recorder_window_seconds), "telemetry.flight_recorder_window_seconds", 30, 3600),
    )
    flags = FeatureFlags(**{
        name: _boolean(feature_raw.get(name, getattr(FeatureFlags(), name)), f"features.{name}")
        for name in asdict(FeatureFlags())
    })
    return Settings(telemetry=telemetry, features=flags)


def validate(path: Path = CONFIG_PATH) -> dict:
    return asdict(load(path))
