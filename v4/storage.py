"""SQLite storage with WAL, bounded state permissions and lightweight migrations."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

DB = Path(os.environ.get("MONITORINGBOT_DB", "/var/lib/monitoringbot/monitoring.db"))
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIRECTORY_MODE = 0o750
SCHEMA = '''
PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,type TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('active','recovered','closed')),started_at REAL NOT NULL,last_seen_at REAL NOT NULL,recovered_at REAL,closed_at REAL,peak REAL,threshold REAL,ack_by TEXT,snapshot_id INTEGER);
CREATE TABLE IF NOT EXISTS incident_events(id INTEGER PRIMARY KEY,incident_id INTEGER NOT NULL REFERENCES incidents(id),time REAL NOT NULL,event TEXT NOT NULL,details TEXT);
CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY,time REAL NOT NULL,kind TEXT NOT NULL,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY,time REAL NOT NULL,user_id TEXT,action TEXT NOT NULL,target TEXT,result TEXT NOT NULL,details TEXT);
CREATE TABLE IF NOT EXISTS pending_actions(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,user_id TEXT,target TEXT,expires_at REAL NOT NULL,data TEXT);
CREATE TABLE IF NOT EXISTS web_auth_replays(digest TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS web_totp_steps(user_id TEXT PRIMARY KEY,time_step INTEGER NOT NULL,accepted_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS metric_samples(id INTEGER PRIMARY KEY,time REAL NOT NULL,cpu REAL NOT NULL,load1 REAL NOT NULL,mem_used INTEGER NOT NULL,mem_cached INTEGER NOT NULL,mem_available INTEGER NOT NULL,disk_used INTEGER NOT NULL,disk_total INTEGER NOT NULL,rx INTEGER NOT NULL,tx INTEGER NOT NULL,read_bytes INTEGER NOT NULL,write_bytes INTEGER NOT NULL,sample_version INTEGER NOT NULL DEFAULT 2,extra TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS metric_rollups(resolution_seconds INTEGER NOT NULL,bucket_at REAL NOT NULL,data TEXT NOT NULL,PRIMARY KEY(resolution_seconds,bucket_at));
CREATE INDEX IF NOT EXISTS ix_metric_samples_time ON metric_samples(time);
CREATE TABLE IF NOT EXISTS command_runs(id TEXT PRIMARY KEY,command TEXT NOT NULL,title TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','timeout','cancelled','interrupted')),user_id TEXT NOT NULL,started_at REAL NOT NULL,finished_at REAL,duration_ms INTEGER,exit_code INTEGER,stdout TEXT NOT NULL DEFAULT '',stderr TEXT NOT NULL DEFAULT '',details TEXT NOT NULL DEFAULT '{}',idempotency_key TEXT,attempts INTEGER NOT NULL DEFAULT 0,max_attempts INTEGER NOT NULL DEFAULT 1,next_attempt_at REAL,cancel_requested_at REAL,updated_at REAL);
CREATE TABLE IF NOT EXISTS task_events(id INTEGER PRIMARY KEY,run_id TEXT NOT NULL REFERENCES command_runs(id),time REAL NOT NULL,event TEXT NOT NULL,details TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS notification_outbox(id TEXT PRIMARY KEY,channel TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('queued','sending','delivered','failed','cancelled')),idempotency_key TEXT NOT NULL UNIQUE,attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at REAL NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL,last_error TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_incidents_status_seen ON incidents(status,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS ix_events_incident_time ON incident_events(incident_id,time DESC);
CREATE INDEX IF NOT EXISTS ix_snapshots_time ON snapshots(time DESC);
CREATE INDEX IF NOT EXISTS ix_audit_time ON audit_log(time DESC);
CREATE INDEX IF NOT EXISTS ix_pending_expiry ON pending_actions(expires_at);
CREATE INDEX IF NOT EXISTS ix_web_auth_replays_expiry ON web_auth_replays(expires_at);
CREATE INDEX IF NOT EXISTS ix_command_runs_started ON command_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS ix_command_runs_status ON command_runs(status,started_at DESC);
CREATE INDEX IF NOT EXISTS ix_metric_rollups_resolution_time ON metric_rollups(resolution_seconds,bucket_at DESC);
CREATE INDEX IF NOT EXISTS ix_task_events_run_time ON task_events(run_id,time DESC);
CREATE UNIQUE INDEX IF NOT EXISTS ix_command_runs_idempotency ON command_runs(user_id,command,idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_outbox_due ON notification_outbox(status,next_attempt_at);
'''


def _private_path(path: Path) -> None:
    """Keep runtime data private even when a legacy file was created permissively."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, _PRIVATE_DIRECTORY_MODE)
    except OSError:
        pass
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        try:
            if candidate.exists():
                os.chmod(candidate, _PRIVATE_FILE_MODE)
        except OSError:
            pass


def connect(path: Path = DB) -> sqlite3.Connection:
    _private_path(path)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    connection.execute("PRAGMA foreign_keys=ON")
    fields = {row[1] for row in connection.execute("PRAGMA table_info(metric_samples)")}
    if "sample_version" not in fields:
        connection.execute("ALTER TABLE metric_samples ADD COLUMN sample_version INTEGER NOT NULL DEFAULT 1")
    if "extra" not in fields:
        connection.execute("ALTER TABLE metric_samples ADD COLUMN extra TEXT NOT NULL DEFAULT '{}'")
    run_fields = {row[1] for row in connection.execute("PRAGMA table_info(command_runs)")}
    # Existing installations predate the durable task fields. SQLite's additive
    # migrations are transactional and leave old task history readable.
    for field, declaration in {
        "idempotency_key": "TEXT",
        "attempts": "INTEGER NOT NULL DEFAULT 0",
        "max_attempts": "INTEGER NOT NULL DEFAULT 1",
        "next_attempt_at": "REAL",
        "cancel_requested_at": "REAL",
        "updated_at": "REAL",
    }.items():
        if field not in run_fields:
            connection.execute(f"ALTER TABLE command_runs ADD COLUMN {field} {declaration}")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_command_runs_idempotency ON command_runs(user_id,command,idempotency_key) WHERE idempotency_key IS NOT NULL")
    connection.execute("UPDATE incidents SET status='closed',closed_at=COALESCE(closed_at,recovered_at) WHERE status='recovered'")
    connection.execute("DELETE FROM pending_actions WHERE expires_at < ?", (time.time(),))
    _private_path(path)
    return connection


def rows(query: str, args=(), path: Path = DB) -> list[dict]:
    with connect(path) as connection:
        return [dict(item) for item in connection.execute(query, args)]


def audit(user, action, target="", result="ok", details=None, path: Path = DB) -> None:
    with connect(path) as connection:
        connection.execute(
            "INSERT INTO audit_log(time,user_id,action,target,result,details) VALUES(?,?,?,?,?,?)",
            (time.time(), str(user) if user else None, action, target, result, json.dumps(details or {})),
        )


def migrate_legacy(state_dir: Path = Path("/var/lib/monitoringbot"), path: Path = DB) -> bool:
    with connect(path) as connection:
        if connection.execute("SELECT count(*) FROM snapshots WHERE kind='legacy-state'").fetchone()[0]:
            return False
        payload = {}
        for file in state_dir.glob("*.json"):
            try:
                payload[file.name] = json.loads(file.read_text())
            except Exception:
                pass
        connection.execute("INSERT INTO snapshots(time,kind,data) VALUES(?,?,?)", (time.time(), "legacy-state", json.dumps(payload)))
        connection.execute("INSERT INTO audit_log(time,action,target,result,details) VALUES(?,?,?,?,?)", (time.time(), "migration", "legacy JSON", "ok", json.dumps({"files": list(payload)})))
    return True
