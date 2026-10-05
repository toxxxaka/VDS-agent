"""Persistent incident lifecycle for one monitored server."""
import json
import time

from .storage import audit, connect


def observe(kind, severity, active, value, threshold, snapshot_id=None, details=None):
    """Open once, update while active, and automatically close on recovery."""
    now = time.time()
    with connect() as connection:
        row = connection.execute("SELECT * FROM incidents WHERE type=? AND status='active' ORDER BY id DESC LIMIT 1", (kind,)).fetchone()
        if active and row is None:
            cursor = connection.execute("INSERT INTO incidents(type,severity,status,started_at,last_seen_at,peak,threshold,snapshot_id) VALUES(?,?,?,?,?,?,?,?)", (kind, severity, "active", now, now, value, threshold, snapshot_id))
            incident_id = cursor.lastrowid
            connection.execute("INSERT INTO incident_events(incident_id,time,event,details) VALUES(?,?,?,?)", (incident_id, now, "opened", json.dumps(details or {})))
            return incident_id, "opened"
        if active:
            peak = max(row["peak"] if row["peak"] is not None else value, value)
            connection.execute("UPDATE incidents SET last_seen_at=?,peak=?,severity=?,snapshot_id=COALESCE(?,snapshot_id) WHERE id=?", (now, peak, severity, snapshot_id, row["id"]))
            connection.execute("INSERT INTO incident_events(incident_id,time,event,details) VALUES(?,?,?,?)", (row["id"], now, "seen", json.dumps(details or {})))
            return row["id"], "seen"
        if row is not None:
            connection.execute("UPDATE incidents SET status='closed',recovered_at=?,closed_at=?,last_seen_at=? WHERE id=?", (now, now, now, row["id"]))
            connection.execute("INSERT INTO incident_events(incident_id,time,event,details) VALUES(?,?,?,?)", (row["id"], now, "recovered", json.dumps(details or {})))
            return row["id"], "recovered"
    return None, None


def ack(incident_id, user):
    """Compatibility endpoint for existing Telegram/API clients; UI does not expose it."""
    with connect() as connection:
        connection.execute("UPDATE incidents SET ack_by=? WHERE id=? AND status!='closed'", (str(user), incident_id))
    audit(user, "incident_ack", str(incident_id))


def close(incident_id, user):
    now = time.time()
    with connect() as connection:
        cursor = connection.execute("UPDATE incidents SET status='closed',closed_at=? WHERE id=? AND status!='closed'", (now, incident_id))
        if cursor.rowcount:
            connection.execute("INSERT INTO incident_events(incident_id,time,event,details) VALUES(?,?,?,?)", (incident_id, now, "closed", json.dumps({"by": str(user)})))
    audit(user, "incident_close", str(incident_id))


def close_all(user):
    """Close active records explicitly. The next unhealthy sample can open a new one."""
    now = time.time()
    with connect() as connection:
        active = connection.execute("SELECT id FROM incidents WHERE status='active'").fetchall()
        for row in active:
            connection.execute("UPDATE incidents SET status='closed',closed_at=? WHERE id=?", (now, row["id"]))
            connection.execute("INSERT INTO incident_events(incident_id,time,event,details) VALUES(?,?,?,?)", (row["id"], now, "closed", json.dumps({"by": str(user), "bulk": True})))
    audit(user, "incident_close_all", result="ok", details={"count": len(active)})
    return len(active)
