import json, sqlite3, time
from pathlib import Path
DB=Path('/var/lib/monitoringbot/monitoring.db')
SCHEMA='''
PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,type TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('active','recovered','closed')),started_at REAL NOT NULL,last_seen_at REAL NOT NULL,recovered_at REAL,closed_at REAL,peak REAL,threshold REAL,ack_by TEXT,snapshot_id INTEGER);
CREATE TABLE IF NOT EXISTS incident_events(id INTEGER PRIMARY KEY,incident_id INTEGER NOT NULL REFERENCES incidents(id),time REAL NOT NULL,event TEXT NOT NULL,details TEXT);
CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY,time REAL NOT NULL,kind TEXT NOT NULL,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY,time REAL NOT NULL,user_id TEXT,action TEXT NOT NULL,target TEXT,result TEXT NOT NULL,details TEXT);
CREATE TABLE IF NOT EXISTS pending_actions(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,user_id TEXT,target TEXT,expires_at REAL NOT NULL,data TEXT);
CREATE TABLE IF NOT EXISTS command_runs(id TEXT PRIMARY KEY,command TEXT NOT NULL,title TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','timeout','cancelled')),user_id TEXT NOT NULL,started_at REAL NOT NULL,finished_at REAL,duration_ms INTEGER,exit_code INTEGER,stdout TEXT NOT NULL DEFAULT '',stderr TEXT NOT NULL DEFAULT '',details TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS ix_incidents_status_seen ON incidents(status,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS ix_events_incident_time ON incident_events(incident_id,time DESC);
CREATE INDEX IF NOT EXISTS ix_snapshots_time ON snapshots(time DESC);
CREATE INDEX IF NOT EXISTS ix_audit_time ON audit_log(time DESC);
CREATE INDEX IF NOT EXISTS ix_pending_expiry ON pending_actions(expires_at);
CREATE INDEX IF NOT EXISTS ix_command_runs_started ON command_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS ix_command_runs_status ON command_runs(status,started_at DESC);
'''
def connect(path=DB):
 path.parent.mkdir(parents=True,exist_ok=True); c=sqlite3.connect(path,timeout=10); c.row_factory=sqlite3.Row; c.executescript(SCHEMA); return c
def rows(q,args=(),path=DB):
 with connect(path) as c:return [dict(x) for x in c.execute(q,args)]
def audit(user,action,target='',result='ok',details=None,path=DB):
 with connect(path) as c:c.execute('INSERT INTO audit_log(time,user_id,action,target,result,details) VALUES(?,?,?,?,?,?)',(time.time(),str(user) if user else None,action,target,result,json.dumps(details or {})))
def migrate_legacy(state_dir=Path('/var/lib/monitoringbot'),path=DB):
 with connect(path) as c:
  if c.execute("SELECT count(*) FROM snapshots WHERE kind='legacy-state'").fetchone()[0]: return False
  payload={}
  for f in state_dir.glob('*.json'):
   try: payload[f.name]=json.loads(f.read_text())
   except Exception: pass
  c.execute('INSERT INTO snapshots(time,kind,data) VALUES(?,?,?)',(time.time(),'legacy-state',json.dumps(payload)))
  c.execute('INSERT INTO audit_log(time,action,target,result,details) VALUES(?,?,?,?,?)',(time.time(),'migration','legacy JSON','ok',json.dumps({'files':list(payload)})))
 return True
