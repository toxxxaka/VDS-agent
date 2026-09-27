import json, time
from .storage import connect

def observe(kind, severity, active, value, threshold, snapshot_id=None, details=None):
    now = time.time()
    with connect() as c:
        row = c.execute("SELECT * FROM incidents WHERE type=? AND status='active' ORDER BY id DESC LIMIT 1", (kind,)).fetchone()
        if active and not row:
            cur = c.execute('INSERT INTO incidents(type,severity,status,started_at,last_seen_at,peak,threshold,snapshot_id) VALUES(?,?,?,?,?,?,?,?)', (kind,severity,'active',now,now,value,threshold,snapshot_id))
            iid = cur.lastrowid
            c.execute('INSERT INTO incident_events(incident_id,time,event,details) VALUES(?,?,?,?)', (iid,now,'opened',json.dumps(details or {})))
            return iid, 'opened'
        if active:
            peak=max(row['peak'] or value,value)
            c.execute('UPDATE incidents SET last_seen_at=?,peak=?,severity=?,snapshot_id=COALESCE(?,snapshot_id) WHERE id=?', (now,peak,severity,snapshot_id,row['id']))
            c.execute('INSERT INTO incident_events(incident_id,time,event,details) VALUES(?,?,?,?)', (row['id'],now,'seen',json.dumps(details or {})))
            return row['id'], 'seen'
        if row:
            c.execute("UPDATE incidents SET status='recovered',recovered_at=?,last_seen_at=? WHERE id=?", (now,now,row['id']))
            c.execute('INSERT INTO incident_events(incident_id,time,event,details) VALUES(?,?,?,?)', (row['id'],now,'recovered',json.dumps(details or {})))
            return row['id'], 'recovered'
    return None, None

def ack(iid, user):
    now=time.time()
    with connect() as c:
        c.execute("UPDATE incidents SET ack_by=? WHERE id=? AND status!='closed'", (str(user),iid))
        c.execute('INSERT INTO audit_log(time,user_id,action,target,result,details) VALUES(?,?,?,?,?,?)', (now,str(user),'incident_ack',str(iid),'ok','{}'))

def close(iid, user):
    now=time.time()
    with connect() as c:
        c.execute("UPDATE incidents SET status='closed',closed_at=? WHERE id=?", (now,iid))
        c.execute('INSERT INTO incident_events(incident_id,time,event,details) VALUES(?,?,?,?)', (iid,now,'closed',json.dumps({'by':str(user)})))
        c.execute('INSERT INTO audit_log(time,user_id,action,target,result,details) VALUES(?,?,?,?,?,?)', (now,str(user),'incident_close',str(iid),'ok','{}'))
