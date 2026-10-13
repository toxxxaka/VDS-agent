"""Read-only service packs and operator-facing reporting views."""
from __future__ import annotations
import html,json,os,subprocess,time
from pathlib import Path
from typing import Any
import psutil
from .storage import connect, rows
from .metrics import query as metric_query
from .intelligence import patch_status,timeline

def run(argv, timeout=8, limit=10000):
 try:r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout,check=False)
 except (OSError,subprocess.TimeoutExpired) as e:return {'available':False,'error':type(e).__name__}
 return {'available':r.returncode==0,'output':r.stdout[-limit:]}

def container_pack():
 helper=Path('/usr/local/libexec/monitoringbot-container-helper')
 if not helper.is_file(): return {'available':False,'reason':'read-only container helper is not installed'}
 return run(['/usr/bin/sudo','-n',str(helper),'summary'],12)

def network_pack():
 io=psutil.net_io_counters(pernic=True)
 stats=psutil.net_if_stats()
 conns=[]
 try:
  for c in psutil.net_connections(kind='tcp'):
   if c.raddr: conns.append({'remote':str(c.raddr.ip),'state':c.status,'pid':c.pid})
 except psutil.Error:pass
 peers={}
 for c in conns: peers[c['remote']]=peers.get(c['remote'],0)+1
 return {'interfaces':{n:{'up':bool(stats.get(n) and stats[n].isup),'drops':v.dropin+v.dropout,'errors':v.errin+v.errout} for n,v in io.items()},'top_peers':sorted(({'ip':k,'connections':v} for k,v in peers.items()),key=lambda x:x['connections'],reverse=True)[:20],'conntrack':run(['/usr/sbin/conntrack','-C'],4,1000),'tcp_retransmits':run(['/usr/bin/ss','-s'],4,3000)}

def web_pack():
 nginx=run(['/usr/bin/journalctl','--no-pager','-u','nginx.service','--since','1 hour ago','--lines','120'],8,8000)
 text=nginx.get('output','')
 return {'nginx':{'journal':text,'errors_5xx_mentions':text.count(' 5')},'php_fpm':{'available':False,'reason':'not configured'},'database':{'available':False,'reason':'read-only monitoring role is not configured'}}

def backup_pack():
 latest=rows("SELECT finished_at,status,details FROM command_runs WHERE command='backup' ORDER BY started_at DESC LIMIT 1")
 return {'latest':latest[0] if latest else None,'restore_test':'sandbox restore is not configured','integrations':{'restic':bool(__import__('shutil').which('restic')),'borg':bool(__import__('shutil').which('borg'))}}

def packs(name='all'):
 allowed={'containers':container_pack,'network':network_pack,'web':web_pack,'backup':backup_pack,'all':None}
 if name not in allowed: raise ValueError('unsupported service pack')
 if name=='all': return {k:f() for k,f in allowed.items() if f}
 return {name:allowed[name]()}

def create_maintenance(actor,start,end,services,note):
 now=time.time(); start=float(start); end=float(end)
 if not(now<=start<end<=now+31*86400):raise ValueError('invalid maintenance window')
 if not isinstance(services,list) or len(services)>20:raise ValueError('invalid services')
 with connect() as c:
  cur=c.execute('INSERT INTO maintenance_windows(actor,start_at,end_at,services,note,created_at) VALUES(?,?,?,?,?,?)',(actor,start,end,json.dumps(services),str(note)[:500],now));return cur.lastrowid

def maintenance():
 now=time.time();return rows('SELECT * FROM maintenance_windows WHERE end_at>=? ORDER BY start_at',(now,))

def report():
 now=time.time(); incidents=rows('SELECT severity,type,started_at,closed_at FROM incidents WHERE started_at>=? ORDER BY id DESC LIMIT 30',(now-7*86400,)); metrics=metric_query('7d');
 body=f'<h1>VDS-Agent weekly report</h1><p>Generated {time.ctime(now)}</p><h2>Capacity</h2><p>Metric points: {len(metrics)}</p><h2>Incidents</h2><ul>'+''.join(f'<li>{html.escape(str(i["severity"]))}: {html.escape(str(i["type"]))}</li>' for i in incidents)+'</ul><h2>Security posture</h2><pre>'+html.escape(json.dumps(patch_status(),indent=2))+'</pre>'
 return '<!doctype html><meta charset=utf-8>'+body

def demo(kind):
 if kind not in {'oom','ssh-anomaly','failed-unit','disk-exhaustion'}:raise ValueError('unsupported demo')
 return {'demo':True,'kind':kind,'message':'Synthetic preview only. No process, service, SSH session or disk state was changed.','timeline':[{'source':'demo','message':f'Simulated {kind} incident'}]}
