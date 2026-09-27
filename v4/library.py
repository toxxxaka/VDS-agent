"""Authenticated source library for scripts intended for client servers."""
import json, secrets, time
from pathlib import Path
from .storage import connect
ROOT=Path('/opt/monitoringbot/client-scripts').resolve()
PUBLIC_URL='https://monitoring.example.com'
SCRIPTS={
 'change-ip':('change-ip.sh','Change public IPv4 for ISPmanager / FASTPANEL','root, changing'),
 'boot-check':('boot-check.sh','Diagnose current and previous boots','root, read-only'),
 'find-space':('find-space.sh','Find large logs, caches and backups','read-only'),
 'network-trace':('network-trace.sh','Interface, gateway, DNS and HTTP diagnostics','read-only'),
 'system-triage':('system-triage.sh','Resources, OOM, SSH and service triage','read-only'),
 'http-timing':('http-timing.sh','DNS, TCP, TLS and TTFB timings','read-only'),
 'process-inspect':('process-inspect.sh','Process executable and network connections','read-only'),
 'web-log-report':('web-log-report.sh','Access-log summary','read-only'),
 'large-files':('large-files.sh','Largest files under a path','read-only'),
 'container-probe':('container-probe.sh','HTTP probe inside a Docker container','read-only'),
 'service-check':('service-check.sh','Check systemd service status','read-only'),
 'site-check':('site-check.sh','HTTP/S site checks','read-only'),
 'cert-watch':('cert-watch.sh','Find expiring local TLS certificates','read-only'),
 'password-gen':('password-gen','Generate strong segmented password','read-only'),
}
def info():
 out=[]
 for key,(filename,title,rights) in SCRIPTS.items():
  path=(ROOT/filename).resolve()
  if path.is_file() and ROOT in path.parents: out.append({'id':key,'filename':filename,'title':title,'rights':rights,'size':path.stat().st_size})
 return out
def content(key):
 filename=SCRIPTS.get(key,('',))[0]; path=(ROOT/filename).resolve()
 if not filename or not path.is_file() or ROOT not in path.parents: raise ValueError('script not found')
 return filename,path.read_text(errors='replace')
def issue_link(user,key):
 filename,_=content(key); token=secrets.token_urlsafe(24)
 with connect() as c:
  c.execute('DELETE FROM pending_actions WHERE expires_at<?',(time.time(),))
  c.execute('INSERT INTO pending_actions(kind,user_id,target,expires_at,data) VALUES(?,?,?,?,?)',('script_download',str(user),key,time.time()+600,json.dumps({'token':token})))
 return {'url':f'{PUBLIC_URL}/download/{token}','command':f"wget -O {filename} '{PUBLIC_URL}/download/{token}' && chmod +x {filename}",'expires_in':600}
def download(token):
 with connect() as c:
  rows=c.execute("SELECT target,data FROM pending_actions WHERE kind='script_download' AND expires_at>?",(time.time(),)).fetchall()
 for row in rows:
  try:
   if secrets.compare_digest(json.loads(row['data']).get('token',''),token): return content(row['target'])
  except (json.JSONDecodeError,TypeError): pass
 return None
