import json,secrets,socket,ssl,string,urllib.parse,urllib.request
from datetime import datetime,timezone
SAFE=string.ascii_letters+string.digits+'!_)(*&^%$#@/+-\\`":?><'
def password():
 return '-'.join(''.join(secrets.choice(SAFE) for _ in range(n)) for n in (5,6,7))
def host(value):
 v=value.strip().lower().split('://')[-1].split('/')[0]
 if not v or len(v)>253 or any(c not in string.ascii_lowercase+string.digits+'.:-' for c in v):raise ValueError('invalid host')
 return v
def ssl_check(value):
 h=host(value); name,port=(h.rsplit(':',1) if ':' in h else (h,'443')); port=int(port)
 ctx=ssl.create_default_context()
 with socket.create_connection((name,port),5) as raw:
  with ctx.wrap_socket(raw,server_hostname=name) as c:
   cert=c.getpeercert(); exp=datetime.strptime(cert['notAfter'],'%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
   return {'host':name,'protocol':c.version(),'cipher':c.cipher()[0],'issuer':dict(x[0] for x in cert.get('issuer',[])).get('commonName','—'),'expires_at':exp.isoformat(),'days_left':int((exp-datetime.now(timezone.utc)).total_seconds()//86400)}
def checkhost(value,kind='http'):
 h=host(value); kind=kind if kind in {'http','ping','tcp','dns'} else 'http'
 url='https://check-host.net/check-'+kind+'?'+urllib.parse.urlencode({'host':h,'max_nodes':'5'})
 req=urllib.request.Request(url,headers={'Accept':'application/json','User-Agent':'Monitoringbot/4'})
 with urllib.request.urlopen(req,timeout=15) as r:return json.load(r)
def cheburcheck_url(value): return 'https://cheburcheck.ru/?q='+urllib.parse.quote(host(value),safe='')
