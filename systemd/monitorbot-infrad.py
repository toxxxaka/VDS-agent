#!/usr/bin/env python3
"""Root bridge for Monitoring infrastructure operations. Fixed protocol only."""
import ipaddress,json,os,pathlib,secrets,socket,struct,subprocess,threading,time
SOCK='/run/monitorbot/infrastructure.sock'; BASE=pathlib.Path('/var/lib/monitoringbot/firewall'); PENDING={}; LOCK=threading.Lock()
def run(*args,check=True):
 return subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15,check=check)
def trusted(conn):
 pid,uid,gid=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)); return uid==__import__('pwd').getpwnam('monitorbot').pw_uid
def profile(name,ip,web):
 addr=ipaddress.ip_address(ip); family='ip6' if addr.version==6 else 'ip'; ssh=f'{family} saddr {addr} tcp dport 22 accept'; https=f'{family} saddr {addr} tcp dport 443 accept'
 if name=='none': return 'delete table inet monitoringbot\n'
 if name=='standard': extras='tcp dport {22,80,443} accept\n'
 elif name=='hard': extras=ssh+'\n'+(https+'\n' if web else '')
 else: raise ValueError('unknown profile')
 return 'table inet monitoringbot { chain input { type filter hook input priority -50; policy drop; iifname "lo" accept; ct state established,related accept; ct state invalid drop; ip protocol icmp accept; ip6 nexthdr ipv6-icmp accept; '+extras+' } }\n'
def state():
 r=run('/usr/sbin/nft','list','ruleset',check=False); return {'ruleset':r.stdout[-120000:],'managed':run('/usr/sbin/nft','list','table','inet','monitoringbot',check=False).stdout}
def save():
 BASE.mkdir(parents=True,exist_ok=True); p=BASE/(time.strftime('%Y%m%d-%H%M%S')+'.nft'); p.write_text(run('/usr/sbin/nft','list','ruleset').stdout); return str(p)
def apply(data):
 name,ip,web=data['profile'],data['source_ip'],bool(data['keep_webui']); text=profile(name,ip,web); backup=save(); f=BASE/'active.nft'; f.write_text(text)
 if name=='none': run('/usr/sbin/nft','delete','table','inet','monitoringbot',check=False)
 else:
  run('/usr/sbin/nft','-c','-f',str(f)); run('/usr/sbin/nft','delete','table','inet','monitoringbot',check=False); run('/usr/sbin/nft','-f',str(f))
 return {'backup':backup,'profile':name,'rollback_seconds':120 if name=='hard' else 0}
def expire(token):
 time.sleep(120)
 with LOCK: data=PENDING.pop(token,None)
 if data:
  run('/usr/sbin/nft','delete','table','inet','monitoringbot',check=False)
def handle(data):
 a=data.get('action')
 if a=='firewall_state': return {'ok':True,**state()}
 if a=='firewall_preview': return {'ok':True,'rules':profile(data['profile'],data['source_ip'],bool(data['keep_webui']))}
 if a=='firewall_request':
  profile(data['profile'],data['source_ip'],bool(data['keep_webui'])); token=secrets.token_urlsafe(32)
  with LOCK:PENDING[token]=data
  return {'ok':True,'token':token,'expires_in':60}
 if a=='firewall_confirm':
  token=data.get('token','')
  with LOCK: request=PENDING.pop(token,None)
  if not request:return {'ok':False,'error':'confirmation expired'}
  result=apply(request)
  if request['profile']=='hard':
   with LOCK: PENDING[token]={'rollback':True}
   threading.Thread(target=expire,args=(token,),daemon=True).start()
   result['rollback_token']=token
  return {'ok':True,**result}
 if a=='firewall_keep':
  with LOCK: kept=PENDING.pop(data.get('token',''),None)
  return {'ok':bool(kept), 'error':'rollback token expired' if not kept else ''}
 if a=='firewall_rollback': run('/usr/sbin/nft','delete','table','inet','monitoringbot',check=False); return {'ok':True}
 return {'ok':False,'error':'unsupported action'}
def main():
 pathlib.Path('/run/monitorbot').mkdir(mode=0o750,exist_ok=True); os.chown('/run/monitorbot',0,__import__('grp').getgrnam('monitorbot').gr_gid)
 try:os.unlink(SOCK)
 except FileNotFoundError:pass
 s=socket.socket(socket.AF_UNIX);s.bind(SOCK);os.chown(SOCK,0,__import__('grp').getgrnam('monitorbot').gr_gid);os.chmod(SOCK,0o660);s.listen(16)
 while True:
  c,_=s.accept()
  try:
   if not trusted(c): raise PermissionError('peer denied')
   raw=c.recv(8192); out=handle(json.loads(raw.decode()))
  except Exception as e: out={'ok':False,'error':type(e).__name__}
  c.sendall((json.dumps(out)+'\n').encode());c.close()
if __name__=='__main__':main()
