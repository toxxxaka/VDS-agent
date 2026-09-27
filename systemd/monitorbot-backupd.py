#!/usr/bin/env python3
"""Root backup bridge; accepts only monitorbot requests over a private Unix socket."""
import json, os, pwd, socket, subprocess
SOCKET='/run/monitorbot/backup.sock'; HELPER='/usr/local/libexec/monitoringbot-backup-helper'; UID=pwd.getpwnam('monitorbot').pw_uid
def reply(conn,value): conn.sendall((json.dumps(value,ensure_ascii=False)+'\n').encode())
def handle(conn):
 try:
  creds=conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12); uid=int.from_bytes(creds[4:8],'little')
  if uid!=UID: reply(conn,{'ok':False,'error':'peer is not monitorbot'}); return
  raw=conn.recv(4096); req=json.loads(raw.decode()); action=req.get('action')
  args=[HELPER]
  if action=='destinations': args+=['destinations']
  elif action=='create': args+=['create','--source',str(req.get('source','')),'--destination',str(req.get('destination','')),'--label',str(req.get('label',''))]
  else: reply(conn,{'ok':False,'error':'unsupported action'}); return
  r=subprocess.run(args,stdin=subprocess.DEVNULL,text=True,capture_output=True,timeout=86500,check=False)
  reply(conn,{'ok':r.returncode==0,'stdout':r.stdout,'stderr':r.stderr,'exit_code':r.returncode})
 except Exception as exc: reply(conn,{'ok':False,'error':type(exc).__name__})
def main():
 try: os.unlink(SOCKET)
 except FileNotFoundError: pass
 os.chown('/run/monitorbot',0,pwd.getpwnam('monitorbot').pw_gid); os.chmod('/run/monitorbot',0o750); s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(SOCKET); os.chown(SOCKET,0,pwd.getpwnam('monitorbot').pw_gid); os.chmod(SOCKET,0o660); s.listen(8)
 while True:
  conn,_=s.accept()
  with conn: handle(conn)
if __name__=='__main__': main()
