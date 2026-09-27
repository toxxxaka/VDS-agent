#!/usr/bin/env python3
"""Root-owned kernel OOM watcher for monitoringbot."""
import json, logging, os, subprocess, time
from pathlib import Path
import requests
from v4.incidents import observe
from v4.snapshots import capture
STATE=Path('/var/lib/monitoringbot-oom/state.json'); TOKEN=os.environ.get('TELEGRAM_BOT_TOKEN',''); CHAT=os.environ.get('TELEGRAM_CHAT_ID','')
S=requests.Session(); S.trust_env=False; LOG=logging.getLogger('monitorbot-oom')
def send(text):
    try: return S.post(f'https://api.telegram.org/bot{TOKEN}/sendMessage',json={'chat_id':CHAT,'text':text},timeout=(5,20)).json().get('ok',False)
    except Exception as e: LOG.warning('Telegram OOM alert failed: %s',type(e).__name__); return False
def load():
    try:return json.loads(STATE.read_text())
    except Exception:return {}
def save(s):
    STATE.parent.mkdir(parents=True,exist_ok=True); p=STATE.with_suffix('.tmp');p.write_text(json.dumps(s));os.chmod(p,0o600);p.replace(STATE)
def journal(cursor=None):
    cmd=['journalctl','-k','-o','json','--no-pager']
    cmd += ['--after-cursor',cursor] if cursor else ['-n','1']
    return subprocess.run(cmd,text=True,capture_output=True,timeout=15,check=False).stdout.splitlines()
def main():
 logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s'); state=load()
 while True:
  try:
   rows=journal(state.get('cursor'))
   for row in rows:
    event=json.loads(row); state['cursor']=event.get('__CURSOR',state.get('cursor')); msg=event.get('MESSAGE','')
    if any(x in msg.lower() for x in ('out of memory','oom-killer','killed process')):
     sid,_=capture('oom');iid,_=observe('OOM','critical',True,1,1,sid,{'kernel':msg[:3000]});send(f'🚨 OOM killer\nIncident: #{iid}\n'+msg[:2800])
   save(state)
  except Exception: LOG.exception('OOM journal scan failed')
  time.sleep(5)
if __name__=='__main__':main()
