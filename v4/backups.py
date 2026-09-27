"""WebUI integration for constrained root rsync backups."""
import json, socket, subprocess
from .tasks import TaskSpec, start_custom_run
from .storage import rows
SOCKET='/run/monitorbot/backup.sock'
def bridge(payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(86510); connection.connect(SOCKET); connection.sendall(json.dumps(payload).encode()); chunks=[]
        while True:
            part=connection.recv(65536)
            if not part: break
            chunks.append(part)
            if b'\n' in part: break
    response=json.loads(b''.join(chunks).decode())
    if not response.get('ok'): raise RuntimeError(response.get('error','backup bridge failed'))
    return response
SPEC=TaskSpec('backup','Backup','Rsync backup with log and metadata','Backups',86400)

def destinations():
    return json.loads(bridge({'action':'destinations'})['stdout'])

def start(user,source,destination,label):
    if not isinstance(source,str) or not isinstance(destination,str) or not isinstance(label,str): raise ValueError('invalid backup parameters')
    if len(source)>2048 or len(label)>100: raise ValueError('backup parameters are too long')
    def handler(_):
        response=bridge({'action':'create','source':source,'destination':destination,'label':label}); result=type('Result',(),{'stdout':response.get('stdout',''),'stderr':response.get('stderr',''),'returncode':response.get('exit_code',1)})
        metadata={}
        for line in result.stdout.splitlines():
            try:
                candidate=json.loads(line)
                if isinstance(candidate,dict): metadata=candidate; break
            except json.JSONDecodeError: pass
        return {'title':'Backup','text':result.stdout,'stderr':result.stderr,'exit_code':result.returncode,'backup':metadata}
    return start_custom_run(user,SPEC,handler,{'source':source,'destination':destination,'label':label})

def history(limit=30):
    return rows("SELECT * FROM command_runs WHERE command='backup' ORDER BY started_at DESC LIMIT ?",(limit,))
