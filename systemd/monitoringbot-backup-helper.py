#!/usr/bin/env python3
"""Root-only, constrained rsync backup helper for Monitoringbot."""
import argparse, datetime as dt, json, os, re, subprocess, sys
from pathlib import Path

LOCAL_ROOT=Path('/root/backups')
MOUNT_PREFIXES=(Path('/mnt'),Path('/media'),Path('/run/media'))
BLOCKED=(Path('/proc'),Path('/sys'),Path('/dev'),Path('/run'))

def mounts():
    result=[{'id':'local','label':'Local server backup storage','path':str(LOCAL_ROOT),'kind':'local'}]
    try:
        data=json.loads(subprocess.run(['/usr/bin/findmnt','-J','-o','TARGET,SOURCE,FSTYPE,OPTIONS'],text=True,capture_output=True,timeout=5,check=True).stdout)
    except Exception:
        return result
    def walk(items):
        for item in items:
            target=Path(item.get('target','/'))
            if any(target == prefix or prefix in target.parents for prefix in MOUNT_PREFIXES) and 'rw' in item.get('options','').split(',') and target.is_dir():
                result.append({'id':'mount:'+str(target),'label':f"External: {target}",'path':str(target),'kind':'external','source':item.get('source',''),'fstype':item.get('fstype','')})
            walk(item.get('children',[]))
    walk(data.get('filesystems',[]))
    return result

def destination(destination_id):
    for item in mounts():
        if item['id']==destination_id:
            base=LOCAL_ROOT if destination_id=='local' else Path(item['path'])/'monitoring-backups'
            base.mkdir(parents=True,exist_ok=True)
            return base.resolve(),item
    raise ValueError('selected destination is unavailable')

def source_path(raw):
    path=Path(raw).expanduser().resolve(strict=True)
    if not path.is_dir(): raise ValueError('source must be an existing directory')
    if any(path == blocked or blocked in path.parents for blocked in BLOCKED): raise ValueError('source cannot be a virtual system filesystem')
    return path

def make_backup(source,dest_id,label):
    src=source_path(source); base,dest=destination(dest_id)
    if base == src or base in src.parents or src in base.parents: raise ValueError('source and destination must not overlap')
    clean=re.sub(r'[^A-Za-z0-9._-]+','-',label.strip())[:64].strip('.-') or src.name or 'backup'
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    folder=base/f'{stamp}--{clean}'
    folder.mkdir(mode=0o700)
    data=folder/'data'; data.mkdir(mode=0o700); log=folder/'backup.log'
    metadata={'created_at':dt.datetime.now(dt.timezone.utc).isoformat(),'label':clean,'source':str(src),'destination':str(folder),'destination_kind':dest['kind'],'rsync':['/usr/bin/rsync','-aHAX','--human-readable','--info=progress2','--partial','--log-file='+str(log),'--',str(src)+'/',str(data)+'/']}
    (folder/'metadata.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2)+'\n')
    process=subprocess.run(metadata['rsync'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=86400,check=False)
    metadata.update({'finished_at':dt.datetime.now(dt.timezone.utc).isoformat(),'exit_code':process.returncode,'log':str(log),'bytes':sum(p.stat().st_size for p in data.rglob('*') if p.is_file())})
    (folder/'metadata.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(metadata,ensure_ascii=False)); print(process.stdout,end=''); print(process.stderr,file=sys.stderr,end='')
    return process.returncode

def main():
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest='action',required=True); sub.add_parser('destinations'); create=sub.add_parser('create'); create.add_argument('--source',required=True); create.add_argument('--destination',required=True); create.add_argument('--label',default='')
    args=parser.parse_args()
    if args.action=='destinations': print(json.dumps(mounts(),ensure_ascii=False)); return 0
    try: return make_backup(args.source,args.destination,args.label)
    except (OSError,ValueError,subprocess.TimeoutExpired) as exc: print(str(exc),file=sys.stderr); return 2
if __name__=='__main__': raise SystemExit(main())
