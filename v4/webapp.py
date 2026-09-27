"""Authenticated Telegram Mini App backend for Monitoringbot v4."""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import subprocess
import time
import urllib.parse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from .incidents import ack, close
from .snapshots import overview
from .backups import destinations as backup_destinations, history as backup_history, start as start_backup
from .library import content as library_content, download as library_download, info as library_info, issue_link as library_issue_link
from .storage import audit, connect, rows
from . import firewall
from . import external_tools
from .tasks import TASKS, get_run, list_runs, start_run

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
AUTH = Path(os.environ.get("MONITORINGBOT_AUTH_CONFIG", "/etc/monitoringbot-main/auth.json"))
TTL = 3600
PENDING_TTL = 60
V3 = None


def cfg():
    return json.loads(AUTH.read_text())


def load_v3():
    global V3
    if V3 is None:
        spec = spec_from_file_location("monitoringbot_v3", "/opt/monitoringbot/v3.py")
        V3 = module_from_spec(spec)
        spec.loader.exec_module(V3)
    return V3


def browser_principal(client_ip):
    """Return an IP-bound browser principal only for configured trusted networks."""
    try:
        address = ipaddress.ip_address(client_ip)
        permitted = [ipaddress.ip_network(value, strict=False) for value in cfg().get("web_allowed_ips", [])]
        if any(address in network for network in permitted):
            return f"browser:{address.compressed}"
    except ValueError:
        pass
    return None


def initdata_ok(raw):
    """Validate Telegram's signed initData and return an allow-listed user id."""
    try:
        query = urllib.parse.parse_qs(raw, strict_parsing=True)
        supplied_hash = query.pop("hash", [None])[0]
        data = {key: value[0] for key, value in query.items()}
        auth_date = int(data["auth_date"])
        user = json.loads(data["user"])
        check = "\n".join(f"{key}={data[key]}" for key in sorted(data))
        secret = hmac.new(b"WebAppData", TOKEN.encode(), hashlib.sha256).digest()
        expected = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        if not supplied_hash or not hmac.compare_digest(supplied_hash, expected):
            return None
        if abs(time.time() - auth_date) > 300:
            return None
        if str(user["id"]) not in {str(item) for item in cfg()["allowed_user_ids"]}:
            return None
        return str(user["id"])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return None


def clear_expired(connection):
    connection.execute("DELETE FROM pending_actions WHERE expires_at < ?", (time.time(),))


def new_session(user):
    with connect() as connection:
        clear_expired(connection)
        cursor = connection.execute(
            "INSERT INTO pending_actions(kind,user_id,target,expires_at,data) VALUES(?,?,?,?,?)",
            ("web_session", user, "", time.time() + TTL, "{}"),
        )
        return cursor.lastrowid


def cookie_session_id(header):
    try:
        cookie = SimpleCookie()
        cookie.load(header or "")
        return int(cookie["mbs"].value)
    except (KeyError, ValueError):
        return None


def web_user(header):
    session_id = cookie_session_id(header)
    if session_id is None:
        return None
    with connect() as connection:
        clear_expired(connection)
        row = connection.execute("SELECT user_id FROM pending_actions WHERE id=? AND kind='web_session'", (session_id,)).fetchone()
        return row["user_id"] if row else None


def create_confirmation(user, kind, target, data=None):
    with connect() as connection:
        clear_expired(connection)
        cursor = connection.execute(
            "INSERT INTO pending_actions(kind,user_id,target,expires_at,data) VALUES(?,?,?,?,?)",
            (kind, user, target, time.time() + PENDING_TTL, json.dumps(data or {})),
        )
        return cursor.lastrowid


def consume_confirmation(user, action_id, allowed_kind):
    with connect() as connection:
        clear_expired(connection)
        row = connection.execute("SELECT * FROM pending_actions WHERE id=? AND user_id=? AND kind=?", (action_id, user, allowed_kind)).fetchone()
        if not row:
            return None
        connection.execute("DELETE FROM pending_actions WHERE id=?", (action_id,))
        return dict(row)


def command_result(command):
    """Execute an allow-listed existing monitor function without shell interpolation."""
    bot = load_v3()
    if command == "status":
        return {"title": "System status", "text": bot.build_status()}
    if command == "daily":
        return {"title": "Daily report", "text": bot.build_daily_report()}
    if command == "ping":
        data = bot.servers()
        text = ["Server availability"]
        for name, item in data.items():
            text.append(f"{'UP' if item['alive'] else 'NO ICMP'}  {name}: {item['ip']}")
        text.append("No ICMP reply does not necessarily mean that a server is unavailable.")
        return {"title": "Server availability", "text": "\n".join(text)}
    if command == "cpu":
        temperature = bot.cpu_temperature()
        text = f"CPU usage: {bot.cpu_usage()}%"
        if temperature is not None:
            text += f"\nTemperature: {temperature}°C"
        return {"title": "CPU", "text": text}
    if command == "ram":
        memory, swap = bot.ram(), bot.swap()
        return {"title": "Memory", "text": f"RAM: {memory['used']} / {memory['total']} GB ({memory['percent']}%)\nSwap: {swap['used']} / {swap['total']} GB ({swap['percent']}%)"}
    if command == "disk":
        disk, smart = bot.disk(), bot.smart()
        text = f"Used: {disk['used']} / {disk['total']} GB ({disk['percent']}%)\nSMART: {smart['health']}"
        if smart["temperature"] is not None:
            text += f"\nTemperature: {smart['temperature']}°C"
        return {"title": "Disk", "text": text}
    if command == "load":
        values = bot.load()
        return {"title": "Load average", "text": f"1 min: {values[0]}\n5 min: {values[1]}\n15 min: {values[2]}"}
    if command == "uptime":
        return {"title": "Uptime", "text": bot.uptime()}
    if command == "sshlogins":
        recent = bot.load_json(bot.SSH_STATE_FILE, {}).get("recent_untrusted_logins", [])
        if not recent:
            return {"title": "SSH logins", "text": "No untrusted successful SSH logins have been recorded."}
        text = ["Recent untrusted SSH logins"]
        for event in recent[-10:]:
            text.append(f"{event['timestamp']} | {event['user']} | {event['method']} | {event['ip']}:{event['port']}")
        return {"title": "SSH logins", "text": "\n".join(text)}
    if command == "sessions":
        return {"title": "SSH sessions", "text": "", "sessions": bot.active_ssh_sessions()}
    raise ValueError("Unsupported command")


def dashboard_payload():
    active = rows("SELECT * FROM incidents WHERE status='active' ORDER BY severity DESC,last_seen_at DESC LIMIT 8")
    counts = rows("SELECT status,COUNT(*) AS count FROM incidents GROUP BY status")
    return {
        "system": overview(),
        "active_incidents": active,
        "incident_counts": {row["status"]: row["count"] for row in counts},
        "runs": list_runs(5),
        "activity": rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 8"),
    }


def metric_payload(period):
    seconds = {"hour": 3600, "day": 86400, "week": 604800}.get(period, 3600)
    raw = rows("SELECT time,data FROM snapshots WHERE kind='periodic' AND time>=? ORDER BY time", (time.time()-seconds,))
    samples=[]; previous=None
    for row in raw:
        try: data=json.loads(row["data"])
        except json.JSONDecodeError: continue
        item={"time":row["time"],"cpu":data["cpu"]["percent"],"ram":data["memory"]["used"],"cached":data["memory"].get("cached",0),"disk_read":0,"disk_write":0,"rx":0,"tx":0}
        if previous:
            delta=max(1,row["time"]-previous["time"])
            item["rx"]=(data["network"]["bytes_recv"]-previous["net"]["bytes_recv"])*8/delta/1_000_000
            item["tx"]=(data["network"]["bytes_sent"]-previous["net"]["bytes_sent"])*8/delta/1_000_000
            item["disk_read"]=(data.get("disk_io",{}).get("read_bytes",0)-previous["io"].get("read_bytes",0))/delta
            item["disk_write"]=(data.get("disk_io",{}).get("write_bytes",0)-previous["io"].get("write_bytes",0))/delta
        samples.append(item); previous={"time":row["time"],"net":data["network"],"io":data.get("disk_io",{})}
    max_points=240
    if len(samples)>max_points:
        step=len(samples)/max_points; samples=[samples[int(i*step)] for i in range(max_points)]
    return {"period":period,"samples":samples,"system":overview()}

def incident_payload(incident_id):
    incident = rows("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if not incident:
        return None
    data = {"incident": incident[0], "events": rows("SELECT * FROM incident_events WHERE incident_id=? ORDER BY time DESC LIMIT 100", (incident_id,))}
    snapshot_id = incident[0].get("snapshot_id")
    if snapshot_id:
        snapshot = rows("SELECT * FROM snapshots WHERE id=?", (snapshot_id,))
        if snapshot:
            try:
                data["snapshot"] = json.loads(snapshot[0]["data"])
            except json.JSONDecodeError:
                data["snapshot"] = None
    return data


HTML = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><script src="https://telegram.org/js/telegram-web-app.js"></script><style>
:root{color-scheme:dark;--bg:#0b1220;--surface:#141f31;--surface2:#1b2a40;--line:#263852;--text:#e8eef8;--muted:#91a2ba;--blue:#4d93ff;--green:#33c78a;--amber:#f3b54a;--red:#ef646d}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input{font:inherit}button{cursor:pointer;border:0}.top{position:sticky;top:0;z-index:5;padding:15px 16px 12px;background:color-mix(in srgb,var(--bg) 94%,transparent);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}.head{display:flex;align-items:center;justify-content:space-between;gap:12px}.head b{font-size:18px}.head small{display:block;color:var(--muted);margin-top:2px}.icon-btn{padding:8px 10px;border-radius:9px;background:var(--surface2);color:var(--text)}main{max-width:760px;margin:auto;padding:14px 14px 94px}h1{font-size:23px;margin:12px 0 4px}h2{font-size:17px;margin:22px 0 10px}.sub{color:var(--muted);margin:0;font-size:13px}.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px;margin:10px 0}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.metric{background:var(--surface);border:1px solid var(--line);border-radius:13px;padding:13px}.metric .label{color:var(--muted);font-size:12px}.metric .value{font-size:20px;font-weight:700;margin-top:4px}.metric .detail{font-size:11px;color:var(--muted);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.status{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}.dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}.dot.active,.dot.completed{background:var(--green);box-shadow:0 0 0 3px #33c78a20}.dot.warning,.dot.running,.dot.queued{background:var(--amber);box-shadow:0 0 0 3px #f3b54a20}.dot.failed,.dot.timeout,.dot.critical{background:var(--red);box-shadow:0 0 0 3px #ef646d20}.incident{border-left:4px solid var(--amber)}.incident.high,.incident.critical{border-color:var(--red)}.row{display:flex;align-items:center;justify-content:space-between;gap:12px}.row button{margin:0}.muted{color:var(--muted)}.tiny{font-size:12px}.link{background:transparent;color:var(--blue);padding:4px 0}.action{width:100%;min-height:76px;text-align:left;padding:12px;border:1px solid var(--line);border-radius:13px;background:var(--surface);color:var(--text)}.action:active{transform:scale(.98)}.action b,.action small{display:block}.action small{color:var(--muted);margin-top:4px;font-size:11px}.tag{padding:3px 7px;border-radius:999px;background:#4d93ff18;color:#9cc5ff;font-size:11px}.primary,.secondary,.danger{padding:9px 12px;border-radius:9px;color:white;background:var(--blue)}.secondary{background:#334967}.danger{background:#9f3340}.primary:disabled{opacity:.55}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:10px 0 0;max-height:48vh;overflow:auto;padding:12px;border-radius:10px;background:#09111d;color:#d5e4f6;font:12px ui-monospace,SFMono-Regular,Menlo,monospace;line-height:1.5}.result-head{display:flex;align-items:center;justify-content:space-between;gap:10px}.result-actions{display:flex;gap:8px;margin-top:10px}.empty{padding:24px;text-align:center;color:var(--muted)}.tabs{position:fixed;bottom:0;left:0;right:0;z-index:5;display:grid;grid-template-columns:repeat(4,1fr);padding:8px max(12px,env(safe-area-inset-left)) calc(8px + env(safe-area-inset-bottom));background:#101a2aee;backdrop-filter:blur(12px);border-top:1px solid var(--line)}.tab{padding:8px 3px;background:transparent;color:var(--muted);font-size:11px}.tab.active{color:#9cc5ff}.tab span{display:block;font-size:17px;margin-bottom:2px}.toast{position:fixed;left:50%;bottom:78px;z-index:10;max-width:90vw;padding:10px 13px;border-radius:10px;background:#233751;color:white;transform:translateX(-50%);box-shadow:0 8px 32px #0008}.hidden{display:none}.service-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.service{padding:10px;border:1px solid var(--line);border-radius:10px}.service b{font-size:13px}.auth{max-width:440px;margin:10vh auto}.auth input{width:140px;padding:9px;border-radius:8px;border:1px solid var(--line);color:#111827}.timeline{border-left:2px solid var(--line);margin:12px 0 0 6px;padding-left:14px}.timeline div{position:relative;margin:0 0 13px}.timeline div:before{content:'';position:absolute;width:8px;height:8px;border-radius:50%;background:var(--blue);left:-19px;top:5px}@media(min-width:620px){.grid.four{grid-template-columns:repeat(4,minmax(0,1fr))}.service-grid{grid-template-columns:repeat(4,minmax(0,1fr))}}@media(max-width:360px){.metric .value{font-size:17px}}

/* Product-console refinement: hierarchy, tactile mobile controls, no decorative clutter. */
:root{--bg:#09111e;--surface:#111c2d;--surface2:#18273b;--line:#2b405b;--text:#edf3fb;--muted:#9bacc2;--blue:#69a7ff;--green:#56d39c;--amber:#ffbd5c;--red:#ff7b86}body{letter-spacing:.005em;background:radial-gradient(1100px 600px at 100% -10%,#172c48 0%,var(--bg) 55%)}.top{padding:18px max(18px,env(safe-area-inset-left)) 14px;background:#09111ef2}.head b{font-size:20px;letter-spacing:-.035em}.head small{font-size:12px;letter-spacing:.02em}.icon-btn{border:1px solid var(--line);padding:9px 12px;transition:background .16s ease,transform .16s ease}.icon-btn:active,.action:active,.primary:active,.secondary:active,.danger:active{transform:scale(.97)}main{max-width:900px;padding:20px 16px 104px}h1{font-size:31px;letter-spacing:-.05em;margin:14px 0 5px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);margin:28px 0 10px}.card{background:linear-gradient(145deg,#142136,#101a2a);border-color:#2a3d57;border-radius:16px;box-shadow:0 14px 34px #00000018}.metric{background:transparent;border-color:#2a3d57;border-radius:12px;padding:14px}.metric .value{font-size:23px;letter-spacing:-.05em}.grid{gap:10px}.action{min-height:82px;background:linear-gradient(145deg,#16263c,#111d30);border-color:#2b405d;border-radius:14px;transition:border-color .16s ease,background .16s ease}.action:hover{border-color:#5b8ccc;background:#172941}.primary,.secondary,.danger{border:1px solid #ffffff20;border-radius:10px;font-weight:650}.primary{background:#4e8ef0}.secondary{background:#263c59}.danger{background:#a94451}.tabs{max-width:900px;margin:auto;left:0;right:0;border:1px solid #2a3d57;border-bottom:0;border-radius:18px 18px 0 0;background:#0f1a2beF}.tab{min-height:52px;font-weight:600;letter-spacing:.01em}.tab span{font-size:16px}.auth{margin:13vh auto}.auth input,select{background:#0b1421;color:var(--text);border:1px solid #38516f;border-radius:10px;padding:11px;margin:8px 6px 8px 0}.auth input{width:158px;color:var(--text)}pre{border:1px solid #243854;background:#08111e;border-radius:12px}.toast{border:1px solid #42648c;background:#172a43}@media (prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto!important}}
</style></head><body><header class="top"><div class="head"><div><b>Monitoring</b><small id="subtitle">Secure server console</small></div><button class="icon-btn" id="logout">Log out</button></div></header><main id="app">Loading…</main><nav class="tabs" id="tabs"><button class="tab active" data-page="dashboard"><span>▦</span>Dashboard</button><button class="tab" data-page="incidents"><span>⚠</span>Incidents</button><button class="tab" data-page="activity"><span>◷</span>Activity</button><button class="tab" data-page="tools"><span>⌘</span>Tools</button></nav><div class="toast hidden" id="toast"></div><script>
const app=document.querySelector('#app'),tg=window.Telegram?.WebApp,init=tg?.initData,toast=document.querySelector('#toast');tg?.ready();let page='dashboard',pollTimer=null;document.querySelector('#subtitle').textContent=init?'Telegram Mini App':'IP-restricted browser console';
const esc=v=>String(v??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));const fmt=n=>n==null?'—':new Intl.NumberFormat().format(n);const gb=n=>n==null?'—':(n/1073741824).toFixed(1)+' GB';const ago=t=>{if(!t)return '—';const s=Math.max(0,Date.now()/1000-t);return s<60?Math.round(s)+'s ago':s<3600?Math.round(s/60)+'m ago':new Date(t*1000).toLocaleString()};
async function api(path,opt={}){const r=await fetch(path,{...opt,headers:{...opt.headers,'X-Telegram-InitData':init||''}});let d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.error||r.status);return d}function note(text){toast.textContent=text;toast.classList.remove('hidden');setTimeout(()=>toast.classList.add('hidden'),3200)}function setPage(next){clearInterval(pollTimer);page=next;document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.dataset.page===page));render()}
function status(value){return `<span class="status"><i class="dot ${esc(value)}"></i>${esc(value)}</span>`}function button(command,title,description){return `<button class="action" data-run="${command}"><b>${esc(title)}</b><small>${esc(description)}</small></button>`}
async function render(){try{const s=await api('/api/session');if(!s.totp){login();return}if(page==='dashboard')return dashboard();if(page==='incidents')return incidents();if(page==='activity')return activity();if(page==='stats')return stats();if(page==='backups')return backups();if(page==='library')return library();if(page==='firewall')return firewallPage();if(page==='networktools')return networkTools();tools()}catch(e){app.innerHTML='<div class="card empty">Authorization failed: '+esc(e.message)+'</div>'}}
async function dashboard(){const d=await api('/api/dashboard');const s=d.system,c=d.incident_counts||{},services=(s.services||[]).map(x=>`<div class="service"><b>${esc(x.name)}</b><br>${status(x.state)}</div>`).join('');const inc=(d.active_incidents||[]).map(incidentCard).join('')||'<div class="card empty">No active incidents.</div>';const recent=(d.runs||[]).map(runRow).join('')||'<div class="card empty">No diagnostic runs yet.</div>';app.innerHTML=`<h1>${esc(s.hostname)}</h1><p class="sub">Updated just now · ${esc(s.cpu.cores)} CPU core(s)</p><div class="grid four"><div class="metric"><div class="label">CPU</div><div class="value">${s.cpu.percent.toFixed(1)}%</div><div class="detail">Load ${s.cpu.load.map(x=>x.toFixed(2)).join(' / ')}</div></div><div class="metric"><div class="label">Memory</div><div class="value">${s.memory.percent.toFixed(1)}%</div><div class="detail">${gb(s.memory.available)} available</div></div><div class="metric"><div class="label">Disk</div><div class="value">${s.disk.percent.toFixed(0)}%</div><div class="detail">${gb(s.disk.free)} free</div></div><div class="metric"><div class="label">Network</div><div class="value">${gb(s.network.bytes_recv)}</div><div class="detail">received since boot</div></div></div><h2>Active incidents <span class="tag">${c.active||0}</span></h2>${inc}<h2>Services</h2><div class="service-grid">${services}</div><h2>Recent diagnostics</h2>${recent}<div class="result-actions"><button class="secondary" data-page-link="stats">Statistics</button><button class="link" data-page-link="activity">View activity →</button></div>`;bind()}
function incidentCard(i){return `<div class="card incident ${esc(i.severity)}"><div class="row"><div><b>${esc(i.type)}</b><br><span class="muted tiny">#${i.id} · ${esc(i.severity)} · started ${ago(i.started_at)}</span></div><button class="link" data-incident="${i.id}">Details</button></div></div>`}function runRow(r){return `<div class="card"><div class="row"><div><b>${esc(r.title)}</b><br><span class="muted tiny">${ago(r.started_at)} · ${r.duration_ms==null?'running':r.duration_ms+' ms'}</span></div>${status(r.status)}</div></div>`}
async function incidents(){const d=await api('/api/incidents');const list=d.incidents||[];app.innerHTML='<h1>Incidents</h1><p class="sub">Active, recovered and closed events.</p>'+(list.map(i=>`<div class="card incident ${esc(i.severity)}"><div class="row"><div><b>${esc(i.type)}</b><br><span class="muted tiny">#${i.id} · ${esc(i.severity)} · ${esc(i.status)} · ${ago(i.last_seen_at)}</span></div><button class="link" data-incident="${i.id}">Open</button></div></div>`).join('')||'<div class="card empty">No incidents.</div>');bind()}
async function openIncident(id){const d=await api('/api/incidents/'+id),i=d.incident;const events=(d.events||[]).map(e=>`<div><b>${esc(e.event)}</b><br><span class="muted tiny">${ago(e.time)}</span></div>`).join('')||'<div class="muted">No events.</div>';const snapshot=d.snapshot?`<h2>Snapshot</h2><pre>${esc(JSON.stringify({cpu:d.snapshot.cpu,memory:d.snapshot.memory,disk:d.snapshot.disk,network:d.snapshot.network},null,2))}</pre>`:'';app.innerHTML=`<button class="link" data-page-link="incidents">← Incidents</button><h1>${esc(i.type)}</h1><div class="card incident ${esc(i.severity)}"><b>#${i.id} · ${esc(i.severity)} · ${esc(i.status)}</b><p class="sub">Started ${ago(i.started_at)} · Last seen ${ago(i.last_seen_at)}</p>${i.ack_by?'<p class="tiny">Acknowledged by '+esc(i.ack_by)+'</p>':''}<div class="result-actions">${i.status!=='closed'?`<button class="secondary" data-incident-action="ack" data-id="${i.id}">Acknowledge</button><button class="danger" data-incident-action="close" data-id="${i.id}">Close</button>`:''}</div></div><h2>Timeline</h2><div class="timeline">${events}</div>${snapshot}`;bind()}
async function activity(){const [a,r]=await Promise.all([api('/api/audit'),api('/api/runs')]);const audit=(a.audit||[]).map(x=>`<div class="card"><div class="row"><div><b>${esc(x.action)}</b><br><span class="muted tiny">${esc(x.target||'server')} · ${ago(x.time)}</span></div>${status(x.result)}</div></div>`).join('')||'<div class="card empty">No activity.</div>';const runs=(r.runs||[]).map(runRow).join('')||'<div class="card empty">No runs.</div>';app.innerHTML='<h1>Activity</h1><p class="sub">Audited actions and diagnostic jobs.</p><h2>Diagnostics</h2>'+runs+'<h2>Audit log</h2>'+audit;bind()}
function tools(){const groups={Monitoring:[['status','System status','Complete status summary'],['daily','Daily report','Extended daily report'],['ping','Server availability','Configured server checks']],Resources:[['cpu','CPU','Usage and temperature'],['ram','Memory','RAM and swap'],['disk','Disk','Capacity and SMART'],['load','Load average','1 / 5 / 15 minutes'],['uptime','Uptime','Server uptime']],Security:[['sessions','SSH sessions','Active authenticated sessions'],['sshlogins','SSH logins','Recent external successful logins']]};let html='<h1>Tools</h1><p class="sub">Controlled diagnostics only. Every execution is audited.</p>';for(const [name,items] of Object.entries(groups))html+='<h2>'+name+'</h2><div class="grid">'+items.map(x=>button(...x)).join('')+'</div>';html+=`<h2>Backups</h2><div class="grid"><button class="action" data-page-link="backups"><b>Create backup</b><small>Rsync, log and metadata</small></button><button class="action" data-page-link="library"><b>Client scripts</b><small>Copy or temporary wget link</small></button></div><h2>Network & security</h2><div class="grid"><button class="action" data-page-link="networktools"><b>Checks & passwords</b><small>SSL, Check-Host, Cheburcheck</small></button><button class="action" data-page-link="firewall"><b>Firewall rules</b><small>Profiles, preview and rollback</small></button></div><h2>Server control</h2><div class="grid"><button class="action" data-power="reboot"><b>Reboot</b><small>Requires confirmation</small></button><button class="action" data-power="poweroff"><b>Shut down</b><small>Requires confirmation</small></button></div>`;app.innerHTML=html;bind()}
function chart(title,subtitle,points,keys,colors,fixed){const vals=points.flatMap(p=>keys.map(k=>p[k]||0));const max=fixed||Math.max(1,...vals)*1.12;const lines=keys.map((k,i)=>{const pts=points.map((p,n)=>`${n/(Math.max(1,points.length-1))*280+24},${94-(p[k]||0)/max*70}`).join(' ');return `<polyline fill="none" stroke="${colors[i]}" stroke-width="2" points="${pts}"/>`}).join('');const grid=[0,25,50,75,100].map(v=>`<line x1="24" x2="304" y1="${94-v*.7}" y2="${94-v*.7}" stroke="#263852"/><text x="2" y="${98-v*.7}" fill="#91a2ba" font-size="9">${(max*v/100).toFixed(max<10?1:0)}</text>`).join('');return `<div class="card"><div class="row"><div><b>${title}</b><br><span class="muted tiny">${subtitle}</span></div></div><svg viewBox="0 0 310 105" width="100%" role="img"><title>${title}</title>${grid}${lines}</svg></div>`}async function stats(period='hour',mode='fixed'){const d=await api('/api/metrics?period='+period),p=d.samples||[],sys=d.system;const fixed=mode==='fixed';const head=`<button class="link" data-page-link="dashboard">← Dashboard</button><h1>Statistics</h1><div class="card"><b>Statistics for</b><div class="result-actions"><button class="${period==='hour'?'primary':'secondary'}" data-stat="hour">Hour</button><button class="${period==='day'?'primary':'secondary'}" data-stat="day">Day</button><button class="${period==='week'?'primary':'secondary'}" data-stat="week">Week</button><button class="${fixed?'primary':'secondary'}" data-scale="fixed">Fixed scale</button><button class="${!fixed?'primary':'secondary'}" data-scale="adaptive">Adaptive</button></div></div>`;app.innerHTML=head+chart('CPU load',`${sys.cpu.cores} core(s)`,p,['cpu'],['#b998ff'],fixed?100:0)+chart('Traffic','Mbps',['rx','tx'].map? p:[],['rx','tx'],['#e9a9ff','#aeea78'],fixed?200:0)+chart('Memory',gb(sys.memory.total),p,['ram','cached'],['#e9a9ff','#aeea78'],fixed?sys.memory.total:0)+chart('Disk I/O','bytes per second',p,['disk_read','disk_write'],['#6ee7f2','#b6a7ff'],0);document.querySelectorAll('[data-stat]').forEach(x=>x.onclick=()=>stats(x.dataset.stat,mode));document.querySelectorAll('[data-scale]').forEach(x=>x.onclick=()=>stats(period,x.dataset.scale));bind()}async function backups(){const [d,h]=await Promise.all([api('/api/backups/destinations'),api('/api/backups')]);const opts=(d.destinations||[]).map(x=>`<option value="${esc(x.id)}">${esc(x.label)} — ${esc(x.path)}</option>`).join('');const history=(h.backups||[]).map(x=>`<div class="card"><b>${esc(x.title)}</b><br><span class="muted tiny">${ago(x.started_at)} · ${esc(x.status)} · ${x.duration_ms||0} ms</span></div>`).join('')||'<div class="card empty">No backups yet.</div>';app.innerHTML=`<button class="link" data-page-link="tools">← Tools</button><h1>Backups</h1><p class="sub">Creates a dated folder with data, backup.log and metadata.json.</p><div class="card"><label class="tiny">Source directory</label><input id="backup-source" style="width:100%;margin:6px 0 10px" placeholder="/home/ai/project"><label class="tiny">Description</label><input id="backup-label" style="width:100%;margin:6px 0 10px" placeholder="project-before-update"><label class="tiny">Destination</label><select id="backup-destination" style="width:100%;margin:6px 0 10px">${opts}</select><button class="primary" id="backup-start">Create backup</button></div><h2>History</h2>${history}`;document.querySelector('#backup-start').onclick=async()=>{try{const r=await api('/api/backups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:document.querySelector('#backup-source').value.trim(),label:document.querySelector('#backup-label').value.trim(),destination:document.querySelector('#backup-destination').value})});showRun(r.id)}catch(e){note(e.message)}};bind()}async function library(){const d=await api('/api/library');app.innerHTML='<button class="link" data-page-link="tools">← Tools</button><h1>Client scripts</h1><p class="sub">These files are for client servers. They are not executed here.</p>'+(d.scripts||[]).map(x=>`<div class="card"><b>${esc(x.title)}</b><br><span class="muted tiny">${esc(x.filename)} · ${esc(x.rights)}</span><div class="result-actions"><button class="secondary" data-script-copy="${x.id}">Copy</button><button class="primary" data-script-link="${x.id}">wget link</button></div></div>`).join('');document.querySelectorAll('[data-script-copy]').forEach(x=>x.onclick=async()=>{const a=await api('/api/library/'+x.dataset.scriptCopy);await navigator.clipboard.writeText(a.content);note('Script copied')});document.querySelectorAll('[data-script-link]').forEach(x=>x.onclick=async()=>{const a=await api('/api/library/'+x.dataset.scriptLink+'/link',{method:'POST'});await navigator.clipboard.writeText(a.command);note('wget command copied; link expires in 10 minutes')});bind()}
async function networkTools(){app.innerHTML=`<button class="link" data-page-link="tools">← Tools</button><h1>Checks & passwords</h1><div class="card"><b>Password generator</b><div class="result-actions"><button class="primary" id="pw">Generate 5-6-7</button></div><pre id="pwout">—</pre></div><div class="card"><b>SSL / external availability</b><input id="net-host" placeholder="example.com or example.com:443"><div class="result-actions"><button class="secondary" data-net="ssl">SSL</button><button class="secondary" data-net="checkhost">Check-Host HTTP</button><button class="secondary" data-net="cheburcheck">Cheburcheck</button></div><pre id="netout">Enter a hostname.</pre></div>`;document.querySelector('#pw').onclick=async()=>{const d=await api('/api/tools/password',{method:'POST'});document.querySelector('#pwout').textContent=d.password};document.querySelectorAll('[data-net]').forEach(b=>b.onclick=async()=>{try{const host=document.querySelector('#net-host').value.trim(),kind=b.dataset.net;const d=await api('/api/tools/'+kind,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host})});if(d.url){window.open(d.url,'_blank','noopener');return}document.querySelector('#netout').textContent=JSON.stringify(d,null,2)}catch(e){note(e.message)}});bind()}
async function firewallPage(){const d=await api('/api/firewall');const ip='${""}';app.innerHTML=`<button class="link" data-page-link="tools">← Tools</button><h1>Firewall</h1><p class="sub">Hard mode automatically rolls back unless the connection is confirmed.</p><div class="card"><select id="fw-profile"><option value="none">No monitoring rules</option><option value="standard">Standard</option><option value="hard">Hard</option></select><input id="fw-ip" placeholder="Trusted IP (auto detected if empty)"><label><input id="fw-web" type="checkbox" checked> Keep WebUI HTTPS for this IP</label><div class="result-actions"><button class="secondary" id="fw-preview">Preview</button><button class="danger" id="fw-apply">Apply</button></div></div><pre>${esc(d.managed||'No Monitoring-managed rules.')}</pre>`;document.querySelector('#fw-preview').onclick=async()=>{try{const x=await api('/api/firewall/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profile:document.querySelector('#fw-profile').value,source_ip:document.querySelector('#fw-ip').value,keep_webui:document.querySelector('#fw-web').checked})});app.querySelector('pre').textContent=x.rules}catch(e){note(e.message)}};document.querySelector('#fw-apply').onclick=async()=>{try{const x=await api('/api/firewall/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profile:document.querySelector('#fw-profile').value,source_ip:document.querySelector('#fw-ip').value,keep_webui:document.querySelector('#fw-web').checked})});if(!confirm('Apply this firewall profile?'))return;const y=await api('/api/firewall/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:x.token})});note('Applied. Hard profile rolls back in 120 seconds.');if(y.rollback_token)setTimeout(()=>api('/api/firewall/keep',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:y.rollback_token})}).catch(()=>{}),1500)}catch(e){note(e.message)}};bind()}
async function start(command){try{const run=await api('/api/runs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command})});showRun(run.id)}catch(e){note('Could not start: '+e.message)}}
async function showRun(id){clearInterval(pollTimer);async function update(){try{const r=await api('/api/runs/'+id);const details=r.details||{};let body=r.stdout||r.stderr||'Waiting for output…';if(details.sessions){body=details.sessions.length?details.sessions.map(s=>`${s.pid} | ${s.user} | ${s.source||'unknown'} | ${s.tty}`).join('\n'):'No active SSH sessions.'}app.innerHTML=`<button class="link" data-page-link="tools">← Tools</button><h1>${esc(r.title)}</h1><div class="card"><div class="row"><span>Started ${ago(r.started_at)}</span>${status(r.status)}</div><pre>${esc(body)}</pre>${r.stderr?'<pre>'+esc(r.stderr)+'</pre>':''}<div class="result-actions"><button class="secondary" data-copy="${id}">Copy output</button>${details.sessions?details.sessions.map(s=>`<button class="danger" data-terminate="${s.pid}">Terminate ${s.pid}</button>`).join(''):''}</div><p class="muted tiny">${r.duration_ms==null?'Running…':`Finished in ${r.duration_ms} ms · exit code ${r.exit_code}`}</p></div>`;bind();if(['completed','failed','timeout','cancelled'].includes(r.status))clearInterval(pollTimer)}catch(e){note(e.message)}}await update();pollTimer=setInterval(update,900)}
async function copyRun(id){const r=await api('/api/runs/'+id);await navigator.clipboard.writeText(r.stdout||r.stderr||'');note('Copied')}
async function requestSSH(pid){try{const d=await api('/api/actions/ssh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:Number(pid)})});confirmBox(d.confirmation_id,`Terminate SSH session ${pid}?`)}catch(e){note(e.message)}}async function requestPower(action){try{const d=await api('/api/actions/power',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});confirmBox(d.confirmation_id,action==='reboot'?'Reboot server?':'Shut down server?')}catch(e){note(e.message)}}function confirmBox(id,text){app.insertAdjacentHTML('afterbegin',`<div class="card incident"><b>${esc(text)}</b><p class="sub">Confirmation is valid for 60 seconds.</p><button class="danger" data-confirm="${id}">Confirm</button><button class="secondary" data-page-link="tools">Cancel</button></div>`);bind()}async function confirmAction(id){try{const d=await api('/api/actions/confirm/'+id,{method:'POST'});note(d.message);setPage('tools')}catch(e){note(e.message)}}
async function incidentAction(action,id){try{await api('/api/incidents/'+id+'/'+action,{method:'POST'});openIncident(id)}catch(e){note(e.message)}}
function bind(){document.querySelectorAll('[data-page-link]').forEach(x=>x.onclick=()=>setPage(x.dataset.pageLink));document.querySelectorAll('[data-run]').forEach(x=>x.onclick=()=>start(x.dataset.run));document.querySelectorAll('[data-incident]').forEach(x=>x.onclick=()=>openIncident(x.dataset.incident));document.querySelectorAll('[data-incident-action]').forEach(x=>x.onclick=()=>incidentAction(x.dataset.incidentAction,x.dataset.id));document.querySelectorAll('[data-copy]').forEach(x=>x.onclick=()=>copyRun(x.dataset.copy));document.querySelectorAll('[data-terminate]').forEach(x=>x.onclick=()=>requestSSH(x.dataset.terminate));document.querySelectorAll('[data-power]').forEach(x=>x.onclick=()=>requestPower(x.dataset.power));document.querySelectorAll('[data-confirm]').forEach(x=>x.onclick=()=>confirmAction(x.dataset.confirm));}
function login(){clearInterval(pollTimer);app.innerHTML='<section class="auth"><h1>Sign in</h1><p class="sub">Enter the current six-digit TOTP code. Browser access is restricted to approved IP addresses.</p><div class="card"><input id="totp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><button class="primary" id="signin">Sign in</button><p id="login-error" class="tiny"></p></div></section>';const submit=async()=>{const code=document.querySelector('#totp').value.trim(),error=document.querySelector('#login-error');if(!/^\d{6}$/.test(code)){error.textContent='Enter a six-digit code.';return}try{await api('/api/totp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});render()}catch(e){error.textContent='Sign in failed: '+e.message}};document.querySelector('#signin').onclick=submit;document.querySelector('#totp').onkeydown=e=>{if(e.key==='Enter')submit()}}
document.querySelector('#tabs').onclick=e=>{const b=e.target.closest('[data-page]');if(b)setPage(b.dataset.page)};document.querySelector('#logout').onclick=async()=>{try{await api('/api/logout',{method:'POST'});login()}catch(e){note(e.message)}};render();
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, payload, headers=None):
        raw = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def auth(self):
        telegram_user = initdata_ok(self.headers.get("X-Telegram-InitData", ""))
        principal = telegram_user or browser_principal(self.headers.get("X-Real-IP", ""))
        return principal, web_user(self.headers.get("Cookie", ""))

    def body(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 4096:
                raise ValueError
            value = json.loads(self.rfile.read(size))
            return value if isinstance(value, dict) else None
        except (ValueError, json.JSONDecodeError):
            return None

    def authenticated_user(self):
        telegram_user, session_user = self.auth()
        if not telegram_user:
            self.reply(401, {"error": "Telegram authorization or an allowed browser IP is required"})
            return None
        if not session_user or session_user != telegram_user:
            self.reply(403, {"error": "TOTP required"})
            return None
        return telegram_user

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(HTML.encode())
            return
        if re.fullmatch(r"/download/[A-Za-z0-9_-]{20,}", self.path):
            item=library_download(self.path.rsplit("/",1)[1])
            if not item:
                self.reply(404,{"error":"download link is invalid or expired"}); return
            filename,text=item; raw=text.encode()
            self.send_response(200); self.send_header("Content-Type","text/plain; charset=utf-8"); self.send_header("Content-Disposition",f'attachment; filename="{filename}"'); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(raw); return
        telegram_user, session_user = self.auth()
        if not telegram_user:
            self.reply(401, {"error": "Telegram authorization or an allowed browser IP is required"})
            return
        if self.path == "/api/session":
            self.reply(200, {"totp": bool(session_user and session_user == telegram_user)})
            return
        if not session_user or session_user != telegram_user:
            self.reply(403, {"error": "TOTP required"})
            return
        if self.path == "/api/dashboard":
            self.reply(200, dashboard_payload())
            return
        if self.path.startswith("/api/metrics"):
            period=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("period", ["hour"])[0]
            self.reply(200, metric_payload(period))
            return
        if self.path == "/api/tools/password":
            self.reply(200,{"password":external_tools.password()}); return
        if self.path == "/api/tools/ssl":
            try:self.reply(200,external_tools.ssl_check(str((self.body() or {}).get("host",""))))
            except Exception as exc:self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/tools/checkhost":
            data=self.body() or {}
            try:self.reply(200,external_tools.checkhost(str(data.get("host","")),str(data.get("kind","http"))))
            except Exception as exc:self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/tools/cheburcheck":
            try:self.reply(200,{"url":external_tools.cheburcheck_url(str((self.body() or {}).get("host","")))})
            except Exception as exc:self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/preview":
            data=self.body() or {}; ip=str(data.get("source_ip") or self.headers.get("X-Real-IP", ""))
            try: self.reply(200, firewall.preview(str(data.get("profile","")),ip,bool(data.get("keep_webui"))))
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/request":
            data=self.body() or {}; ip=str(data.get("source_ip") or self.headers.get("X-Real-IP", ""))
            try:
                result=firewall.request_apply(str(data.get("profile","")),ip,bool(data.get("keep_webui"))); audit(telegram_user,"firewall_request",str(data.get("profile","")),"pending",{"ip":ip}); self.reply(200,result)
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/confirm":
            try: result=firewall.confirm(str((self.body() or {}).get("token",""))); audit(telegram_user,"firewall_apply","","ok" if result.get("ok") else "failed"); self.reply(200,result)
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/keep":
            try: self.reply(200,firewall._bridge({"action":"firewall_keep","token":str((self.body() or {}).get("token",""))}))
            except RuntimeError as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/rollback":
            try: self.reply(200,firewall.rollback()); audit(telegram_user,"firewall_rollback")
            except RuntimeError as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/backups":
            self.reply(200, {"backups": backup_history()})
            return
        if self.path == "/api/backups/destinations":
            try: self.reply(200, {"destinations": backup_destinations()})
            except RuntimeError as exc: self.reply(500, {"error": str(exc)})
            return
        if self.path == "/api/library":
            self.reply(200, {"scripts": library_info()})
            return
        if re.fullmatch(r"/api/library/[a-z0-9-]+", self.path):
            try:
                filename, text=library_content(self.path.rsplit("/",1)[1]); self.reply(200,{"filename":filename,"content":text})
            except ValueError as exc: self.reply(404,{"error":str(exc)})
            return
        if self.path == "/api/incidents":
            self.reply(200, {"incidents": rows("SELECT * FROM incidents ORDER BY id DESC LIMIT 100")})
            return
        if re.fullmatch(r"/api/incidents/\d+", self.path):
            payload = incident_payload(int(self.path.rsplit("/", 1)[1]))
            self.reply(200, payload) if payload else self.reply(404, {"error": "incident not found"})
            return
        if self.path == "/api/audit":
            self.reply(200, {"audit": rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100")})
            return
        if self.path == "/api/runs":
            self.reply(200, {"runs": list_runs(100)})
            return
        if re.fullmatch(r"/api/runs/[0-9a-f-]{36}", self.path):
            run = get_run(self.path.rsplit("/", 1)[1])
            self.reply(200, run) if run else self.reply(404, {"error": "run not found"})
            return
        if self.path == "/api/firewall":
            try: self.reply(200, firewall.state())
            except RuntimeError as exc: self.reply(503, {"error": str(exc)})
            return
        if self.path == "/api/settings":
            self.reply(200, {"settings": {"allowed_users": len(cfg()["allowed_user_ids"]), "session_seconds": TTL, "tasks": [spec.__dict__ for spec in TASKS.values()]}})
            return
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        telegram_user, session_user = self.auth()
        if not telegram_user:
            self.reply(401, {"error": "Telegram authorization or an allowed browser IP is required"})
            return
        if self.path == "/api/totp":
            data = self.body() or {}
            code = str(data.get("code", ""))
            if not re.fullmatch(r"\d{6}", code) or not load_v3().totp_valid(cfg()["totp_secret"], code):
                audit(telegram_user, "web_totp", result="denied")
                self.reply(403, {"error": "invalid TOTP"})
                return
            session_id = new_session(telegram_user)
            audit(telegram_user, "web_totp", result="ok")
            self.reply(200, {"ok": True}, {"Set-Cookie": f"mbs={session_id}; HttpOnly; Secure; SameSite=Strict; Path=/"})
            return
        if not session_user or session_user != telegram_user:
            self.reply(403, {"error": "TOTP required"})
            return
        if self.path == "/api/tools/password":
            self.reply(200,{"password":external_tools.password()}); return
        if self.path == "/api/tools/ssl":
            try:self.reply(200,external_tools.ssl_check(str((self.body() or {}).get("host",""))))
            except Exception as exc:self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/tools/checkhost":
            data=self.body() or {}
            try:self.reply(200,external_tools.checkhost(str(data.get("host","")),str(data.get("kind","http"))))
            except Exception as exc:self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/tools/cheburcheck":
            try:self.reply(200,{"url":external_tools.cheburcheck_url(str((self.body() or {}).get("host","")))})
            except Exception as exc:self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/preview":
            data=self.body() or {}; ip=str(data.get("source_ip") or self.headers.get("X-Real-IP", ""))
            try: self.reply(200, firewall.preview(str(data.get("profile","")),ip,bool(data.get("keep_webui"))))
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/request":
            data=self.body() or {}; ip=str(data.get("source_ip") or self.headers.get("X-Real-IP", ""))
            try:
                result=firewall.request_apply(str(data.get("profile","")),ip,bool(data.get("keep_webui"))); audit(telegram_user,"firewall_request",str(data.get("profile","")),"pending",{"ip":ip}); self.reply(200,result)
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/confirm":
            try: result=firewall.confirm(str((self.body() or {}).get("token",""))); audit(telegram_user,"firewall_apply","","ok" if result.get("ok") else "failed"); self.reply(200,result)
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/keep":
            try: self.reply(200,firewall._bridge({"action":"firewall_keep","token":str((self.body() or {}).get("token",""))}))
            except RuntimeError as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/firewall/rollback":
            try: self.reply(200,firewall.rollback()); audit(telegram_user,"firewall_rollback")
            except RuntimeError as exc: self.reply(400,{"error":str(exc)})
            return
        if self.path == "/api/backups":
            data=self.body() or {}
            try: self.reply(202,start_backup(telegram_user,data.get("source",""),data.get("destination",""),data.get("label","")))
            except (ValueError,RuntimeError) as exc: self.reply(400,{"error":str(exc)})
            return
        if re.fullmatch(r"/api/library/[a-z0-9-]+/link", self.path):
            try: self.reply(200,library_issue_link(telegram_user,self.path.split("/")[-2]))
            except ValueError as exc: self.reply(404,{"error":str(exc)})
            return
        if self.path == "/api/runs":
            command = str((self.body() or {}).get("command", ""))
            try:
                self.reply(202, start_run(telegram_user, command, command_result))
            except ValueError as exc:
                self.reply(400, {"error": str(exc)})
            return
        if self.path.startswith("/api/commands/"):
            command = self.path.rsplit("/", 1)[1]
            try:
                result = command_result(command)
                audit(telegram_user, "web_command", command, "ok")
                self.reply(200, result)
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                audit(telegram_user, "web_command", command, "failed")
                self.reply(500, {"error": f"command failed: {type(error).__name__}"})
            return
        if self.path == "/api/actions/ssh":
            pid = (self.body() or {}).get("pid")
            if not isinstance(pid, int) or pid < 2:
                self.reply(400, {"error": "invalid SSH session"})
                return
            session = next((item for item in load_v3().active_ssh_sessions() if item["pid"] == pid), None)
            if not session:
                self.reply(404, {"error": "SSH session was not found"})
                return
            confirmation_id = create_confirmation(telegram_user, "web_ssh_terminate", session["id"], {"pid": pid})
            audit(telegram_user, "killssh_request", str(pid), "pending")
            self.reply(200, {"confirmation_id": confirmation_id, "expires_in": PENDING_TTL})
            return
        if self.path == "/api/actions/power":
            action = (self.body() or {}).get("action")
            if action not in {"reboot", "poweroff"}:
                self.reply(400, {"error": "invalid power action"})
                return
            confirmation_id = create_confirmation(telegram_user, "web_power", action)
            audit(telegram_user, f"{action}_request", result="pending")
            self.reply(200, {"confirmation_id": confirmation_id, "expires_in": PENDING_TTL})
            return
        if re.fullmatch(r"/api/actions/confirm/\d+", self.path):
            action_id = int(self.path.rsplit("/", 1)[1])
            pending = consume_confirmation(telegram_user, action_id, "web_ssh_terminate")
            if pending:
                try:
                    result = subprocess.run(["/usr/bin/sudo", "-n", "/usr/local/libexec/monitoringbot-ssh-session-helper", "terminate", pending["target"]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                    ok = result.returncode == 0
                except (OSError, subprocess.TimeoutExpired):
                    ok = False
                audit(telegram_user, "killssh", pending["target"], "ok" if ok else "failed")
                self.reply(200, {"ok": ok, "message": "SSH session terminated." if ok else "SSH session was not terminated; it may already be closed."})
                return
            pending = consume_confirmation(telegram_user, action_id, "web_power")
            if pending:
                action = pending["target"]
                try:
                    result = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/systemctl", action], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                    ok = result.returncode == 0
                except (OSError, subprocess.TimeoutExpired):
                    ok = False
                audit(telegram_user, action, "server", "ok" if ok else "failed")
                self.reply(200, {"ok": ok, "message": "Command accepted." if ok else "Privileged command was rejected or failed."})
                return
            self.reply(404, {"error": "confirmation is invalid or has expired"})
            return
        if self.path == "/api/logout":
            session_id = cookie_session_id(self.headers.get("Cookie", ""))
            if session_id is not None:
                with connect() as connection:
                    connection.execute("DELETE FROM pending_actions WHERE id=? AND kind='web_session' AND user_id=?", (session_id, telegram_user))
            audit(telegram_user, "web_logout")
            self.reply(200, {"ok": True}, {"Set-Cookie": "mbs=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"})
            return
        if re.fullmatch(r"/api/incidents/\d+/(ack|close)", self.path):
            _, _, _, incident_id, action = self.path.split("/")
            (ack if action == "ack" else close)(int(incident_id), telegram_user)
            self.reply(200, {"ok": True})
            return
        self.reply(404, {"error": "not found"})

    def log_message(self, *_args):
        pass


def main():
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("MONITORINGBOT_WEB_PORT", "8787"))), Handler).serve_forever()


if __name__ == "__main__":
    main()
