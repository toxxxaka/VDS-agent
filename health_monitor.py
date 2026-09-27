#!/usr/bin/env python3
"""Continuous CPU/load and inbound-traffic alerts for monitoringbot."""
import argparse, json, logging, os, socket, time
from pathlib import Path
import requests
from v4.incidents import observe
from v4.snapshots import capture
try:
    import psutil
except ImportError:
    psutil = None

CONFIG = Path(os.environ.get("MONITORINGBOT_HEALTH_CONFIG", "/etc/monitoringbot-main/health.json"))
STATE = Path(os.environ.get("MONITORINGBOT_HEALTH_STATE", "/var/lib/monitoringbot/health_state.json"))
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
LOG = logging.getLogger("monitorbot-health")
SESSION = requests.Session(); SESSION.trust_env = False

DEFAULT = {"interval_seconds": 10, "consecutive_samples": 3, "reminder_seconds": 900,
           "cpu_percent": 90, "load_one": 1.0, "per_cpu_load": 1.0,
           "inbound_mbps": 50, "inbound_pps": 10000, "syn_recv": 200, "tcp_connections": 2000}

def load_config():
    try:
        cfg = json.loads(CONFIG.read_text())
        return {**DEFAULT, **cfg}
    except Exception:
        return DEFAULT.copy()

def load_state():
    try: return json.loads(STATE.read_text())
    except Exception: return {"alerts": {}, "network": {}}

def save_state(state):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    temp = STATE.with_suffix(".tmp")
    temp.write_text(json.dumps(state)); os.chmod(temp, 0o600); temp.replace(STATE)

def send(text):
    if not TOKEN or not CHAT_ID: return False
    try:
        response = SESSION.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": text}, timeout=(5, 20))
        response.raise_for_status(); return bool(response.json().get("ok"))
    except Exception as exc:
        LOG.warning("Telegram notification failed: %s", type(exc).__name__); return False

def default_interface():
    with open("/proc/net/route") as handle:
        next(handle)
        for line in handle:
            fields = line.split()
            if len(fields) > 1 and fields[1] == "00000000": return fields[0]
    return None

def net_counters(interface):
    for line in Path("/proc/net/dev").read_text().splitlines():
        if ":" not in line: continue
        name, data = line.split(":", 1)
        if name.strip() == interface:
            values = data.split(); return int(values[0]), int(values[1])
    return 0, 0

def tcp_counts():
    # /proc avoids spawning a large ss process every ten seconds.
    total = syn_recv = 0
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:] + Path("/proc/net/tcp6").read_text().splitlines()[1:]:
        state = line.split()[3]
        if state == "0A": continue
        total += 1
        if state == "03": syn_recv += 1
    return total, syn_recv

def notify(state, key, active, text, cfg):
    alerts = state.setdefault("alerts", {})
    record = alerts.setdefault(key, {"count": 0, "active": False, "last_sent": 0})
    record["count"] = record["count"] + 1 if active else 0
    now = time.time()
    if active and record["count"] >= cfg["consecutive_samples"]:
        if not record["active"] or now - record["last_sent"] >= cfg["reminder_seconds"]:
            snapshot_id, _ = capture(key)
            iid, event = observe(key, "high", True, 0, 0, snapshot_id, {"message": text})
            send(f"{text}\nIncident: #{iid}"); record["last_sent"] = now
        record["active"] = True
    elif not active and record["active"]:
        iid, event = observe(key, "high", False, 0, 0, None, {})
        send(f"✅ Восстановление: {key}" + (f"\nIncident: #{iid}" if iid else ""))
        record.update({"active": False, "count": 0, "last_sent": now})

def sample(state, cfg):
    cores = os.cpu_count() or 1
    load1, load5, load15 = os.getloadavg(); per_core = load1 / cores
    cpu = psutil.cpu_percent(interval=None) if psutil else 0.0
    context = f"CPU: {cpu:.0f}%\nLA: {load1:.2f} / {load5:.2f} / {load15:.2f}\nНа ядро: {per_core:.2f}\nЯдер: {cores}"
    notify(state, "CPU", cpu >= cfg["cpu_percent"], f"⚠️ Высокая загрузка CPU\n{context}", cfg)
    notify(state, "LA 1 мин", load1 > cfg["load_one"], f"⚠️ Высокий Load Average\n{context}", cfg)
    notify(state, "LA на ядро", per_core > cfg["per_cpu_load"], f"⚠️ Высокая нагрузка на ядро\n{context}", cfg)
    interface = default_interface()
    if not interface: return
    received, packets = net_counters(interface); old = state.setdefault("network", {}).get(interface)
    state["network"][interface] = {"time": time.time(), "bytes": received, "packets": packets}
    if not old: return
    elapsed = max(time.time() - old["time"], 0.1)
    mbps = (received - old["bytes"]) * 8 / elapsed / 1_000_000
    pps = (packets - old["packets"]) / elapsed
    total, syn = tcp_counts()
    context = f"Интерфейс: {interface}\nВходящий трафик: {mbps:.1f} Мбит/с\nПакеты: {pps:.0f}/с\nTCP: {total}\nSYN-RECV: {syn}"
    notify(state, "Входящий трафик", mbps >= cfg["inbound_mbps"], f"⚠️ Высокий входящий трафик\n{context}", cfg)
    notify(state, "Пакеты в секунду", pps >= cfg["inbound_pps"], f"⚠️ Высокая частота пакетов\n{context}", cfg)
    notify(state, "SYN-RECV", syn >= cfg["syn_recv"], f"⚠️ Много TCP SYN-RECV\n{context}", cfg)
    notify(state, "TCP-соединения", total >= cfg["tcp_connections"], f"⚠️ Много TCP-соединений\n{context}", cfg)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-alerts", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.test_alerts:
        for title in ("Высокая загрузка CPU", "Высокий Load Average", "Высокая нагрузка на ядро", "Высокий входящий трафик", "Высокая частота пакетов", "Много TCP SYN-RECV", "Много TCP-соединений"):
            send(f"🧪 ТЕСТ: {title}\nЭто проверочное уведомление monitoringbot.")
        return
    if psutil is None: raise SystemExit("python3-psutil is required")
    psutil.cpu_percent(interval=None)
    while True:
        cfg, state = load_config(), load_state()
        try: sample(state, cfg); save_state(state)
        except Exception: LOG.exception("Health sample failed")
        time.sleep(cfg["interval_seconds"])
if __name__ == "__main__": main()
