#!/usr/bin/env python3
"""Continuous CPU/load and inbound-traffic alerts for monitoringbot."""
import argparse, json, logging, os, socket, time
from pathlib import Path
import requests
from v4.incidents import observe
from v4.snapshots import capture
from v4.alerting import AlertPolicy, advance
from v4.config import load as load_settings
from v4.flight_recorder import FlightRecorder
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
RECORDER = None

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

def _quiet_now(cfg, now):
    # UTC hour ranges, e.g. [[23, 7]]. A quiet period suppresses delivery but
    # never hides incidents or recovery in the database.
    for item in cfg.get("quiet_hours", []):
        if isinstance(item, list) and len(item) == 2 and all(isinstance(value, int) for value in item):
            hour = time.gmtime(now).tm_hour
            if (item[0] <= item[1] and item[0] <= hour < item[1]) or (item[0] > item[1] and (hour >= item[0] or hour < item[1])):
                return True
    return False


def _flight():
    global RECORDER
    telemetry = load_settings().telemetry
    if not telemetry.flight_recorder_enabled:
        return None
    if RECORDER is None or RECORDER.interval_seconds != telemetry.flight_recorder_interval_seconds:
        RECORDER = FlightRecorder(telemetry.flight_recorder_interval_seconds, telemetry.flight_recorder_window_seconds)
    return RECORDER


def notify(state, key, active, text, cfg, severity="high"):
    alerts = state.setdefault("alerts", {})
    now = time.time()
    policy = AlertPolicy(
        for_samples=max(1, int(cfg.get("consecutive_samples", 3))),
        recovery_samples=max(1, int(cfg.get("recovery_samples", 1))),
        reminder_seconds=max(30, int(cfg.get("reminder_seconds", 900))),
        severity=severity,
        quiet=_quiet_now(cfg, now),
    )
    record, event = advance(alerts.get(key), active, policy, now)
    alerts[key] = record
    if event in {"opened", "reminder"}:
        recorder = _flight()
        evidence = recorder.snapshot(key, now) if recorder and event == "opened" else None
        snapshot_id, _ = capture(key, evidence)
        iid, _ = observe(key, severity, True, 0, 0, snapshot_id, {"message": text, "alert_event": event})
        if not policy.quiet:
            send(f"{text}\nIncident: #{iid}")
    elif event == "recovered":
        iid, _ = observe(key, severity, False, 0, 0, None, {})
        if not policy.quiet:
            send(f"✅ Восстановление: {key}" + (f"\nIncident: #{iid}" if iid else ""))


def _sample_intelligence(state, cfg):
    """Observe failed units and optional detect-only intelligence independently of network state."""
    try:
        from v4.intelligence import failed_units, ioc_checks, listener_baseline
        failed = set(failed_units())
        known = {key.removeprefix("Failed unit: ") for key in state.get("alerts", {}) if key.startswith("Failed unit: ")}
        for unit in sorted(failed | known):
            notify(state, f"Failed unit: {unit}", unit in failed, f"🔴 systemd unit failed: {unit}", cfg, severity="critical")
        settings = load_settings().features
        scan_due = float(state.get("intelligence_scan_at", 0)) <= time.time()
        if scan_due and (settings.port_baseline_detection or settings.ioc_detect_only):
            findings = {}
            if settings.port_baseline_detection:
                ports = listener_baseline()
                findings["new_listeners"] = ports.get("new_listeners", [])
                for listener in findings["new_listeners"]:
                    notify(state, f"New listener: {listener}", True, f"⚠️ New listening socket: {listener}", cfg, severity="high")
            if settings.ioc_detect_only:
                iocs = ioc_checks()
                findings["ioc"] = iocs.get("new", {})
                for category, values in findings["ioc"].items():
                    if values:
                        notify(state, f"IOC: {category}", True, f"⚠️ Detect-only IOC change: {category} ({len(values)})", cfg, severity="high")
            state["intelligence_last_scan"] = findings
            state["intelligence_scan_at"] = time.time() + 900
    except Exception:
        LOG.exception("Incident intelligence sample failed")

def sample(state, cfg):
    cores = os.cpu_count() or 1
    load1, load5, load15 = os.getloadavg(); per_core = load1 / cores
    cpu = psutil.cpu_percent(interval=None) if psutil else 0.0
    context = f"CPU: {cpu:.0f}%\nLA: {load1:.2f} / {load5:.2f} / {load15:.2f}\nНа ядро: {per_core:.2f}\nЯдер: {cores}"
    recorder = _flight()
    if recorder:
        recorder.append({"time": time.time(), "cpu_percent": cpu, "load1": load1, "load5": load5, "load15": load15, "cores": cores})
    if load_settings().features.adaptive_baseline:
        from v4.baseline import shadow
        candidate = shadow("cpu", cpu)
        state["baseline_shadow"] = candidate
        if candidate["would_alert"]:
            LOG.info("Adaptive CPU baseline would alert; static policy remains authoritative")
    notify(state, "CPU", cpu >= cfg["cpu_percent"], f"⚠️ Высокая загрузка CPU\n{context}", cfg)
    notify(state, "LA 1 мин", load1 > cfg["load_one"], f"⚠️ Высокий Load Average\n{context}", cfg)
    notify(state, "LA на ядро", per_core > cfg["per_cpu_load"], f"⚠️ Высокая нагрузка на ядро\n{context}", cfg)
    _sample_intelligence(state, cfg)
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
