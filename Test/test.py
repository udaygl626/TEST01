#!/usr/bin/env python3
"""
☕ J.A.R.V.I.S Coffee Server Dashboard
Modern, live-updating server monitoring with login authentication,
session tracking, htop-style process view, Docker container monitoring,
network stats, dynamic manual threshold adjustments, and hierarchical topology tracking.
"""

import threading
import time
import json
import os
import socket
import re
from datetime import datetime, timedelta , timezone
from collections import deque
from functools import wraps

import psutil
from flask import Flask, render_template_string, jsonify, request, session, redirect, url_for
import subprocess
from flask import jsonify
import docker


# Imports for our external production logic layers
import alert
import network_manager
import chatbot_agent

try:
    import docker
    docker_client = docker.from_env()
    _DOCKER_SDK_OK = True
except Exception as _docker_err:
    docker_client = None
    _DOCKER_SDK_OK = False
    print(f"⚠️ Docker SDK unavailable — Docker Health tab disabled: {_docker_err}")


# ── Docker host mounts: make psutil read host's /proc and /sys ────
_HOST_PROC = os.environ.get("HOST_PROC", "")
_HOST_SYS = os.environ.get("HOST_SYS", "")
if _HOST_PROC:
    psutil.PROCFS_PATH = _HOST_PROC
if _HOST_SYS:
    psutil.SYSFS_PATH = _HOST_SYS

import logging
from logging.handlers import RotatingFileHandler

# ── Basic logging setup ──────────────────────────────────────────
# Writes to console (visible via `docker logs`) AND to a file that
# survives container restarts, so 500 errors are actually debuggable
# instead of showing a blank HTML page with no clue what broke.
LOG_DIR_PATH = "/root/hermes_media/system_dashboard/logs"
os.makedirs(LOG_DIR_PATH, exist_ok=True)

logger = logging.getLogger("jarvis")
logger.setLevel(logging.INFO)

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
))

_file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR_PATH, "jarvis.log"),
    maxBytes=5 * 1024 * 1024,  # 5MB per file
    backupCount=3
)
_file_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
))

logger.addHandler(_console_handler)
logger.addHandler(_file_handler)

app = Flask(__name__)
app.secret_key = 'jarvis-coffee-dashboard-secret-2026'

# ── Auth config ───────────────────────────────────────────────────
AUTH_USER = "admin"
AUTH_PASS = "Welcome12#"

# ── Session / login tracking ──────────────────────────────────────
SESSION_FILE = "/root/hermes_media/system_dashboard/sessions.json"
session_lock = threading.Lock()

def load_sessions():
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_sessions(sessions):
    try:
        os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
        with open(SESSION_FILE, "w") as f:
            json.dump(sessions, f, indent=2)
    except Exception:
        pass

def get_location_from_ip(ip):
    """Try to get approximate location from IP using ip-api.com (free, no auth)."""
    try:
        if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "192.168.", "127.", "0.")):
            return "Local/Private"
        result = subprocess.check_output(
            ["curl", "-s", "--max-time", "5",
             f"http://ip-api.com/json/{ip}?fields=status,city,country,isp"],
            text=True, timeout=8
        )
        data = json.loads(result)
        if data.get("status") == "success":
            city = data.get("city", "")
            country = data.get("country", "")
            isp = data.get("isp", "")
            parts = [p for p in [city, country] if p]
            loc = ", ".join(parts)
            if isp:
                loc += f" ({isp})"
            return loc
    except Exception:
        pass
    return "Unknown"

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ── Cached slow data ─────────────────────────────────────────────
cache_lock = threading.Lock()
cached = {
    "docker": [],
    "security": {},
    "logs": [],
    "last_docker": 0,
    "last_security": 0,
    "last_logs": 0,
}

# ── Docker cache thread ──────────────────────────────────────────
def refresh_docker():
    while True:
        try:
            containers = []
            result = subprocess.check_output(
                ["docker", "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"],
                text=True, timeout=10
            )
            for line in result.strip().split("\n"):
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) < 5:
                    continue
                containers.append({
                    "id": parts[0][:12], "name": parts[1], "image": parts[2],
                    "status": parts[3], "ports": parts[4],
                    "cpu": None, "mem": None, "mem_perc": None, "net_io": None, "block_io": None,
                })
            try:
                stats_result = subprocess.check_output(
                    ["docker", "stats", "--no-stream", "--format",
                     "{{.ID}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.BlockIO}}"],
                    text=True, timeout=20
                )
                stats_map = {}
                for line in stats_result.strip().split("\n"):
                    if not line:
                        continue
                    sp = line.split("|")
                    if len(sp) >= 4:
                        stats_map[sp[0][:12]] = {
                            "cpu": sp[1].strip(), "mem_usage": sp[2].strip(),
                            "mem_perc": sp[3].strip(),
                            "net_io": sp[4].strip() if len(sp) > 4 else "",
                            "block_io": sp[5].strip() if len(sp) > 5 else "",
                        }
                for c in containers:
                    if c["id"] in stats_map:
                        s = stats_map[c["id"]]
                        c["cpu"] = s["cpu"]
                        c["mem"] = s["mem_usage"]
                        c["mem_perc"] = s["mem_perc"]
                        c["net_io"] = s["net_io"]
                        c["block_io"] = s["block_io"]
            except Exception:
                pass
            with cache_lock:
                cached["docker"] = containers
                cached["last_docker"] = time.time()
        except Exception:
            pass
        time.sleep(10)

threading.Thread(target=refresh_docker, daemon=True).start()

# ── Security cache thread ────────────────────────────────────────
def refresh_security():
    while True:
        info = {}
        try:
            result = subprocess.check_output(
                ["bash", "-c", "journalctl -u ssh --since '1 hour ago' --no-pager -q 2>/dev/null | grep -c 'Failed' || echo 0"],
                text=True, timeout=5
            )
            info["failed_ssh"] = int(result.strip()) if result.strip().isdigit() else 0
        except Exception:
            info["failed_ssh"] = "N/A"
        try:
            external_ports = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr.ip not in ('127.0.0.1', '::1', '::'):
                    external_ports.append(conn.laddr.port)
            info["external_ports"] = sorted(set(external_ports))
        except Exception:
            info["external_ports"] = []
        try:
            result = subprocess.check_output(["last", "-n", "5"], text=True, timeout=5)
            logins = [l for l in result.strip().split("\n") if l and not l.startswith("wtmp") and not l.startswith("btmp")]
            info["last_logins"] = logins[:5]
        except Exception:
            info["last_logins"] = []
        try:
            result = subprocess.check_output(["ufw", "status"], text=True, timeout=5)
            info["firewall"] = result.strip().split("\n")[0] if result.strip() else "Unknown"
        except Exception:
            info["firewall"] = "ufw not available"
        try:
            result = subprocess.check_output(["bash", "-c", "apt list --upgradable -qq 2>/dev/null | grep -c '/' || echo 0"], text=True, timeout=8)
            info["upgradable"] = int(result.strip()) if result.strip().isdigit() else 0
        except Exception:
            info["upgradable"] = "N/A"

        with cache_lock:
            cached["security"] = info
            cached["last_security"] = time.time()
        time.sleep(30)

threading.Thread(target=refresh_security, daemon=True).start()

# ── Logs cache thread ────────────────────────────────────────────
def refresh_logs():
    while True:
        try:
            result = subprocess.check_output(
                ["journalctl", "-n", "30", "--no-pager", "-q", "-p", "warning"],
                text=True, timeout=5
            )
            logs = result.strip().split("\n") if result.strip() else []
        except Exception:
            logs = []

        # NEW: pull the last 100 lines of our own application log so
        # request errors, chatbot failures, etc. show up on the dashboard
        # instead of only living in the file on disk.
        try:
            app_logs = []
            jarvis_log_path = os.path.join(LOG_DIR_PATH, "jarvis.log")
            if os.path.exists(jarvis_log_path):
                with open(jarvis_log_path, "r") as f:
                    app_logs = [line.rstrip("\n") for line in f.readlines()[-100:]]
        except Exception:
            app_logs = []

        with cache_lock:
            cached["logs"] = logs
            cached["app_logs"] = app_logs
            cached["last_logs"] = time.time()
        time.sleep(15)
threading.Thread(target=refresh_logs, daemon=True).start()
# ── Microburst Tracking System (100ms Granularity Worker) ──────────
microburst_lock = threading.Lock()
network_high_water_marks = {
    "max_sent_bps_100ms": 0.0,
    "max_recv_bps_100ms": 0.0
}

def monitor_microbursts_worker():
    global network_high_water_marks
    try:
        last_counters = psutil.net_io_counters()
        last_time = time.time()
    except Exception:
        return

    while True:
        time.sleep(0.1)
        try:
            now = time.time()
            counters = psutil.net_io_counters()
            elapsed = now - last_time
            if elapsed <= 0:
                continue

            sent_speed = (counters.bytes_sent - last_counters.bytes_sent) / elapsed
            recv_speed = (counters.bytes_recv - last_counters.bytes_recv) / elapsed

            with microburst_lock:
                if sent_speed > network_high_water_marks["max_sent_bps_100ms"]:
                    network_high_water_marks["max_sent_bps_100ms"] = sent_speed
                if recv_speed > network_high_water_marks["max_recv_bps_100ms"]:
                    network_high_water_marks["max_recv_bps_100ms"] = recv_speed

            last_counters = counters
            last_time = now
        except Exception:
            pass

threading.Thread(target=monitor_microbursts_worker, daemon=True).start()

# ── Dynamic Target Historical Metric Pools (Maintained per Container) ──
container_history_lock = threading.Lock()
container_history_cache = {} # Map containing {'container_name': {'cpu': deque, 'mem': deque}}

def monitor_container_historical_trends():
    """Background sampling loop mapping sub-trends for charts when containers are targeted."""
    while True:
        time.sleep(3)
        with cache_lock:
            current_dockers = list(cached.get("docker", []))
        registered_servers = network_manager.load_registered_servers()
        docker_names_set = {c["name"] for c in current_dockers if c.get("name")}
        external_servers = [s for s in registered_servers if s.get("name") not in docker_names_set]
        
        with container_history_lock:
            # Clean obsolete containers out of memory tracking pools
            active_names = {c["name"] for c in current_dockers if c.get("name")}
            for name in list(container_history_cache.keys()):
                if name not in active_names:
                    del container_history_cache[name]

            for c in current_dockers:
                name = c.get("name")
                if not name: continue
                if name not in container_history_cache:
                    container_history_cache[name] = {
                        "cpu": deque([0.0] * 60, maxlen=60),
                        "mem": deque([0.0] * 60, maxlen=60)
                    }
                
                # Clean string representations out of docker stats output ('4.2%' -> 4.2)
                try:
                    raw_cpu = c.get("cpu") or "0%"
                    cpu_val = float(raw_cpu.replace("%","").strip())
                except Exception:
                    cpu_val = 0.0
                try:
                    raw_mem = c.get("mem_perc") or "0%"
                    mem_val = float(raw_mem.replace("%","").strip())
                except Exception:
                    mem_val = 0.0
                
                container_history_cache[name]["cpu"].append(cpu_val)
                container_history_cache[name]["mem"].append(mem_val)
        for srv in external_servers:
                name = srv.get("name")
                srv_ip = srv.get("ip")
                if not name:
                    continue
                if name not in container_history_cache:
                    container_history_cache[name] = {
                        "cpu": deque([0.0] * 60, maxlen=60),
                        "mem": deque([0.0] * 60, maxlen=60)
                    }
                try:
                    ext_metrics = network_manager.query_prometheus_host_metrics(srv_ip)
                    cpu_val = float(ext_metrics.get("cpu_percent") or 0.0) if ext_metrics else 0.0
                    mem_val = float(ext_metrics.get("memory_percent") or 0.0) if ext_metrics else 0.0
                except Exception:
                    cpu_val, mem_val = 0.0, 0.0

                container_history_cache[name]["cpu"].append(cpu_val)
                container_history_cache[name]["mem"].append(mem_val)

threading.Thread(target=monitor_container_historical_trends, daemon=True).start()

# ── Host History tracking ──
cpu_history = deque([0.0] * 60, maxlen=60)
mem_history = deque([0.0] * 60, maxlen=60)
psutil.cpu_percent(interval=None)

# ── Helpers ──────────────────────────────────────────────────────
def bytes_human(n):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def seconds_human(s):
    return str(timedelta(seconds=int(s)))

def get_hardware_interface_errors():
    error_metrics = {}
    net_dir = os.path.join(_HOST_SYS if _HOST_SYS else "/sys", "class", "net")
    if not os.path.exists(net_dir):
        return error_metrics
    try:
        for interface in os.listdir(net_dir):
            if interface == "lo" or interface.startswith("veth"):
                continue
            stats_path = os.path.join(net_dir, interface, "statistics")
            if os.path.exists(stats_path):
                with open(os.path.join(stats_path, "rx_errors"), "r") as f:
                    rx_err = int(f.read().strip())
                with open(os.path.join(stats_path, "tx_errors"), "r") as f:
                    tx_err = int(f.read().strip())
                with open(os.path.join(stats_path, "rx_dropped"), "r") as f:
                    rx_drop = int(f.read().strip())
                error_metrics[interface] = {
                    "rx_errors": rx_err,
                    "tx_errors": tx_err,
                    "rx_dropped": rx_drop
                }
    except Exception:
        pass
    return error_metrics

def get_processes(limit=80, target="main_server"):
    if target == "main_server" or not target:
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent',
                                       'memory_percent', 'memory_info', 'status',
                                       'num_threads', 'cmdline']):
            try:
                info = p.info
                cmdline = info.get('cmdline', [])
                cmd = ' '.join(cmdline) if cmdline else info.get('name', '')
                if len(cmd) > 100:
                    cmd = cmd[:97] + '...'
                procs.append({
                    'pid': int(info['pid']), 
                    'name': info.get('name', ''),
                    'user': info.get('username', ''),
                    'cpu': round(float(info.get('cpu_percent', 0.0)), 1),
                    'mem': round(float(info.get('memory_percent', 0.0)), 1),
                    'mem_rss': bytes_human(info['memory_info'].rss) if info.get('memory_info') else '',
                    'status': info.get('status', ''),
                    'threads': int(info.get('num_threads', 0)), 
                    'cmd': cmd,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        procs.sort(key=lambda x: x['cpu'], reverse=True)
        return procs[:limit]
    else:
        try:
            output = subprocess.check_output(["docker", "top", target, "-o", "pid,user,cpu,mem,vsz,stat,comm"], text=True)
            lines = output.strip().split("\n")[1:]
            container_procs = []
            for line in lines:
                parts = re.split(r'\s+', line.strip(), maxsplit=6)
                if len(parts) >= 6:
                    # Clean out non-numeric entries safely to preserve sorting data types
                    try:
                        cpu_val = round(float(parts[2].replace('%','')), 1)
                    except ValueError:
                        cpu_val = 0.0
                    try:
                        mem_val = round(float(parts[3].replace('%','')), 1)
                    except ValueError:
                        mem_val = 0.0

                    container_procs.append({
                        'pid': int(parts[0]) if parts[0].isdigit() else parts[0], 
                        'user': parts[1], 
                        'cpu': cpu_val, 
                        'mem': mem_val,
                        'mem_rss': parts[4] if 'B' in parts[4] else parts[4] + " KB", 
                        'status': parts[5], 
                        'threads': 1, 
                        'cmd': parts[6] if len(parts) > 6 else parts[5],
                    })
            container_procs.sort(key=lambda x: x['cpu'], reverse=True)
            return container_procs[:limit]
        except Exception:
            return []

def get_disk_partitions(target="main_server"):
    if target == "main_server" or not target:
        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    'device': part.device, 'mountpoint': part.mountpoint,
                    'fstype': part.fstype,
                    'total': bytes_human(usage.total), 'used': bytes_human(usage.used),
                    'free': bytes_human(usage.free), 'percent': int(usage.percent),
                })
            except PermissionError:
                continue
        return disks
    else:
        try:
            output = subprocess.check_output(["docker", "exec", target, "df", "-h"], text=True)
            disks = []
            for line in output.strip().split("\n")[1:]:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 6 and parts[0] != "Filesystem":
                    try:
                        pct = int(parts[4].replace('%', ''))
                    except ValueError:
                        pct = 0
                    disks.append({
                        'device': parts[0], 'mountpoint': parts[5], 'fstype': 'overlay',
                        'total': parts[1], 'used': parts[2], 'free': parts[3], 
                        'percent': pct
                    })
            return disks
        except Exception:
            return []

def get_network_connections():
    listening = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                proc_name = ''
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except Exception:
                    pass
                listening.append({'pid': conn.pid, 'local': f"{conn.laddr.ip}:{conn.laddr.port}", 'process': proc_name})
    except (psutil.AccessDenied, Exception):
        pass
    return listening[:40]
# ── Background Alert Scanner (evaluates thresholds for EVERY scope, ─────
#     not just whatever the UI dropdown happens to be pointed at) ───────
def background_alert_scanner():
    """
    /api/all only ever evaluated alert.evaluate_metrics() for the single
    'target' the browser was requesting — so a rule on a container or
    external server would never fire unless someone was actively looking
    at that scope. This loop evaluates ALL scopes on a fixed interval,
    independent of what's currently shown on screen.
    """
    while True:
        try:
            # ── Main host scope ──
            try:
                cpu_percent = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                net_metrics = network_manager.get_scoped_network_metrics(target="main_server")

                raw_rx_err = int(net_metrics.get("errors_rx", 0)) if isinstance(net_metrics.get("errors_rx"), int) else 0
                raw_tx_err = int(net_metrics.get("errors_tx", 0)) if isinstance(net_metrics.get("errors_tx"), int) else 0
                raw_rx_drop = int(net_metrics.get("drops_rx", 0)) if isinstance(net_metrics.get("drops_rx"), int) else 0
                raw_tx_drop = int(net_metrics.get("drops_tx", 0)) if isinstance(net_metrics.get("drops_tx"), int) else 0
                total_network_errors = raw_rx_err + raw_tx_err + raw_rx_drop + raw_tx_drop

                with microburst_lock:
                    host_kb_speed = (network_high_water_marks["max_sent_bps_100ms"] +
                                      network_high_water_marks["max_recv_bps_100ms"]) / 1024.0

                host_metrics = {
                    "cpu_percent": cpu_percent,
                    "mem_percent": round(mem.percent, 1),
                    "disk_percent": float(disk.percent),
                    "net_throughput_kb_per_sec": host_kb_speed,
                    "net_errors_total": float(total_network_errors)
                }
                alert.evaluate_metrics("local_master", host_metrics, target_scope="main_server")
            except Exception as e:
                print(f"background_alert_scanner: main_server eval error: {e}")

            # ── Docker container scopes ──
            with cache_lock:
                docker_snapshot = list(cached.get("docker", []))

            for c in docker_snapshot:
                name = c.get("name")
                if not name:
                    continue
                # ── Docker container crash/recovery detection (ALL containers, ──
            #     including stopped ones — cached["docker"] only holds RUNNING
            #     containers since that's what the Docker tab/UI should show,
            #     so this queries independently and doesn't touch that cache
            #     or any UI-facing logic. ──
            try:
                all_containers_raw = subprocess.check_output(
                    ["docker", "ps", "-a", "--format", "{{.Names}}|{{.Status}}"],
                    text=True, timeout=10
                )
                container_lines = [l for l in all_containers_raw.strip().split("\n") if l]

                # Build a one-time snapshot summary of every container's
                # status, so each crash/recovery email includes full context
                # instead of just the single container that changed state.
                fleet_status_lines = []
                for line in container_lines:
                    parts = line.split("|")
                    if len(parts) < 2:
                        continue
                    s_name, s_status = parts[0], parts[1]
                    is_up = s_status.lower().startswith("up")
                    icon = "🟢" if is_up else "🔴"
                    fleet_status_lines.append(f"  {icon} {s_name} — {s_status}")
                fleet_summary = "\n".join(fleet_status_lines) if fleet_status_lines else "  (no containers found)"

                for line in container_lines:
                    parts = line.split("|")
                    if len(parts) < 2:
                        continue
                    c_name, c_status = parts[0], parts[1]
                    is_running = c_status.lower().startswith("up")

                    alert.check_state_transition(
                        key=f"container:{c_name}",
                        is_up=is_running,
                        up_subject=f"🟢 Jarvis: Container '{c_name}' is BACK ONLINE",
                        up_body=(
                            f"Container '{c_name}' is running again.\n\n"
                            f"Status: {c_status}\n"
                            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                            f"── Current fleet status ──\n{fleet_summary}"
                        ),
                        down_subject=f"🔴 Jarvis: Container '{c_name}' is DOWN",
                        down_body=(
                            f"Container '{c_name}' has stopped or crashed.\n\n"
                            f"Status: {c_status}\n"
                            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                            f"── Current fleet status ──\n{fleet_summary}"
                        )
                    )
            except Exception as e:
                print(f"background_alert_scanner: container state-scan error: {e}")
                try:
                    c_cpu = float(str(c.get("cpu", "0")).replace("%", "").strip())
                    c_mem = float(str(c.get("mem_perc", "0")).replace("%", "").strip())

                    raw_io = c.get("net_io", "0B / 0B") or "0B / 0B"
                    kb_match = re.findall(r'([\d.]+)\s*(KB|MB|B)', raw_io, re.IGNORECASE)
                    total_kb_speed = 0.0
                    for val, unit in kb_match:
                        v = float(val)
                        if 'mb' in unit.lower(): v *= 1024
                        elif 'b' in unit.lower() and 'kb' not in unit.lower(): v /= 1024
                        total_kb_speed += v

                    container_disks = get_disk_partitions(target=name)
                    disk_pct = float(container_disks[0]["percent"]) if container_disks else 0.0

                    net_metrics = network_manager.get_scoped_network_metrics(target=name)
                    raw_rx_err = int(net_metrics.get("errors_rx", 0)) if isinstance(net_metrics.get("errors_rx"), int) else 0
                    raw_tx_err = int(net_metrics.get("errors_tx", 0)) if isinstance(net_metrics.get("errors_tx"), int) else 0
                    raw_rx_drop = int(net_metrics.get("drops_rx", 0)) if isinstance(net_metrics.get("drops_rx"), int) else 0
                    raw_tx_drop = int(net_metrics.get("drops_tx", 0)) if isinstance(net_metrics.get("drops_tx"), int) else 0
                    container_net_errors = raw_rx_err + raw_tx_err + raw_rx_drop + raw_tx_drop

                    container_metrics = {
                        "cpu_percent": c_cpu,
                        "mem_percent": c_mem,
                        "disk_percent": disk_pct,
                        "net_throughput_kb_per_sec": total_kb_speed,
                        "net_errors_total": float(container_net_errors)
                    }
                    alert.evaluate_metrics("local_master", container_metrics, target_scope=name)
                except Exception as e:
                    print(f"background_alert_scanner: container '{name}' eval error: {e}")

            # ── Registered external server scopes ──
            registered_servers = network_manager.load_registered_servers()
            docker_names = {c.get("name") for c in docker_snapshot if c.get("name")}

            for srv in registered_servers:
                srv_name = srv.get("name")
                srv_ip = srv.get("ip")
                if not srv_name or srv_name in docker_names:
                    continue  # already handled above as a container match
                try:
                    external_metrics = network_manager.query_prometheus_host_metrics(srv_ip)

                    # Crash/recovery detection — must run even when metrics
                    # came back empty, since "no data" IS the down state.
                    alert.check_state_transition(
                        key=f"external:{srv_name}",
                        is_up=external_metrics is not None,
                        up_subject=f"🟢 Jarvis: Server '{srv_name}' is BACK ONLINE",
                        up_body=f"Server '{srv_name}' ({srv_ip}) is reachable again.\n\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                        down_subject=f"🔴 Jarvis: Server '{srv_name}' is DOWN",
                        down_body=f"Server '{srv_name}' ({srv_ip}) is unreachable or Prometheus has no data for it.\n\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    )

                    if not external_metrics:
                        continue

                    container_metrics = {
                        "cpu_percent": external_metrics.get("cpu_percent") or 0.0,
                        "mem_percent": external_metrics.get("memory_percent") or 0.0,
                        "disk_percent": external_metrics.get("disk_percent") or 0.0,
                        "net_throughput_kb_per_sec":
                            (external_metrics.get("network_receive") or 0.0) +
                            (external_metrics.get("network_transmit") or 0.0),
                        "net_errors_total": 0.0
                    }
                    alert.evaluate_metrics("local_master", container_metrics, target_scope=srv_name)
                except Exception as e:
                    print(f"background_alert_scanner: external server '{srv_name}' eval error: {e}")

        except Exception as e:
            print(f"background_alert_scanner: top-level loop error: {e}")

        time.sleep(15)

threading.Thread(target=background_alert_scanner, daemon=True).start()
# ── Login Page Template ──────────────────────────────────────────
LOGIN_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>☕ J.A.R.V.I.S — Login</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#0d0d0d;--bg2:#161616;--bg3:#1e1e1e;--bg4:#2a2a2a;--border:#333;--text:#e0e0e0;--text-dim:#888;--accent:#c8956c;--accent-light:#e8b88a;--green:#4ade80;--red:#f87171;--blue:#60a5fa}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden;position:relative}
#bg-canvas{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none}
.login-container{width:100%;max-width:420px;padding:24px;position:relative;z-index:1}
.login-card{background:rgba(22,22,22,0.85);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(200,149,108,0.2);border-radius:16px;padding:40px 32px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,0.5),inset 0 1px 0 rgba(255,255,255,0.03)}
.login-icon{font-size:3rem;margin-bottom:12px;animation:float 3s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
.login-card h1{font-size:1.5rem;font-weight:700;color:var(--accent-light);margin-bottom:4px}
.login-card .subtitle{font-size:0.8rem;color:var(--text-dim);margin-bottom:32px}
.form-group{margin-bottom:18px;text-align:left}
.form-group label{display:block;font-size:0.75rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);margin-bottom:6px}
.form-group input{width:100%;background:rgba(30,30,30,0.8);border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:8px;font-size:0.9rem;font-family:'JetBrains Mono',monospace;outline:none;transition:border-color 0.3s,box-shadow 0.3s}
.form-group input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(200,149,108,0.15)}
.btn-login{width:100%;background:linear-gradient(135deg,#c8956c,#b8845a);color:#fff;border:none;padding:12px;border-radius:8px;font-size:0.95rem;font-weight:600;cursor:pointer;transition:all 0.3s;margin-top:8px;position:relative;overflow:hidden}
.btn-login::before{content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.15),transparent);transition:left 0.5s}
.btn-login:hover::before{left:100%}
.btn-login:hover{opacity:0.92;transform:translateY(-1px);box-shadow:0 4px 15px rgba(200,149,108,0.3)}
.error-msg{background:rgba(248,113,113,0.1);border:1px solid rgba(248,113,113,0.3);color:var(--red);padding:10px 14px;border-radius:8px;font-size:0.82rem;margin-bottom:18px;animation:shake 0.4s ease}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-4px)}75%{transform:translateX(4px)}}
.footer-text{margin-top:24px;font-size:0.7rem;color:var(--text-dim)}
</style>
</head>
<body>
<canvas id="bg-canvas"></canvas>
<div class="login-container">
  <div class="login-card">
    <div class="login-icon">☕</div>
    <h1>J.A.R.V.I.S</h1>
    <div class="subtitle">Server Dashboard — Authentication Required</div>
    {% if error %}
    <div class="error-msg">⚠️ {{ error }}</div>
    {% endif %}
    <form method="POST" action="/login">
      <div class="form-group">
        <label>Username</label>
        <input type="text" name="username" placeholder="Enter username" required autofocus>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter password" required>
      </div>
      <button type="submit" class="btn-login">Sign In →</button>
    </form>
    <div class="footer-text">Secure access • All sessions logged</div>
  </div>
</div>
</body>
</html>"""

# ── Main Dashboard Template (With the dropdown added inside dashboard content) ──
TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>☕ J.A.R.V.I.S — Server Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
<div class="header">
  <div class="header-left">
    <span style="font-size:1.5rem">☕</span>
    <div><h1>J.A.R.V.I.S Dashboard</h1><div class="subtitle" id="hostname">Server Monitoring Dashboard</div></div>
  </div>
  <div class="header-right">
    <span id="clock">--:--:--</span>
    <a href="#" onclick="switchTab('profile',document.querySelector('.tab:last-child'))">👤 Profile</a>
    <a href="/logout">🚪 Logout</a>
  </div>
</div>
<div class="tabs">
  <div class="tab active" onclick="switchTab('overview',this)">📊 Overview</div>
  <div class="tab" onclick="switchTab('processes',this)">⚡ Processes</div>
  <div class="tab" onclick="switchTab('docker',this)">🐳 Docker</div>
  <div class="tab" id="network-tab-btn" onclick="switchTab('network',this)">🌐 Network</div>
  <div class="tab" onclick="switchTab('disks',this)">💾 Disks</div>
  <div class="tab" onclick="switchTab('security',this)">🔒 Security</div>
  <div class="tab" onclick="switchTab('alerts',this)">🔔 Alert Settings</div>
    <div class="tab" onclick="switchTab('dockerhealth',this)">🩺 Docker Health</div>
  <div class="tab" onclick="switchTab('logs',this)">📋 Logs</div>
  <div class="tab" onclick="switchTab('profile',this)">👤 Profile</div>
</div>
<div class="content">

<div class="scope-selector-container">
  <label for="metrics-scope-target">🖥️ SCOPE TARGET TARGET LAYER:</label>
  <select id="metrics-scope-target" onchange="onScopeTargetChanged()">
    <option value="main_server">Main Host Server Node (Default)</option>
  </select>
</div>

<div id="tab-overview" class="tab-content active">
  <div class="stats-grid">
    <div class="stat-card">
      <div class="label" id="cpu-card-title">CPU Usage</div>
      <div class="value" id="cpu-val" style="color:var(--green)">0%</div>
      <div class="bar"><div class="bar-fill" id="cpu-bar" style="width:0%;background:var(--green)"></div></div>
      <div class="sub" id="cpu-cores">-- cores</div>
      <div class="core-bars" id="core-bars"></div>
    </div>
    <div class="stat-card">
      <div class="label" id="mem-card-title">Memory</div>
      <div class="value" id="mem-val" style="color:var(--blue)">0%</div>
      <div class="bar"><div class="bar-fill" id="mem-bar" style="width:0%;background:var(--blue)"></div></div>
      <div class="sub" id="mem-detail">-- / --</div>
    </div>
    <div class="stat-card">
      <div class="label" id="disk-card-title">Disk (/)</div>
      <div class="value" id="disk-val" style="color:var(--purple)">0%</div>
      <div class="bar"><div class="bar-fill" id="disk-bar" style="width:0%;background:var(--purple)"></div></div>
      <div class="sub" id="disk-detail">-- / --</div>
    </div>
    <div class="stat-card">
      <div class="label">Uptime</div>
      <div class="value" id="uptime-val" style="font-size:1.2rem;color:var(--orange)">--</div>
      <div class="sub" id="boot-time">Boot: --</div>
    </div>
    <div class="stat-card">
      <div class="label">Load Average</div>
      <div class="value" id="load-val" style="font-size:1.2rem;color:var(--yellow)">--</div>
      <div class="sub">1 / 5 / 15 min</div>
    </div>
  </div>
  <div class="charts-row">
    <div class="chart-card"><h3 id="cpu-chart-title">📈 CPU History (60s)</h3><div class="chart-container"><canvas id="cpuChart"></canvas></div></div>
    <div class="chart-card"><h3 id="mem-chart-title">📈 Memory History (60s)</h3><div class="chart-container"><canvas id="memChart"></canvas></div></div>
  </div>
  <div class="two-col">
    <div class="table-card">
      <div class="table-header"><h3>🐳 Docker Containers</h3><span class="badge" id="docker-count">0</span></div>
      <div class="table-wrapper">
        <table><thead><tr><th>Name</th><th>Status</th><th>CPU</th><th>Mem</th></tr></thead><tbody id="docker-overview"></tbody></table>
      </div>
    </div>
    <div class="table-card">
      <div class="table-header"><h3>🌐 Listening Ports</h3><span class="badge" id="port-count">0</span></div>
      <div class="table-wrapper">
        <table><thead><tr><th>Port</th><th>Process</th><th>PID</th></tr></thead><tbody id="ports-overview"></tbody></table>
      </div>
    </div>
  </div>
</div>

<div id="tab-processes" class="tab-content">
  <div class="table-card">
    <div class="table-header">
      <h3>⚡ Running Processes (htop-style)</h3>
      <div style="display:flex;gap:8px;align-items:center">
        <input type="text" id="proc-search" placeholder="Search name, pid, cmd..." oninput="filterProcs()"
               style="background:var(--bg4);border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:6px;font-size:0.78rem;font-family:'JetBrains Mono',monospace;outline:none;width:220px">
        <span class="badge" id="proc-count">0 procs</span>
      </div>
    </div>
    <div class="table-wrapper">
      <table><thead><tr><th>PID</th><th>User</th><th>CPU%</th><th>MEM%</th><th>RSS</th><th>Status</th><th>Thr</th><th>Command</th></tr></thead>
      <tbody id="proc-table"></tbody></table>
    </div>
  </div>
</div>

<div id="tab-docker" class="tab-content">
  <div class="table-card">
    <div class="table-header"><h3>🐳 Docker Containers</h3><span class="badge" id="docker-full-count">0</span></div>
    <div class="table-wrapper">
      <table><thead><tr><th>ID</th><th>Name</th><th>Image</th><th>Status</th><th>Ports</th><th>CPU</th><th>Memory</th><th>Net I/O</th><th>Block I/O</th></tr></thead>
      <tbody id="docker-table"></tbody></table>
    </div>
  </div>
</div>

<div id="tab-network" class="tab-content">
  <div class="stats-grid">
    <div class="stat-card"><div class="label">Bytes Sent</div><div class="value" id="net-sent" style="font-size:1.2rem;color:var(--green)">--</div></div>
    <div class="stat-card"><div class="label">Bytes Received</div><div class="value" id="net-recv" style="font-size:1.2rem;color:var(--blue)">--</div></div>
    <div class="stat-card"><div class="label">Packets Sent / Err</div><div class="value" id="net-pkts-sent" style="font-size:1.1rem;color:var(--purple)">--</div></div>
    <div class="stat-card"><div class="label">Packets Received / Err</div><div class="value" id="net-pkts-recv" style="font-size:1.1rem;color:var(--cyan)">--</div></div>
    <div class="stat-card"><div class="label">Active TCP Sockets</div><div class="value" id="net-conns" style="font-size:1.2rem;color:var(--orange)">--</div></div>
  </div>
  
  <div class="two-col" style="grid-template-columns: 1fr 2fr; gap: 20px; align-items: start; margin-top:14px;">
    <div class="stat-card" style="background:var(--bg2);">
      <div class="label" style="color:var(--accent-light); font-weight:700; margin-bottom:12px;">Link New Downstream Asset</div>
      <form action="/api/network/server/add" method="POST">
        <div style="margin-bottom:10px;">
          <label style="display:block; font-size:0.7rem; color:var(--text-dim); margin-bottom:4px;">SERVER IDENTIFIER / NAME</label>
          <input type="text" name="name" placeholder="e.g. Production-Database-01" required style="width:100%;">
        </div>
        <div style="margin-bottom:14px;">
          <label style="display:block; font-size:0.7rem; color:var(--text-dim); margin-bottom:4px;">IP ADDRESS / TARGET URL</label>
          <input type="text" name="ip" placeholder="e.g. 192.168.1.100" required style="width:100%;">
        </div>
        <button type="submit" style="width:100%;">Register Server Target</button>
      </form>
    </div>

    <div class="table-card" style="margin-bottom:0;">
      <div class="table-header"><h3>🔗 Infrastructure Topology Ledger</h3></div>
      <div id="topology-drilldown-container" style="padding:14px; display:flex; flex-direction:column; gap:10px;"></div>
    </div>
  </div>

  <div class="table-card" style="margin-top:14px">
    <div class="table-header"><h3>🌐 Listening Ports</h3></div>
    <div class="table-wrapper"><table><thead><tr><th>Address</th><th>PID</th><th>Process</th></tr></thead><tbody id="net-ports-table"></tbody></table></div>
  </div>
</div>

<div id="tab-disks" class="tab-content">
  <div class="table-card">
    <div class="table-header"><h3>💾 Disk Partitions</h3></div>
    <table><thead><tr><th>Device</th><th>Mount</th><th>Type</th><th>Total</th><th>Used</th><th>Free</th><th>Usage</th></tr></thead><tbody id="disk-table"></tbody></table>
  </div>
  <div class="table-card" style="margin-top:14px">
    <div class="table-header"><h3>📊 Disk I/O</h3></div>
    <div style="padding:18px;font-family:'JetBrains Mono',monospace;font-size:0.82rem" id="disk-io">Loading...</div>
  </div>
</div>

<div id="tab-security" class="tab-content">
  <div class="stats-grid">
    <div class="stat-card"><div class="label">Failed SSH (1h)</div><div class="value" id="sec-ssh" style="color:var(--green)">0</div></div>
    <div class="stat-card"><div class="label">Open Ports (external)</div><div class="value" id="sec-ports" style="color:var(--yellow)">0</div></div>
    <div class="stat-card"><div class="label">Upgradable Packages</div><div class="value" id="sec-updates" style="color:var(--blue)">--</div></div>
    <div class="stat-card"><div class="label">Firewall</div><div class="value" id="sec-firewall" style="font-size:0.9rem;color:var(--green)">--</div></div>
  </div>
  <div class="table-card" style="margin-top:14px">
    <div class="table-header"><h3>🔑 Recent Logins</h3></div>
    <div id="sec-logins" style="padding:14px 18px;font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:var(--text-dim)">Loading...</div>
  </div>
  <div class="table-card" style="margin-top:14px">
    <div class="table-header"><h3>🌐 External Ports</h3></div>
    <div id="sec-ext-ports" style="padding:14px 18px;font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:var(--text-dim)">Loading...</div>
  </div>
</div>

<div id="tab-alerts" class="tab-content">
  <div class="two-col" style="grid-template-columns: 1fr 2fr;">
    <div class="stat-card">
      <div class="label" style="color:var(--accent-light); font-weight:700; margin-bottom:12px;">Create Threshold Boundary</div>
      <form action="/api/alerts/add" method="POST">
        <input type="hidden" name="target_scope" id="alert-form-hidden-target" value="main_server">
        <div style="margin-bottom:10px;">
          <label style="display:block; font-size:0.7rem;">TARGET NODE SCOPE</label>
          <select name="server_id" style="width:100%;"><option value="local_master">Local Master</option><option value="all">Global Matrix</option></select>
        </div>
        <div style="margin-bottom:10px;">
          <label style="display:block; font-size:0.7rem;">METRIC CHANNEL</label>
          <select name="metric" style="width:100%;">
            <option value="cpu_percent">CPU Usage (%)</option>
            <option value="mem_percent">Memory Usage (%)</option>
            <option value="disk_percent">Disk Capacity Used (%)</option>
            <option value="active_connections">Active TCP Connections (count)</option>
            <option value="net_throughput_kb_per_sec">Network I/O Throughput (KB/s)</option>
            <option value="net_errors_total">Network Errors + Drops (count)</option>
          </select>
        </div>
        <div style="margin-bottom:10px;">
          <label style="display:block; font-size:0.7rem;">CONDITION</label>
          <select name="condition" style="width:100%;">
            <option value="greater_than">Greater Than (&gt;)</option>
            <option value="less_than">Less Than (&lt;)</option>
            <option value="equal_to">Equal To (==)</option>
          </select>
        </div>
        <div style="margin-bottom:14px;">
          <label style="display:block; font-size:0.7rem;">THRESHOLD VALUE</label>
          <input type="number" step="any" name="value" placeholder="e.g. 85 for %, 500 for count/KB" required style="width:100%;">
        </div>
        <button type="submit" style="width:100%;">Save Alert Rule</button>
      </form>
    </div>
    <div class="table-card">
      <div class="table-header"><h3>Active System Threshold Constraints</h3></div>
      <table>
        <thead><tr><th>ID</th><th>Server Scope</th><th>Target Scope</th><th>Metric</th><th>Condition</th><th>Limit</th><th>Operations</th></tr></thead>
        <tbody id="manual-alerts-registry-table"></tbody>
      </table>
    </div>
  </div>
</div>

<div id="tab-logs" class="tab-content">
  <div class="table-card">
    <div class="table-header"><h3>📋 Recent System Logs (Warning+)</h3></div>
    <div id="log-entries" style="max-height:800px;overflow-y:auto">Loading...</div>
  </div>
</div>

<div id="tab-dockerhealth" class="tab-content">
  <div class="table-card">
    <div class="table-header"><h3>🩺 Docker Container Health</h3></div>
    <div class="table-wrapper">
      <table><thead><tr><th>ID</th><th>Name</th><th>Image</th><th>Status</th><th>Health</th><th>Restarts</th><th>Uptime</th><th>Ports</th></tr></thead>
      <tbody id="docker-health-table"></tbody></table>
    </div>
  </div>
</div>

<div id="tab-profile" class="tab-content">
  <div class="stats-grid">
    <div class="stat-card">
      <div class="label">Current User</div>
      <div class="value" id="profile-user" style="font-size:1.2rem;color:var(--accent-light)">admin</div>
      <div class="sub">Authenticated session</div>
    </div>
    <div class="stat-card">
      <div class="label">Current IP</div>
      <div class="value" id="profile-ip" style="font-size:1.2rem;color:var(--cyan)">--</div>
      <div class="sub" id="profile-location">Detecting location...</div>
    </div>
    <div class="stat-card">
      <div class="label">Browser</div>
      <div class="value" id="profile-browser" style="font-size:0.9rem;color:var(--purple)">--</div>
      <div class="sub" id="profile-os">Detecting...</div>
    </div>
    <div class="stat-card">
      <div class="label">Session Started</div>
      <div class="value" id="profile-session-start" style="font-size:1rem;color:var(--orange)">--</div>
      <div class="sub">Login time</div>
    </div>
  </div>
  <div class="table-card" style="margin-top:14px">
    <div class="table-header"><h3>📜 Login / Logout History</h3><span class="badge" id="session-count">0 sessions</span></div>
    <div class="table-wrapper">
      <table class="session-table"><thead><tr><th>#</th><th>Action</th><th>IP Address</th><th>Location</th><th>Browser</th><th>OS</th><th>Time</th></tr></thead>
      <tbody id="session-table"></tbody></table>
    </div>
  </div>
</div>

</div>
<script src="{{ url_for('static', filename='script.js') }}"></script>
<script>
  // FIX: Auto-switch to network tab if redirected back after adding a server.
  // The server-add form POSTs to /api/network/server/add which redirects to /?tab=network.
  (function() {
    const params = new URLSearchParams(window.location.search);
    const tab = params.get('tab');
    if (tab) {
      const tabBtn = document.getElementById(tab + '-tab-btn');
      if (tabBtn) {
        // Use setTimeout to ensure script.js switchTab is available
        setTimeout(function() { switchTab(tab, tabBtn); }, 0);
      }
      // Clean the URL so refresh doesn't re-trigger the switch
      window.history.replaceState({}, document.title, '/');
    }
  })();
</script>
</body>
</html>"""

# ── Routes ───────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == AUTH_USER and password == AUTH_PASS:
            session['logged_in'] = True
            session['user'] = username
            session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            session['ip'] = request.remote_addr
            session['user_agent'] = request.headers.get('User-Agent', '')

            ip = request.remote_addr
            ua = request.headers.get('User-Agent', '')
            browser, os_info = parse_user_agent(ua)
            location = get_location_from_ip(ip)
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logger.info(f"Login successful — user '{username}' from {ip} ({location})")

            with session_lock:
                sessions = load_sessions()
                sessions.append({
                    "action": "login", "ip": ip, "location": location,
                    "browser": browser, "os": os_info, "time": now,
                })
                save_sessions(sessions)

            return redirect(url_for('index'))
        else:
            logger.info(f"Login failed — invalid credentials from {request.remote_addr}")
            return render_template_string(LOGIN_TEMPLATE, error="Invalid username or password")
    return render_template_string(LOGIN_TEMPLATE, error=None)

@app.route('/logout')
def logout():
    if session.get('logged_in'):
        ip = request.remote_addr
        ua = request.headers.get('User-Agent', '')
        browser, os_info = parse_user_agent(ua)
        location = get_location_from_ip(ip)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logger.info(f"Logout — user '{session.get('user', 'unknown')}' from {ip} ({location})")


        with session_lock:
            sessions = load_sessions()
            sessions.append({
                "action": "logout", "ip": ip, "location": location,
                "browser": browser, "os": os_info, "time": now,
            })
            save_sessions(sessions)

    session.clear()
    return redirect(url_for('login_page'))

@app.route('/')
@login_required
def index():
    return render_template_string(TEMPLATE)

@app.route('/api/all')
@login_required
def api_all():
    import platform
    target = request.args.get('target', 'main_server')
    registered_servers = network_manager.load_registered_servers()
    is_remote = any(s["name"] == target for s in registered_servers)

    cpu_percent = psutil.cpu_percent(interval=None)
    cpu_per_core = psutil.cpu_percent(percpu=True, interval=None)
    cpu_cores = psutil.cpu_count()
    
    try:
        freq = psutil.cpu_freq()
        cpu_freq = round(freq.current) if freq else 'N/A'
    except Exception:
        cpu_freq = 'N/A'

    cpu_history.append(cpu_percent)
    cpu_history_list = list(cpu_history)

    mem = psutil.virtual_memory()
    mem_history.append(mem.percent)
    mem_history_list = list(mem_history)

    disk = psutil.disk_usage('/')
    uptime_s = time.time() - psutil.boot_time()
    boot_ts = datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')

    try:
        load_avg = list(os.getloadavg())
    except OSError:
        load_avg = [0, 0, 0]

    hostname = socket.gethostname()
    plat = platform.platform()

    try:
        dio = psutil.disk_io_counters()
        disk_io_read = bytes_human(dio.read_bytes) if dio else 'N/A'
        disk_io_write = bytes_human(dio.write_bytes) if dio else 'N/A'
    except Exception:
        disk_io_read = disk_io_write = 'N/A'

   
    with cache_lock:
        docker_data = cached["docker"]
        security_data = cached["security"]
        logs_data = cached["logs"]
        app_logs_data = cached.get("app_logs", [])


    with microburst_lock:
        burst_stats = network_high_water_marks.copy()

    container_trends = {}
    with container_history_lock:
        for k, v in container_history_cache.items():
            container_trends[k] = {
                "cpu_history": list(v["cpu"]),
                "mem_history": list(v["mem"])
            }

    # Extract our newly defined high-fidelity telemetry block natively from network_manager
    if is_remote:
        net_metrics = {
        "throughput_sent": "N/A",
        "throughput_recv": "N/A",
        "errors_rx": "N/A",
        "errors_tx": "N/A",
        "drops_rx": "N/A",
        "drops_tx": "N/A",
        "active_connections": "N/A",
    }
    else:
        net_metrics = network_manager.get_scoped_network_metrics(target=target)

    if is_remote:
        scoped_procs = []
    else:
        scoped_procs = get_processes(80, target=target)

    if is_remote:
        scoped_disks = []
    else:
        scoped_disks = get_disk_partitions(target=target)

    if target != "main_server":
        disk_io_read = "N/A"
        disk_io_write = "N/A"

    try:
        raw_rx_err = int(net_metrics.get("errors_rx", 0)) if isinstance(net_metrics.get("errors_rx"), int) else 0
        raw_tx_err = int(net_metrics.get("errors_tx", 0)) if isinstance(net_metrics.get("errors_tx"), int) else 0
        raw_rx_drop = int(net_metrics.get("drops_rx", 0)) if isinstance(net_metrics.get("drops_rx"), int) else 0
        raw_tx_drop = int(net_metrics.get("drops_tx", 0)) if isinstance(net_metrics.get("drops_tx"), int) else 0
        total_network_errors = raw_rx_err + raw_tx_err + raw_rx_drop + raw_tx_drop
    except Exception:
        total_network_errors = 0

    external_metrics = None
    if target != "main_server":

        with cache_lock:
            matched_container = next((c for c in cached["docker"] if c["name"] == target), None)
        
        if matched_container:
            try:
                c_cpu = float(str(matched_container.get("cpu", "0")).replace("%","").strip())
                c_mem = float(str(matched_container.get("mem_perc", "0")).replace("%","").strip())

                raw_io = matched_container.get("net_io", "0B / 0B")
                kb_match = re.findall(r'([\d.]+)\s*(KB|MB|B)', raw_io, re.IGNORECASE)
                total_kb_speed = 0.0
                for val, unit in kb_match:
                    v = float(val)
                    if 'mb' in unit.lower(): v *= 1024
                    elif 'b' in unit.lower() and 'kb' not in unit.lower(): v /= 1024
                    total_kb_speed += v
            except Exception:
                c_cpu, c_mem, total_kb_speed = 0.0, 0.0, 0.0

            container_metrics = {
                "cpu_percent": c_cpu,
                "mem_percent": c_mem,
                "disk_percent": float(scoped_disks[0]["percent"]) if scoped_disks else 0.0,
                "net_throughput_kb_per_sec": total_kb_speed,
                "net_errors_total": float(total_network_errors)
            }
            alert.evaluate_metrics("local_master", container_metrics, target_scope=target)
        else:
            # Not a Docker container — check if it's a registered external server,
            # and if so, pull real CPU/Mem from Prometheus node_exporter data.
            registered_servers = network_manager.load_registered_servers()
            srv_record = next((s for s in registered_servers if s["name"] == target), None)
            if srv_record:
                external_metrics = network_manager.query_prometheus_host_metrics(srv_record["ip"])

                if external_metrics:

                    container_metrics = {
                        "cpu_percent": external_metrics["cpu_percent"] or 0.0,
                        "mem_percent": external_metrics["memory_percent"] or 0.0,
                        "disk_percent": external_metrics["disk_percent"] or 0.0,
                        "net_throughput_kb_per_sec":
                            (external_metrics["network_receive"] or 0.0) +
                            (external_metrics["network_transmit"] or 0.0),
                        "net_errors_total": float(total_network_errors)
                    }

                    alert.evaluate_metrics(
                        "local_master",
                        container_metrics,
                        target_scope=target
                    )

                    # FIX: net_metrics was hard-set to "N/A" placeholders above
                    # (is_remote branch) and nothing ever overwrote it with the
                    # real Prometheus values — that's why Bytes Sent/Received
                    # never updated, even though network_receive/transmit were
                    # being queried correctly the whole time.
                    net_metrics["throughput_recv"] = network_manager.bytes_human(external_metrics["network_receive"] or 0.0) + "/s"
                    net_metrics["throughput_sent"] = network_manager.bytes_human(external_metrics["network_transmit"] or 0.0) + "/s"

                    # FIX: scoped_disks was hard-set to [] for any is_remote
                    # target, so the Disks tab stayed empty. We do have
                    # disk_percent from Prometheus, so surface at least that —
                    # total/used/free stay "N/A" since there's no PromQL query
                    # yet for node_filesystem_size_bytes / node_filesystem_avail_bytes.
                    scoped_disks = [{
                        "device": "Prometheus", "mountpoint": "/",
                        "fstype": "N/A", "total": "N/A", "used": "N/A", "free": "N/A",
                        "percent": round(external_metrics["disk_percent"] or 0.0, 1)
                    }]

                else:
                    print("Prometheus returned None")
    
    
    else:
        try:
            host_kb_speed = (network_high_water_marks["max_sent_bps_100ms"] + network_high_water_marks["max_recv_bps_100ms"]) / 1024.0
        except Exception:
            host_kb_speed = 0.0

        host_metrics = {
            "cpu_percent": cpu_percent,
            "mem_percent": round(mem.percent, 1),
            "disk_percent": float(disk.percent),
            "net_throughput_kb_per_sec": host_kb_speed,
            "net_errors_total": float(total_network_errors)
        }
        alert.evaluate_metrics("local_master", host_metrics, target_scope="main_server")
        
    return jsonify({
        "cpu_percent": cpu_percent, 
        "cpu_per_core": cpu_per_core, 
        "cpu_cores": cpu_cores,
        "cpu_freq": cpu_freq, 
        "cpu_history": cpu_history_list, 
        "mem_percent": round(mem.percent, 1),
        "mem_used": round(mem.used / (1024**3), 2), 
        "mem_total": round(mem.total / (1024**3), 2),
        "mem_available": round(mem.available / (1024**3), 2), 
        "mem_history": mem_history_list,
        "disk_percent": disk.percent, 
        "disk_used": round(disk.used / (1024**3), 2),
        "disk_total": round(disk.total / (1024**3), 2), 
        
        # Mapped to high-fidelity network scopes
        "net_sent_human": net_metrics["throughput_sent"],
        "net_recv_human": net_metrics["throughput_recv"], 
        "net_errors_rx": f"{net_metrics['errors_rx']} errs" if isinstance(net_metrics['errors_rx'], int) else net_metrics['errors_rx'],
        "net_errors_tx": f"{net_metrics['errors_tx']} errs" if isinstance(net_metrics['errors_tx'], int) else net_metrics['errors_tx'],
        "net_drops_rx": f"{net_metrics['drops_rx']} drops" if isinstance(net_metrics['drops_rx'], int) else net_metrics['drops_rx'],
        "net_drops_tx": f"{net_metrics['drops_tx']} drops" if isinstance(net_metrics['drops_tx'], int) else net_metrics['drops_tx'],
        "active_connections": net_metrics["active_connections"],
        
        "uptime_human": seconds_human(uptime_s),
        "boot_time": boot_ts, 
        "load_avg": [round(l, 2) for l in load_avg], 
        "hostname": hostname,
        "platform": plat, 
         "docker": docker_data,
        "registered_servers": network_manager.load_registered_servers(),
        "external_server_metrics":
          external_metrics if external_metrics else {},
        "listening": get_network_connections(),
        "processes": scoped_procs,          
        "disks": scoped_disks,              
        "disk_io_read": disk_io_read, 
        "disk_io_write": disk_io_write,
        "security": security_data, 
        "logs": logs_data,
        "app_logs": app_logs_data,
        "interface_hardware_errors": get_hardware_interface_errors(),
        "microburst_peak_sent_bps": bytes_human(burst_stats["max_sent_bps_100ms"]) + "/s",
        "microburst_peak_recv_bps": bytes_human(burst_stats["max_recv_bps_100ms"]) + "/s",
        "container_historical_trends": container_trends
    })

@app.route('/api/network/topology')
@login_required
def api_network_topology():
    target = request.args.get('target', 'main_server')

    # Compute host speeds ONCE here — get_network_speeds() is a differential counter.
    # Calling it twice in the same request resets the baseline mid-flight and the
    # second call always returns ~0 B/s because elapsed≈0 and byte-delta≈0.
    speeds = network_manager.get_network_speeds()
    host_sent = network_manager.bytes_human(speeds["sent_speed"]) + "/s"
    host_recv = network_manager.bytes_human(speeds["recv_speed"]) + "/s"

    if target != "main_server":
        with cache_lock:
            docker_names = {c["name"] for c in cached.get("docker", [])}

        if target in docker_names:
            # Genuine Docker container — read its isolated network namespace
            net_metrics = network_manager.get_scoped_network_metrics(target=target)
            scope_latency = "0.1"
            scope_loss = 0
            scope_sent = net_metrics["throughput_sent"]
            scope_recv = net_metrics["throughput_recv"]
        else:
            # Registered server — reuse the already-computed host speeds (no second call).
            # Look up the stored IP and probe it for a real latency reading.
            scope_sent = host_sent
            scope_recv = host_recv
            registered_servers = network_manager.load_registered_servers()
            srv_record = next((s for s in registered_servers if s["name"] == target), None)
            if srv_record:
                srv_ip = srv_record["ip"]
                port_match = re.search(r':(\d+)', srv_ip)
                probe_port = int(port_match.group(1)) if port_match else 80
                clean_host = re.sub(r'https?://', '', srv_ip.split(':')[0]).strip('/')
                srv_perf = network_manager.probe_local_tcp_latency(clean_host, port=probe_port)
                scope_latency = srv_perf["latency_avg_ms"]
                scope_loss = srv_perf["packet_loss_percent"]

                # Prometheus is authoritative on up/down if it's scraping this host;
                # TCP probe stays as the latency reading since `up` has no RTT value.
                prom_status = network_manager.check_prometheus_status(clean_host)
                if prom_status is not None:
                    if prom_status["online"]:
                        scope_loss = 0
                        if scope_latency == "N/A": scope_latency = "0.0"
                    else:
                        scope_loss = 100
                        scope_latency = "N/A"
            else:
                scope_latency = "N/A"
                scope_loss = 100

        return jsonify([{
            "id": 999, "server_id": f"Scope: {target}", "ip_address": target,
            "latency_ms": scope_latency, "packet_loss_percent": scope_loss, "jitter_ms": "0.0",
            "bytes_sent_sec": scope_sent,
            "bytes_recv_sec": scope_recv,
            "containers": []
        }])
    # FIX: ICMP ping to 127.0.0.1 fails inside containers (no CAP_NET_RAW).
    # Use TCP socket probe against the dashboard's own port instead — always reachable.
    local_perf = network_manager.probe_local_tcp_latency("127.0.0.1", port=8010)
    
    topology_data = [{
        "id": 0, "server_id": "Local Master Server Node", "ip_address": socket.gethostname(),
        "latency_ms": local_perf["latency_avg_ms"],
        "packet_loss_percent": local_perf["packet_loss_percent"],
        "jitter_ms": local_perf["jitter_ms"],
        "bytes_sent_sec": bytes_human(speeds["sent_speed"]) + "/s",
        "bytes_recv_sec": bytes_human(speeds["recv_speed"]) + "/s", "containers": []
    }]
    
    with cache_lock:
        docker_cache = cached.get("docker", [])
    for container in docker_cache:
        topology_data[0]["containers"].append({"id": container["id"], "name": container["name"], "ip": "172.17.0.1", "io": container["net_io"]})

    registered_servers = network_manager.load_registered_servers()
    for srv in registered_servers:
        srv_ip = srv["ip"]
        srv_name = srv["name"]
        
        # 1. DYNAMIC LATENCY EVALUATION VIA ACTIVE SOCKET PROBING
        # Splits out custom port syntax if provided (e.g. "localhost:27017" or "127.0.0.1:27017")
        port_match = re.search(r':(\d+)', srv_ip)
        probe_port = int(port_match.group(1)) if port_match else 80
        clean_host = re.sub(r'https?://', '', srv_ip.split(':')[0]).strip('/')
        
        # FIX Bug A: Use probe_local_tcp_latency which tries multiple ports before
        # giving up. The old code only tried one port (defaulting to 80 when no port
        # was in the IP string) then fell back to ICMP ping — which also fails inside
        # containers without CAP_NET_RAW. probe_local_tcp_latency tries the user-
        # supplied port first, then 80/443/22, then ICMP as a last resort.
        srv_perf = network_manager.probe_local_tcp_latency(clean_host, port=probe_port)
        srv_latency = srv_perf["latency_avg_ms"]
        packet_loss = srv_perf["packet_loss_percent"]
        jitter = srv_perf["jitter_ms"]

        # FIX: Containers on isolated docker networks (e.g. a mock server with
        # no exposed port / no CAP_NET_RAW for ping) will always fail direct
        if packet_loss == 100 or srv_latency == "N/A":
            prom_status = network_manager.check_prometheus_status(clean_host)
            if prom_status is not None:
                if prom_status["online"]:
                    packet_loss = 0
                    if srv_latency == "N/A":
                        srv_latency = "0.0"
                else:
                    packet_loss = 100
                    srv_latency = "N/A"
         
        # 2. DYNAMIC NETWORK TELEMETRY ROUTING
        # If the registered server matches a running Docker container by name, use its
        # docker stats net_io. Otherwise use the host-level throughput — same source
        # the scope-dropdown view uses, so both views show consistent data.
        matched_container = next(
            (c for c in docker_cache if c["name"].lower() == srv_name.lower()), 
            None
        )

        if matched_container and matched_container.get("net_io"):
            raw_io = matched_container["net_io"]
            io_parts = raw_io.split("/")
            sent_speed = io_parts[0].strip() + "/s" if len(io_parts) > 0 else "0.0 B/s"
            recv_speed = io_parts[1].strip() + "/s" if len(io_parts) > 1 else "0.0 B/s"
        else:
            # Non-container registered server — reuse host speeds computed once at the
            # top of this function. A second call to get_network_speeds() resets the
            # differential baseline and always returns ~0 B/s.
            sent_speed = host_sent
            recv_speed = host_recv

        topology_data.append({
            "id": srv["id"], 
            "server_id": srv_name, 
            "ip_address": srv_ip,
            "latency_ms": srv_latency,
            "packet_loss_percent": packet_loss,
            "jitter_ms": jitter,
            "bytes_sent_sec": sent_speed, 
            "bytes_recv_sec": recv_speed, 
            "containers": []
        })
        
    return jsonify(topology_data)

@app.route('/api/network/server/add', methods=['POST'])
@login_required
def api_add_custom_server():
    name = request.form.get('name')
    ip = request.form.get('ip')
    if name and ip: 
        network_manager.add_server_node(name, ip)
        logger.info(f"Server registered — '{name}' ({ip})")

    
    return redirect('/?tab=network')

@app.route('/api/network/server/delete/<int:srv_id>', methods=['POST'])
@login_required
def api_delete_custom_server(srv_id):
    network_manager.delete_server_node(srv_id)
    logger.info(f"Server #{srv_id} removed")

    return redirect('/')

@app.route('/api/alerts/add', methods=['POST'])
@login_required
def api_add_threshold():
    target_scope = request.form.get('target_scope', 'main_server')
    metric = request.form.get('metric')
    condition = request.form.get('condition')
    value = request.form.get('value')
    alert.add_threshold_rule(
        request.form.get('server_id'), 
        metric, 
        condition, 
        value,
        target_scope=target_scope
    )
    logger.info(f"Alert rule created — {metric} {condition} {value} on scope '{target_scope}'")
    return redirect('/')
# ── ADD THIS ENDPOINT ANYWHERE AMONG YOUR ROUTES IN APP.PY ──
@app.route('/api/metrics/remote-cpu')
@login_required
def get_remote_cpu_metric():
    """
    Queries the local Prometheus container API directly over the virtual network 
    to extract the current value of the cross-server randomized CPU metric.
    """
    import requests
    try:
        # Querying Prometheus's official HTTP Instant Query API
        prom_url = "http://jarvis-prometheus:9090/api/v1/query"
        params = {'query': 'server_mock_cpu'}
        
        response = requests.get(prom_url, params=params, timeout=2)
        result = response.json()
        
        # Parse out the actual numeric metric value from the Prometheus JSON structure
        if result.get('status') == 'success' and result['data']['result']:
            current_value = result['data']['result'][0]['value'][1]
            return jsonify({"remote_cpu": int(current_value)})
            
        return jsonify({"remote_cpu": 0, "status": "No data returned yet"})
    except Exception as e:
        return jsonify({"remote_cpu": 0, "error": str(e)})
    
@app.route('/api/alerts/delete/<int:rule_id>', methods=['POST'])
@login_required
def api_delete_threshold(rule_id): 
    alert.delete_threshold_rule(rule_id)
    logger.info(f"Alert rule #{rule_id} deleted")

    return redirect('/')

@app.route('/api/alerts/list')
@login_required
def api_list_thresholds(): 
    return jsonify(alert.load_thresholds())

@app.route('/api/profile')
@login_required
def api_profile():
    ip = session.get('ip', request.remote_addr)
    ua = session.get('user_agent', request.headers.get('User-Agent', ''))
    browser, os_info = parse_user_agent(ua)
    location = get_location_from_ip(ip)

    with session_lock:
        sessions = load_sessions()

    return jsonify({
        "user": session.get('user', 'admin'), "ip": ip, "location": location,
        "browser": browser, "os": os_info, "session_start": session.get('login_time', '--'),
        "sessions": list(reversed(sessions[-50:])),
    })

def parse_user_agent(ua):
    ua_lower = ua.lower()
    browser, os_info = "Unknown", "Unknown"

    if "edg" in ua_lower: browser = "Microsoft Edge"
    elif "chrome" in ua_lower and "edg" not in ua_lower: browser = "Google Chrome"
    elif "firefox" in ua_lower: browser = "Firefox"
    elif "safari" in ua_lower and "chrome" not in ua_lower: browser = "Safari"

    if "windows" in ua_lower: os_info = "Windows"
    elif "macintosh" in ua_lower or "mac os" in ua_lower: os_info = "macOS"
    elif "linux" in ua_lower: os_info = "Linux"
    elif "android" in ua_lower: os_info = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower: os_info = "iOS"

    return browser, os_info

@app.route('/api/alerts/notifications')
@login_required
def api_get_notifications():
    """Dedicated lightweight endpoint for streaming real-time unread alert toasts."""
    return jsonify(alert.get_unread_notifications())


@app.route('/api/chatbot/chat', methods=['POST'])
@login_required
def chatbot_endpoint():
    """
    Ingestion routing node that receives JSON string text from script.js
    and passes it directly into the real LLM reasoning pipeline.
    """
    data = request.get_json() or {}
    user_message = data.get("message", "").strip()
    current_scope = data.get("scope")  # currently-selected dashboard target, if sent
    
    if not user_message:
        return jsonify({"response": "I didn't catch anything, broskii. Try typing a message!"})
        
    try:
        ai_reply = chatbot_agent.run_agent_pipeline(user_message, current_scope=current_scope)
        return jsonify({"response": ai_reply})
    except Exception as e:
        print(f"Core LLM routing engine execution failure: {e}")
        return jsonify({"response": "⚠️ Internal copilot agent encountered an operational hitch."})

# ── ADD THIS IN APP.PY AMONG YOUR CHAT ROUTES ──
@app.route('/api/chat/history', methods=['GET'])
@login_required # Remove this decorator if your dashboard doesn't use authentication yet
def get_ui_chat_history():
    """
    Invokes your agent's load function to pull past JSON chat logs 
    and serve them straight to the UI on a page refresh.
    """
    from chatbot_agent import load_chat_history
    try:
        history = load_chat_history()
        return jsonify({"status": "success", "history": history})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/chat/sessions', methods=['GET'])
@login_required
def get_chat_sessions_route():
    """Lists past chat conversations, most recent first, for a history sidebar."""
    from chatbot_agent import get_chat_sessions
    try:
        sessions = get_chat_sessions()
        return jsonify({"status": "success", "sessions": sessions})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/chat/session/<session_id>', methods=['GET'])
@login_required
def get_chat_session_messages_route(session_id):
    """Returns all messages belonging to one specific past chat session."""
    from chatbot_agent import get_session_messages
    try:
        messages = get_session_messages(session_id)
        return jsonify({"status": "success", "messages": messages})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

from werkzeug.exceptions import HTTPException

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    # FIX: HTTPException covers normal Flask flow control (404 Not Found,
    # 405 Method Not Allowed, etc.) — these aren't application bugs and
    # were previously being logged as full [ERROR] tracebacks, flooding
    # the Logs tab every time something hit a nonexistent route like
    # /metrics. Only genuine unhandled server errors get logged now.
    if isinstance(e, HTTPException):
        return e

    logger.exception(f"Unhandled exception on {request.method} {request.path}")
    return jsonify({"error": "Internal server error"}), 500

@app.route('/healthz')
def healthz():
    """Lightweight, unauthenticated endpoint for Docker's healthcheck to hit."""
    return jsonify({"status": "ok"}), 200

@app.route('/api/docker-status')
def docker_status():

    return jsonify(get_docker_containers())

def get_docker_containers():

    if not _DOCKER_SDK_OK or docker_client is None:
        return []

    try:
        containers = docker_client.containers.list(all=True)
    except Exception:
        logger.exception("Failed to list docker containers via SDK")
        return []

    container_data = []

    for c in containers:

        try:
            info = c.attrs
            state = info.get("State", {})

            # Docker health (if available)
            health = state.get("Health", {}).get("Status", "No Healthcheck")

            # Uptime
            started = state.get("StartedAt")

            try:
                started_time = datetime.fromisoformat(
                    started.replace("Z", "+00:00")
                )
                uptime = str(
                    datetime.now(timezone.utc) - started_time
                ).split(".")[0]
            except Exception:
                uptime = "-"

            # FIX: c.image.tags triggers a live Docker API lookup by image ID.
            # If that image was since removed/rebuilt (dangling reference),
            # this throws ImageNotFound and crashes the ENTIRE endpoint —
            # not just this one container's row. Fall back to the raw image
            # string from container config instead, which is always present
            # and never triggers a live lookup.
            try:
                image_name = c.image.tags[0] if c.image.tags else c.image.short_id
            except Exception:
                image_name = info.get("Config", {}).get("Image", "unknown")

            container_data.append({

                "id": c.short_id,

                "name": c.name,

                "image": image_name,

                "status": state.get("Status"),

                "health": health,

                "restart_count": info.get("RestartCount", 0),

                "uptime": uptime,

                "ports": info.get(
                    "NetworkSettings", {}
                ).get("Ports", {})

            })

        except Exception:
            # One bad container shouldn't blank out the whole table —
            # log it and skip, keep the rest of the data intact.
            logger.exception(f"Failed reading container info for {getattr(c, 'name', 'unknown')}")
            continue

    return container_data


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8010)