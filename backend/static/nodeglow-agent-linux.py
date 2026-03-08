#!/usr/bin/env python3
"""
Nodeglow Agent for Linux — lightweight system monitoring.

Collects CPU, memory, disk, network, load, uptime, and top processes.
Reports to your Nodeglow instance via HTTP. Zero dependencies (stdlib only).

Usage:
    python3 nodeglow-agent-linux.py --server http://nodeglow:8000 --token YOUR_TOKEN

    # Or via environment variables:
    NODEGLOW_SERVER=http://nodeglow:8000 NODEGLOW_TOKEN=YOUR_TOKEN python3 nodeglow-agent-linux.py

    # Install as systemd service:
    python3 nodeglow-agent-linux.py --install --server http://nodeglow:8000 --token YOUR_TOKEN
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

__version__ = "1.5.0"

import logging
import logging.handlers


def _setup_logging():
    """Set up file + console logging in the Nodeglow install dir."""
    if getattr(sys, 'frozen', False):
        log_dir = os.path.dirname(sys.executable)
    else:
        log_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(log_dir, "nodeglow-agent.log")
    logger = logging.getLogger("nodeglow")
    logger.setLevel(logging.DEBUG)
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(message)s", datefmt="%Y-%m-%d %H:%M:%S",
    ))
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[nodeglow-agent] %(message)s"))
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


log = _setup_logging()


# ── Collectors ───────────────────────────────────────────────────────────────

def get_cpu_percent():
    """Read /proc/stat twice to calculate CPU usage."""
    try:
        def read_stat():
            with open("/proc/stat") as f:
                parts = f.readline().split()
            vals = [int(x) for x in parts[1:]]
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            return idle, sum(vals)

        idle1, total1 = read_stat()
        time.sleep(0.5)
        idle2, total2 = read_stat()
        d_total = total2 - total1
        if d_total == 0:
            return 0.0
        return round((1.0 - (idle2 - idle1) / d_total) * 100, 1)
    except Exception:
        return None


def get_memory():
    """Parse /proc/meminfo for memory stats."""
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(":")] = int(parts[1])
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        used = total - avail
        total_mb = round(total / 1024, 1)
        used_mb = round(used / 1024, 1)
        pct = round(used / total * 100, 1) if total > 0 else 0
        swap_total = info.get("SwapTotal", 0)
        swap_free = info.get("SwapFree", 0)
        swap_used = swap_total - swap_free
        return {
            "total_mb": total_mb,
            "used_mb": used_mb,
            "pct": pct,
            "swap_total_mb": round(swap_total / 1024, 1),
            "swap_used_mb": round(swap_used / 1024, 1),
        }
    except Exception:
        return None


def get_disks():
    """Get mounted filesystem usage via /proc/mounts + os.statvfs."""
    disks = []
    skip_fs = {
        "proc", "sysfs", "devpts", "tmpfs", "cgroup", "cgroup2", "overlay",
        "squashfs", "devtmpfs", "securityfs", "pstore", "bpf", "tracefs",
        "debugfs", "hugetlbfs", "mqueue", "fusectl", "configfs", "autofs",
        "efivarfs", "ramfs", "nsfs", "fuse.lxcfs",
    }
    seen = set()
    mtab = "/proc/mounts" if os.path.exists("/proc/mounts") else "/etc/mtab"
    try:
        with open(mtab) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mount, fs = parts[0], parts[1], parts[2]
                if fs in skip_fs or mount.startswith(("/snap/", "/sys/", "/run/")):
                    continue
                if mount in seen:
                    continue
                seen.add(mount)
                try:
                    st = os.statvfs(mount)
                    total = st.f_blocks * st.f_frsize
                    free = st.f_bavail * st.f_frsize
                    if total == 0:
                        continue
                    used = total - free
                    disks.append({
                        "mount": mount,
                        "device": device,
                        "fs": fs,
                        "total_gb": round(total / 1073741824, 1),
                        "used_gb": round(used / 1073741824, 1),
                        "pct": round(used / total * 100, 1),
                    })
                except OSError:
                    pass
    except Exception:
        pass
    return disks


def get_load():
    """System load averages."""
    try:
        l1, l5, l15 = os.getloadavg()
        return {"load_1": round(l1, 2), "load_5": round(l5, 2), "load_15": round(l15, 2)}
    except Exception:
        return None


def get_uptime():
    """System uptime in seconds from /proc/uptime."""
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return None


def get_network():
    """Network I/O from /proc/net/dev (excludes lo)."""
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()[2:]
        rx = tx = 0
        interfaces = []
        for line in lines:
            parts = line.split()
            iface = parts[0].rstrip(":")
            if iface == "lo":
                continue
            iface_rx = int(parts[1])
            iface_tx = int(parts[9])
            rx += iface_rx
            tx += iface_tx
            interfaces.append({
                "name": iface,
                "rx_mb": round(iface_rx / 1048576, 1),
                "tx_mb": round(iface_tx / 1048576, 1),
            })
        return {
            "rx_bytes": rx, "tx_bytes": tx,
            "rx_mb": round(rx / 1048576, 1), "tx_mb": round(tx / 1048576, 1),
            "interfaces": interfaces,
        }
    except Exception:
        return None


def get_cpu_temp():
    """CPU temperature from thermal zones."""
    try:
        for i in range(10):
            path = f"/sys/class/thermal/thermal_zone{i}/temp"
            type_path = f"/sys/class/thermal/thermal_zone{i}/type"
            if os.path.exists(path):
                with open(type_path) as f:
                    zone_type = f.read().strip()
                if "cpu" in zone_type.lower() or "x86" in zone_type.lower() or i == 0:
                    with open(path) as f:
                        return round(int(f.read().strip()) / 1000, 1)
    except Exception:
        pass
    return None


def get_top_processes(n=10):
    """Top N processes by CPU via ps."""
    procs = []
    try:
        out = subprocess.check_output(
            ["ps", "aux", "--sort=-pcpu"], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.strip().splitlines()[1:n + 1]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({
                    "user": parts[0], "pid": int(parts[1]),
                    "cpu": float(parts[2]), "mem": float(parts[3]),
                    "cmd": parts[10][:100],
                })
    except Exception:
        pass
    return procs


def get_docker_containers():
    """List running Docker containers if docker is available."""
    containers = []
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}"],
            stderr=subprocess.DEVNULL, text=True, timeout=5,
        )
        for line in out.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                containers.append({"name": parts[0], "status": parts[1], "image": parts[2]})
    except Exception:
        pass
    return containers


# ── Log collector ───────────────────────────────────────────────────────────

# journalctl priority → syslog severity (same numbering)
_last_log_cursor = None  # journald cursor for dedup


def get_recent_logs(max_entries=200):
    """Collect recent system log entries via journalctl."""
    global _last_log_cursor

    cmd = [
        "journalctl", "--no-pager", "-o", "json",
        "-p", "warning",  # priority 0-4 (emerg..warning)
        "-n", str(max_entries),
    ]
    if _last_log_cursor:
        cmd += ["--after-cursor", _last_log_cursor]
    else:
        cmd += ["--since", "-60s"]

    logs = []
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return logs

        newest_cursor = None
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            priority = int(entry.get("PRIORITY", 6))
            ts_usec = entry.get("__REALTIME_TIMESTAMP")
            if ts_usec:
                ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ts_usec) / 1_000_000))
            else:
                ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            msg = entry.get("MESSAGE", "")
            if isinstance(msg, list):
                msg = " ".join(str(m) for m in msg)
            if len(msg) > 500:
                msg = msg[:500]

            logs.append({
                "timestamp": ts,
                "severity": priority,
                "app_name": entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM", ""),
                "message": msg,
                "facility": int(entry.get("SYSLOG_FACILITY", 1)),
            })

            newest_cursor = entry.get("__CURSOR")

        if newest_cursor:
            _last_log_cursor = newest_cursor

    except FileNotFoundError:
        # journalctl not available, try reading /var/log/syslog
        return _get_syslog_fallback()
    except Exception:
        pass

    return logs


def _get_syslog_fallback(max_lines=100):
    """Fallback: read recent lines from /var/log/syslog or /var/log/messages."""
    import re
    logs = []
    for path in ("/var/log/syslog", "/var/log/messages"):
        try:
            result = subprocess.run(
                ["tail", "-n", str(max_lines), path],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().splitlines():
                # Basic syslog line: "Mon DD HH:MM:SS hostname app[pid]: message"
                m = re.match(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\S+?)(?:\[\d+\])?:\s*(.*)", line)
                if m:
                    logs.append({
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "severity": 4,  # warning (conservative)
                        "app_name": m.group(2),
                        "message": m.group(3)[:500],
                        "facility": 1,
                    })
            if logs:
                break
        except Exception:
            continue
    return logs


def send_logs(server, token, hostname, logs):
    """Send collected logs to the server."""
    if not logs:
        return True
    url = f"{server.rstrip('/')}/api/agent/logs"
    payload = json.dumps({"hostname": hostname, "logs": logs}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 200
    except Exception as e:
        log.error("Log send error: %s", e)
        return False


def collect_all():
    """Collect all system metrics."""
    data = {
        "hostname": socket.gethostname(),
        "platform": "Linux",
        "platform_release": platform.release(),
        "arch": platform.machine(),
        "agent_version": __version__,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    cpu = get_cpu_percent()
    if cpu is not None:
        data["cpu_pct"] = cpu

    mem = get_memory()
    if mem:
        data["memory"] = mem

    disks = get_disks()
    if disks:
        data["disks"] = disks

    load = get_load()
    if load:
        data["load"] = load

    uptime = get_uptime()
    if uptime is not None:
        data["uptime_s"] = uptime

    network = get_network()
    if network:
        data["network"] = network

    temp = get_cpu_temp()
    if temp is not None:
        data["cpu_temp"] = temp

    procs = get_top_processes(8)
    if procs:
        data["processes"] = procs

    containers = get_docker_containers()
    if containers:
        data["docker_containers"] = containers

    return data


# ── Reporter ─────────────────────────────────────────────────────────────────

def send_metrics(server, token, data):
    """Send metrics to server. Returns (ok, server_config) tuple."""
    url = f"{server.rstrip('/')}/api/agent/report"
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                try:
                    resp_data = json.loads(resp.read())
                    return True, resp_data.get("config", {})
                except Exception:
                    return True, {}
            return False, {}
    except urllib.error.HTTPError as e:
        log.error("HTTP %d: %s", e.code, e.read().decode()[:200])
        return False, {}
    except Exception as e:
        log.error("Send error: %s", e)
        return False, {}


# ── Systemd installer ────────────────────────────────────────────────────────

SYSTEMD_UNIT = """[Unit]
Description=Nodeglow Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=NODEGLOW_SERVER={server}
Environment=NODEGLOW_TOKEN={token}
Environment=NODEGLOW_INTERVAL={interval}
ExecStart={python} {script}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""


def install_systemd(server, token, interval):
    if os.geteuid() != 0:
        log.error("--install requires root (use sudo)")
        sys.exit(1)

    script_path = os.path.abspath(__file__)
    python_path = sys.executable

    unit = SYSTEMD_UNIT.format(
        server=server, token=token, interval=interval,
        python=python_path, script=script_path,
    )

    unit_path = "/etc/systemd/system/nodeglow-agent.service"
    with open(unit_path, "w") as f:
        f.write(unit)

    os.system("systemctl daemon-reload")
    os.system("systemctl enable nodeglow-agent")
    os.system("systemctl start nodeglow-agent")
    log.info("Installed and started nodeglow-agent.service")
    log.info("  Config: %s", unit_path)
    log.info("  Status: systemctl status nodeglow-agent")
    log.info("  Logs:   journalctl -u nodeglow-agent -f")


# ── Auto-update ──────────────────────────────────────────────────────────────

def _get_own_hash():
    """SHA256 of our own script file."""
    path = os.path.abspath(__file__)
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""


def check_and_update(server):
    """Check server for a newer agent version; download + replace + restart if found."""
    try:
        url = f"{server.rstrip('/')}/api/agent/version/linux"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        remote_hash = data.get("hash", "")
        if not remote_hash:
            return False

        local_hash = _get_own_hash()
        if local_hash == remote_hash:
            return False

        log.info("Update available (local=%s... remote=%s...)", local_hash[:12], remote_hash[:12])

        # Download new version to temp file
        own_path = os.path.abspath(__file__)
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".py", dir=os.path.dirname(own_path))
        os.close(tmp_fd)

        try:
            download_url = f"{server.rstrip('/')}/agents/download/linux"
            urllib.request.urlretrieve(download_url, tmp_path)

            # Verify the download matches the expected hash
            with open(tmp_path, "rb") as f:
                dl_hash = hashlib.sha256(f.read()).hexdigest()
            if dl_hash != remote_hash:
                log.error("Download hash mismatch, aborting update")
                os.remove(tmp_path)
                return False

            # Replace: atomic rename
            os.chmod(tmp_path, 0o755)
            os.replace(tmp_path, own_path)

            log.info("Updated successfully, restarting...")

            # Restart via exec (replaces current process)
            os.execv(sys.executable, [sys.executable, own_path])

        except Exception as e:
            log.error("Update failed: %s", e)
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return False

    except Exception as e:
        log.error("Update check failed: %s", e)
        return False


# ── Config file support ───────────────────────────────────────────────────────

def _load_config_file():
    """Load config.json from next to the script."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

_file_config = _load_config_file()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Nodeglow Agent for Linux")
    parser.add_argument("--server", "-s", default=os.environ.get("NODEGLOW_SERVER", _file_config.get("server", "")))
    parser.add_argument("--token", "-t", default=os.environ.get("NODEGLOW_TOKEN", _file_config.get("token", "")))
    parser.add_argument("--interval", "-i", type=int, default=int(os.environ.get("NODEGLOW_INTERVAL", str(_file_config.get("interval", 30)))))
    parser.add_argument("--once", action="store_true", help="Report once and exit")
    parser.add_argument("--dry-run", action="store_true", help="Print metrics, don't send")
    parser.add_argument("--install", action="store_true", help="Install as systemd service")
    args = parser.parse_args()

    if args.dry_run:
        print(json.dumps(collect_all(), indent=2))
        return

    if not args.server:
        log.error("--server or NODEGLOW_SERVER required")
        sys.exit(1)
    if not args.token:
        log.error("--token or NODEGLOW_TOKEN required")
        sys.exit(1)

    if args.install:
        install_systemd(args.server, args.token, args.interval)
        return

    log.info("v%s | %s | Linux %s", __version__, socket.gethostname(), platform.release())
    log.info("reporting to %s every %ds", args.server, args.interval)
    log.info("auto-update check every 5 minutes")

    update_interval = 300  # 5 minutes
    last_update_check = 0

    log_interval = 60  # collect logs every 60 seconds
    last_log_send = 0
    server_log_levels = [1, 2, 3]  # default: Critical, Error, Warning

    while True:
        try:
            data = collect_all()
            ok, srv_config = send_metrics(args.server, args.token, data)
            if ok:
                log.info("OK cpu=%s%% mem=%s%% load=%s", data.get('cpu_pct', '?'), data.get('memory', {}).get('pct', '?'), data.get('load', {}).get('load_1', '?'))
                # Update log levels from server config
                if "log_levels" in srv_config:
                    try:
                        new_levels = [int(x) for x in srv_config["log_levels"].split(",") if x.strip()]
                        if new_levels != server_log_levels:
                            log.info("Log levels updated: %s", new_levels)
                        server_log_levels = new_levels
                    except Exception:
                        pass

            # Send logs less frequently than metrics
            now = time.time()
            if now - last_log_send >= log_interval:
                last_log_send = now
                try:
                    logs = get_recent_logs()
                    if logs:
                        lok = send_logs(args.server, args.token, socket.gethostname(), logs)
                        log.info("Logs: %d entries %s", len(logs), "sent" if lok else "FAILED")
                except Exception as e:
                    log.error("Log collect error: %s", e)

        except Exception as e:
            log.error("Main loop error: %s", e)
        if args.once:
            break

        # Check for updates every 5 minutes
        now = time.time()
        if now - last_update_check >= update_interval:
            last_update_check = now
            check_and_update(args.server)

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
