#!/usr/bin/env python3
"""
Nodeglow Agent for Windows — lightweight system monitoring.

Collects CPU, memory, disk, network, uptime, and top processes.
Reports to your Nodeglow instance via HTTP. Zero dependencies (stdlib only).

Usage:
    python nodeglow-agent-windows.py --server http://nodeglow:8000 --token YOUR_TOKEN

    # Or via environment variables:
    set NODEGLOW_SERVER=http://nodeglow:8000
    set NODEGLOW_TOKEN=YOUR_TOKEN
    python nodeglow-agent-windows.py

    # Install as Windows service (requires admin):
    python nodeglow-agent-windows.py --install --server http://nodeglow:8000 --token YOUR_TOKEN

Requires: Python 3.8+ (no additional packages needed)
"""
import argparse
import ctypes
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

__version__ = "1.2.0"


# ── WMI helpers via PowerShell ───────────────────────────────────────────────

def _ps(cmd, timeout=10):
    """Run a PowerShell command and return stdout."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _ps_json(cmd, timeout=10):
    """Run PowerShell command that outputs JSON."""
    raw = _ps(cmd + " | ConvertTo-Json -Compress", timeout)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


# ── Collectors ───────────────────────────────────────────────────────────────

def get_cpu_percent():
    """CPU usage via performance counter (sampled over 1 second)."""
    try:
        raw = _ps(
            "(Get-Counter '\\Processor(_Total)\\% Processor Time' -SampleInterval 1).CounterSamples[0].CookedValue"
        )
        return round(float(raw), 1)
    except Exception:
        pass
    # Fallback: wmic
    try:
        out = subprocess.check_output(
            ["wmic", "cpu", "get", "loadpercentage"], text=True, timeout=5,
            stderr=subprocess.DEVNULL, creationflags=0x08000000,
        )
        for line in out.strip().splitlines()[1:]:
            line = line.strip()
            if line:
                return float(line)
    except Exception:
        pass
    return None


def get_memory():
    """Memory via PowerShell CIM."""
    try:
        data = _ps_json(
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object TotalVisibleMemorySize, FreePhysicalMemory"
        )
        if data:
            total_kb = data.get("TotalVisibleMemorySize", 0)
            free_kb = data.get("FreePhysicalMemory", 0)
            used_kb = total_kb - free_kb
            total_mb = round(total_kb / 1024, 1)
            used_mb = round(used_kb / 1024, 1)
            pct = round(used_kb / total_kb * 100, 1) if total_kb > 0 else 0
            return {"total_mb": total_mb, "used_mb": used_mb, "pct": pct}
    except Exception:
        pass
    return None


def get_disks():
    """Disk usage via PowerShell CIM."""
    disks = []
    try:
        data = _ps_json(
            "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | "
            "Select-Object DeviceID, Size, FreeSpace, FileSystem"
        )
        if data is None:
            return disks
        # Single disk returns dict, multiple returns list
        if isinstance(data, dict):
            data = [data]
        for d in data:
            size = d.get("Size", 0)
            free = d.get("FreeSpace", 0)
            if size and size > 0:
                used = size - free
                disks.append({
                    "mount": d.get("DeviceID", "?"),
                    "fs": d.get("FileSystem", ""),
                    "total_gb": round(size / 1073741824, 1),
                    "used_gb": round(used / 1073741824, 1),
                    "pct": round(used / size * 100, 1),
                })
    except Exception:
        pass
    return disks


def get_uptime():
    """System uptime via kernel32 GetTickCount64."""
    try:
        lib = ctypes.windll.kernel32
        lib.GetTickCount64.restype = ctypes.c_uint64
        return int(lib.GetTickCount64() / 1000)
    except Exception:
        pass
    return None


def get_network():
    """Network I/O via PowerShell CIM."""
    try:
        data = _ps_json(
            "Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface | "
            "Select-Object Name, BytesReceivedPersec, BytesSentPersec"
        )
        if data is None:
            return None
        if isinstance(data, dict):
            data = [data]
        rx = tx = 0
        interfaces = []
        for iface in data:
            name = iface.get("Name", "?")
            iface_rx = iface.get("BytesReceivedPersec", 0)
            iface_tx = iface.get("BytesSentPersec", 0)
            rx += iface_rx
            tx += iface_tx
            interfaces.append({
                "name": name,
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
    """CPU temperature (requires admin or specific hardware support)."""
    try:
        raw = _ps(
            "Get-CimInstance MSAcpi_ThermalZoneTemperature -Namespace root/wmi 2>$null | "
            "Select-Object -First 1 -ExpandProperty CurrentTemperature"
        )
        if raw:
            # Value is in tenths of Kelvin
            kelvin_tenths = int(raw)
            celsius = round((kelvin_tenths / 10) - 273.15, 1)
            if 0 < celsius < 120:
                return celsius
    except Exception:
        pass
    return None


def get_top_processes(n=10):
    """Top N processes by CPU."""
    procs = []
    try:
        data = _ps_json(
            f"Get-Process | Sort-Object CPU -Descending | Select-Object -First {n} "
            "Id, ProcessName, @{N='CpuPct';E={[math]::Round($_.CPU,1)}}, "
            "@{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}}"
        )
        if data is None:
            return procs
        if isinstance(data, dict):
            data = [data]
        for p in data:
            procs.append({
                "pid": p.get("Id", 0),
                "cmd": p.get("ProcessName", "?"),
                "cpu": p.get("CpuPct", 0),
                "mem_mb": p.get("MemMB", 0),
            })
    except Exception:
        pass
    return procs


def collect_all():
    """Collect all system metrics."""
    data = {
        "hostname": socket.gethostname(),
        "platform": "Windows",
        "platform_release": platform.version(),
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

    return data


# ── Reporter ─────────────────────────────────────────────────────────────────

def send_metrics(server, token, data):
    url = f"{server.rstrip('/')}/api/agent/report"
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        print(f"[nodeglow-agent] HTTP {e.code}: {e.read().decode()[:200]}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[nodeglow-agent] Error: {e}", file=sys.stderr)
        return False


# ── Windows Service / Task Scheduler installer ───────────────────────────────

def install_task(server, token, interval):
    """Install as a Windows Scheduled Task that runs at logon."""
    script_path = os.path.abspath(__file__)
    python_path = sys.executable
    task_name = "NodeglowAgent"

    # Create a wrapper batch file
    bat_dir = os.path.join(os.environ.get("APPDATA", ""), "Nodeglow")
    os.makedirs(bat_dir, exist_ok=True)
    bat_path = os.path.join(bat_dir, "nodeglow-agent.bat")

    with open(bat_path, "w") as f:
        f.write(f'@echo off\n')
        f.write(f'set NODEGLOW_SERVER={server}\n')
        f.write(f'set NODEGLOW_TOKEN={token}\n')
        f.write(f'set NODEGLOW_INTERVAL={interval}\n')
        f.write(f'"{python_path}" "{script_path}"\n')

    # Register scheduled task
    cmd = (
        f'schtasks /create /tn "{task_name}" /tr "{bat_path}" '
        f'/sc onlogon /rl highest /f'
    )
    ret = os.system(cmd)
    if ret == 0:
        print(f"Installed scheduled task: {task_name}")
        print(f"  Script: {bat_path}")
        print(f"  To start now: schtasks /run /tn \"{task_name}\"")
        print(f"  To remove:    schtasks /delete /tn \"{task_name}\" /f")

        # Also start it now
        os.system(f'start "" "{bat_path}"')
        print(f"  Agent started.")
    else:
        print(f"Error: Failed to create scheduled task (run as Administrator)", file=sys.stderr)
        sys.exit(1)


# ── Config file support ───────────────────────────────────────────────────────

def _load_config_file():
    """Load config.json from next to the executable/script."""
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
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


# ── Auto-update ──────────────────────────────────────────────────────────────

def _get_own_hash():
    """SHA256 of our own executable or script file."""
    if getattr(sys, 'frozen', False):
        path = sys.executable
    else:
        path = os.path.abspath(__file__)
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""


def check_and_update(server):
    """Check server for a newer agent version; download + replace + restart if found."""
    try:
        url = f"{server.rstrip('/')}/api/agent/version/windows"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        remote_hash = data.get("hash", "")
        if not remote_hash:
            return False

        local_hash = _get_own_hash()
        if local_hash == remote_hash:
            return False

        print(f"[nodeglow-agent] Update available (local={local_hash[:12]}... remote={remote_hash[:12]}...)")

        # Download new version to temp file
        download_url = f"{server.rstrip('/')}/agents/download/windows"
        if getattr(sys, 'frozen', False):
            own_path = sys.executable
        else:
            own_path = os.path.abspath(__file__)

        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".exe" if getattr(sys, 'frozen', False) else ".py",
                                             dir=os.path.dirname(own_path))
        os.close(tmp_fd)

        try:
            urllib.request.urlretrieve(download_url, tmp_path)

            # Verify the download matches the expected hash
            with open(tmp_path, "rb") as f:
                dl_hash = hashlib.sha256(f.read()).hexdigest()
            if dl_hash != remote_hash:
                print(f"[nodeglow-agent] Download hash mismatch, aborting update", file=sys.stderr)
                os.remove(tmp_path)
                return False

            # On Windows: rename old → .old, move new → original, then restart
            old_backup = own_path + ".old"
            if os.path.exists(old_backup):
                try:
                    os.remove(old_backup)
                except Exception:
                    pass

            os.rename(own_path, old_backup)
            shutil.move(tmp_path, own_path)

            print(f"[nodeglow-agent] Updated successfully, restarting...")

            # Restart: launch new process, exit current
            if getattr(sys, 'frozen', False):
                subprocess.Popen([own_path], creationflags=0x00000008)  # DETACHED_PROCESS
            else:
                subprocess.Popen([sys.executable, own_path], creationflags=0x00000008)
            sys.exit(0)

        except Exception as e:
            print(f"[nodeglow-agent] Update failed: {e}", file=sys.stderr)
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return False

    except Exception as e:
        print(f"[nodeglow-agent] Update check failed: {e}", file=sys.stderr)
        return False


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Nodeglow Agent for Windows")
    parser.add_argument("--server", "-s", default=os.environ.get("NODEGLOW_SERVER", _file_config.get("server", "")))
    parser.add_argument("--token", "-t", default=os.environ.get("NODEGLOW_TOKEN", _file_config.get("token", "")))
    parser.add_argument("--interval", "-i", type=int, default=int(os.environ.get("NODEGLOW_INTERVAL", str(_file_config.get("interval", 30)))))
    parser.add_argument("--once", action="store_true", help="Report once and exit")
    parser.add_argument("--dry-run", action="store_true", help="Print metrics, don't send")
    parser.add_argument("--install", action="store_true", help="Install as scheduled task")
    args = parser.parse_args()

    if args.dry_run:
        print(json.dumps(collect_all(), indent=2))
        return

    if not args.server:
        print("Error: --server or NODEGLOW_SERVER required", file=sys.stderr)
        sys.exit(1)
    if not args.token:
        print("Error: --token or NODEGLOW_TOKEN required", file=sys.stderr)
        sys.exit(1)

    if args.install:
        install_task(args.server, args.token, args.interval)
        return

    print(f"[nodeglow-agent] v{__version__} | {socket.gethostname()} | Windows {platform.version()}")
    print(f"[nodeglow-agent] reporting to {args.server} every {args.interval}s")
    print(f"[nodeglow-agent] auto-update check every 5 minutes")

    update_interval = 300  # 5 minutes
    last_update_check = 0

    while True:
        try:
            data = collect_all()
            ok = send_metrics(args.server, args.token, data)
            if ok:
                print(f"[nodeglow-agent] OK cpu={data.get('cpu_pct', '?')}% "
                      f"mem={data.get('memory', {}).get('pct', '?')}%")
        except Exception as e:
            print(f"[nodeglow-agent] error: {e}", file=sys.stderr)
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
