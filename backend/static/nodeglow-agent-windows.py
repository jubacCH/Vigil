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

__version__ = "1.5.0"


# ── File logging ───────────────────────────────────────────────────────────

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

    # Rotating file handler: 2 MB max, keep 3 backups
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[nodeglow-agent] %(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

log = _setup_logging()


# ── WMI helpers via PowerShell ───────────────────────────────────────────────

def _ps(cmd, timeout=10):
    """Run a PowerShell command and return stdout (UTF-8)."""
    try:
        # Force UTF-8 output to avoid CP1252 mangling German umlauts etc.
        wrapped = f"[Console]::OutputEncoding = [Text.Encoding]::UTF8; {cmd}"
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", wrapped],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout,
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


def get_os_info():
    """Detailed OS information."""
    try:
        data = _ps_json(
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Caption, Version, BuildNumber, OSArchitecture, "
            "InstallDate, LastBootUpTime, RegisteredUser, Organization"
        )
        if data:
            info = {
                "os_name": data.get("Caption", "").strip(),
                "os_version": data.get("Version", ""),
                "build": data.get("BuildNumber", ""),
                "os_arch": data.get("OSArchitecture", ""),
            }
            if data.get("RegisteredUser"):
                info["registered_user"] = data["RegisteredUser"]
            return info
    except Exception:
        pass
    return None


def get_cpu_info():
    """CPU model, cores, speed."""
    try:
        data = _ps_json(
            "Get-CimInstance Win32_Processor | Select-Object -First 1 "
            "Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, "
            "CurrentClockSpeed, L2CacheSize, L3CacheSize"
        )
        if data:
            return {
                "model": data.get("Name", "").strip(),
                "cores": data.get("NumberOfCores", 0),
                "threads": data.get("NumberOfLogicalProcessors", 0),
                "max_mhz": data.get("MaxClockSpeed", 0),
                "current_mhz": data.get("CurrentClockSpeed", 0),
                "l2_cache_kb": data.get("L2CacheSize", 0),
                "l3_cache_kb": data.get("L3CacheSize", 0),
            }
    except Exception:
        pass
    return None


def get_swap():
    """Page file (swap) usage."""
    try:
        data = _ps_json(
            "Get-CimInstance Win32_PageFileUsage | "
            "Select-Object Name, AllocatedBaseSize, CurrentUsage"
        )
        if data is None:
            return None
        if isinstance(data, dict):
            data = [data]
        total_mb = sum(d.get("AllocatedBaseSize", 0) for d in data)
        used_mb = sum(d.get("CurrentUsage", 0) for d in data)
        if total_mb > 0:
            return {
                "total_mb": total_mb,
                "used_mb": used_mb,
                "pct": round(used_mb / total_mb * 100, 1),
            }
    except Exception:
        pass
    return None


def get_ip_addresses():
    """Network adapter IP addresses and MAC."""
    try:
        data = _ps_json(
            "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | "
            "Select-Object Description, IPAddress, MACAddress, DefaultIPGateway, DNSServerSearchOrder"
        )
        if data is None:
            return None
        if isinstance(data, dict):
            data = [data]
        adapters = []
        for a in data:
            ips = a.get("IPAddress", []) or []
            gw = a.get("DefaultIPGateway", []) or []
            dns = a.get("DNSServerSearchOrder", []) or []
            adapters.append({
                "name": a.get("Description", "?"),
                "ips": ips if isinstance(ips, list) else [ips],
                "mac": a.get("MACAddress", ""),
                "gateway": gw if isinstance(gw, list) else [gw],
                "dns": dns if isinstance(dns, list) else [dns],
            })
        return adapters
    except Exception:
        pass
    return None


def get_services():
    """Running Windows services (auto-start only to keep it relevant)."""
    services = []
    try:
        data = _ps_json(
            "Get-CimInstance Win32_Service -Filter \"StartMode='Auto'\" | "
            "Select-Object Name, DisplayName, State, ProcessId"
        )
        if data is None:
            return services
        if isinstance(data, dict):
            data = [data]
        for s in data:
            services.append({
                "name": s.get("Name", ""),
                "display": s.get("DisplayName", ""),
                "state": s.get("State", ""),
                "pid": s.get("ProcessId", 0),
            })
    except Exception:
        pass
    return services


def get_listening_ports():
    """TCP ports in LISTEN state."""
    ports = []
    try:
        data = _ps_json(
            "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
            "Select-Object LocalAddress, LocalPort, OwningProcess | "
            "Sort-Object LocalPort -Unique"
        )
        if data is None:
            return ports
        if isinstance(data, dict):
            data = [data]
        for p in data:
            ports.append({
                "addr": p.get("LocalAddress", ""),
                "port": p.get("LocalPort", 0),
                "pid": p.get("OwningProcess", 0),
            })
    except Exception:
        pass
    return ports


def get_gpu():
    """GPU info via CIM (works for all GPUs)."""
    gpus = []
    try:
        data = _ps_json(
            "Get-CimInstance Win32_VideoController | "
            "Select-Object Name, AdapterRAM, DriverVersion, CurrentRefreshRate, "
            "VideoModeDescription, Status"
        )
        if data is None:
            return gpus
        if isinstance(data, dict):
            data = [data]
        for g in data:
            vram = g.get("AdapterRAM", 0)
            gpus.append({
                "name": g.get("Name", "").strip(),
                "vram_mb": round(vram / 1048576, 0) if vram else 0,
                "driver": g.get("DriverVersion", ""),
                "resolution": g.get("VideoModeDescription", ""),
                "status": g.get("Status", ""),
            })
    except Exception:
        pass
    # Try nvidia-smi for utilization
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=utilization.gpu,utilization.memory,temperature.gpu,memory.used,memory.total",
             "--format=csv,noheader,nounits"],
            text=True, timeout=5, stderr=subprocess.DEVNULL, creationflags=0x08000000,
        )
        for i, line in enumerate(out.strip().splitlines()):
            parts = [x.strip() for x in line.split(",")]
            if len(parts) >= 5 and i < len(gpus):
                gpus[i]["gpu_pct"] = float(parts[0])
                gpus[i]["vram_pct"] = float(parts[1])
                gpus[i]["temp_c"] = float(parts[2])
                gpus[i]["vram_used_mb"] = float(parts[3])
                gpus[i]["vram_total_mb"] = float(parts[4])
    except Exception:
        pass
    return gpus


def get_logged_in_users():
    """Currently logged-in users."""
    users = []
    try:
        data = _ps_json(
            "Get-CimInstance Win32_LogonSession -Filter \"LogonType=2 or LogonType=10\" | "
            "ForEach-Object { $s=$_; Get-CimAssociatedInstance -InputObject $s -ResultClassName Win32_Account 2>$null | "
            "Select-Object Name, @{N='LogonType';E={$s.LogonType}}, @{N='StartTime';E={$s.StartTime}} } | "
            "Select-Object -Unique Name, LogonType, StartTime"
        )
        if data is None:
            return users
        if isinstance(data, dict):
            data = [data]
        for u in data:
            logon_type = u.get("LogonType", 0)
            users.append({
                "name": u.get("Name", ""),
                "type": "console" if logon_type == 2 else "rdp" if logon_type == 10 else str(logon_type),
            })
    except Exception:
        pass
    # Fallback: simple query user
    if not users:
        try:
            out = subprocess.check_output(["query", "user"], text=True, timeout=5,
                                           stderr=subprocess.DEVNULL, creationflags=0x08000000)
            for line in out.strip().splitlines()[1:]:
                parts = line.split()
                if parts:
                    name = parts[0].lstrip(">")
                    users.append({"name": name, "type": "session"})
        except Exception:
            pass
    return users


def get_pending_updates():
    """Check for pending Windows Updates (can be slow, max 15s timeout)."""
    try:
        raw = _ps(
            "$s = New-Object -ComObject Microsoft.Update.Session; "
            "$u = $s.CreateUpdateSearcher(); "
            "$r = $u.Search('IsInstalled=0 and IsHidden=0'); "
            "$r.Updates | Select-Object -First 20 Title, "
            "@{N='KB';E={($_.KBArticleIDs -join ',')}}, "
            "@{N='Severity';E={$_.MsrcSeverity}} | ConvertTo-Json -Compress",
            timeout=15,
        )
        if not raw:
            return {"count": 0, "updates": []}
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        updates = []
        for u in data:
            updates.append({
                "title": u.get("Title", "")[:120],
                "kb": u.get("KB", ""),
                "severity": u.get("Severity", ""),
            })
        return {"count": len(updates), "updates": updates}
    except Exception:
        pass
    return None


def get_docker_containers():
    """List running Docker containers if docker is available."""
    containers = []
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}"],
            stderr=subprocess.DEVNULL, text=True, timeout=5,
            creationflags=0x08000000,
        )
        for line in out.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                containers.append({"name": parts[0], "status": parts[1], "image": parts[2]})
    except Exception:
        pass
    return containers


def get_installed_software():
    """Top installed software (by size, max 20)."""
    try:
        data = _ps_json(
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
            "Where-Object { $_.DisplayName -and $_.EstimatedSize } | "
            "Sort-Object EstimatedSize -Descending | "
            "Select-Object -First 20 DisplayName, DisplayVersion, Publisher, "
            "@{N='SizeMB';E={[math]::Round($_.EstimatedSize/1024,1)}}",
            timeout=10,
        )
        if data is None:
            return []
        if isinstance(data, dict):
            data = [data]
        return [{"name": s.get("DisplayName", ""), "version": s.get("DisplayVersion", ""),
                 "publisher": s.get("Publisher", ""), "size_mb": s.get("SizeMB", 0)} for s in data]
    except Exception:
        return []


def get_bios_info():
    """BIOS / firmware info."""
    try:
        data = _ps_json(
            "Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Name, Version, SerialNumber, ReleaseDate"
        )
        if data:
            return {
                "manufacturer": data.get("Manufacturer", "").strip(),
                "name": data.get("Name", "").strip(),
                "version": data.get("Version", "").strip(),
                "serial": data.get("SerialNumber", "").strip(),
            }
    except Exception:
        pass
    return None


def get_motherboard():
    """Motherboard info."""
    try:
        data = _ps_json(
            "Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product, SerialNumber, Version"
        )
        if data:
            return {
                "manufacturer": data.get("Manufacturer", "").strip(),
                "product": data.get("Product", "").strip(),
                "serial": data.get("SerialNumber", "").strip(),
            }
    except Exception:
        pass
    return None


def get_ram_sticks():
    """Physical RAM modules."""
    try:
        data = _ps_json(
            "Get-CimInstance Win32_PhysicalMemory | "
            "Select-Object Manufacturer, PartNumber, Speed, Capacity, DeviceLocator"
        )
        if data is None:
            return []
        if isinstance(data, dict):
            data = [data]
        sticks = []
        for m in data:
            cap = m.get("Capacity", 0)
            sticks.append({
                "slot": m.get("DeviceLocator", "").strip(),
                "manufacturer": m.get("Manufacturer", "").strip(),
                "part": m.get("PartNumber", "").strip(),
                "speed_mhz": m.get("Speed", 0),
                "size_gb": round(cap / 1073741824, 1) if cap else 0,
            })
        return sticks
    except Exception:
        return []


def get_firewall_status():
    """Windows Firewall profile status."""
    try:
        data = _ps_json(
            "Get-NetFirewallProfile | Select-Object Name, Enabled"
        )
        if data is None:
            return None
        if isinstance(data, dict):
            data = [data]
        return {p.get("Name", ""): p.get("Enabled", False) for p in data}
    except Exception:
        return None


# ── Collect all ──────────────────────────────────────────────────────────────

# Static info collected once (doesn't change between reports)
_static_info = None
_static_info_time = 0


def _get_static_info():
    """Collect slow-changing system info (cached for 1 hour)."""
    global _static_info, _static_info_time
    if _static_info and (time.time() - _static_info_time) < 3600:
        return _static_info

    info = {}

    os_info = get_os_info()
    if os_info:
        info["os_info"] = os_info

    cpu_info = get_cpu_info()
    if cpu_info:
        info["cpu_info"] = cpu_info

    bios = get_bios_info()
    if bios:
        info["bios"] = bios

    board = get_motherboard()
    if board:
        info["motherboard"] = board

    ram = get_ram_sticks()
    if ram:
        info["ram_sticks"] = ram

    software = get_installed_software()
    if software:
        info["installed_software"] = software

    _static_info = info
    _static_info_time = time.time()
    return info


# ── Log collector ───────────────────────────────────────────────────────────

# Severity mapping: Windows Event Log Level → Syslog severity
_WIN_LEVEL_TO_SYSLOG = {
    1: 2,   # Critical → Critical
    2: 3,   # Error → Error
    3: 4,   # Warning → Warning
    4: 6,   # Information → Informational
    5: 7,   # Verbose → Debug
}

_last_log_ts = None  # ISO timestamp of last collected log


def get_recent_logs(max_events=200, levels=None):
    """Collect recent Windows Event Log entries (System + Application)."""
    global _last_log_ts

    if levels is None:
        levels = [1, 2, 3]  # Critical, Error, Warning
    if not levels:
        return []

    level_str = ",".join(str(l) for l in levels)

    # Build StartTime for FilterHashtable — this is natively supported and efficient
    if _last_log_ts:
        # Parse ISO timestamp back to PowerShell DateTime
        # Subtract 1 second to avoid missing events at exact boundary
        start_time_expr = f"[DateTime]::Parse('{_last_log_ts}').ToLocalTime().AddSeconds(-1)"
    else:
        # First run: look back 2 minutes to catch events from before agent started
        start_time_expr = "(Get-Date).AddSeconds(-120)"

    logs = []
    for log_name in ("System", "Application"):
        # Use _ps directly with ConvertTo-Json inside the try block.
        # _ps_json appends "| ConvertTo-Json" AFTER catch which breaks PowerShell parsing.
        ps_cmd = (
            f"try {{ "
            f"$startTime = {start_time_expr}; "
            f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; Level={level_str}; StartTime=$startTime}} "
            f"-MaxEvents {max_events} -ErrorAction Stop | "
            f"ForEach-Object {{ @{{ "
            f"ts = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); "
            f"level = $_.Level; "
            f"source = $_.ProviderName; "
            f"id = $_.Id; "
            f"msg = if ($_.Message) {{ if ($_.Message.Length -gt 500) {{ $_.Message.Substring(0,500) }} else {{ $_.Message }} }} else {{ '' }} "
            f"}} }} | ConvertTo-Json -Compress"
            f"}} catch {{ }}"
        )
        raw = _ps(ps_cmd, timeout=15)
        if not raw:
            result = None
        else:
            try:
                result = json.loads(raw)
            except Exception:
                result = None
        if result:
            # PowerShell returns single object (not array) if only 1 result
            if isinstance(result, dict):
                result = [result]
            for entry in result:
                if not isinstance(entry, dict):
                    continue
                logs.append({
                    "timestamp": entry.get("ts", ""),
                    "severity": _WIN_LEVEL_TO_SYSLOG.get(entry.get("level"), 6),
                    "app_name": entry.get("source", ""),
                    "message": (entry.get("msg") or "").replace("\r\n", " ").replace("\n", " "),
                    "facility": 1 if log_name == "Application" else 0,  # user vs kern
                })

    if logs:
        # Update last timestamp to newest entry
        newest = max((l["timestamp"] for l in logs if l["timestamp"]), default=None)
        if newest:
            _last_log_ts = newest

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
        "platform": "Windows",
        "platform_release": platform.version(),
        "arch": platform.machine(),
        "agent_version": __version__,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # Dynamic metrics (every report)
    cpu = get_cpu_percent()
    if cpu is not None:
        data["cpu_pct"] = cpu

    mem = get_memory()
    if mem:
        data["memory"] = mem

    swap = get_swap()
    if swap:
        data["swap"] = swap

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

    procs = get_top_processes(10)
    if procs:
        data["processes"] = procs

    ips = get_ip_addresses()
    if ips:
        data["network_adapters"] = ips

    services = get_services()
    if services:
        data["services"] = services

    ports = get_listening_ports()
    if ports:
        data["listening_ports"] = ports

    gpus = get_gpu()
    if gpus:
        data["gpus"] = gpus

    users = get_logged_in_users()
    if users:
        data["logged_in_users"] = users

    containers = get_docker_containers()
    if containers:
        data["docker_containers"] = containers

    firewall = get_firewall_status()
    if firewall:
        data["firewall"] = firewall

    # Static info (cached, refreshed hourly)
    data.update(_get_static_info())

    # Pending updates (slow, only every 30 min)
    now = time.time()
    if not hasattr(collect_all, '_update_time') or (now - collect_all._update_time) > 1800:
        updates = get_pending_updates()
        if updates:
            collect_all._update_result = updates
        collect_all._update_time = now
    if hasattr(collect_all, '_update_result') and collect_all._update_result:
        data["pending_updates"] = collect_all._update_result

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
        log.info("Installed scheduled task: %s", task_name)
        log.info("  Script: %s", bat_path)
        log.info("  To start now: schtasks /run /tn \"%s\"", task_name)
        log.info("  To remove:    schtasks /delete /tn \"%s\" /f", task_name)

        # Also start it now
        os.system(f'start "" "{bat_path}"')
        log.info("  Agent started.")
    else:
        log.error("Failed to create scheduled task (run as Administrator)")
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

        log.info("Update available (local=%s... remote=%s...)", local_hash[:12], remote_hash[:12])

        # Download new version to temp file
        download_url = f"{server.rstrip('/')}/agents/download/windows"
        if getattr(sys, 'frozen', False):
            own_path = sys.executable
        else:
            own_path = os.path.abspath(__file__)

        own_dir = os.path.dirname(own_path)
        own_name = os.path.basename(own_path)
        is_exe = getattr(sys, 'frozen', False)
        suffix = ".exe" if is_exe else ".py"

        tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix, dir=own_dir)
        os.close(tmp_fd)

        try:
            urllib.request.urlretrieve(download_url, tmp_path)

            # Verify the download matches the expected hash
            with open(tmp_path, "rb") as f:
                dl_hash = hashlib.sha256(f.read()).hexdigest()
            if dl_hash != remote_hash:
                log.error("Download hash mismatch, aborting update")
                os.remove(tmp_path)
                return False

            if is_exe:
                # Windows: running .exe CAN be renamed but NOT deleted.
                # IMPORTANT: Always restart via batch script to avoid inheriting
                # the PyInstaller _MEI temp dir from the old process.
                old_backup = own_path + ".old"
                if os.path.exists(old_backup):
                    try:
                        os.remove(old_backup)
                    except Exception:
                        pass

                # Use a one-shot Scheduled Task for restart — most reliable method on Windows.
                # The task runs in a clean session, avoiding _MEI temp dir inheritance.
                task_name = "NodeglowAgentRestart"
                try:
                    os.rename(own_path, old_backup)
                    shutil.move(tmp_path, own_path)
                    log.info("Updated successfully (v%s), scheduling restart...", __version__)
                except PermissionError:
                    # Can't rename running exe — write new exe next to it
                    # and use the task to do the swap
                    log.warning("Cannot rename running exe, deferred swap")
                    new_path = own_path + ".new"
                    shutil.move(tmp_path, new_path)
                    # Task will move .new over the original after we exit
                    swap_cmd = f'cmd /c timeout /t 2 /nobreak >nul & move /Y "{new_path}" "{own_path}" & "{own_path}"'
                    subprocess.Popen(swap_cmd, shell=True, creationflags=0x00000208)
                    sys.exit(0)

                # Create a one-shot scheduled task that starts in 5 seconds
                schtasks_cmd = (
                    f'schtasks /create /tn "{task_name}" /tr "\"{own_path}\"" '
                    f'/sc once /st 00:00 /f /rl highest'
                )
                os.system(schtasks_cmd)
                # Run it immediately
                os.system(f'schtasks /run /tn "{task_name}"')
                # Schedule cleanup (delete the task after 30s)
                cleanup_cmd = f'cmd /c timeout /t 30 /nobreak >nul & schtasks /delete /tn "{task_name}" /f'
                subprocess.Popen(cleanup_cmd, shell=True, creationflags=0x00000208)
            else:
                # Script mode: just replace the file and re-exec
                shutil.move(tmp_path, own_path)
                log.info("Updated successfully (v%s), restarting...", __version__)
                subprocess.Popen(
                    [sys.executable, own_path],
                    creationflags=0x00000008,
                )

            sys.exit(0)

        except SystemExit:
            raise  # let sys.exit(0) propagate
        except Exception as e:
            log.error("Update failed: %s", e)
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return False

    except SystemExit:
        raise
    except Exception as e:
        log.error("Update check failed: %s", e)
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
        log.error("--server or NODEGLOW_SERVER required")
        sys.exit(1)
    if not args.token:
        log.error("--token or NODEGLOW_TOKEN required")
        sys.exit(1)

    if args.install:
        install_task(args.server, args.token, args.interval)
        return

    # Clean up leftover files from previous updates
    if getattr(sys, 'frozen', False):
        own_dir = os.path.dirname(sys.executable)
        for leftover in [sys.executable + ".old", os.path.join(own_dir, "_update.bat"), os.path.join(own_dir, "_restart.vbs"), sys.executable + ".new"]:
            if os.path.exists(leftover):
                try:
                    os.remove(leftover)
                    log.debug("Cleaned up: %s", leftover)
                except Exception:
                    pass

    log.info("v%s | %s | Windows %s", __version__, socket.gethostname(), platform.version())
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
                log.info("OK cpu=%s%% mem=%s%%", data.get('cpu_pct', '?'), data.get('memory', {}).get('pct', '?'))
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
                    logs = get_recent_logs(levels=server_log_levels)
                    if logs:
                        lok = send_logs(args.server, args.token, socket.gethostname(), logs)
                        log.info("Logs: %d entries %s", len(logs), "sent" if lok else "FAILED")
                    else:
                        log.debug("No new log events")
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
