"""
Agent router — register agents, receive metrics, serve UI + WebSocket live feed.
"""
import hashlib
import json
import logging
import secrets
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, select, update

from database import AsyncSessionLocal, PingHost, PingResult, get_setting, set_setting
from models.agent import Agent, AgentSnapshot
from services.websocket import broadcast_agent_metric

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="templates")


async def _get_enrollment_key() -> str:
    """Get or create the global agent enrollment key."""
    async with AsyncSessionLocal() as db:
        key = await get_setting(db, "agent_enrollment_key")
        if not key:
            key = secrets.token_hex(16)
            await set_setting(db, "agent_enrollment_key", key)
            await db.commit()
        return key


# ── API: Agent self-enrollment ────────────────────────────────────────────────

@router.post("/api/agent/enroll")
async def agent_enroll(request: Request):
    """Agent self-registers using the enrollment key. Returns a token."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    enroll_key = body.get("enrollment_key", "")
    hostname = body.get("hostname", "").strip()
    plat = body.get("platform", "")
    arch = body.get("arch", "")

    if not enroll_key or not hostname:
        return JSONResponse({"error": "enrollment_key and hostname required"}, status_code=400)

    expected_key = await _get_enrollment_key()
    if enroll_key != expected_key:
        return JSONResponse({"error": "Invalid enrollment key"}, status_code=403)

    async with AsyncSessionLocal() as db:
        # Check if agent with this hostname already exists → return existing token
        result = await db.execute(select(Agent).where(Agent.hostname == hostname))
        existing = result.scalar_one_or_none()
        if existing:
            existing.platform = plat or existing.platform
            existing.arch = arch or existing.arch
            existing.last_seen = datetime.utcnow()
            await db.commit()
            return {"ok": True, "token": existing.token, "agent_id": existing.id}

        # Create new agent
        token = secrets.token_hex(24)
        agent = Agent(name=hostname, hostname=hostname, token=token, platform=plat, arch=arch)
        db.add(agent)

        # Auto-create PingHost if not already present
        ping_result = await db.execute(select(PingHost).where(PingHost.hostname == hostname))
        if not ping_result.scalar_one_or_none():
            db.add(PingHost(
                name=hostname,
                hostname=hostname,
                check_type="icmp",
                source="agent",
                source_detail=f"auto-enrolled agent",
            ))

        await db.commit()
        await db.refresh(agent)
        logger.info("Agent auto-enrolled: %s (id=%d)", hostname, agent.id)
        return {"ok": True, "token": agent.token, "agent_id": agent.id}


# ── API: Agent reports metrics ───────────────────────────────────────────────

@router.post("/api/agent/report")
async def agent_report(request: Request):
    """Receive metrics from a Nodeglow agent."""
    # Auth via Bearer token
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse({"error": "Missing token"}, status_code=401)
    token = auth[7:].strip()
    if not token:
        return JSONResponse({"error": "Empty token"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Agent).where(Agent.token == token, Agent.enabled == True))
        agent = result.scalar_one_or_none()
        if not agent:
            return JSONResponse({"error": "Invalid or disabled token"}, status_code=403)

        # Update agent metadata
        agent.last_seen = datetime.utcnow()
        agent.hostname = body.get("hostname", agent.hostname)
        agent.platform = body.get("platform", agent.platform)
        agent.arch = body.get("arch", agent.arch)
        agent.agent_version = body.get("agent_version", agent.agent_version)

        # Extract primary disk (highest usage or root)
        disks = body.get("disks", [])
        primary_disk_pct = None
        if disks:
            root = next((d for d in disks if d.get("mount") == "/"), None)
            primary_disk_pct = root["pct"] if root else disks[0].get("pct")

        mem = body.get("memory", {})
        load = body.get("load", {})

        snap = AgentSnapshot(
            agent_id=agent.id,
            timestamp=datetime.utcnow(),
            cpu_pct=body.get("cpu_pct"),
            mem_pct=mem.get("pct"),
            mem_used_mb=mem.get("used_mb"),
            mem_total_mb=mem.get("total_mb"),
            disk_pct=primary_disk_pct,
            load_1=load.get("load_1"),
            load_5=load.get("load_5"),
            load_15=load.get("load_15"),
            uptime_s=body.get("uptime_s"),
            rx_bytes=body.get("network", {}).get("rx_bytes"),
            tx_bytes=body.get("network", {}).get("tx_bytes"),
            data_json=json.dumps(body),
        )
        db.add(snap)
        await db.commit()

    # Broadcast to all WebSocket clients (global hub)
    await broadcast_agent_metric(agent.id, agent.name, {
        "hostname": body.get("hostname"),
        "cpu_pct": body.get("cpu_pct"),
        "mem_pct": mem.get("pct"),
        "disk_pct": primary_disk_pct,
        "load_1": load.get("load_1"),
        "uptime_s": body.get("uptime_s"),
    })

    return {"ok": True}


# ── UI: Agent list ───────────────────────────────────────────────────────────

@router.get("/agents")
async def agents_list(request: Request):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Agent).order_by(Agent.name))
        agents = result.scalars().all()

        # Get latest snapshot for each agent
        agent_data = []
        for agent in agents:
            snap_r = await db.execute(
                select(AgentSnapshot)
                .where(AgentSnapshot.agent_id == agent.id)
                .order_by(AgentSnapshot.timestamp.desc())
                .limit(1)
            )
            snap = snap_r.scalar_one_or_none()
            online = False
            if agent.last_seen:
                online = (datetime.utcnow() - agent.last_seen).total_seconds() < 120
            agent_data.append({
                "agent": agent,
                "snap": snap,
                "online": online,
            })

    return templates.TemplateResponse("agents.html", {
        "request": request,
        "agents": agent_data,
        "active_page": "agents",
    })


# ── UI: Agent detail ────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}")
async def agent_detail(request: Request, agent_id: int):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
        if not agent:
            return RedirectResponse("/agents", status_code=302)

        # Last 60 snapshots (~ 30 min at 30s interval)
        snaps_r = await db.execute(
            select(AgentSnapshot)
            .where(AgentSnapshot.agent_id == agent_id)
            .order_by(AgentSnapshot.timestamp.desc())
            .limit(60)
        )
        snapshots = list(reversed(snaps_r.scalars().all()))

        # Latest full data
        latest = snapshots[-1] if snapshots else None
        full_data = json.loads(latest.data_json) if latest and latest.data_json else {}

        online = False
        if agent.last_seen:
            online = (datetime.utcnow() - agent.last_seen).total_seconds() < 120

    return templates.TemplateResponse("agent_detail.html", {
        "request": request,
        "agent": agent,
        "snapshots": snapshots,
        "full_data": full_data,
        "online": online,
        "active_page": "agents",
    })


# ── CRUD: Add agent ─────────────────────────────────────────────────────────

@router.post("/agents/add")
async def agent_add(request: Request):
    form = await request.form()
    name = form.get("name", "").strip()
    if not name:
        return RedirectResponse("/agents", status_code=302)

    token = secrets.token_hex(24)  # 48 char hex token

    async with AsyncSessionLocal() as db:
        agent = Agent(name=name, token=token)
        db.add(agent)
        await db.commit()
        await db.refresh(agent)
        agent_id = agent.id

    return RedirectResponse(f"/agents/{agent_id}", status_code=302)


# ── CRUD: Delete agent ──────────────────────────────────────────────────────

@router.post("/agents/{agent_id}/delete")
async def agent_delete(request: Request, agent_id: int):
    async with AsyncSessionLocal() as db:
        # Get agent hostname to clean up PingHost
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
        if agent and agent.hostname:
            # Find agent-sourced PingHost and delete its results first
            ph = await db.execute(
                select(PingHost).where(PingHost.hostname == agent.hostname, PingHost.source == "agent")
            )
            ping_host = ph.scalar_one_or_none()
            if ping_host:
                await db.execute(delete(PingResult).where(PingResult.host_id == ping_host.id))
                await db.execute(delete(PingHost).where(PingHost.id == ping_host.id))
        await db.execute(delete(AgentSnapshot).where(AgentSnapshot.agent_id == agent_id))
        await db.execute(delete(Agent).where(Agent.id == agent_id))
        await db.commit()
    return RedirectResponse("/agents", status_code=302)


# ── CRUD: Regenerate token ──────────────────────────────────────────────────

@router.post("/agents/{agent_id}/regenerate-token")
async def agent_regenerate_token(request: Request, agent_id: int):
    new_token = secrets.token_hex(24)
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Agent).where(Agent.id == agent_id).values(token=new_token)
        )
        await db.commit()
    return RedirectResponse(f"/agents/{agent_id}", status_code=302)


# ── Install scripts (universal one-liner endpoints) ──────────────────────────

@router.get("/install/linux")
async def install_linux(request: Request):
    """Universal Linux installer. Usage: curl -sSL <url>/install/linux | sudo bash"""
    server_url = f"{request.url.scheme}://{request.url.netloc}"
    enrollment_key = await _get_enrollment_key()

    script = f'''#!/bin/bash
set -e

# ── Nodeglow Agent Installer for Linux ──────────────────────────────────────
SERVER="{server_url}"
ENROLLMENT_KEY="{enrollment_key}"
INSTALL_DIR="/opt/nodeglow"
SERVICE_NAME="nodeglow-agent"
CONFIG_FILE="$INSTALL_DIR/config.json"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║       Nodeglow Agent Installer           ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "  Error: Please run as root (sudo)"
    exit 1
fi

# Check dependencies
if ! command -v python3 &>/dev/null; then
    echo "  Error: Python 3 is required but not installed."
    exit 1
fi
if ! command -v curl &>/dev/null; then
    echo "  Error: curl is required but not installed."
    exit 1
fi

HOSTNAME=$(hostname)

echo "  [1/5] Creating install directory..."
mkdir -p "$INSTALL_DIR"

echo "  [2/5] Enrolling agent ($HOSTNAME)..."
ENROLL_RESPONSE=$(curl -sSL -X POST "$SERVER/api/agent/enroll" \\
    -H "Content-Type: application/json" \\
    -d "{{\\"enrollment_key\\": \\"$ENROLLMENT_KEY\\", \\"hostname\\": \\"$HOSTNAME\\", \\"platform\\": \\"Linux\\", \\"arch\\": \\"$(uname -m)\\"}}")

# Extract token from JSON response
TOKEN=$(echo "$ENROLL_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [ -z "$TOKEN" ]; then
    echo "  Error: Enrollment failed. Response: $ENROLL_RESPONSE"
    exit 1
fi
echo "  Enrolled successfully."

echo "  [3/5] Downloading agent..."
curl -sSL "$SERVER/agents/download/linux" -o "$INSTALL_DIR/nodeglow-agent.py"
chmod +x "$INSTALL_DIR/nodeglow-agent.py"

echo "  [4/5] Writing configuration..."
cat > "$CONFIG_FILE" << CONF
{{
  "server": "$SERVER",
  "token": "$TOKEN",
  "interval": 30
}}
CONF

echo "  [5/5] Creating systemd service..."
cat > /etc/systemd/system/${{SERVICE_NAME}}.service << 'UNIT'
[Unit]
Description=Nodeglow Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/nodeglow
ExecStart=/usr/bin/python3 /opt/nodeglow/nodeglow-agent.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT

echo "  [6/6] Testing connection..."
TEST_OUTPUT=$(python3 "$INSTALL_DIR/nodeglow-agent.py" --once 2>&1)
if echo "$TEST_OUTPUT" | grep -q "OK"; then
    echo "  Connection test: SUCCESS"
    echo "  $TEST_OUTPUT" | grep "\\[nodeglow-agent\\]" | tail -1 | sed 's/^/  /'
else
    echo "  Connection test: FAILED"
    echo "  $TEST_OUTPUT" | tail -3 | sed 's/^/  /'
    echo ""
    echo "  The agent will retry when the service starts."
fi

systemctl daemon-reload
systemctl enable ${{SERVICE_NAME}} --quiet
systemctl restart ${{SERVICE_NAME}}

echo ""
echo "  Done! Agent '$HOSTNAME' is running."
echo ""
echo "  Status:  systemctl status ${{SERVICE_NAME}}"
echo "  Logs:    journalctl -u ${{SERVICE_NAME}} -f"
echo "  Remove:  systemctl disable ${{SERVICE_NAME}} && rm /etc/systemd/system/${{SERVICE_NAME}}.service && rm -rf $INSTALL_DIR"
echo ""
'''

    from fastapi.responses import Response
    return Response(content=script, media_type="text/plain")


@router.get("/install/windows")
async def install_windows(request: Request):
    """Universal Windows installer. Usage: irm <url>/install/windows | iex"""
    server_url = f"{request.url.scheme}://{request.url.netloc}"
    enrollment_key = await _get_enrollment_key()

    script = f'''# ── Nodeglow Agent Installer for Windows ─────────────────────────────────────
$ErrorActionPreference = "Stop"
$Server = "{server_url}"
$EnrollmentKey = "{enrollment_key}"
$InstallDir = "$env:ProgramData\\Nodeglow"
$TaskName = "NodeglowAgent"

Write-Host ""
Write-Host "  === Nodeglow Agent Installer ===" -ForegroundColor Cyan
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Host "  Error: Please run as Administrator" -ForegroundColor Red
    exit 1
}}

$Hostname = $env:COMPUTERNAME

Write-Host "  [1/5] Creating install directory..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "  [2/5] Enrolling agent ($Hostname)..."
$body = @{{
    enrollment_key = $EnrollmentKey
    hostname = $Hostname
    platform = "Windows"
    arch = $env:PROCESSOR_ARCHITECTURE
}} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "$Server/api/agent/enroll" -Method Post -Body $body -ContentType "application/json"
if (-not $response.token) {{
    Write-Host "  Error: Enrollment failed." -ForegroundColor Red
    exit 1
}}
$Token = $response.token
Write-Host "  Enrolled successfully."

Write-Host "  [3/5] Downloading agent..."
Invoke-WebRequest -Uri "$Server/agents/download/windows" -OutFile "$InstallDir\\nodeglow-agent.exe" -UseBasicParsing

Write-Host "  [4/5] Writing configuration..."
@"
{{
  "server": "$Server",
  "token": "$Token",
  "interval": 30
}}
"@ | Out-File -FilePath "$InstallDir\\config.json" -Encoding UTF8 -Force

Write-Host "  [5/5] Creating scheduled task..."
$Action = New-ScheduledTaskAction -Execute "$InstallDir\\nodeglow-agent.exe" -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Write-Host "  [6/6] Testing connection..."
try {{
    $testOutput = & "$InstallDir\\nodeglow-agent.exe" --once 2>&1 | Out-String
    if ($testOutput -match "OK") {{
        Write-Host "  Connection test: SUCCESS" -ForegroundColor Green
        $testOutput -split "`n" | Where-Object {{ $_ -match "\\[nodeglow-agent\\].*OK" }} | Select-Object -Last 1 | ForEach-Object {{ Write-Host "  $_" -ForegroundColor Gray }}
    }} else {{
        Write-Host "  Connection test: FAILED" -ForegroundColor Yellow
        $testOutput -split "`n" | Select-Object -Last 3 | ForEach-Object {{ Write-Host "  $_" -ForegroundColor Yellow }}
        Write-Host "  The agent will retry when the task starts." -ForegroundColor Yellow
    }}
}} catch {{
    Write-Host "  Connection test: ERROR - $($_.Exception.Message)" -ForegroundColor Yellow
}}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Nodeglow Monitoring Agent" | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "  Done! Agent '$Hostname' is running." -ForegroundColor Green
Write-Host ""
Write-Host "  Status:  Get-ScheduledTask -TaskName $TaskName"
Write-Host "  Stop:    Stop-ScheduledTask -TaskName $TaskName"
Write-Host "  Remove:  Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false; Remove-Item -Recurse $InstallDir"
Write-Host ""
'''

    from fastapi.responses import Response
    return Response(content=script, media_type="text/plain")


# ── Download: Agent files (used by install scripts) ──────────────────────────

@router.get("/agents/download/{platform}")
async def agent_download(request: Request, platform: str):
    """Download generic agent exe/script (no token — config.json used instead)."""
    if platform == "windows":
        return FileResponse("static/nodeglow-agent.exe",
                            filename="nodeglow-agent.exe", media_type="application/octet-stream")
    return FileResponse("static/nodeglow-agent-linux.py",
                        filename="nodeglow-agent-linux.py", media_type="text/x-python")


# ── API: Agent version check (for auto-update) ────────────────────────────────

_agent_file_cache: dict[str, tuple[str, float]] = {}  # platform -> (hash, mtime)


def _get_agent_hash(platform: str) -> str:
    """Get SHA256 hash of the current agent binary/script. Cached by mtime."""
    if platform == "windows":
        path = Path("static/nodeglow-agent.exe")
    else:
        path = Path("static/nodeglow-agent-linux.py")

    if not path.exists():
        return ""

    mtime = path.stat().st_mtime
    cached = _agent_file_cache.get(platform)
    if cached and cached[1] == mtime:
        return cached[0]

    h = hashlib.sha256(path.read_bytes()).hexdigest()
    _agent_file_cache[platform] = (h, mtime)
    return h


@router.get("/api/agent/version/{platform}")
async def agent_version(platform: str):
    """Returns the current agent version hash. Agents poll this to check for updates."""
    if platform not in ("windows", "linux"):
        return JSONResponse({"error": "Invalid platform"}, status_code=400)
    return {"hash": _get_agent_hash(platform)}


# ── API: List agents (JSON) ─────────────────────────────────────────────────

@router.get("/api/agents")
async def api_agents_list(request: Request):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Agent).order_by(Agent.name))
        agents = result.scalars().all()
        out = []
        for a in agents:
            online = False
            if a.last_seen:
                online = (datetime.utcnow() - a.last_seen).total_seconds() < 120
            out.append({
                "id": a.id,
                "name": a.name,
                "hostname": a.hostname,
                "platform": a.platform,
                "online": online,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            })
    return out
