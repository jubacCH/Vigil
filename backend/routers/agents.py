"""
Agent router — register agents, receive metrics, serve UI + WebSocket live feed.
"""
import io
import json
import logging
import secrets
import zipfile
from datetime import datetime

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, select, update

from database import AsyncSessionLocal
from models.agent import Agent, AgentSnapshot
from services.websocket import broadcast_agent_metric

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="templates")


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


# ── Install scripts (one-liner endpoints) ────────────────────────────────────

@router.get("/agents/{agent_id}/install/linux")
async def agent_install_linux(request: Request, agent_id: int):
    """Serve a bash install script. Usage: curl -sSL <url> | sudo bash"""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
    if not agent:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    server_url = f"{request.url.scheme}://{request.url.netloc}"
    token = agent.token

    script = f'''#!/bin/bash
set -e

# ── Nodeglow Agent Installer for Linux ──────────────────────────────────────
# Server: {server_url}
# Agent:  {agent.name}

INSTALL_DIR="/opt/nodeglow"
SERVICE_NAME="nodeglow-agent"
AGENT_URL="{server_url}/agents/{agent_id}/download/linux"

echo "╔══════════════════════════════════════════╗"
echo "║       Nodeglow Agent Installer           ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Please run as root (sudo)"
    exit 1
fi

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

echo "[1/4] Creating install directory..."
mkdir -p "$INSTALL_DIR"

echo "[2/4] Downloading agent..."
curl -sSL "$AGENT_URL" -o "$INSTALL_DIR/nodeglow-agent.py"
chmod +x "$INSTALL_DIR/nodeglow-agent.py"

echo "[3/4] Creating systemd service..."
cat > /etc/systemd/system/${{SERVICE_NAME}}.service << 'UNIT'
[Unit]
Description=Nodeglow Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/nodeglow/nodeglow-agent.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT

echo "[4/4] Starting service..."
systemctl daemon-reload
systemctl enable ${{SERVICE_NAME}}
systemctl restart ${{SERVICE_NAME}}

echo ""
echo "Done! Agent is running."
echo "  Status:  systemctl status ${{SERVICE_NAME}}"
echo "  Logs:    journalctl -u ${{SERVICE_NAME}} -f"
echo "  Stop:    systemctl stop ${{SERVICE_NAME}}"
echo "  Remove:  systemctl disable ${{SERVICE_NAME}} && rm /etc/systemd/system/${{SERVICE_NAME}}.service && rm -rf $INSTALL_DIR"
'''

    from fastapi.responses import Response
    return Response(content=script, media_type="text/plain")


@router.get("/agents/{agent_id}/install/windows")
async def agent_install_windows(request: Request, agent_id: int):
    """Serve a PowerShell install script. Usage: irm <url> | iex"""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
    if not agent:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    server_url = f"{request.url.scheme}://{request.url.netloc}"
    token = agent.token

    script = f'''# ── Nodeglow Agent Installer for Windows ─────────────────────────────────────
# Server: {server_url}
# Agent:  {agent.name}

$ErrorActionPreference = "Stop"
$InstallDir = "$env:ProgramData\\Nodeglow"
$ExeUrl = "{server_url}/agents/download/windows"
$ConfigJson = @"
{{
  "server": "{server_url}",
  "token": "{token}",
  "interval": 30
}}
"@

Write-Host ""
Write-Host "=== Nodeglow Agent Installer ===" -ForegroundColor Cyan
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Host "Error: Please run as Administrator" -ForegroundColor Red
    exit 1
}}

Write-Host "[1/4] Creating install directory..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "[2/4] Downloading agent..."
Invoke-WebRequest -Uri $ExeUrl -OutFile "$InstallDir\\nodeglow-agent.exe" -UseBasicParsing

Write-Host "[3/4] Writing configuration..."
$ConfigJson | Out-File -FilePath "$InstallDir\\config.json" -Encoding UTF8 -Force

Write-Host "[4/4] Creating scheduled task..."
$TaskName = "NodeglowAgent"
$Action = New-ScheduledTaskAction -Execute "$InstallDir\\nodeglow-agent.exe" -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Remove existing task if present
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Nodeglow Monitoring Agent" | Out-Null

# Start now
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "Done! Agent is running." -ForegroundColor Green
Write-Host "  Status:  Get-ScheduledTask -TaskName $TaskName"
Write-Host "  Logs:    Get-Content $InstallDir\\nodeglow-agent.log"
Write-Host "  Stop:    Stop-ScheduledTask -TaskName $TaskName"
Write-Host "  Remove:  Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false; Remove-Item -Recurse $InstallDir"
'''

    from fastapi.responses import Response
    return Response(content=script, media_type="text/plain")


# ── Download: Agent files (used by install scripts) ──────────────────────────

@router.get("/agents/{agent_id}/download/linux")
async def agent_download_linux(request: Request, agent_id: int):
    """Download Linux agent script with token + server URL pre-configured."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
    if not agent:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    server_url = f"{request.url.scheme}://{request.url.netloc}"
    token = agent.token

    with open("static/nodeglow-agent-linux.py") as f:
        script = f.read()

    enrollment_block = f'''

# ── Auto-enrolled configuration (baked in at download) ──────────────────────
_ENROLLED_SERVER = "{server_url}"
_ENROLLED_TOKEN  = "{token}"
'''
    script = script.replace(
        '__version__ = "1.1.0"\n',
        f'__version__ = "1.1.0"\n{enrollment_block}',
    )
    script = script.replace(
        'default=os.environ.get("NODEGLOW_SERVER", "")',
        'default=os.environ.get("NODEGLOW_SERVER", _ENROLLED_SERVER)',
    )
    script = script.replace(
        'default=os.environ.get("NODEGLOW_TOKEN", "")',
        'default=os.environ.get("NODEGLOW_TOKEN", _ENROLLED_TOKEN)',
    )

    from fastapi.responses import Response
    return Response(content=script, media_type="text/x-python")


# Generic download (without enrollment)
@router.get("/agents/download/{platform}")
async def agent_download_generic(request: Request, platform: str):
    """Download generic agent exe/script (no token baked in)."""
    if platform == "windows":
        return FileResponse("static/nodeglow-agent.exe",
                            filename="nodeglow-agent.exe", media_type="application/octet-stream")
    return FileResponse("static/nodeglow-agent-linux.py",
                        filename="nodeglow-agent-linux.py", media_type="text/x-python")


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
