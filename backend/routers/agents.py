"""
Agent router — register agents, receive metrics, serve UI + WebSocket live feed.
"""
import json
import logging
import secrets
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


# ── Download: Agent script (with embedded token + server) ────────────────────

@router.get("/agents/{agent_id}/download/{platform}")
async def agent_download_enrolled(request: Request, agent_id: int, platform: str):
    """Download agent script with token + server URL pre-configured."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
    if not agent:
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    server_url = f"{request.url.scheme}://{request.url.netloc}"
    token = agent.token

    # Pick the right template file
    if platform == "windows":
        template_file = "static/nodeglow-agent-windows.py"
        filename = "nodeglow-agent-windows.py"
    else:
        template_file = "static/nodeglow-agent-linux.py"
        filename = "nodeglow-agent-linux.py"

    with open(template_file) as f:
        script = f.read()

    # Inject auto-enrollment: add config block right after __version__ line
    enrollment_block = f'''

# ── Auto-enrolled configuration (baked in at download) ──────────────────────
_ENROLLED_SERVER = "{server_url}"
_ENROLLED_TOKEN  = "{token}"
'''
    script = script.replace(
        f'__version__ = "1.1.0"\n',
        f'__version__ = "1.1.0"\n{enrollment_block}',
    )

    # Patch the defaults in argparse to use enrolled values
    script = script.replace(
        """default=os.environ.get("NODEGLOW_SERVER", "")""",
        """default=os.environ.get("NODEGLOW_SERVER", _ENROLLED_SERVER)""",
    )
    script = script.replace(
        """default=os.environ.get("NODEGLOW_TOKEN", "")""",
        """default=os.environ.get("NODEGLOW_TOKEN", _ENROLLED_TOKEN)""",
    )

    from fastapi.responses import Response
    return Response(
        content=script,
        media_type="text/x-python",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# Generic download (without enrollment)
@router.get("/agents/download/{platform}")
async def agent_download_generic(request: Request, platform: str):
    """Download generic agent script (no token baked in)."""
    if platform == "windows":
        return FileResponse("static/nodeglow-agent-windows.py",
                            filename="nodeglow-agent-windows.py", media_type="text/x-python")
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
