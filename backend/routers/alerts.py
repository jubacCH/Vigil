import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    PingHost, PingResult,
    UnifiController, UnifiSnapshot,
    UnasServer, UnasSnapshot,
    PiholeInstance, PiholeSnapshot,
    AdguardInstance, AdguardSnapshot,
    PortainerInstance, PortainerSnapshot,
    TruenasServer, TruenasSnapshot,
    SynologyServer, SynologySnapshot,
    FirewallInstance, FirewallSnapshot,
    HassInstance, HassSnapshot,
    GiteaInstance, GiteaSnapshot,
    NutInstance, NutSnapshot,
    RedfishServer, RedfishSnapshot,
    SpeedtestConfig, SpeedtestResult,
    ProxmoxCluster, ProxmoxSnapshot,
    get_db,
)
from models.integration import IntegrationConfig
from services import snapshot as snap_svc

router = APIRouter(prefix="/alerts")
templates = Jinja2Templates(directory="templates")

_INTEGRATION_LABELS = {
    "proxmox": "Proxmox", "unifi": "UniFi", "unas": "UniFi NAS",
    "pihole": "Pi-hole", "adguard": "AdGuard", "portainer": "Portainer",
    "truenas": "TrueNAS", "synology": "Synology", "firewall": "Firewall",
    "hass": "Home Assistant", "gitea": "Gitea", "phpipam": "phpIPAM",
    "speedtest": "Speedtest", "ups": "UPS / NUT", "redfish": "Redfish",
}

_URL_PREFIX = {
    "proxmox": "/proxmox", "unifi": "/unifi", "unas": "/unas",
    "pihole": "/pihole", "adguard": "/adguard", "portainer": "/portainer",
    "truenas": "/truenas", "synology": "/synology", "firewall": "/firewall",
    "hass": "/hass", "gitea": "/gitea", "phpipam": "/phpipam",
    "speedtest": "/speedtest", "ups": "/ups", "redfish": "/redfish",
}


@router.get("", response_class=HTMLResponse)
async def alerts_page(request: Request, db: AsyncSession = Depends(get_db)):
    alerts = []

    # ── Offline hosts ─────────────────────────────────────────────────────────
    hosts = (await db.execute(
        select(PingHost).where(PingHost.enabled == True, PingHost.maintenance == False)
    )).scalars().all()

    for host in hosts:
        latest = (await db.execute(
            select(PingResult)
            .where(PingResult.host_id == host.id)
            .order_by(PingResult.timestamp.desc())
            .limit(1)
        )).scalar_one_or_none()

        if latest and not latest.success:
            alerts.append({
                "severity": "critical",
                "category": "Host offline",
                "name": host.name,
                "detail": host.hostname,
                "url": f"/ping/{host.id}",
                "time": latest.timestamp,
            })

        # SSL expiry warning
        if host.ssl_expiry_days is not None and host.ssl_expiry_days <= 30:
            sev = "critical" if host.ssl_expiry_days <= 7 else "warning"
            alerts.append({
                "severity": sev,
                "category": "SSL expiry",
                "name": host.name,
                "detail": f"Expires in {host.ssl_expiry_days} days",
                "url": f"/ping/{host.id}",
                "time": None,
            })

    # ── Integration failures ──────────────────────────────────────────────────
    all_configs = (await db.execute(select(IntegrationConfig))).scalars().all()

    if all_configs:
        # New generic tables
        all_snaps = await snap_svc.get_latest_batch_all(db)
        for cfg in all_configs:
            snap = all_snaps.get(cfg.type, {}).get(cfg.id)
            label = _INTEGRATION_LABELS.get(cfg.type, cfg.type)
            prefix = _URL_PREFIX.get(cfg.type, f"/{cfg.type}")

            if snap and not snap.ok:
                url = f"{prefix}/{cfg.id}" if cfg.type != "speedtest" else prefix
                alerts.append({
                    "severity": "warning",
                    "category": f"{label} error",
                    "name": cfg.name,
                    "detail": snap.error or "Connection error",
                    "url": url,
                    "time": snap.timestamp,
                })

            # UPS on battery check
            if cfg.type == "ups" and snap and snap.ok and snap.data_json:
                try:
                    d = json.loads(snap.data_json)
                    status = d.get("status", "").lower()
                    if "onbatt" in status or "on battery" in status:
                        alerts.append({
                            "severity": "critical",
                            "category": "UPS on battery",
                            "name": cfg.name,
                            "detail": f"Status: {d.get('status', '?')} – Charge: {d.get('charge_pct', '?')}%",
                            "url": f"/ups/{cfg.id}",
                            "time": snap.timestamp,
                        })
                except Exception:
                    pass
    else:
        # Fall back to old per-integration tables
        for label, config_model, snap_model, snap_fk, url_prefix in [
            ("Proxmox",       ProxmoxCluster,   ProxmoxSnapshot,   "cluster_id",  "/proxmox"),
            ("UniFi",         UnifiController,  UnifiSnapshot,     "controller_id","/unifi"),
            ("UniFi NAS",     UnasServer,       UnasSnapshot,      "server_id",   "/unas"),
            ("Pi-hole",       PiholeInstance,   PiholeSnapshot,    "instance_id", "/pihole"),
            ("AdGuard",       AdguardInstance,  AdguardSnapshot,   "instance_id", "/adguard"),
            ("Portainer",     PortainerInstance,PortainerSnapshot, "instance_id", "/portainer"),
            ("TrueNAS",       TruenasServer,    TruenasSnapshot,   "server_id",   "/truenas"),
            ("Synology",      SynologyServer,   SynologySnapshot,  "server_id",   "/synology"),
            ("Firewall",      FirewallInstance, FirewallSnapshot,  "instance_id", "/firewall"),
            ("Home Assistant",HassInstance,     HassSnapshot,      "instance_id", "/hass"),
            ("Gitea",         GiteaInstance,    GiteaSnapshot,     "instance_id", "/gitea"),
            ("UPS / NUT",     NutInstance,      NutSnapshot,       "instance_id", "/ups"),
            ("Redfish",       RedfishServer,    RedfishSnapshot,   "server_id",   "/redfish"),
        ]:
            instances = (await db.execute(select(config_model))).scalars().all()
            for inst in instances:
                snap = (await db.execute(
                    select(snap_model)
                    .where(getattr(snap_model, snap_fk) == inst.id)
                    .order_by(snap_model.timestamp.desc())
                    .limit(1)
                )).scalar_one_or_none()

                if snap and not snap.ok:
                    alerts.append({
                        "severity": "warning",
                        "category": f"{label} error",
                        "name": inst.name,
                        "detail": snap.error or "Connection error",
                        "url": f"{url_prefix}/{inst.id}",
                        "time": snap.timestamp,
                    })

        # Speedtest
        for st in (await db.execute(select(SpeedtestConfig))).scalars().all():
            snap = (await db.execute(
                select(SpeedtestResult)
                .where(SpeedtestResult.config_id == st.id)
                .order_by(SpeedtestResult.timestamp.desc())
                .limit(1)
            )).scalar_one_or_none()
            if snap and not snap.ok:
                alerts.append({
                    "severity": "warning",
                    "category": "Speedtest error",
                    "name": st.name,
                    "detail": snap.error or "Test failed",
                    "url": "/speedtest",
                    "time": snap.timestamp,
                })

        # UPS on battery (old tables)
        for nut in (await db.execute(select(NutInstance))).scalars().all():
            snap = (await db.execute(
                select(NutSnapshot)
                .where(NutSnapshot.instance_id == nut.id, NutSnapshot.ok == True)
                .order_by(NutSnapshot.timestamp.desc())
                .limit(1)
            )).scalar_one_or_none()
            if snap:
                try:
                    d = json.loads(snap.data_json)
                    status = d.get("status", "").lower()
                    if "onbatt" in status or "on battery" in status:
                        alerts.append({
                            "severity": "critical",
                            "category": "UPS on battery",
                            "name": nut.name,
                            "detail": f"Status: {d.get('status', '?')} – Charge: {d.get('charge_pct', '?')}%",
                            "url": f"/ups/{nut.id}",
                            "time": snap.timestamp,
                        })
                except Exception:
                    pass

    # Sort: critical first, then by time desc
    alerts.sort(key=lambda a: (0 if a["severity"] == "critical" else 1, -(a["time"].timestamp() if a["time"] else 0)))

    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "alerts": alerts,
        "active_page": "alerts",
    })
