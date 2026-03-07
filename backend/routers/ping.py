import asyncio
import ipaddress
import json
import socket
from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import cast, func, select, Integer
from sqlalchemy.ext.asyncio import AsyncSession

from utils.ping import check_host
from database import PingHost, PingResult, get_db
from models.agent import Agent, AgentSnapshot
from models.integration import IntegrationConfig, Snapshot
from models.syslog import SyslogMessage
from services import integration as int_svc
from services import snapshot as snap_svc

router = APIRouter(prefix="/ping")
templates = Jinja2Templates(directory="templates")


async def _dns_resolve(hostname: str) -> dict:
    """Resolve hostname→IP or IP→hostname. Returns {ip, fqdn}, either may be None."""
    # Strip URL scheme / path to get raw host
    raw = hostname
    for prefix in ("https://", "http://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            break
    raw = raw.split("/")[0].split(":")[0]

    loop = asyncio.get_event_loop()
    result: dict = {"ip": None, "fqdn": None}
    try:
        ipaddress.ip_address(raw)
        # It's an IP → reverse lookup
        result["ip"] = raw
        try:
            fqdn = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: socket.gethostbyaddr(raw)[0]),
                timeout=2.0,
            )
            result["fqdn"] = fqdn
        except Exception:
            pass
    except ValueError:
        # It's a hostname → forward lookup
        result["fqdn"] = raw
        try:
            ip = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: socket.gethostbyname(raw)),
                timeout=2.0,
            )
            result["ip"] = ip
        except Exception:
            pass
    return result


def _heatmap_30d(results_30d: list) -> list[dict]:
    """Return list of 30 dicts {date, color} for heatmap, oldest first."""
    now = datetime.utcnow().date()
    by_day: dict = {}
    for r in results_30d:
        d = r.timestamp.date()
        if d not in by_day:
            by_day[d] = {"total": 0, "ok": 0}
        by_day[d]["total"] += 1
        if r.success:
            by_day[d]["ok"] += 1

    result = []
    for i in range(29, -1, -1):
        day = now - timedelta(days=i)
        if day in by_day:
            pct = by_day[day]["ok"] / by_day[day]["total"] * 100
            color = "emerald" if pct >= 95 else "yellow" if pct >= 80 else "red"
        else:
            color = "slate"
        result.append({"date": day.strftime("%d.%m"), "color": color})
    return result


def _uptime_pct(results: list) -> float:
    if not results:
        return 0.0
    return round(sum(1 for r in results if r.success) / len(results) * 100, 1)


# ── API (JSON) ─────────────────────────────────────────────────────────────────

@router.get("/api/status")
async def api_status(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PingHost).where(PingHost.enabled == True))
    hosts = result.scalars().all()
    out = []
    for host in hosts:
        latest = await db.execute(
            select(PingResult)
            .where(PingResult.host_id == host.id)
            .order_by(PingResult.timestamp.desc())
            .limit(1)
        )
        lr = latest.scalar_one_or_none()
        out.append({
            "id": host.id,
            "name": host.name,
            "hostname": host.hostname,
            "check_type": host.check_type or "icmp",
            "maintenance": host.maintenance or False,
            "online": lr.success if lr else None,
            "latency_ms": lr.latency_ms if lr else None,
        })
    return out


@router.get("/api/test/{host_id}")
async def test_ping(host_id: int, db: AsyncSession = Depends(get_db)):
    host = await db.get(PingHost, host_id)
    if not host:
        return {"success": False, "error": "Host not found"}
    ok, latency = await check_host(host)
    return {"success": ok, "latency_ms": latency}


# ── HTML views ─────────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def ping_list(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PingHost).order_by(PingHost.name))
    hosts = result.scalars().all()

    host_data = []
    now = datetime.utcnow()
    window_24h = now - timedelta(hours=24)
    window_30d = now - timedelta(days=30)

    # Batch uptime queries – 3 queries total regardless of host count
    uptime_map: dict[int, dict] = {}
    for window, key in [
        (timedelta(hours=24), "h24"),
        (timedelta(days=7),   "d7"),
        (timedelta(days=30),  "d30"),
    ]:
        rows = await db.execute(
            select(
                PingResult.host_id,
                func.count().label("total"),
                func.sum(cast(PingResult.success, Integer)).label("ok"),
            )
            .where(PingResult.timestamp >= now - window)
            .group_by(PingResult.host_id)
        )
        for host_id, total, ok in rows:
            if host_id not in uptime_map:
                uptime_map[host_id] = {}
            uptime_map[host_id][key] = round((ok or 0) / total * 100, 1) if total else None

    # Batch: latest result per host (1 query)
    from sqlalchemy import and_
    latest_subq = (
        select(PingResult.host_id, func.max(PingResult.id).label("max_id"))
        .group_by(PingResult.host_id)
    ).subquery()
    latest_rows = (await db.execute(
        select(PingResult).join(latest_subq, PingResult.id == latest_subq.c.max_id)
    )).scalars().all()
    latest_by_host = {r.host_id: r for r in latest_rows}

    # Batch: 30-day heatmap data (1 query — daily aggregates instead of raw rows)
    heatmap_rows = (await db.execute(
        select(
            PingResult.host_id,
            func.date(PingResult.timestamp).label("day"),
            func.count().label("total"),
            func.sum(cast(PingResult.success, Integer)).label("ok"),
        )
        .where(PingResult.timestamp >= window_30d)
        .group_by(PingResult.host_id, func.date(PingResult.timestamp))
    )).all()
    heatmap_agg: dict[int, dict[str, tuple]] = {}
    for row in heatmap_rows:
        heatmap_agg.setdefault(row.host_id, {})[str(row.day)] = (row.total, row.ok or 0)

    for host in hosts:
        latest_result = latest_by_host.get(host.id)
        um = uptime_map.get(host.id, {})
        uptime = um.get("h24") or 0

        # Build heatmap from pre-aggregated daily data
        heatmap = []
        agg = heatmap_agg.get(host.id, {})
        for i in range(30):
            d = (now - timedelta(days=29 - i)).date()
            day_data = agg.get(str(d))
            if day_data:
                total_d, ok_d = day_data
                heatmap.append(round(ok_d / total_d * 100, 1) if total_d > 0 else None)
            else:
                heatmap.append(None)

        host_data.append({
            "host": host,
            "online": latest_result.success if latest_result else None,
            "latency": latest_result.latency_ms if latest_result else None,
            "last_check": latest_result.timestamp if latest_result else None,
            "uptime_pct": uptime,
            "heatmap": heatmap,
        })

    return templates.TemplateResponse("ping.html", {
        "request": request,
        "host_data": host_data,
        "uptime_map": uptime_map,
        "active_page": "ping",
    })


@router.get("/{host_id}", response_class=HTMLResponse)
async def ping_detail(host_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    host = await db.get(PingHost, host_id)
    if not host:
        return RedirectResponse(url="/ping")

    dns_info = await _dns_resolve(host.hostname)

    now = datetime.utcnow()
    window_2h  = now - timedelta(hours=2)
    window_24h = now - timedelta(hours=24)
    window_7d  = now - timedelta(days=7)
    window_15d = now - timedelta(days=15)
    window_30d = now - timedelta(days=30)

    # Fetch 15d of results in one query — used for all chart ranges + SLA
    results_15d_q = await db.execute(
        select(PingResult)
        .where(PingResult.host_id == host_id, PingResult.timestamp >= window_15d)
        .order_by(PingResult.timestamp.asc())
    )
    results_15d_all = results_15d_q.scalars().all()

    # Split into time windows
    results    = [r for r in results_15d_all if r.timestamp >= window_24h]  # 24h subset
    results_2h = [r for r in results_15d_all if r.timestamp >= window_2h]

    def _build_chart(rows, window_start, window_end, fmt="%d.%m %H:%M", max_pts=600):
        """Downsample rows and pad to full window so axis always spans the range."""
        if rows:
            step = max(1, len(rows) // max_pts)
            sampled = rows[::step]
            labels = [r.timestamp.strftime(fmt) for r in sampled]
            values = [round(r.latency_ms, 2) if r.success and r.latency_ms else 0 for r in sampled]
        else:
            labels, values = [], []
        # Prepend window start if not already there
        start_lbl = window_start.strftime(fmt)
        if not labels or labels[0] != start_lbl:
            labels.insert(0, start_lbl)
            values.insert(0, 0)
        # Append window end (now)
        end_lbl = window_end.strftime(fmt)
        if labels[-1] != end_lbl:
            labels.append(end_lbl)
            values.append(values[-1])
        return labels, values

    chart_labels,     chart_latency     = _build_chart(results,         window_24h, now)
    chart_2h_labels,  chart_2h_latency  = _build_chart(results_2h,      window_2h,  now, fmt="%H:%M", max_pts=120)
    chart_15d_labels, chart_15d_latency = _build_chart(results_15d_all, window_15d, now)

    total = len(results)
    success_c = sum(1 for r in results if r.success)
    uptime_24h = round((success_c / total * 100) if total > 0 else 0, 1)
    latencies = [r.latency_ms for r in results if r.success and r.latency_ms is not None]
    avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else None
    min_lat = round(min(latencies), 2) if latencies else None
    max_lat = round(max(latencies), 2) if latencies else None

    # 7d SLA (from 15d cache), 30d needs separate query
    results_7d = [r for r in results_15d_all if r.timestamp >= window_7d]
    uptime_7d = _uptime_pct(results_7d)

    results_30d_q = await db.execute(
        select(PingResult).where(PingResult.host_id == host_id, PingResult.timestamp >= window_30d)
    )
    results_30d = results_30d_q.scalars().all()
    uptime_30d = _uptime_pct(results_30d)
    heatmap_30d = _heatmap_30d(results_30d)

    latest_q = await db.execute(
        select(PingResult)
        .where(PingResult.host_id == host_id)
        .order_by(PingResult.timestamp.desc())
        .limit(1)
    )
    latest = latest_q.scalar_one_or_none()

    # latency threshold alarm
    threshold_alarm = (
        latest is not None
        and latest.success
        and latest.latency_ms is not None
        and host.latency_threshold_ms is not None
        and latest.latency_ms > host.latency_threshold_ms
    )

    # Look up Proxmox metrics for this host (by name or hostname match)
    proxmox_guest = None
    proxmox_history: dict = {}
    px_configs = (await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.type == "proxmox")
    )).scalars().all()
    px_latest = await snap_svc.get_latest_batch(db, "proxmox")
    for cfg in px_configs:
        snap = px_latest.get(cfg.id)
        if not snap or not snap.ok or not snap.data_json:
            continue
        snap_data = json.loads(snap.data_json)
        for g in snap_data.get("vms", []) + snap_data.get("containers", []):
            if g.get("name") in (host.hostname, host.name):
                proxmox_guest = {**g, "cluster_name": cfg.name, "snap_time": snap.timestamp}
                break
        if proxmox_guest:
            hist_snaps = (await db.execute(
                select(Snapshot)
                .where(
                    Snapshot.entity_type == "proxmox",
                    Snapshot.entity_id == cfg.id,
                    Snapshot.ok == True,
                    Snapshot.timestamp >= window_7d,
                )
                .order_by(Snapshot.timestamp.asc())
            )).scalars().all()

            all_px = []
            for hs in hist_snaps:
                hs_data = json.loads(hs.data_json)
                for g in hs_data.get("vms", []) + hs_data.get("containers", []):
                    if g.get("name") in (host.hostname, host.name):
                        mem_total = g.get("mem_total_gb", 0)
                        mem_pct = round(g.get("mem_used_gb", 0) / mem_total * 100, 1) if mem_total > 0 else 0
                        all_px.append({
                            "ts": hs.timestamp,
                            "cpu": g.get("cpu_pct", 0),
                            "mem": mem_pct,
                            "disk": g.get("disk_pct", 0),
                        })
                        break

            def _px_range(rows, fmt, max_pts=300):
                step = max(1, len(rows) // max_pts)
                sampled = rows[::step]
                return {
                    "labels": [r["ts"].strftime(fmt) for r in sampled],
                    "cpu":    [r["cpu"]  for r in sampled],
                    "mem":    [r["mem"]  for r in sampled],
                    "disk":   [r["disk"] for r in sampled],
                }

            rows_2h  = [r for r in all_px if r["ts"] >= window_2h]
            rows_24h = [r for r in all_px if r["ts"] >= window_24h]
            proxmox_history = {
                "2h":  _px_range(rows_2h,  "%H:%M", 120),
                "24h": _px_range(rows_24h, "%H:%M", 288),
                "7d":  _px_range(all_px,   "%d.%m %H:%M", 504),
            }
            break

    # Look up UniFi client info by host IP or MAC
    unifi_client = None
    host_ip  = (dns_info.get("ip") or "").strip()
    host_mac = (host.mac_address or "").strip().lower()

    unifi_latest = await snap_svc.get_latest_batch(db, "unifi")
    for snap in unifi_latest.values():
        if not snap or not snap.ok or not snap.data_json:
            continue
        try:
            ud = json.loads(snap.data_json)
            for c in ud.get("clients", []) + [
                {**d, "_is_device": True} for d in ud.get("devices", [])
            ]:
                c_ip  = (c.get("ip") or "").strip()
                c_mac = (c.get("mac") or "").strip().lower()
                if (host_ip and c_ip == host_ip) or (host_mac and c_mac == host_mac):
                    unifi_client = c
                    break
        except Exception:
            pass
        if unifi_client:
            break

    # Syslog message count (24h) – match by host_id, source_ip, or hostname
    syslog_count = 0
    try:
        since_24h = datetime.utcnow() - timedelta(hours=24)
        syslog_filter = SyslogMessage.host_id == host.id
        # Also match by IP or hostname for messages without host_id
        raw_host = host.hostname
        for prefix in ("https://", "http://"):
            if raw_host.startswith(prefix):
                raw_host = raw_host[len(prefix):]
        raw_host = raw_host.split("/")[0].split(":")[0]
        syslog_filter = syslog_filter | (SyslogMessage.source_ip == raw_host)
        if host.name:
            syslog_filter = syslog_filter | (SyslogMessage.hostname.ilike(host.name))
        syslog_count = (await db.execute(
            select(func.count(SyslogMessage.id))
            .where(syslog_filter, SyslogMessage.timestamp >= since_24h)
        )).scalar() or 0
    except Exception:
        pass

    # ── Health score (same formula as dashboard gravity well) ───────────────
    _online = latest.success if latest else None
    _lat = latest.latency_ms if latest else None
    _thr = host.latency_threshold_ms
    if _online is False:
        health_score = 1.0
    elif host.maintenance:
        health_score = 0.5
    elif _online is None:
        health_score = 0.8
    else:
        _hs = 0.0
        if _lat is not None and _thr:
            r = _lat / _thr
            if r <= 0.5: _hs += r * 0.05
            elif r <= 0.8: _hs += 0.025 + (r - 0.5) / 0.3 * 0.075
            elif r <= 1.0: _hs += 0.10 + (r - 0.8) / 0.2 * 0.10
            else: _hs += 0.20
        elif _lat is not None:
            _hs += min(_lat / 200.0, 0.20)
        deficit = 1 - uptime_24h / 100.0
        if deficit > 0: _hs += min((deficit ** 0.5) * 0.15, 0.15)
        # Packet loss from last 20 results
        recent = results[-20:] if results else []
        if recent:
            losses = sum(1 for r in recent if not r.success)
            if losses > 0: _hs += min((losses / len(recent)) ** 0.6 * 0.10, 0.10)
        # Proxmox guest metrics
        if proxmox_guest:
            from database import get_setting as _gs
            _cpu_t = int(await _gs(db, "proxmox_cpu_threshold", "85"))
            _ram_t = int(await _gs(db, "proxmox_ram_threshold", "85"))
            _disk_t = int(await _gs(db, "proxmox_disk_threshold", "90"))
            for metric, threshold, weight in [
                (proxmox_guest.get("cpu_pct", 0), _cpu_t, 0.15),
                ((proxmox_guest.get("mem_used_gb", 0) / max(proxmox_guest.get("mem_total_gb", 1), 0.01)) * 100, _ram_t, 0.15),
                (proxmox_guest.get("disk_pct", 0), _disk_t, 0.10),
            ]:
                r = metric / threshold if threshold else 0
                if r <= 0.5: _hs += r * (weight * 0.2)
                elif r <= 0.8: _hs += weight * 0.1 + (r - 0.5) / 0.3 * (weight * 0.4)
                elif r <= 1.0: _hs += weight * 0.5 + (r - 0.8) / 0.2 * (weight * 0.5)
                else: _hs += weight
        # Syslog errors
        if syslog_count > 0:
            _hs += min((syslog_count ** 0.4) / 10.0 * 0.10, 0.10)
        health_score = round(min(_hs, 1.0), 3)
    health_pct = round((1 - health_score) * 100)

    # ── Agent metrics (if an agent reports for this host) ────────────────────
    agent_data = None
    agent_snapshots = []
    # Try matching by hostname, name, or IP
    _host_matches = [host.hostname.lower(), host.name.lower()]
    if dns_info.get("ip"):
        _host_matches.append(dns_info["ip"].lower())
    agent_obj = None
    for _match in _host_matches:
        if agent_obj:
            break
        agent_obj = (await db.execute(
            select(Agent).where(func.lower(Agent.hostname) == _match)
        )).scalar_one_or_none()
    if agent_obj:
        snaps_q = await db.execute(
            select(AgentSnapshot)
            .where(AgentSnapshot.agent_id == agent_obj.id)
            .order_by(AgentSnapshot.timestamp.desc())
            .limit(60)
        )
        agent_snapshots = list(reversed(snaps_q.scalars().all()))
        if agent_snapshots:
            latest_snap = agent_snapshots[-1]
            agent_data = json.loads(latest_snap.data_json) if latest_snap.data_json else {}
            agent_data["_snap"] = latest_snap
            agent_data["_agent"] = agent_obj
            agent_data["_online"] = (
                agent_obj.last_seen and
                (datetime.utcnow() - agent_obj.last_seen).total_seconds() < 120
            )

    return templates.TemplateResponse("ping_detail.html", {
        "request": request,
        "host": host,
        "dns_info": dns_info,
        "latest": latest,
        "uptime_pct": uptime_24h,
        "health_pct": health_pct,
        "uptime_7d": uptime_7d,
        "uptime_30d": uptime_30d,
        "avg_latency": avg_lat,
        "min_latency": min_lat,
        "max_latency": max_lat,
        "chart_labels": chart_labels,
        "chart_latency": chart_latency,
        "chart_2h_labels": chart_2h_labels,
        "chart_2h_latency": chart_2h_latency,
        "chart_15d_labels": chart_15d_labels,
        "chart_15d_latency": chart_15d_latency,
        "heatmap_30d": heatmap_30d,
        "threshold_alarm": threshold_alarm,
        "proxmox_guest": proxmox_guest,
        "proxmox_history": proxmox_history,
        "unifi_client": unifi_client,
        "syslog_count": syslog_count,
        "agent_data": agent_data,
        "agent_snapshots": agent_snapshots,
        "all_hosts": (await db.execute(
            select(PingHost).where(PingHost.id != host.id).order_by(PingHost.name)
        )).scalars().all(),
        "active_page": "ping",
        "saved": request.query_params.get("saved"),
        "active_tab": request.query_params.get("tab", "info"),
    })


# ── CRUD actions ───────────────────────────────────────────────────────────────

@router.post("/add")
async def add_ping_host(
    name: str = Form(...),
    hostname: str = Form(...),
    check_types: List[str] = Form(default=["icmp"]),
    port: str = Form(""),
    latency_threshold_ms: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    check_type = ",".join(t.strip() for t in check_types if t.strip()) or "icmp"
    db.add(PingHost(
        name=name.strip(),
        hostname=hostname.strip(),
        check_type=check_type,
        port=int(port) if port.strip() else None,
        latency_threshold_ms=float(latency_threshold_ms) if latency_threshold_ms.strip() else None,
    ))
    await db.commit()
    return RedirectResponse(url="/ping", status_code=303)


@router.post("/{host_id}/edit")
async def edit_ping_host(
    host_id: int,
    name: str = Form(...),
    hostname: str = Form(...),
    check_types: List[str] = Form(default=["icmp"]),
    port: str = Form(""),
    latency_threshold_ms: str = Form(""),
    parent_id: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    host = await db.get(PingHost, host_id)
    if host:
        host.name = name.strip()
        host.hostname = hostname.strip()
        host.check_type = ",".join(t.strip() for t in check_types if t.strip()) or "icmp"
        host.port = int(port) if port.strip() else None
        host.latency_threshold_ms = float(latency_threshold_ms) if latency_threshold_ms.strip() else None
        host.parent_id = int(parent_id) if parent_id.strip() else None
        await db.commit()
    return RedirectResponse(url=f"/ping/{host_id}?tab=info&saved=1", status_code=303)


@router.post("/{host_id}/delete")
async def delete_ping_host(host_id: int, db: AsyncSession = Depends(get_db)):
    host = await db.get(PingHost, host_id)
    if host:
        await db.delete(host)
        await db.commit()
    return RedirectResponse(url="/ping", status_code=303)


@router.post("/{host_id}/toggle")
async def toggle_ping_host(host_id: int, db: AsyncSession = Depends(get_db)):
    host = await db.get(PingHost, host_id)
    if host:
        host.enabled = not host.enabled
        await db.commit()
    return RedirectResponse(url=f"/ping/{host_id}?tab=info", status_code=303)


@router.post("/{host_id}/maintenance")
async def toggle_maintenance(host_id: int, db: AsyncSession = Depends(get_db)):
    host = await db.get(PingHost, host_id)
    if host:
        host.maintenance = not host.maintenance
        await db.commit()
    return RedirectResponse(url=f"/ping/{host_id}?tab=info", status_code=303)
