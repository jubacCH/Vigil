import json
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    PingHost, PingResult,
    ProxmoxCluster, ProxmoxSnapshot,
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
    get_db, get_setting, set_setting, is_setup_complete, decrypt_value,
)
from models.integration import IntegrationConfig, Snapshot
from services import integration as int_svc
from services import snapshot as snap_svc

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# ── Default dashboard widget layout (gridstack 12-col, cellHeight=40px) ──────
VALID_WIDGET_IDS = {
    "integrations", "syslog", "gravity", "offline", "hosts", "proxmox", "top10",
    "speedtest", "heatmap", "storage", "containers", "ups", "ssl", "alerts",
    "uptime", "clock", "quickstats",
}
DEFAULT_LAYOUT = [
    {"id": "integrations", "x": 0, "y": 0,  "w": 6,  "h": 4},
    {"id": "syslog",       "x": 6, "y": 0,  "w": 6,  "h": 4},
    {"id": "gravity",      "x": 0, "y": 4,  "w": 12, "h": 12},
    {"id": "offline",      "x": 0, "y": 16, "w": 12, "h": 6},
    {"id": "hosts",        "x": 0, "y": 22, "w": 12, "h": 8},
    {"id": "proxmox",      "x": 0, "y": 30, "w": 12, "h": 6},
    {"id": "top10",        "x": 0, "y": 36, "w": 12, "h": 12},
]


# ── Helper: build integration_health from new generic tables ─────────────────

_INTEGRATION_META = {
    "proxmox":      {"label": "Proxmox",        "color": "orange",  "url_prefix": "/proxmox"},
    "unifi":        {"label": "UniFi",           "color": "blue",    "url_prefix": "/unifi"},
    "unas":         {"label": "UniFi NAS",       "color": "cyan",    "url_prefix": "/unas"},
    "pihole":       {"label": "Pi-hole",         "color": "red",     "url_prefix": "/pihole"},
    "adguard":      {"label": "AdGuard",         "color": "emerald", "url_prefix": "/adguard"},
    "portainer":    {"label": "Portainer",       "color": "teal",    "url_prefix": "/portainer"},
    "truenas":      {"label": "TrueNAS",         "color": "slate",   "url_prefix": "/truenas"},
    "synology":     {"label": "Synology",        "color": "blue",    "url_prefix": "/synology"},
    "firewall":     {"label": "Firewall",        "color": "orange",  "url_prefix": "/firewall"},
    "hass":         {"label": "Home Assistant",   "color": "orange",  "url_prefix": "/hass"},
    "gitea":        {"label": "Gitea",           "color": "green",   "url_prefix": "/gitea"},
    "phpipam":      {"label": "phpIPAM",         "color": "purple",  "url_prefix": "/phpipam"},
    "speedtest":    {"label": "Speedtest",       "color": "blue",    "url_prefix": "/speedtest"},
    "ups":          {"label": "UPS / NUT",       "color": "yellow",  "url_prefix": "/ups"},
    "redfish":      {"label": "Redfish",         "color": "purple",  "url_prefix": "/redfish"},
}


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    if not await is_setup_complete(db):
        return RedirectResponse(url="/setup")

    now = datetime.utcnow()
    window_24h = now - timedelta(hours=24)

    # ── Global thresholds (read once, used throughout) ─────────────────────────
    global_latency_threshold = await get_setting(db, "latency_threshold_ms", "")
    global_latency_ms = int(global_latency_threshold) if global_latency_threshold.strip() else None
    px_cpu_threshold     = int(await get_setting(db, "proxmox_cpu_threshold", "85"))
    px_ram_pct_threshold = int(await get_setting(db, "proxmox_ram_threshold", "85"))
    px_disk_threshold    = int(await get_setting(db, "proxmox_disk_threshold", "90"))

    # ── Ping hosts (batch queries instead of N+1) ───────────────────────────
    hosts_result = await db.execute(select(PingHost).where(PingHost.enabled == True))
    hosts = hosts_result.scalars().all()
    host_ids = [h.id for h in hosts]

    window_2h = now - timedelta(hours=2)
    host_stats = []
    ping_alarms: list[dict] = []

    # Batch 1: latest result per host (single query)
    latest_by_host: dict[int, PingResult] = {}
    if host_ids:
        latest_sub = (
            select(PingResult.host_id, func.max(PingResult.id).label("max_id"))
            .where(PingResult.host_id.in_(host_ids))
            .group_by(PingResult.host_id)
            .subquery()
        )
        latest_rows = (await db.execute(
            select(PingResult).join(latest_sub, PingResult.id == latest_sub.c.max_id)
        )).scalars().all()
        latest_by_host = {r.host_id: r for r in latest_rows}

    # Batch 2: 24h stats per host (total, success, avg latency) in one query
    stats_by_host: dict[int, dict] = {}
    if host_ids:
        stats_rows = (await db.execute(
            select(
                PingResult.host_id,
                func.count().label("total"),
                func.count().filter(PingResult.success == True).label("success"),
                func.avg(PingResult.latency_ms).filter(PingResult.success == True).label("avg_lat"),
            )
            .where(PingResult.host_id.in_(host_ids), PingResult.timestamp >= window_24h)
            .group_by(PingResult.host_id)
        )).all()
        for row in stats_rows:
            stats_by_host[row.host_id] = {
                "total": row.total,
                "success": row.success,
                "avg_lat": row.avg_lat,
            }

    # Batch 3: sparkline data (last 2h) – fetch all at once, group in Python
    sparklines_by_host: dict[int, list] = defaultdict(list)
    if host_ids:
        spark_rows = (await db.execute(
            select(PingResult.host_id, PingResult.success, PingResult.latency_ms)
            .where(PingResult.host_id.in_(host_ids), PingResult.timestamp >= window_2h)
            .order_by(PingResult.host_id, PingResult.timestamp.asc())
        )).all()
        for row in spark_rows:
            sparklines_by_host[row.host_id].append(
                row.latency_ms if row.success else None
            )
        # Limit to 60 points per host
        for hid in sparklines_by_host:
            sparklines_by_host[hid] = sparklines_by_host[hid][-60:]

    for host in hosts:
        latest_row = latest_by_host.get(host.id)
        st = stats_by_host.get(host.id, {"total": 0, "success": 0, "avg_lat": None})
        total_count = st["total"]
        success_count = st["success"]
        avg_latency_raw = st["avg_lat"]
        sparkline = sparklines_by_host.get(host.id, [])

        avg_latency = round(avg_latency_raw, 2) if avg_latency_raw is not None else None
        uptime_pct = round((success_count / total_count * 100) if total_count > 0 else 0, 1)

        # Latency threshold alarm (skip maintenance hosts)
        effective_threshold = host.latency_threshold_ms if host.latency_threshold_ms is not None else global_latency_ms
        if (
            not host.maintenance
            and latest_row and latest_row.success
            and latest_row.latency_ms is not None
            and effective_threshold is not None
            and latest_row.latency_ms > effective_threshold
        ):
            ping_alarms.append({
                "name": host.name,
                "hostname": host.hostname,
                "latency": latest_row.latency_ms,
                "threshold": effective_threshold,
                "host_id": host.id,
            })

        # Health score for gravity well (0.0 = perfect, 1.0 = critical)
        _online = latest_row.success if latest_row else None
        _lat = latest_row.latency_ms if latest_row else None
        if _online is False:
            health_score = 1.0
        elif host.maintenance:
            health_score = 0.5
        elif _online is None:
            health_score = 0.8
        else:
            score = 0.0
            # Latency vs threshold (weight 0.4)
            if _lat is not None and effective_threshold:
                score += min(_lat / effective_threshold, 2.0) * 0.2
            elif _lat is not None:
                score += min(_lat / 100.0, 1.0) * 0.2
            # Uptime deficit (weight 0.3): 100% → 0, 95% → 0.15, 90% → 0.3
            score += (1 - uptime_pct / 100.0) * 0.3
            # Packet loss from sparkline (weight 0.3)
            if sparkline:
                losses = sum(1 for v in sparkline if v is None)
                score += (losses / len(sparkline)) * 0.3
            health_score = round(min(score, 1.0), 3)

        host_stats.append({
            "host": host,
            "online": _online,
            "latency": _lat,
            "uptime_pct": uptime_pct,
            "avg_latency": avg_latency,
            "last_check": latest_row.timestamp if latest_row else None,
            "sparkline": sparkline,
            "health_score": health_score,
        })

    # Exclude maintenance hosts from counts and Top-10
    active_stats = [s for s in host_stats if not s["host"].maintenance]
    online_count  = sum(1 for s in active_stats if s["online"])
    offline_count = sum(1 for s in active_stats if s["online"] is False)

    # ── Top 10 Ping ───────────────────────────────────────────────────────────
    with_latency = [s for s in active_stats if s["avg_latency"] is not None]
    top_latency  = sorted(with_latency, key=lambda s: s["avg_latency"], reverse=True)[:10]
    top_downtime = sorted(active_stats, key=lambda s: s["uptime_pct"])[:10]

    # ── Proxmox clusters ────────────────────────────────────────────────────
    # Try new generic tables first, fall back to old ProxmoxCluster table
    px_configs_result = await db.execute(
        select(IntegrationConfig)
        .where(IntegrationConfig.type == "proxmox")
        .order_by(IntegrationConfig.name)
    )
    px_configs = px_configs_result.scalars().all()
    _use_new_px = len(px_configs) > 0

    if _use_new_px:
        class _PxCluster:
            def __init__(self, cfg):
                self.id = cfg.id
                self.name = cfg.name
                try:
                    d = int_svc.decrypt_config(cfg.config_json)
                    self.host = d.get("host", "")
                except Exception:
                    self.host = ""
        proxmox_clusters = [_PxCluster(c) for c in px_configs]
    else:
        px_result = await db.execute(select(ProxmoxCluster).order_by(ProxmoxCluster.name))
        proxmox_clusters = px_result.scalars().all()

    anomaly_threshold = float(await get_setting(db, "anomaly_threshold", "2.0"))

    all_guests: list[dict] = []
    anomalies:  list[dict] = []   # Statistical deviations (current >> historical mean)
    warnings:   list[dict] = []   # Absolute threshold breaches (always above limit)

    if _use_new_px:
        px_snapshots = await snap_svc.get_latest_batch(db, "proxmox")
    else:
        px_snapshots = {}

    for cluster in proxmox_clusters:
        if _use_new_px:
            latest_snap = px_snapshots.get(cluster.id)
            if not latest_snap or not latest_snap.ok or not latest_snap.data_json:
                continue
            latest_data = json.loads(latest_snap.data_json)
        else:
            latest_snap = (await db.execute(
                select(ProxmoxSnapshot)
                .where(ProxmoxSnapshot.cluster_id == cluster.id, ProxmoxSnapshot.ok == True)
                .order_by(ProxmoxSnapshot.timestamp.desc())
                .limit(1)
            )).scalar_one_or_none()
            if not latest_snap or not latest_snap.data_json:
                continue
            latest_data = json.loads(latest_snap.data_json)

        guests_now = latest_data.get("vms", []) + latest_data.get("containers", [])

        # Historical snapshots for anomaly baseline
        if _use_new_px:
            hist_snaps = (await db.execute(
                select(Snapshot)
                .where(
                    Snapshot.entity_type == "proxmox",
                    Snapshot.entity_id == cluster.id,
                    Snapshot.ok == True,
                    Snapshot.timestamp >= window_24h,
                    Snapshot.timestamp < latest_snap.timestamp,
                )
            )).scalars().all()
        else:
            hist_snaps = (await db.execute(
                select(ProxmoxSnapshot)
                .where(
                    ProxmoxSnapshot.cluster_id == cluster.id,
                    ProxmoxSnapshot.ok == True,
                    ProxmoxSnapshot.timestamp >= window_24h,
                    ProxmoxSnapshot.timestamp < latest_snap.timestamp,
                )
            )).scalars().all()

        # Sort historical snapshots by time (oldest first) so recent slicing works
        hist_snaps_sorted = sorted(hist_snaps, key=lambda s: s.timestamp)

        # Build per-guest time series from ALL historical snapshots
        hist: dict[int, dict] = defaultdict(lambda: {"cpu": [], "mem": []})
        for snap in hist_snaps_sorted:
            snap_data = json.loads(snap.data_json)
            for g in snap_data.get("vms", []) + snap_data.get("containers", []):
                gid = g.get("id")
                if gid is not None:
                    hist[gid]["cpu"].append(g.get("cpu_pct", 0))
                    hist[gid]["mem"].append(g.get("mem_used_gb", 0))

        # Stddev floors to prevent micro-fluctuations from triggering anomalies
        CPU_STD_FLOOR = 3.0    # minimum 3% stddev
        MEM_STD_FLOOR = 0.3    # minimum 0.3 GB stddev
        SUSTAINED_WINDOW = 5   # check last N snapshots
        SUSTAINED_MIN = 3      # require at least this many above threshold

        for g in guests_now:
            gid = g.get("id")
            all_guests.append({**g, "cluster_name": cluster.name})
            cur_cpu  = g.get("cpu_pct", 0)
            cur_mem  = g.get("mem_used_gb", 0)
            mem_total = g.get("mem_total_gb", 0)
            cur_mem_pct = round(cur_mem / mem_total * 100, 1) if mem_total > 0 else 0

            # ── Statistical anomalies (sustained deviation from baseline) ──
            if gid in hist and len(hist[gid]["cpu"]) >= 6:
                all_cpu = hist[gid]["cpu"]
                mean_cpu = sum(all_cpu) / len(all_cpu)
                std_cpu = max((sum((x - mean_cpu) ** 2 for x in all_cpu) / len(all_cpu)) ** 0.5, CPU_STD_FLOOR)
                if cur_cpu > 10 and mean_cpu > 0:
                    # Check last N snapshots + current for sustained anomaly
                    recent_values = all_cpu[-SUSTAINED_WINDOW:] + [cur_cpu]
                    anomalous_count = sum(1 for v in recent_values if (v - mean_cpu) / std_cpu >= anomaly_threshold)
                    if anomalous_count >= SUSTAINED_MIN:
                        z_score = (cur_cpu - mean_cpu) / std_cpu
                        # Severity: combines z-score magnitude with how sustained it is
                        severity = round(z_score * (anomalous_count / len(recent_values)), 1)
                        anomalies.append({
                            "name": g["name"], "type": g["type"], "node": g["node"],
                            "cluster_name": cluster.name, "metric": "CPU",
                            "current": cur_cpu, "mean": round(mean_cpu, 1),
                            "factor": round(z_score, 1),
                            "sustained": anomalous_count,
                            "severity": severity,
                        })

            if gid in hist and len(hist[gid]["mem"]) >= 6:
                all_mem = hist[gid]["mem"]
                mean_mem = sum(all_mem) / len(all_mem)
                std_mem = max((sum((x - mean_mem) ** 2 for x in all_mem) / len(all_mem)) ** 0.5, MEM_STD_FLOOR)
                if cur_mem > 0.5 and mean_mem > 0:
                    recent_values = all_mem[-SUSTAINED_WINDOW:] + [cur_mem]
                    anomalous_count = sum(1 for v in recent_values if (v - mean_mem) / std_mem >= anomaly_threshold)
                    if anomalous_count >= SUSTAINED_MIN:
                        z_score = (cur_mem - mean_mem) / std_mem
                        severity = round(z_score * (anomalous_count / len(recent_values)), 1)
                        anomalies.append({
                            "name": g["name"], "type": g["type"], "node": g["node"],
                            "cluster_name": cluster.name, "metric": "RAM",
                            "current": round(cur_mem, 2), "mean": round(mean_mem, 2),
                            "factor": round(z_score, 1),
                            "sustained": anomalous_count,
                            "severity": severity,
                        })

            # ── Absolute threshold warnings (persistent resource pressure) ──
            if cur_cpu >= px_cpu_threshold:
                warnings.append({
                    "name": g["name"], "type": g["type"], "node": g["node"],
                    "cluster_name": cluster.name, "metric": "CPU",
                    "current": cur_cpu, "threshold": px_cpu_threshold,
                })
            if cur_mem_pct >= px_ram_pct_threshold:
                warnings.append({
                    "name": g["name"], "type": g["type"], "node": g["node"],
                    "cluster_name": cluster.name, "metric": "RAM",
                    "current": cur_mem_pct, "threshold": px_ram_pct_threshold,
                })
            disk_pct = g.get("disk_pct", 0)
            if disk_pct >= px_disk_threshold:
                warnings.append({
                    "name": g["name"], "type": g["type"], "node": g["node"],
                    "cluster_name": cluster.name, "metric": "Disk",
                    "current": disk_pct, "threshold": px_disk_threshold,
                })

    # Merge ping alarms into anomalies list
    for pa in ping_alarms:
        anomalies.append({
            "name": pa["name"], "type": "Host", "node": pa["hostname"],
            "cluster_name": "Ping", "metric": "Latency",
            "current": pa["latency"], "mean": pa["threshold"], "factor": None,
            "host_id": pa["host_id"],
            "sustained": None, "severity": 99,  # ping alarms always high priority
        })

    # Sort anomalies by severity (highest first)
    anomalies.sort(key=lambda a: a.get("severity", 0), reverse=True)

    running_guests = [g for g in all_guests if g.get("running")]
    top_cpu  = sorted(running_guests, key=lambda g: g.get("cpu_pct", 0), reverse=True)[:10]
    top_ram  = sorted(running_guests, key=lambda g: g.get("mem_used_gb", 0), reverse=True)[:10]
    top_disk = sorted(
        [g for g in running_guests if g.get("disk_total_gb", 0) > 0],
        key=lambda g: g.get("disk_pct", 0),
        reverse=True,
    )[:10]

    # Build name/hostname -> PingHost.id map for linking Proxmox VMs to host objects
    all_ph = (await db.execute(select(PingHost))).scalars().all()
    ping_host_map: dict[str, int] = {}
    for h in all_ph:
        # Exact matches
        ping_host_map[h.hostname] = h.id
        ping_host_map.setdefault(h.name, h.id)
        # Lowercase matches
        ping_host_map.setdefault(h.hostname.lower(), h.id)
        ping_host_map.setdefault(h.name.lower(), h.id)
        # Strip URL parts for hostname matching (https://host:port/path → host)
        raw = h.hostname
        for pfx in ("https://", "http://"):
            if raw.startswith(pfx):
                raw = raw[len(pfx):]
                break
        short_host = raw.split("/")[0].split(":")[0]
        ping_host_map.setdefault(short_host, h.id)
        ping_host_map.setdefault(short_host.lower(), h.id)
        # Also map short hostname (before first dot) for FQDN matching
        if "." in short_host:
            ping_host_map.setdefault(short_host.split(".")[0].lower(), h.id)

    # Pre-fetch all integration configs (used by topology + integration health)
    all_configs_result = await db.execute(
        select(IntegrationConfig).order_by(IntegrationConfig.type, IntegrationConfig.name)
    )
    all_configs = all_configs_result.scalars().all()

    # ── Build topology tree ──────────────────────────────────────────────────
    # Map host id -> parent_id using: 1) DB parent_id, 2) Proxmox VM/LXC → node
    topology: dict[int, int | None] = {}  # child_id → parent_id
    host_by_id = {h.id: h for h in all_ph}

    # First pass: use DB parent_id
    for h in all_ph:
        topology[h.id] = getattr(h, 'parent_id', None)

    # Second pass: auto-detect Proxmox VM/LXC → Proxmox node relationships
    # Find all Proxmox node hostnames in PingHosts
    px_node_names: set[str] = set()
    for cluster in proxmox_clusters:
        if _use_new_px:
            snap = px_snapshots.get(cluster.id)
            if not snap or not snap.ok or not snap.data_json:
                continue
            d = json.loads(snap.data_json)
        else:
            continue
        for node_info in d.get("nodes", []):
            px_node_names.add(node_info.get("node", ""))
        # Map VM/LXC name → node name
        for g in d.get("vms", []) + d.get("containers", []):
            guest_name = (g.get("name") or "").strip()
            node_name = (g.get("node") or "").strip()
            if not guest_name or not node_name:
                continue
            # Find the PingHost for this guest (try exact, lowercase, and short name)
            guest_ph_id = (ping_host_map.get(guest_name)
                           or ping_host_map.get(guest_name.lower()))
            # Find the PingHost for the Proxmox node
            node_ph_id = (ping_host_map.get(node_name)
                          or ping_host_map.get(node_name.lower()))
            if guest_ph_id and node_ph_id and guest_ph_id != node_ph_id:
                # Only auto-link if no manual parent_id is set
                if topology.get(guest_ph_id) is None:
                    topology[guest_ph_id] = node_ph_id

    # Third pass: auto-detect UniFi device hierarchy (Gateway → Switch → AP)
    # Build IP → PingHost.id map for UniFi matching
    ip_to_ph: dict[str, int] = {}
    for h in all_ph:
        raw = h.hostname
        for pfx in ("https://", "http://"):
            if raw.startswith(pfx):
                raw = raw[len(pfx):]
                break
        raw = raw.split("/")[0].split(":")[0]
        ip_to_ph[raw] = h.id
        ip_to_ph[h.name] = h.id

    unifi_configs = [c for c in all_configs if c.type == "unifi"]
    if unifi_configs:
        unifi_snaps = await snap_svc.get_latest_batch(db, "unifi")
        for ucfg in unifi_configs:
            usnap = unifi_snaps.get(ucfg.id)
            if not usnap or not usnap.ok or not usnap.data_json:
                continue
            ud = json.loads(usnap.data_json)
            devices = ud.get("devices", [])
            # Find gateway/router PingHost id
            gw_ph_id = None
            sw_ph_ids: list[int] = []
            ap_ph_ids: list[int] = []
            for dev in devices:
                dev_ip = (dev.get("ip") or "").strip()
                dev_name = (dev.get("name") or "").strip()
                dtype = dev.get("type", "")
                ph_id = ip_to_ph.get(dev_ip) or ip_to_ph.get(dev_name) or ping_host_map.get(dev_name)
                if not ph_id:
                    continue
                if dtype in ("ugw", "usg", "udm", "udmpro", "uxg"):
                    gw_ph_id = ph_id
                elif dtype == "usw":
                    sw_ph_ids.append(ph_id)
                elif dtype == "uap":
                    ap_ph_ids.append(ph_id)
            # Link: switches → gateway, APs → first switch (or gateway)
            if gw_ph_id:
                for sw_id in sw_ph_ids:
                    if topology.get(sw_id) is None:
                        topology[sw_id] = gw_ph_id
                parent_for_ap = sw_ph_ids[0] if sw_ph_ids else gw_ph_id
                for ap_id in ap_ph_ids:
                    if topology.get(ap_id) is None:
                        topology[ap_id] = parent_for_ap

    # ── Integration health ──────────────────────────────────────────────────
    integration_health = []
    # Filter out proxmox (shown separately)
    non_px_configs = [c for c in all_configs if c.type != "proxmox"]

    if non_px_configs:
        all_snaps = await snap_svc.get_latest_batch_all(db)
        for cfg in non_px_configs:
            meta = _INTEGRATION_META.get(cfg.type, {"label": cfg.type, "color": "slate", "url_prefix": f"/{cfg.type}"})
            snap = all_snaps.get(cfg.type, {}).get(cfg.id)
            url = f"{meta['url_prefix']}/{cfg.id}" if cfg.type != "speedtest" else meta["url_prefix"]
            integration_health.append({
                "label": meta["label"],
                "name": cfg.name,
                "url": url,
                "color": meta["color"],
                "ok": snap.ok if snap else None,
                "error": snap.error if snap and not snap.ok else None,
                "cached_at": snap.timestamp if snap else None,
            })
    else:
        # Fall back to old per-integration tables
        for label, config_model, snap_model, snap_fk, url_prefix, color in [
            ("UniFi",         UnifiController,   UnifiSnapshot,     "controller_id", "/unifi",     "blue"),
            ("UniFi NAS",     UnasServer,        UnasSnapshot,      "server_id",     "/unas",      "cyan"),
            ("Pi-hole",       PiholeInstance,    PiholeSnapshot,    "instance_id",   "/pihole",    "red"),
            ("AdGuard",       AdguardInstance,   AdguardSnapshot,   "instance_id",   "/adguard",   "emerald"),
            ("Portainer",     PortainerInstance, PortainerSnapshot, "instance_id",   "/portainer", "teal"),
            ("TrueNAS",       TruenasServer,     TruenasSnapshot,   "server_id",     "/truenas",   "slate"),
            ("Synology",      SynologyServer,    SynologySnapshot,  "server_id",     "/synology",  "blue"),
            ("Firewall",      FirewallInstance,  FirewallSnapshot,  "instance_id",   "/firewall",  "orange"),
            ("Home Assistant",HassInstance,      HassSnapshot,      "instance_id",   "/hass",      "orange"),
            ("Gitea",         GiteaInstance,     GiteaSnapshot,     "instance_id",   "/gitea",     "green"),
            ("UPS / NUT",     NutInstance,       NutSnapshot,       "instance_id",   "/ups",       "yellow"),
            ("Redfish",       RedfishServer,     RedfishSnapshot,   "server_id",     "/redfish",   "purple"),
        ]:
            instances = (await db.execute(select(config_model))).scalars().all()
            if not instances:
                continue
            for inst in instances:
                snap = (await db.execute(
                    select(snap_model)
                    .where(getattr(snap_model, snap_fk) == inst.id)
                    .order_by(snap_model.timestamp.desc())
                    .limit(1)
                )).scalar_one_or_none()
                integration_health.append({
                    "label": label,
                    "name": inst.name,
                    "url": f"{url_prefix}/{inst.id}",
                    "color": color,
                    "ok": snap.ok if snap else None,
                    "error": snap.error if snap and not snap.ok else None,
                    "cached_at": snap.timestamp if snap else None,
                })
        # Speedtest
        for st in (await db.execute(select(SpeedtestConfig))).scalars().all():
            snap = (await db.execute(
                select(SpeedtestResult)
                .where(SpeedtestResult.config_id == st.id)
                .order_by(SpeedtestResult.timestamp.desc())
                .limit(1)
            )).scalar_one_or_none()
            integration_health.append({
                "label": "Speedtest",
                "name": st.name,
                "url": "/speedtest",
                "color": "blue",
                "ok": snap.ok if snap else None,
                "error": snap.error if snap and not snap.ok else None,
                "cached_at": snap.timestamp if snap else None,
            })

    # Active incidents
    from models.incident import Incident
    active_incidents = (await db.execute(
        select(Incident)
        .where(Incident.status.in_(["open", "acknowledged"]))
        .order_by(Incident.created_at.desc())
        .limit(5)
    )).scalars().all()

    # ── Syslog stats (last 24h) ──────────────────────────────────────────────
    from models.syslog import SyslogMessage, SEVERITY_LABELS
    syslog_stats = {"total": 0, "by_severity": {}, "top_sources": [], "error_rate_1h": 0}
    try:
        syslog_stats["total"] = (await db.execute(
            select(func.count(SyslogMessage.id))
            .where(SyslogMessage.timestamp >= window_24h)
        )).scalar() or 0

        sev_rows = (await db.execute(
            select(SyslogMessage.severity, func.count(SyslogMessage.id).label("cnt"))
            .where(SyslogMessage.timestamp >= window_24h)
            .group_by(SyslogMessage.severity)
            .order_by(SyslogMessage.severity)
        )).all()
        syslog_stats["by_severity"] = {
            row.severity: {"count": row.cnt, "label": SEVERITY_LABELS.get(row.severity, f"Sev {row.severity}")}
            for row in sev_rows if row.severity is not None
        }

        src_rows = (await db.execute(
            select(SyslogMessage.source_ip, func.count(SyslogMessage.id).label("cnt"))
            .where(SyslogMessage.timestamp >= window_24h)
            .group_by(SyslogMessage.source_ip)
            .order_by(func.count(SyslogMessage.id).desc())
            .limit(5)
        )).all()
        syslog_stats["top_sources"] = [{"ip": row.source_ip, "count": row.cnt} for row in src_rows]

        window_1h = now - timedelta(hours=1)
        syslog_stats["error_rate_1h"] = (await db.execute(
            select(func.count(SyslogMessage.id))
            .where(SyslogMessage.severity <= 3, SyslogMessage.timestamp >= window_1h)
        )).scalar() or 0
    except Exception:
        pass  # syslog table may not exist yet

    # ── Speedtest (latest + 24h history) ─────────────────────────────────────
    speedtest_data = None
    speedtest_history = []
    try:
        st_configs = [c for c in all_configs if c.type == "speedtest"]
        if st_configs:
            st_snap = (await snap_svc.get_latest_batch(db, "speedtest")).get(st_configs[0].id)
            if st_snap and st_snap.ok and st_snap.data_json:
                st_d = json.loads(st_snap.data_json)
                speedtest_data = {
                    "download_mbps": st_d.get("download_mbps", 0),
                    "upload_mbps": st_d.get("upload_mbps", 0),
                    "ping_ms": st_d.get("ping_ms", 0),
                    "server_name": st_d.get("server_name", ""),
                    "timestamp": st_snap.timestamp.strftime("%d.%m %H:%M") if st_snap.timestamp else "",
                }
                # History: last 24h snapshots
                hist_rows = (await db.execute(
                    select(Snapshot)
                    .where(Snapshot.entity_type == "speedtest", Snapshot.entity_id == st_configs[0].id,
                           Snapshot.ok == True, Snapshot.timestamp >= window_24h)
                    .order_by(Snapshot.timestamp.asc())
                )).scalars().all()
                for hr in hist_rows:
                    hd = json.loads(hr.data_json)
                    speedtest_history.append({
                        "download_mbps": hd.get("download_mbps", 0),
                        "upload_mbps": hd.get("upload_mbps", 0),
                    })
    except Exception:
        pass

    # ── Storage pools (TrueNAS/Synology/UNAS) ────────────────────────────────
    storage_pools = []
    try:
        all_snaps_cache = await snap_svc.get_latest_batch_all(db)
        for stype, label in [("truenas", "TrueNAS"), ("synology", "Synology"), ("unas", "UNAS")]:
            type_snaps = all_snaps_cache.get(stype, {})
            type_configs = [c for c in all_configs if c.type == stype]
            for cfg in type_configs:
                snap = type_snaps.get(cfg.id)
                if not snap or not snap.ok or not snap.data_json:
                    continue
                sd = json.loads(snap.data_json)
                pools_key = "pools" if stype in ("truenas", "unas") else "volumes"
                for pool in sd.get(pools_key, []):
                    storage_pools.append({
                        "name": pool.get("name", "?"),
                        "source": f"{label}: {cfg.name}",
                        "healthy": pool.get("healthy", True),
                        "pct": pool.get("pct", 0),
                        "used_gb": pool.get("used_gb", 0),
                        "total_gb": pool.get("size_gb", 0),
                    })
    except Exception:
        pass

    # ── Containers (Portainer) ────────────────────────────────────────────────
    container_data = None
    try:
        port_configs = [c for c in all_configs if c.type == "portainer"]
        if port_configs:
            port_snaps = all_snaps_cache.get("portainer", {})
            envs = []
            total_running = total_stopped = 0
            for cfg in port_configs:
                snap = port_snaps.get(cfg.id)
                if not snap or not snap.ok or not snap.data_json:
                    continue
                pd = json.loads(snap.data_json)
                for env in pd.get("environments", []):
                    envs.append(env)
                    total_running += env.get("containers_running", 0)
                    total_stopped += env.get("containers_stopped", 0)
            if envs:
                container_data = {"environments": envs, "running": total_running, "stopped": total_stopped}
    except Exception:
        pass

    # ── UPS / NUT ─────────────────────────────────────────────────────────────
    ups_data = None
    try:
        ups_configs = [c for c in all_configs if c.type == "ups"]
        if ups_configs:
            ups_snaps = all_snaps_cache.get("ups", {})
            units = []
            any_on_battery = False
            for cfg in ups_configs:
                snap = ups_snaps.get(cfg.id)
                if not snap or not snap.ok or not snap.data_json:
                    continue
                ud = json.loads(snap.data_json)
                on_bat = ud.get("on_battery", False)
                if on_bat:
                    any_on_battery = True
                units.append({
                    "name": cfg.name,
                    "status_label": ud.get("status_label", ud.get("status", "?")),
                    "on_battery": on_bat,
                    "battery_pct": ud.get("battery_pct", 0),
                    "load_pct": ud.get("load_pct", 0),
                    "runtime_s": ud.get("runtime_s", 0),
                    "model": ud.get("model", ""),
                })
            if units:
                ups_data = {"units": units, "on_battery": any_on_battery}
    except Exception:
        pass

    # ── SSL certificates ──────────────────────────────────────────────────────
    ssl_certs = []
    try:
        https_hosts = [h for h in hosts if "https" in (h.check_type or "")]
        for h in sorted(https_hosts, key=lambda x: x.ssl_expiry_days if x.ssl_expiry_days is not None else 9999):
            ssl_certs.append({
                "host_id": h.id,
                "name": h.name,
                "days": h.ssl_expiry_days,
            })
    except Exception:
        pass

    # ── Recent incidents (for alerts widget) ──────────────────────────────────
    recent_incidents = []
    try:
        recent_incidents = (await db.execute(
            select(Incident)
            .order_by(Incident.created_at.desc())
            .limit(10)
        )).scalars().all()
    except Exception:
        pass

    # ── Uptime ranking ────────────────────────────────────────────────────────
    uptime_ranking = sorted(
        [{"host_id": s["host"].id, "name": s["host"].name, "uptime": s["uptime_pct"]}
         for s in active_stats if not s["host"].maintenance],
        key=lambda x: x["uptime"],
    )[:15]

    # ── Heatmap (7-day per-host availability) ─────────────────────────────────
    heatmap_data = []
    heatmap_days = []
    try:
        window_7d = now - timedelta(days=7)
        # Day labels
        for i in range(7):
            d = (now - timedelta(days=6 - i))
            heatmap_days.append(d.strftime("%a")[:2])

        # Batch query: per-host per-day success rate
        from sqlalchemy import cast, Date
        day_stats = (await db.execute(
            select(
                PingResult.host_id,
                cast(PingResult.timestamp, Date).label("day"),
                func.count().label("total"),
                func.count().filter(PingResult.success == True).label("ok"),
            )
            .where(PingResult.host_id.in_(host_ids), PingResult.timestamp >= window_7d)
            .group_by(PingResult.host_id, cast(PingResult.timestamp, Date))
        )).all()

        # Build lookup: (host_id, date_str) -> pct
        day_map: dict[tuple, float] = {}
        for row in day_stats:
            pct = round(row.ok / row.total * 100, 1) if row.total > 0 else None
            day_map[(row.host_id, str(row.day))] = pct

        # Top 15 hosts by lowest uptime (most interesting)
        heatmap_hosts = sorted(
            [h for h in hosts if not h.maintenance],
            key=lambda h: min(
                (day_map.get((h.id, str((now - timedelta(days=6 - i)).date())), 100) or 100)
                for i in range(7)
            ),
        )[:15]

        for h in heatmap_hosts:
            days = []
            for i in range(7):
                d = (now - timedelta(days=6 - i)).date()
                days.append(day_map.get((h.id, str(d))))
            heatmap_data.append({"host_id": h.id, "name": h.name, "days": days})
    except Exception:
        pass

    # ── Vigil uptime ──────────────────────────────────────────────────────────
    vigil_uptime = ""
    try:
        import os
        _start = float(os.environ.get("VIGIL_START_TIME", "0"))
        if _start > 0:
            delta = now.timestamp() - _start
        else:
            delta = 0
        if delta > 86400:
            vigil_uptime = f"{int(delta // 86400)}d {int((delta % 86400) // 3600)}h"
        elif delta > 3600:
            vigil_uptime = f"{int(delta // 3600)}h {int((delta % 3600) // 60)}m"
        elif delta > 0:
            vigil_uptime = f"{int(delta // 60)}m"
    except Exception:
        pass

    # Dashboard widget layout
    layout_json = await get_setting(db, "dashboard_layout")
    try:
        layout = json.loads(layout_json) if layout_json else DEFAULT_LAYOUT
        # Detect old format (has 'size' key instead of 'x'/'y') and fall back
        if layout and isinstance(layout[0], dict) and "x" not in layout[0]:
            layout = DEFAULT_LAYOUT
        # Migrate old 80px-cellHeight layouts to 40px (double h and y)
        elif layout and max(w.get("h", 0) for w in layout) <= 8:
            for w in layout:
                w["h"] = w.get("h", 2) * 2
                w["y"] = w.get("y", 0) * 2
    except (json.JSONDecodeError, TypeError, IndexError):
        layout = DEFAULT_LAYOUT

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "host_stats": host_stats,
        "online_count": online_count,
        "offline_count": offline_count,
        "total_count": len(active_stats),
        "proxmox_clusters": proxmox_clusters,
        "top_latency": top_latency,
        "top_downtime": top_downtime,
        "top_cpu": top_cpu,
        "top_ram": top_ram,
        "top_disk": top_disk,
        "ping_host_map": ping_host_map,
        "anomalies": anomalies,
        "warnings": warnings,
        "integration_health": integration_health,
        "active_incidents": active_incidents,
        "syslog_stats": syslog_stats,
        "topology": topology,
        "layout": layout,
        "speedtest_data": speedtest_data,
        "speedtest_history": speedtest_history,
        "storage_pools": storage_pools,
        "container_data": container_data,
        "ups_data": ups_data,
        "ssl_certs": ssl_certs,
        "recent_incidents": recent_incidents,
        "uptime_ranking": uptime_ranking,
        "heatmap_data": heatmap_data,
        "heatmap_days": heatmap_days,
        "vigil_uptime": vigil_uptime,
        "active_page": "dashboard",
    })


@router.post("/api/dashboard-layout")
async def save_dashboard_layout(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    widgets = body.get("layout")
    if not isinstance(widgets, list):
        return JSONResponse({"ok": False, "error": "Invalid layout"}, status_code=400)
    cleaned = []
    for w in widgets:
        wid = w.get("id")
        if wid not in VALID_WIDGET_IDS:
            continue
        cleaned.append({
            "id": wid,
            "x": max(0, min(11, int(w.get("x", 0)))),
            "y": max(0, int(w.get("y", 0))),
            "w": max(1, min(12, int(w.get("w", 12)))),
            "h": max(1, min(24, int(w.get("h", 4)))),
        })
    await set_setting(db, "dashboard_layout", json.dumps(cleaned))
    await db.commit()
    return JSONResponse({"ok": True})
