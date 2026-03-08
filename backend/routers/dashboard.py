import json
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from templating import templates, localtime
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    PingHost, PingResult,
    get_db, get_setting, set_setting, is_setup_complete,
)
from models.integration import IntegrationConfig, Snapshot
from services import integration as int_svc
from services import snapshot as snap_svc
from services import ping as ping_svc

router = APIRouter()

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


# ── Helper: build integration_health from generic tables ─────────────────

_INTEGRATION_META = {
    "proxmox":      {"label": "Proxmox",        "color": "orange",  "url_prefix": "/integration/proxmox"},
    "unifi":        {"label": "UniFi",           "color": "blue",    "url_prefix": "/integration/unifi"},
    "unas":         {"label": "UniFi NAS",       "color": "cyan",    "url_prefix": "/integration/unas"},
    "pihole":       {"label": "Pi-hole",         "color": "red",     "url_prefix": "/integration/pihole"},
    "adguard":      {"label": "AdGuard",         "color": "emerald", "url_prefix": "/integration/adguard"},
    "portainer":    {"label": "Portainer",       "color": "teal",    "url_prefix": "/integration/portainer"},
    "truenas":      {"label": "TrueNAS",         "color": "slate",   "url_prefix": "/integration/truenas"},
    "synology":     {"label": "Synology",        "color": "blue",    "url_prefix": "/integration/synology"},
    "firewall":     {"label": "Firewall",        "color": "orange",  "url_prefix": "/integration/firewall"},
    "hass":         {"label": "Home Assistant",   "color": "orange",  "url_prefix": "/integration/hass"},
    "gitea":        {"label": "Gitea",           "color": "green",   "url_prefix": "/integration/gitea"},
    "phpipam":      {"label": "phpIPAM",         "color": "purple",  "url_prefix": "/integration/phpipam"},
    "speedtest":    {"label": "Speedtest",       "color": "blue",    "url_prefix": "/integration/speedtest"},
    "ups":          {"label": "UPS / NUT",       "color": "yellow",  "url_prefix": "/integration/ups"},
    "redfish":      {"label": "Redfish",         "color": "purple",  "url_prefix": "/integration/redfish"},
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

    # ── Ping hosts (batch queries via service) ─────────────────────────────
    hosts_result = await db.execute(select(PingHost).where(PingHost.enabled == True))
    hosts = hosts_result.scalars().all()
    host_ids = [h.id for h in hosts]

    host_stats = []
    ping_alarms: list[dict] = []

    latest_by_host = await ping_svc.get_latest_by_host(db, host_ids)
    stats_by_host = await ping_svc.get_24h_stats(db, host_ids)
    sparklines_by_host = await ping_svc.get_sparklines(db, host_ids)

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

        host_stats.append({
            "host": host,
            "online": latest_row.success if latest_row else None,
            "latency": latest_row.latency_ms if latest_row else None,
            "uptime_pct": uptime_pct,
            "avg_latency": avg_latency,
            "last_check": latest_row.timestamp if latest_row else None,
            "sparkline": sparkline,
            "effective_threshold": effective_threshold,
            "health_score": 0.0,  # computed later with all metrics
        })

    # Exclude maintenance hosts from counts and Top-10
    active_stats = [s for s in host_stats if not s["host"].maintenance]
    online_count  = sum(1 for s in active_stats if s["online"])
    offline_count = sum(1 for s in active_stats if s["online"] is False)

    # ── Top 10 Ping ───────────────────────────────────────────────────────────
    with_latency = [s for s in active_stats if s["avg_latency"] is not None]
    top_latency  = sorted(with_latency, key=lambda s: s["avg_latency"], reverse=True)[:10]
    top_downtime = sorted(active_stats, key=lambda s: s["uptime_pct"])[:10]

    # ── Pre-fetch all integration data ────────────────────────────────────────
    all_configs_result = await db.execute(
        select(IntegrationConfig).order_by(IntegrationConfig.type, IntegrationConfig.name)
    )
    all_configs = all_configs_result.scalars().all()
    all_snaps_cache = await snap_svc.get_latest_batch_all(db)

    # ── Proxmox clusters ──────────────────────────────────────────────────────
    px_configs = [c for c in all_configs if c.type == "proxmox"]

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

    anomaly_threshold = float(await get_setting(db, "anomaly_threshold", "2.0"))

    all_guests: list[dict] = []
    anomalies:  list[dict] = []
    warnings:   list[dict] = []

    px_snapshots = await snap_svc.get_latest_batch(db, "proxmox")

    for cluster in proxmox_clusters:
        latest_snap = px_snapshots.get(cluster.id)
        if not latest_snap or not latest_snap.ok or not latest_snap.data_json:
            continue
        latest_data = json.loads(latest_snap.data_json)

        guests_now = latest_data.get("vms", []) + latest_data.get("containers", [])

        # Historical snapshots for anomaly baseline
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
        CPU_STD_FLOOR = 3.0
        MEM_STD_FLOOR = 0.3
        SUSTAINED_WINDOW = 5
        SUSTAINED_MIN = 3

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
                    recent_values = all_cpu[-SUSTAINED_WINDOW:] + [cur_cpu]
                    anomalous_count = sum(1 for v in recent_values if (v - mean_cpu) / std_cpu >= anomaly_threshold)
                    if anomalous_count >= SUSTAINED_MIN:
                        z_score = (cur_cpu - mean_cpu) / std_cpu
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
            "sustained": None, "severity": 99,
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
        ping_host_map[h.hostname] = h.id
        ping_host_map.setdefault(h.name, h.id)
        ping_host_map.setdefault(h.hostname.lower(), h.id)
        ping_host_map.setdefault(h.name.lower(), h.id)
        raw = h.hostname
        for pfx in ("https://", "http://"):
            if raw.startswith(pfx):
                raw = raw[len(pfx):]
                break
        short_host = raw.split("/")[0].split(":")[0]
        ping_host_map.setdefault(short_host, h.id)
        ping_host_map.setdefault(short_host.lower(), h.id)
        if "." in short_host:
            ping_host_map.setdefault(short_host.split(".")[0].lower(), h.id)

    # ── Build topology tree ──────────────────────────────────────────────────
    topology: dict[int, int | None] = {}
    host_by_id = {h.id: h for h in all_ph}

    for h in all_ph:
        topology[h.id] = getattr(h, 'parent_id', None)

    # Auto-detect Proxmox VM/LXC → Proxmox node relationships
    px_node_names: set[str] = set()
    for cluster in proxmox_clusters:
        snap = px_snapshots.get(cluster.id)
        if not snap or not snap.ok or not snap.data_json:
            continue
        d = json.loads(snap.data_json)
        for node_info in d.get("nodes", []):
            px_node_names.add(node_info.get("node", ""))
        for g in d.get("vms", []) + d.get("containers", []):
            guest_name = (g.get("name") or "").strip()
            node_name = (g.get("node") or "").strip()
            if not guest_name or not node_name:
                continue
            guest_ph_id = (ping_host_map.get(guest_name)
                           or ping_host_map.get(guest_name.lower()))
            node_ph_id = (ping_host_map.get(node_name)
                          or ping_host_map.get(node_name.lower()))
            if guest_ph_id and node_ph_id and guest_ph_id != node_ph_id:
                if topology.get(guest_ph_id) is None:
                    topology[guest_ph_id] = node_ph_id

    # Auto-detect UniFi device hierarchy (Gateway → Switch → AP)
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
    non_px_configs = [c for c in all_configs if c.type != "proxmox"]

    for cfg in non_px_configs:
        meta = _INTEGRATION_META.get(cfg.type, {"label": cfg.type, "color": "slate", "url_prefix": f"/integration/{cfg.type}"})
        snap = all_snaps_cache.get(cfg.type, {}).get(cfg.id)
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
        pass

    # ── Speedtest (latest + 24h history) ─────────────────────────────────────
    speedtest_data = None
    speedtest_history = []
    try:
        st_configs = [c for c in all_configs if c.type == "speedtest"]
        if st_configs:
            st_snap = all_snaps_cache.get("speedtest", {}).get(st_configs[0].id)
            if st_snap and st_snap.ok and st_snap.data_json:
                st_d = json.loads(st_snap.data_json)
                speedtest_data = {
                    "download_mbps": st_d.get("download_mbps", 0),
                    "upload_mbps": st_d.get("upload_mbps", 0),
                    "ping_ms": st_d.get("ping_ms", 0),
                    "server_name": st_d.get("server_name", ""),
                    "timestamp": localtime(st_snap.timestamp, "%d.%m %H:%M") if st_snap.timestamp else "",
                }
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
        for i in range(7):
            d = (now - timedelta(days=6 - i))
            heatmap_days.append(d.strftime("%a")[:2])

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

        day_map: dict[tuple, float] = {}
        for row in day_stats:
            pct = round(row.ok / row.total * 100, 1) if row.total > 0 else None
            day_map[(row.host_id, str(row.day))] = pct

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

    # ── Nodeglow uptime ────────────────────────────────────────────────────────
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

    # ── Compute health scores (gravity well) with ALL metrics ──────────────
    guest_metrics_by_host: dict[int, dict] = {}
    for g in all_guests:
        if not g.get("running"):
            continue
        gname = g.get("name", "").lower()
        gnode = g.get("node", "").lower()
        host_id = ping_host_map.get(gname) or ping_host_map.get(gnode)
        if not host_id:
            continue
        cpu_ratio = g.get("cpu_pct", 0) / px_cpu_threshold if px_cpu_threshold else 0
        mem_total = g.get("mem_total_gb", 0)
        ram_pct = (g.get("mem_used_gb", 0) / mem_total * 100) if mem_total > 0 else 0
        ram_ratio = ram_pct / px_ram_pct_threshold if px_ram_pct_threshold else 0
        disk_ratio = g.get("disk_pct", 0) / px_disk_threshold if px_disk_threshold else 0
        prev = guest_metrics_by_host.get(host_id)
        if prev:
            prev["cpu"] = max(prev["cpu"], cpu_ratio)
            prev["ram"] = max(prev["ram"], ram_ratio)
            prev["disk"] = max(prev["disk"], disk_ratio)
        else:
            guest_metrics_by_host[host_id] = {"cpu": cpu_ratio, "ram": ram_ratio, "disk": disk_ratio}

    syslog_errors_by_host: dict[int, int] = {}
    try:
        syslog_err_rows = (await db.execute(
            select(SyslogMessage.host_id, func.count(SyslogMessage.id).label("cnt"))
            .where(SyslogMessage.host_id.isnot(None), SyslogMessage.severity <= 3,
                   SyslogMessage.timestamp >= window_24h)
            .group_by(SyslogMessage.host_id)
        )).all()
        syslog_errors_by_host = {row.host_id: row.cnt for row in syslog_err_rows}
    except Exception:
        pass

    int_errors_by_host: set[int] = set()
    for ih in integration_health:
        if not ih.get("ok"):
            host_str = ih.get("host", "").lower()
            hid = ping_host_map.get(host_str)
            if hid:
                int_errors_by_host.add(hid)

    for s in host_stats:
        h = s["host"]
        if s["online"] is False:
            s["health_score"] = 1.0
            continue
        if h.maintenance:
            s["health_score"] = 0.5
            continue
        if s["online"] is None:
            s["health_score"] = 0.8
            continue

        score = 0.0
        _lat = s["latency"]
        _thr = s["effective_threshold"]

        if _lat is not None and _thr:
            ratio = _lat / _thr
            if ratio <= 0.5:
                score += ratio * 0.05
            elif ratio <= 0.8:
                score += 0.025 + (ratio - 0.5) / 0.3 * 0.075
            elif ratio <= 1.0:
                score += 0.10 + (ratio - 0.8) / 0.2 * 0.10
            else:
                score += 0.20
        elif _lat is not None:
            score += min(_lat / 200.0, 0.20)

        deficit = 1 - s["uptime_pct"] / 100.0
        if deficit > 0:
            score += min((deficit ** 0.5) * 0.15, 0.15)

        sp = s["sparkline"]
        if sp:
            losses = sum(1 for v in sp if v is None)
            if losses > 0:
                score += min((losses / len(sp)) ** 0.6 * 0.10, 0.10)

        gm = guest_metrics_by_host.get(h.id)
        if gm:
            cpu_r = gm["cpu"]
            if cpu_r <= 0.5:
                score += cpu_r * 0.03
            elif cpu_r <= 0.8:
                score += 0.015 + (cpu_r - 0.5) / 0.3 * 0.06
            elif cpu_r <= 1.0:
                score += 0.075 + (cpu_r - 0.8) / 0.2 * 0.075
            else:
                score += 0.15

            ram_r = gm["ram"]
            if ram_r <= 0.5:
                score += ram_r * 0.03
            elif ram_r <= 0.8:
                score += 0.015 + (ram_r - 0.5) / 0.3 * 0.06
            elif ram_r <= 1.0:
                score += 0.075 + (ram_r - 0.8) / 0.2 * 0.075
            else:
                score += 0.15

            disk_r = gm["disk"]
            if disk_r <= 0.7:
                score += disk_r * 0.02
            elif disk_r <= 0.9:
                score += 0.014 + (disk_r - 0.7) / 0.2 * 0.04
            elif disk_r <= 1.0:
                score += 0.054 + (disk_r - 0.9) / 0.1 * 0.046
            else:
                score += 0.10

        err_count = syslog_errors_by_host.get(h.id, 0)
        if err_count > 0:
            score += min((err_count ** 0.4) / 10.0 * 0.10, 0.10)

        if h.id in int_errors_by_host:
            score += 0.05

        s["health_score"] = round(min(score, 1.0), 3)

    # Dashboard widget layout
    layout_json = await get_setting(db, "dashboard_layout")
    try:
        layout = json.loads(layout_json) if layout_json else DEFAULT_LAYOUT
        if layout and isinstance(layout[0], dict) and "x" not in layout[0]:
            layout = DEFAULT_LAYOUT
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
