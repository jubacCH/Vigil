"""System status / self-monitoring page."""

import asyncio
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timedelta

import psutil
from fastapi import APIRouter, Depends, Request
from templating import templates, localtime
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db

router = APIRouter()


def _collect_system_info() -> dict:
    """Collect all psutil + OS data in one shot (runs in thread executor)."""
    start_ts = float(os.environ.get("VIGIL_START_TIME", "0"))
    now_ts = time.time()
    uptime_seconds = int(now_ts - start_ts) if start_ts > 0 else 0

    # Git version
    git_commit = "—"
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=2, cwd="/app"
        )
        if result.returncode == 0:
            git_commit = result.stdout.strip()
    except Exception:
        pass

    app_info = {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "hostname": platform.node(),
        "pid": os.getpid(),
        "uptime_seconds": uptime_seconds,
        "uptime_human": _format_duration(uptime_seconds),
        "start_time": localtime(datetime.utcfromtimestamp(start_ts), "%Y-%m-%d %H:%M:%S") if start_ts else "—",
        "git_commit": git_commit,
    }

    # CPU + Memory + Disk
    cpu_pct = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)

    # Disk I/O
    dio = psutil.disk_io_counters()
    disk_io = {}
    if dio:
        disk_io = {
            "read_gb": round(dio.read_bytes / (1024**3), 2),
            "write_gb": round(dio.write_bytes / (1024**3), 2),
            "read_count": dio.read_count,
            "write_count": dio.write_count,
        }

    # Network I/O
    nio = psutil.net_io_counters()
    net_io = {}
    if nio:
        net_io = {
            "sent_gb": round(nio.bytes_sent / (1024**3), 2),
            "recv_gb": round(nio.bytes_recv / (1024**3), 2),
            "packets_sent": nio.packets_sent,
            "packets_recv": nio.packets_recv,
            "errin": nio.errin,
            "errout": nio.errout,
            "dropin": nio.dropin,
            "dropout": nio.dropout,
        }

    # Network interfaces
    net_if = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface, addr_list in addrs.items():
            if iface == "lo":
                continue
            ipv4 = next((a.address for a in addr_list if a.family.name == "AF_INET"), None)
            if not ipv4:
                continue
            is_up = stats.get(iface, None)
            net_if.append({
                "name": iface,
                "ip": ipv4,
                "up": is_up.isup if is_up else False,
                "speed": is_up.speed if is_up else 0,
            })
    except Exception:
        pass

    system_info = {
        "cpu_count": psutil.cpu_count(),
        "cpu_pct": cpu_pct,
        "load_1m": round(load_avg[0], 2),
        "load_5m": round(load_avg[1], 2),
        "load_15m": round(load_avg[2], 2),
        "mem_total_gb": round(mem.total / (1024**3), 1),
        "mem_used_gb": round(mem.used / (1024**3), 1),
        "mem_pct": mem.percent,
        "swap_total_gb": round(swap.total / (1024**3), 1),
        "swap_used_gb": round(swap.used / (1024**3), 1),
        "swap_pct": swap.percent,
        "disk_total_gb": round(disk.total / (1024**3), 1),
        "disk_used_gb": round(disk.used / (1024**3), 1),
        "disk_pct": round(disk.percent, 1),
        "disk_io": disk_io,
        "net_io": net_io,
        "net_if": net_if,
    }

    # Process info
    proc = psutil.Process(os.getpid())
    proc_mem = proc.memory_info()
    cpu_times = proc.cpu_times()
    process_info = {
        "rss_mb": round(proc_mem.rss / (1024**2), 1),
        "vms_mb": round(proc_mem.vms / (1024**2), 1),
        "threads": proc.num_threads(),
        "open_files": len(proc.open_files()),
        "connections": len(proc.net_connections()),
        "cpu_user": round(cpu_times.user, 1),
        "cpu_system": round(cpu_times.system, 1),
    }

    return {
        "app_info": app_info,
        "system_info": system_info,
        "process_info": process_info,
    }


def _collect_logs() -> list[str]:
    """Read log lines (runs in thread executor)."""
    try:
        result = subprocess.run(
            ["tail", "-n", "100", "/proc/1/fd/1"],
            capture_output=True, text=True, timeout=1
        )
        if result.stdout:
            return result.stdout.strip().split("\n")[-100:]
    except Exception:
        pass
    return []


@router.get("/system/status")
async def system_status(request: Request, db: AsyncSession = Depends(get_db)):
    now = datetime.utcnow()
    loop = asyncio.get_event_loop()

    # ── Run psutil + logs in thread pool (non-blocking) ──────────────────
    sysinfo_fut = loop.run_in_executor(None, _collect_system_info)
    logs_fut = loop.run_in_executor(None, _collect_logs)

    # ── Database stats + top tables (single query) ───────────────────────
    db_stats = {}
    top_tables = []
    try:
        row = (await db.execute(text("""
            SELECT
                (SELECT count(*) FROM ping_hosts) AS host_count,
                (SELECT reltuples::bigint FROM pg_class WHERE relname = 'ping_results') AS result_count,
                (SELECT count(*) FROM integration_configs) AS config_count,
                (SELECT reltuples::bigint FROM pg_class WHERE relname = 'snapshots') AS snapshot_count,
                (SELECT reltuples::bigint FROM pg_class WHERE relname = 'syslog_messages') AS syslog_count,
                (SELECT pg_size_pretty(pg_database_size(current_database()))) AS db_size,
                (SELECT min(timestamp) FROM ping_results) AS oldest_ping,
                (SELECT max(timestamp) FROM ping_results) AS newest_ping
        """))).one()
        db_stats = {
            "db_size": row.db_size or "—",
            "host_count": row.host_count or 0,
            "result_count": max(row.result_count or 0, 0),
            "config_count": row.config_count or 0,
            "snapshot_count": max(row.snapshot_count or 0, 0),
            "syslog_count": max(row.syslog_count or 0, 0),
            "oldest_ping": localtime(row.oldest_ping, "%Y-%m-%d %H:%M") if row.oldest_ping else "—",
            "newest_ping": localtime(row.newest_ping, "%Y-%m-%d %H:%M") if row.newest_ping else "—",
        }
        # Top tables by size
        tt_rows = (await db.execute(text("""
            SELECT relname AS name,
                   pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
                   pg_total_relation_size(c.oid) AS raw_size,
                   reltuples::bigint AS rows
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r'
            ORDER BY pg_total_relation_size(c.oid) DESC
            LIMIT 10
        """))).all()
        for t in tt_rows:
            top_tables.append({
                "name": t.name,
                "size": t.total_size,
                "raw_size": t.raw_size,
                "rows": max(t.rows, 0),
            })
    except Exception as e:
        db_stats = {"error": str(e)}

    # ── DB connection pool status ────────────────────────────────────────
    pool_info = {}
    try:
        from models.base import engine
        pool = engine.pool
        pool_info = {
            "size": pool.size(),
            "checked_in": pool.checkedin(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
            "max_overflow": engine.pool._max_overflow,
        }
    except Exception:
        pass

    # ── Scheduler status ─────────────────────────────────────────────────
    scheduler_jobs = []
    try:
        from scheduler import scheduler
        for job in scheduler.get_jobs():
            next_run = job.next_run_time
            scheduler_jobs.append({
                "id": job.id,
                "name": job.name or job.id,
                "trigger": str(job.trigger),
                "next_run": localtime(next_run, "%H:%M:%S") if next_run else "paused",
            })
    except Exception:
        pass

    # ── Integration health (LATERAL join) ────────────────────────────────
    integration_summary = []
    try:
        rows = (await db.execute(text("""
            SELECT c.type, c.name, s.ok, s.timestamp AS ts, s.error
            FROM integration_configs c
            LEFT JOIN LATERAL (
                SELECT ok, timestamp, error FROM snapshots
                WHERE entity_type = c.type AND entity_id = c.id
                ORDER BY timestamp DESC LIMIT 1
            ) s ON true
            WHERE c.enabled = true
            ORDER BY c.type, c.name
        """))).all()
        for r in rows:
            integration_summary.append({
                "type": r.type,
                "name": r.name,
                "ok": r.ok,
                "last_check": localtime(r.ts, "%H:%M:%S") if r.ts else "—",
                "error": r.error[:100] if r.error else None,
            })
    except Exception:
        pass

    # ── Ping check stats (last hour) ─────────────────────────────────────
    ping_stats = {}
    try:
        window_1h = now - timedelta(hours=1)
        row = (await db.execute(text("""
            SELECT count(*) AS total,
                   count(*) FILTER (WHERE success) AS ok,
                   round(avg(latency_ms)::numeric, 2) AS avg_lat,
                   round(max(latency_ms)::numeric, 2) AS max_lat
            FROM ping_results WHERE timestamp >= :since
        """).bindparams(since=window_1h))).one()
        if row.total:
            ping_stats = {
                "checks_1h": row.total,
                "success_rate": round(float(row.ok) / row.total * 100, 1),
                "avg_latency": float(row.avg_lat) if row.avg_lat else 0,
                "max_latency": float(row.max_lat) if row.max_lat else 0,
            }
    except Exception:
        pass

    # ── Syslog receiver status ───────────────────────────────────────────
    syslog_status = {"running": False}
    try:
        from services.syslog import _udp_transport, _tcp_server, _buffer
        syslog_status["running"] = _udp_transport is not None
        syslog_status["buffer_size"] = len(_buffer)
        # Messages per minute (last 10 min)
        ten_min_ago = now - timedelta(minutes=10)
        syslog_rate = (await db.execute(text("""
            SELECT count(*) AS cnt FROM syslog_messages WHERE received_at >= :since
        """).bindparams(since=ten_min_ago))).scalar() or 0
        syslog_status["msg_per_min"] = round(syslog_rate / 10, 1)
    except Exception:
        pass

    # ── SSL certificate expiry (soonest) ─────────────────────────────────
    ssl_certs = []
    try:
        rows = (await db.execute(text("""
            SELECT name, hostname, ssl_expiry_days
            FROM ping_hosts
            WHERE ssl_expiry_days IS NOT NULL
            ORDER BY ssl_expiry_days ASC
            LIMIT 5
        """))).all()
        for r in rows:
            ssl_certs.append({
                "name": r.name,
                "hostname": r.hostname,
                "days": r.ssl_expiry_days,
            })
    except Exception:
        pass

    # ── Notification channel config ──────────────────────────────────────
    notification_info = {}
    try:
        from database import Setting
        settings = {}
        s_rows = (await db.execute(text(
            "SELECT key, value FROM settings WHERE key LIKE 'alert_%' OR key LIKE 'smtp_%' OR key LIKE 'telegram_%' OR key LIKE 'discord_%'"
        ))).all()
        for s in s_rows:
            settings[s.key] = s.value

        notification_info = {
            "telegram": bool(settings.get("telegram_bot_token") and settings.get("telegram_chat_id")),
            "discord": bool(settings.get("discord_webhook_url")),
            "email": bool(settings.get("smtp_host") and settings.get("smtp_to")),
        }
    except Exception:
        pass

    # ── Data retention ───────────────────────────────────────────────────
    retention_info = {}
    try:
        oldest_snap = (await db.execute(text(
            "SELECT min(timestamp) FROM snapshots"
        ))).scalar()
        oldest_syslog = (await db.execute(text(
            "SELECT min(received_at) FROM syslog_messages"
        ))).scalar()
        retention_info = {
            "ping_age": _format_age(row.oldest_ping) if db_stats.get("oldest_ping") != "—" else "—",
            "snap_age": _format_age(oldest_snap) if oldest_snap else "—",
            "syslog_age": _format_age(oldest_syslog) if oldest_syslog else "—",
        }
    except Exception:
        pass

    # ── Await thread pool results ────────────────────────────────────────
    sysinfo = await sysinfo_fut
    log_lines = await logs_fut

    return templates.TemplateResponse("system_status.html", {
        "request": request,
        "app_info": sysinfo["app_info"],
        "system_info": sysinfo["system_info"],
        "process_info": sysinfo["process_info"],
        "db_stats": db_stats,
        "top_tables": top_tables,
        "pool_info": pool_info,
        "scheduler_jobs": scheduler_jobs,
        "integration_summary": integration_summary,
        "log_lines": log_lines,
        "ping_stats": ping_stats,
        "syslog_status": syslog_status,
        "ssl_certs": ssl_certs,
        "notification_info": notification_info,
        "retention_info": retention_info,
        "active_page": "system",
    })


def _format_duration(seconds: int) -> str:
    if seconds <= 0:
        return "—"
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    m = (seconds % 3600) // 60
    if d > 0:
        return f"{d}d {h}h {m}m"
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"


def _format_age(dt) -> str:
    """Format a datetime as a human-readable age string."""
    if not dt:
        return "—"
    delta = datetime.utcnow() - dt
    days = delta.days
    if days > 30:
        return f"{days // 30}mo {days % 30}d"
    if days > 0:
        return f"{days}d"
    hours = delta.seconds // 3600
    return f"{hours}h"
