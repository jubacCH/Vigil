"""System status / self-monitoring page."""

import asyncio
import os
import platform
import sys
import time
from datetime import datetime, timedelta

import psutil
from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import PingHost, PingResult, Setting, get_db
from models.integration import IntegrationConfig, Snapshot
from models.syslog import SyslogMessage

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _collect_system_info() -> tuple[dict, dict, dict]:
    """Collect psutil data in one shot (runs in thread executor)."""
    start_ts = float(os.environ.get("VIGIL_START_TIME", "0"))
    now_ts = time.time()
    uptime_seconds = int(now_ts - start_ts) if start_ts > 0 else 0

    app_info = {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "hostname": platform.node(),
        "pid": os.getpid(),
        "uptime_seconds": uptime_seconds,
        "uptime_human": _format_duration(uptime_seconds),
        "start_time": datetime.fromtimestamp(start_ts).strftime("%Y-%m-%d %H:%M:%S") if start_ts else "—",
    }

    cpu_pct = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)

    system_info = {
        "cpu_count": psutil.cpu_count(),
        "cpu_pct": cpu_pct,
        "load_1m": round(load_avg[0], 2),
        "load_5m": round(load_avg[1], 2),
        "load_15m": round(load_avg[2], 2),
        "mem_total_gb": round(mem.total / (1024**3), 1),
        "mem_used_gb": round(mem.used / (1024**3), 1),
        "mem_pct": mem.percent,
        "disk_total_gb": round(disk.total / (1024**3), 1),
        "disk_used_gb": round(disk.used / (1024**3), 1),
        "disk_pct": round(disk.percent, 1),
    }

    proc = psutil.Process(os.getpid())
    proc_mem = proc.memory_info()
    process_info = {
        "rss_mb": round(proc_mem.rss / (1024**2), 1),
        "vms_mb": round(proc_mem.vms / (1024**2), 1),
        "threads": proc.num_threads(),
        "open_files": len(proc.open_files()),
        "connections": len(proc.net_connections()),
    }

    return app_info, system_info, process_info


def _collect_logs() -> list[str]:
    """Read log lines (runs in thread executor)."""
    import subprocess
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

    # ── Database stats (single query with estimated counts for big tables) ─
    db_stats = {}
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
            "oldest_ping": row.oldest_ping.strftime("%Y-%m-%d %H:%M") if row.oldest_ping else "—",
            "newest_ping": row.newest_ping.strftime("%Y-%m-%d %H:%M") if row.newest_ping else "—",
        }
    except Exception as e:
        db_stats = {"error": str(e)}

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
                "next_run": next_run.strftime("%H:%M:%S") if next_run else "paused",
            })
    except Exception:
        pass

    # ── Integration health (batch: LATERAL join for latest snapshot) ──────
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
                "last_check": r.ts.strftime("%H:%M:%S") if r.ts else "—",
                "error": r.error[:100] if r.error else None,
            })
    except Exception:
        pass

    # ── Ping check stats (last hour, single query) ───────────────────────
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

    # ── Await thread pool results ────────────────────────────────────────
    app_info, system_info, process_info = await sysinfo_fut
    log_lines = await logs_fut

    return templates.TemplateResponse("system_status.html", {
        "request": request,
        "app_info": app_info,
        "system_info": system_info,
        "process_info": process_info,
        "db_stats": db_stats,
        "scheduler_jobs": scheduler_jobs,
        "integration_summary": integration_summary,
        "log_lines": log_lines,
        "ping_stats": ping_stats,
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
