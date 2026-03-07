"""System status / self-monitoring page."""

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


@router.get("/system/status")
async def system_status(request: Request, db: AsyncSession = Depends(get_db)):
    now = datetime.utcnow()

    # ── Application info ─────────────────────────────────────────────────
    start_ts = float(os.environ.get("VIGIL_START_TIME", "0"))
    uptime_seconds = int(now.timestamp() - start_ts) if start_ts > 0 else 0

    app_info = {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "hostname": platform.node(),
        "pid": os.getpid(),
        "uptime_seconds": uptime_seconds,
        "uptime_human": _format_duration(uptime_seconds),
        "start_time": datetime.fromtimestamp(start_ts).strftime("%Y-%m-%d %H:%M:%S") if start_ts else "—",
    }

    # ── System resources (host machine) ──────────────────────────────────
    cpu_pct = psutil.cpu_percent(interval=0.1)
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

    # ── Process info ─────────────────────────────────────────────────────
    proc = psutil.Process(os.getpid())
    proc_mem = proc.memory_info()
    process_info = {
        "rss_mb": round(proc_mem.rss / (1024**2), 1),
        "vms_mb": round(proc_mem.vms / (1024**2), 1),
        "threads": proc.num_threads(),
        "open_files": len(proc.open_files()),
        "connections": len(proc.net_connections()),
    }

    # ── Database stats ───────────────────────────────────────────────────
    db_stats = {}
    try:
        # Table sizes
        host_count = (await db.execute(select(func.count(PingHost.id)))).scalar() or 0
        result_count = (await db.execute(select(func.count(PingResult.id)))).scalar() or 0
        config_count = (await db.execute(select(func.count(IntegrationConfig.id)))).scalar() or 0
        snapshot_count = (await db.execute(select(func.count(Snapshot.id)))).scalar() or 0
        syslog_count = 0
        try:
            syslog_count = (await db.execute(select(func.count(SyslogMessage.id)))).scalar() or 0
        except Exception:
            pass

        # DB size (PostgreSQL)
        db_size = "—"
        try:
            row = (await db.execute(text("SELECT pg_size_pretty(pg_database_size(current_database()))"))).scalar()
            db_size = row or "—"
        except Exception:
            pass

        # Oldest/newest ping result
        oldest_ping = (await db.execute(select(func.min(PingResult.timestamp)))).scalar()
        newest_ping = (await db.execute(select(func.max(PingResult.timestamp)))).scalar()

        db_stats = {
            "db_size": db_size,
            "host_count": host_count,
            "result_count": result_count,
            "config_count": config_count,
            "snapshot_count": snapshot_count,
            "syslog_count": syslog_count,
            "oldest_ping": oldest_ping.strftime("%Y-%m-%d %H:%M") if oldest_ping else "—",
            "newest_ping": newest_ping.strftime("%Y-%m-%d %H:%M") if newest_ping else "—",
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

    # ── Integration health summary ───────────────────────────────────────
    integration_summary = []
    try:
        configs = (await db.execute(
            select(IntegrationConfig).where(IntegrationConfig.enabled == True)
            .order_by(IntegrationConfig.type, IntegrationConfig.name)
        )).scalars().all()

        from services import snapshot as snap_svc
        for cfg in configs:
            latest = (await db.execute(
                select(Snapshot)
                .where(Snapshot.entity_type == cfg.type, Snapshot.entity_id == cfg.id)
                .order_by(Snapshot.timestamp.desc())
                .limit(1)
            )).scalar_one_or_none()
            integration_summary.append({
                "type": cfg.type,
                "name": cfg.name,
                "ok": latest.ok if latest else None,
                "last_check": latest.timestamp.strftime("%H:%M:%S") if latest and latest.timestamp else "—",
                "error": latest.error[:100] if latest and latest.error else None,
            })
    except Exception:
        pass

    # ── Recent application logs (last 100 lines from Docker stdout) ──────
    log_lines = []
    try:
        import subprocess
        result = subprocess.run(
            ["tail", "-n", "100", "/proc/1/fd/1"],
            capture_output=True, text=True, timeout=2
        )
        if result.stdout:
            log_lines = result.stdout.strip().split("\n")[-100:]
    except Exception:
        pass
    # Fallback: try uvicorn log file
    if not log_lines:
        try:
            import subprocess
            result = subprocess.run(
                ["tail", "-n", "100", "/dev/stderr"],
                capture_output=True, text=True, timeout=2
            )
        except Exception:
            pass

    # ── Ping check stats (last hour) ─────────────────────────────────────
    ping_stats = {}
    try:
        window_1h = now - timedelta(hours=1)
        row = (await db.execute(
            select(
                func.count(PingResult.id).label("total"),
                func.sum(func.cast(PingResult.success, sqltype=None)).label("ok"),
                func.avg(PingResult.latency_ms).label("avg_lat"),
                func.max(PingResult.latency_ms).label("max_lat"),
            ).where(PingResult.timestamp >= window_1h)
        )).one_or_none()
        if row and row.total:
            from sqlalchemy import Integer as SaInt
            ok_count = (await db.execute(
                select(func.count(PingResult.id))
                .where(PingResult.timestamp >= window_1h, PingResult.success == True)
            )).scalar() or 0
            ping_stats = {
                "checks_1h": row.total,
                "success_rate": round(ok_count / row.total * 100, 1) if row.total else 0,
                "avg_latency": round(float(row.avg_lat), 2) if row.avg_lat else 0,
                "max_latency": round(float(row.max_lat), 2) if row.max_lat else 0,
            }
    except Exception:
        pass

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
