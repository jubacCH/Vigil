"""
Background scheduler – generic integration collection + ping checks + cleanup.
"""
import logging
from datetime import datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import delete, select

from database import AsyncSessionLocal, PingHost, PingResult
from models.integration import IntegrationConfig
from services import integration as int_svc
from services import snapshot as snap_svc

logger = logging.getLogger(__name__)
scheduler = AsyncIOScheduler()


# ── Generic integration collection ───────────────────────────────────────────


async def run_integration_checks():
    """
    Generic collector loop: for each registered integration, fetch all configs
    and run collect(). Stores results as Snapshots.
    """
    from integrations import get_registry

    registry = get_registry()
    if not registry:
        return

    async with AsyncSessionLocal() as db:
        # Get all enabled configs in one query
        result = await db.execute(
            select(IntegrationConfig).where(IntegrationConfig.enabled == True)
        )
        all_configs = result.scalars().all()

    if not all_configs:
        return

    # Group by type
    by_type: dict[str, list] = {}
    for cfg in all_configs:
        by_type.setdefault(cfg.type, []).append(cfg)

    for integration_type, configs in by_type.items():
        integration_cls = registry.get(integration_type)
        if not integration_cls:
            continue

        async with AsyncSessionLocal() as db:
            for cfg in configs:
                try:
                    config_dict = int_svc.decrypt_config(cfg.config_json)
                    instance = integration_cls(config=config_dict)
                    result = await instance.collect()

                    if result.success:
                        await snap_svc.save(
                            db, integration_type, cfg.id,
                            ok=True, data=result.data,
                        )
                        # Run post-snapshot hook (e.g., auto-import hosts)
                        try:
                            await instance.on_snapshot(result.data, config_dict, db)
                        except Exception as hook_exc:
                            logger.warning(
                                "on_snapshot hook failed [%s/%s]: %s",
                                integration_type, cfg.name, hook_exc,
                            )
                    else:
                        await snap_svc.save(
                            db, integration_type, cfg.id,
                            ok=False, error=result.error,
                        )
                except Exception as exc:
                    logger.error(
                        "Integration collect [%s/%s]: %s",
                        integration_type, cfg.name, exc,
                    )
                    await snap_svc.save(
                        db, integration_type, cfg.id,
                        ok=False, error=str(exc),
                    )
            await db.commit()

    logger.debug("Integration check done for %d type(s), %d config(s)",
                 len(by_type), len(all_configs))


# ── Ping checks ──────────────────────────────────────────────────────────────


async def run_ping_checks():
    """Ping all enabled hosts concurrently and store results."""
    import asyncio as _asyncio
    from collectors.ping import check_host

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(PingHost).where(PingHost.enabled == True))
        hosts = result.scalars().all()

    if not hosts:
        return

    active_hosts = [h for h in hosts if not h.maintenance]
    if not active_hosts:
        return

    # Load previous results for state-change detection
    async with AsyncSessionLocal() as db:
        from sqlalchemy import func as sa_func
        sub = (
            select(PingResult.host_id, sa_func.max(PingResult.timestamp).label("max_ts"))
            .group_by(PingResult.host_id)
            .subquery()
        )
        prev_rows = await db.execute(
            select(PingResult.host_id, PingResult.success)
            .join(sub, (PingResult.host_id == sub.c.host_id) & (PingResult.timestamp == sub.c.max_ts))
        )
        prev_success: dict[int, bool] = {row.host_id: row.success for row in prev_rows}

    # Run all checks concurrently with semaphore to limit parallelism
    sem = _asyncio.Semaphore(50)

    async def _check_one(host):
        async with sem:
            success, latency = await check_host(host)
            return host, success, latency

    results = await _asyncio.gather(*[_check_one(h) for h in active_hosts])

    # Batch-write all results in one transaction
    now = datetime.utcnow()
    async with AsyncSessionLocal() as db:
        for host, success, latency in results:
            db.add(PingResult(
                host_id=host.id,
                timestamp=now,
                success=success,
                latency_ms=latency,
            ))

            # Notify on state change
            prev = prev_success.get(host.id)
            if prev is True and not success:
                from notifications import notify
                _asyncio.create_task(notify(
                    f"Host offline: {host.name}",
                    f"Host {host.hostname} is no longer reachable.",
                    "critical"
                ))
            elif prev is False and success:
                from notifications import notify
                _asyncio.create_task(notify(
                    f"Host back online: {host.name}",
                    f"Host {host.hostname} is reachable again.",
                    "info"
                ))

        await db.commit()

    logger.debug("Ping check done for %d hosts (concurrent)", len(active_hosts))


# ── SSL expiry check ─────────────────────────────────────────────────────────


async def update_ssl_expiry():
    """Update ssl_expiry_days for all HTTPS hosts."""
    from collectors.ping import get_ssl_expiry_days
    from sqlalchemy import update as sa_update

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(PingHost).where(PingHost.enabled == True, PingHost.check_type == "https")
        )
        hosts = result.scalars().all()

    if not hosts:
        return

    async with AsyncSessionLocal() as db:
        for host in hosts:
            hostname = host.hostname
            for prefix in ("https://", "http://"):
                if hostname.startswith(prefix):
                    hostname = hostname[len(prefix):]
                    break
            hostname = hostname.split("/")[0].split(":")[0]
            days = await get_ssl_expiry_days(hostname, port=host.port or 443)
            if days is not None:
                await db.execute(
                    sa_update(PingHost).where(PingHost.id == host.id).values(ssl_expiry_days=days)
                )
        await db.commit()


# ── Cleanup ───────────────────────────────────────────────────────────────────


async def cleanup_old_results():
    """Delete old ping results, snapshots, and syslog messages."""
    from database import get_setting

    async with AsyncSessionLocal() as db:
        ping_ret = int(await get_setting(db, "ping_retention_days", "30"))
        int_ret = int(await get_setting(db, "integration_retention_days", "7"))

    async with AsyncSessionLocal() as db:
        # Ping results
        ping_cutoff = datetime.utcnow() - timedelta(days=ping_ret)
        await db.execute(delete(PingResult).where(PingResult.timestamp < ping_cutoff))
        # Integration snapshots
        await snap_svc.cleanup_all(db, int_ret)
        # Syslog messages – smart retention by severity
        from models.syslog import SyslogMessage, RETENTION_DAYS
        total_deleted = 0
        for sev, days in RETENTION_DAYS.items():
            cutoff = datetime.utcnow() - timedelta(days=days)
            r = await db.execute(
                delete(SyslogMessage)
                .where(SyslogMessage.severity == sev, SyslogMessage.timestamp < cutoff)
            )
            total_deleted += r.rowcount
        # Also clean messages with NULL severity older than 7 days
        null_cutoff = datetime.utcnow() - timedelta(days=7)
        r = await db.execute(
            delete(SyslogMessage)
            .where(SyslogMessage.severity.is_(None), SyslogMessage.timestamp < null_cutoff)
        )
        total_deleted += r.rowcount
        await db.commit()

    logger.info("Cleanup done (ping: %dd, integrations: %dd, syslog: %d msgs)", ping_ret, int_ret, total_deleted)


# ── Speedtest (old-style, not yet migrated to generic) ───────────────────────


async def run_speedtest_check():
    """Run a scheduled speedtest if configured."""
    from database import SpeedtestConfig, SpeedtestResult
    from collectors.speedtest import run_speedtest

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(SpeedtestConfig).limit(1))
        cfg = result.scalar_one_or_none()

    if not cfg or not cfg.schedule_minutes:
        return

    try:
        data = await run_speedtest(cfg.server_id)
        async with AsyncSessionLocal() as db:
            db.add(SpeedtestResult(
                config_id=cfg.id, timestamp=datetime.utcnow(), ok=True,
                download_mbps=data["download_mbps"], upload_mbps=data["upload_mbps"],
                ping_ms=data["ping_ms"], server_name=data["server_name"],
            ))
            await db.commit()
        logger.info("Speedtest: %.1f/%.1f Mbps, %.0fms",
                    data["download_mbps"], data["upload_mbps"], data["ping_ms"])
    except Exception as exc:
        logger.warning("Speedtest failed: %s", exc)
        async with AsyncSessionLocal() as db:
            db.add(SpeedtestResult(
                config_id=cfg.id, timestamp=datetime.utcnow(),
                ok=False, error=str(exc),
            ))
            await db.commit()


# ── Scheduler lifecycle ──────────────────────────────────────────────────────


async def run_correlation():
    """Run the correlation engine."""
    from services.correlation import run_correlation as _run
    await _run()


async def run_log_intelligence():
    """Run the log intelligence engine (template flush, baselines, precursors)."""
    from services.log_intelligence import run_intelligence
    await run_intelligence()


async def start_scheduler():
    """Read intervals from DB, then register and start all jobs."""
    from database import get_setting, SpeedtestConfig

    async with AsyncSessionLocal() as db:
        ping_interval = int(await get_setting(db, "ping_interval", "60"))
        proxmox_interval = int(await get_setting(db, "proxmox_interval", "60"))

        # Speedtest schedule
        result = await db.execute(select(SpeedtestConfig).limit(1))
        st_cfg = result.scalar_one_or_none()
        st_minutes = st_cfg.schedule_minutes if st_cfg else 60

    scheduler.add_job(run_ping_checks, "interval", seconds=ping_interval,
                      id="ping_checks", replace_existing=True)
    scheduler.add_job(run_integration_checks, "interval", seconds=proxmox_interval,
                      id="integration_checks", replace_existing=True)
    scheduler.add_job(run_speedtest_check, "interval", minutes=st_minutes,
                      id="speedtest_checks", replace_existing=True)
    scheduler.add_job(run_correlation, "interval", seconds=60,
                      id="correlation", replace_existing=True)
    scheduler.add_job(update_ssl_expiry, "interval", hours=6,
                      id="ssl_expiry", replace_existing=True)
    scheduler.add_job(cleanup_old_results, "cron", hour=3, minute=0,
                      id="cleanup", replace_existing=True)
    scheduler.add_job(run_log_intelligence, "interval", seconds=30,
                      id="log_intelligence", replace_existing=True)
    scheduler.start()
    logger.info("Scheduler started (ping=%ds, integrations=%ds, speedtest=%dm)",
                ping_interval, proxmox_interval, st_minutes)


def stop_scheduler():
    scheduler.shutdown(wait=False)
