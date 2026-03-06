"""
Background scheduler – generic integration collection + ping checks + cleanup.
"""
import json
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
    """Ping all enabled hosts and store results."""
    import asyncio as _asyncio
    from collectors.ping import check_host, get_ssl_expiry_days

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(PingHost).where(PingHost.enabled == True))
        hosts = result.scalars().all()

    if not hosts:
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

    async with AsyncSessionLocal() as db:
        for host in hosts:
            if host.maintenance:
                continue
            success, latency = await check_host(host)
            db.add(PingResult(
                host_id=host.id,
                timestamp=datetime.utcnow(),
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

    logger.debug("Ping check done for %d hosts", len(hosts))


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
    """Delete old ping results and snapshots."""
    async with AsyncSessionLocal() as db:
        from models.settings import get_setting
        retention_str = await get_setting(db, "data_retention_days", "30")
        retention = int(retention_str)

    cutoff = datetime.utcnow() - timedelta(days=retention)

    async with AsyncSessionLocal() as db:
        # Ping results
        await db.execute(delete(PingResult).where(PingResult.timestamp < cutoff))
        # Snapshots
        await snap_svc.cleanup_all(db, retention)
        await db.commit()

    logger.info("Cleanup done (retention: %d days)", retention)


# ── Scheduler lifecycle ──────────────────────────────────────────────────────


def start_scheduler():
    scheduler.add_job(run_ping_checks, "interval", seconds=60,
                      id="ping_checks", replace_existing=True)
    scheduler.add_job(run_integration_checks, "interval", seconds=60,
                      id="integration_checks", replace_existing=True)
    scheduler.add_job(update_ssl_expiry, "interval", hours=6,
                      id="ssl_expiry", replace_existing=True)
    scheduler.add_job(cleanup_old_results, "cron", hour=3, minute=0,
                      id="cleanup", replace_existing=True)
    scheduler.start()
    logger.info("Scheduler started")


def stop_scheduler():
    scheduler.shutdown(wait=False)
