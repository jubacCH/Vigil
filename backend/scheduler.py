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
    from utils.ping import check_host

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(PingHost).where(PingHost.enabled == True))
        hosts = result.scalars().all()

    if not hosts:
        return

    active_hosts = [h for h in hosts if not h.maintenance]
    if not active_hosts:
        return

    # Separate agent-sourced hosts — they use agent heartbeat, not ICMP
    agent_hosts = [h for h in active_hosts if h.source == "agent"]
    ping_hosts = [h for h in active_hosts if h.source != "agent"]

    # Handle agent-sourced hosts via agent last_seen
    if agent_hosts:
        from models.agent import Agent
        from sqlalchemy import func as sa_func
        async with AsyncSessionLocal() as db:
            for host in agent_hosts:
                # Find matching agent by name (PingHost.name == Agent.hostname)
                agent_r = await db.execute(
                    select(Agent).where(sa_func.lower(Agent.hostname) == host.name.lower())
                )
                agent = agent_r.scalar_one_or_none()
                success = False
                if agent and agent.last_seen:
                    success = (datetime.utcnow() - agent.last_seen).total_seconds() < 120
                db.add(PingResult(
                    host_id=host.id,
                    timestamp=datetime.utcnow(),
                    success=success,
                    latency_ms=0 if success else None,
                ))
                from services.websocket import broadcast_ping_update
                _asyncio.create_task(broadcast_ping_update(host.id, host.name, success, 0 if success else None))
            await db.commit()

    active_hosts = ping_hosts

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

            # Broadcast live update via WebSocket
            from services.websocket import broadcast_ping_update
            _asyncio.create_task(broadcast_ping_update(host.id, host.name, success, latency))

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
    from utils.ping import get_ssl_expiry_days
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
        # Agent snapshots: keep 7 days
        from models.agent import AgentSnapshot
        agent_cutoff = datetime.utcnow() - timedelta(days=7)
        await db.execute(delete(AgentSnapshot).where(AgentSnapshot.timestamp < agent_cutoff))
        await db.commit()

    logger.info("Cleanup done (ping: %dd, integrations: %dd, syslog: %d msgs)", ping_ret, int_ret, total_deleted)


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
    from database import get_setting

    async with AsyncSessionLocal() as db:
        ping_interval = int(await get_setting(db, "ping_interval", "60"))
        integration_interval = int(await get_setting(db, "proxmox_interval", "60"))

    scheduler.add_job(run_ping_checks, "interval", seconds=ping_interval,
                      id="ping_checks", replace_existing=True)
    scheduler.add_job(run_integration_checks, "interval", seconds=integration_interval,
                      id="integration_checks", replace_existing=True)
    scheduler.add_job(run_correlation, "interval", seconds=60,
                      id="correlation", replace_existing=True)
    scheduler.add_job(update_ssl_expiry, "interval", hours=6,
                      id="ssl_expiry", replace_existing=True)
    scheduler.add_job(cleanup_old_results, "cron", hour=3, minute=0,
                      id="cleanup", replace_existing=True)
    scheduler.add_job(run_log_intelligence, "interval", seconds=30,
                      id="log_intelligence", replace_existing=True)
    scheduler.start()
    logger.info("Scheduler started (ping=%ds, integrations=%ds)",
                ping_interval, integration_interval)


def stop_scheduler():
    scheduler.shutdown(wait=False)
