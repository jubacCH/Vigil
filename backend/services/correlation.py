"""
Correlation engine – runs periodically (60s) to detect and group related issues
into Incidents. Supports deduplication and auto-resolve.

Rules:
1. host_down_syslog  – Host offline + syslog errors from same host (5min window)
2. multi_host_down   – 3+ hosts offline simultaneously → network problem
3. integration_host  – Integration unreachable + associated host offline
4. syslog_spike      – Syslog error rate 5x above baseline + latency increase
"""
import hashlib
import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import func, select, and_

from models.base import AsyncSessionLocal
from models.ping import PingHost, PingResult
from models.syslog import SyslogMessage
from models.integration import IntegrationConfig, Snapshot
from models.incident import Incident, IncidentEvent

log = logging.getLogger("nodeglow.correlation")


def _host_ids_hash(host_ids: list[int]) -> str:
    """Deterministic hash of sorted host IDs for dedup."""
    return hashlib.sha256(",".join(str(i) for i in sorted(host_ids)).encode()).hexdigest()[:16]


async def _find_or_create_incident(
    db, rule: str, title: str, severity: str,
    host_ids: list[int], event_type: str, summary: str, detail: str = None,
) -> Incident:
    """Find existing open incident for this rule+hosts combo, or create new one."""
    h = _host_ids_hash(host_ids)

    existing = (await db.execute(
        select(Incident).where(
            Incident.rule == rule,
            Incident.host_ids_hash == h,
            Incident.status.in_(["open", "acknowledged"]),
        )
    )).scalar_one_or_none()

    if existing:
        # Append event to existing incident
        existing.updated_at = datetime.utcnow()
        db.add(IncidentEvent(
            incident_id=existing.id,
            event_type=event_type,
            summary=summary,
            detail=detail,
        ))
        return existing

    # Create new incident
    incident = Incident(
        rule=rule,
        title=title,
        severity=severity,
        host_ids_hash=h,
    )
    db.add(incident)
    await db.flush()

    db.add(IncidentEvent(
        incident_id=incident.id,
        event_type="created",
        summary=summary,
        detail=detail,
    ))

    # Send notification for new incidents
    try:
        from notifications import notify
        await notify(
            f"🔴 Incident: {title}",
            summary,
            severity=severity,
        )
    except Exception as exc:
        log.warning("Failed to send incident notification: %s", exc)

    return incident


async def _get_offline_hosts(db) -> list[PingHost]:
    """Get hosts that are currently offline (latest result = fail, not in maintenance)."""
    # Subquery: latest PingResult per host
    sub = (
        select(PingResult.host_id, func.max(PingResult.id).label("max_id"))
        .group_by(PingResult.host_id)
        .subquery()
    )
    results = await db.execute(
        select(PingHost, PingResult)
        .join(sub, PingHost.id == sub.c.host_id)
        .join(PingResult, PingResult.id == sub.c.max_id)
        .where(
            PingHost.enabled == True,
            PingHost.maintenance == False,
            PingResult.success == False,
        )
    )
    return [row[0] for row in results.all()]


# ── Rule 1: Host Down + Syslog Errors ───────────────────────────────────────

async def _rule_host_down_syslog(db):
    """Host offline AND syslog severity <= 3 from same host in 5min window."""
    offline_hosts = await _get_offline_hosts(db)
    if not offline_hosts:
        return

    window = datetime.utcnow() - timedelta(minutes=5)

    for host in offline_hosts:
        # Check for error-level syslog messages from this host
        syslog_count = (await db.execute(
            select(func.count(SyslogMessage.id)).where(
                SyslogMessage.host_id == host.id,
                SyslogMessage.severity <= 3,  # error and above
                SyslogMessage.timestamp >= window,
            )
        )).scalar() or 0

        if syslog_count > 0:
            await _find_or_create_incident(
                db,
                rule="host_down_syslog",
                title=f"{host.name} offline with syslog errors",
                severity="critical",
                host_ids=[host.id],
                event_type="host_down",
                summary=f"{host.name} ({host.hostname}) is offline with {syslog_count} syslog errors in the last 5min",
            )


# ── Rule 2: Multi-Host Down ─────────────────────────────────────────────────

async def _rule_multi_host_down(db):
    """3+ hosts offline simultaneously → likely network problem."""
    offline_hosts = await _get_offline_hosts(db)
    if len(offline_hosts) < 3:
        return

    # Group by /24 subnet (simple heuristic)
    subnets: dict[str, list[PingHost]] = {}
    for host in offline_hosts:
        hostname = host.hostname.strip()
        parts = hostname.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            subnet = ".".join(parts[:3]) + ".0/24"
        else:
            subnet = "unknown"
        subnets.setdefault(subnet, []).append(host)

    for subnet, hosts in subnets.items():
        if len(hosts) >= 3:
            host_ids = [h.id for h in hosts]
            names = ", ".join(h.name for h in hosts[:5])
            if len(hosts) > 5:
                names += f" (+{len(hosts) - 5} more)"
            await _find_or_create_incident(
                db,
                rule="multi_host_down",
                title=f"Network issue: {len(hosts)} hosts down in {subnet}",
                severity="critical",
                host_ids=host_ids,
                event_type="host_down",
                summary=f"{len(hosts)} hosts offline in {subnet}: {names}",
            )

    # Also trigger if 3+ hosts down across all subnets (no single subnet has 3+)
    total_offline = len(offline_hosts)
    already_covered = sum(len(h) for h in subnets.values() if len(h) >= 3)
    remaining = total_offline - already_covered
    if remaining >= 3:
        uncovered = [h for s, hosts in subnets.items() if len(hosts) < 3 for h in hosts]
        host_ids = [h.id for h in uncovered]
        names = ", ".join(h.name for h in uncovered[:5])
        if len(uncovered) > 5:
            names += f" (+{len(uncovered) - 5} more)"
        await _find_or_create_incident(
            db,
            rule="multi_host_down",
            title=f"Multiple hosts down ({len(uncovered)} across subnets)",
            severity="warning",
            host_ids=host_ids,
            event_type="host_down",
            summary=f"{len(uncovered)} hosts offline across multiple subnets: {names}",
        )


# ── Rule 3: Integration + Host ──────────────────────────────────────────────

async def _rule_integration_host(db):
    """Integration unreachable AND the host running it is also offline."""
    from services import snapshot as snap_svc

    offline_hosts = await _get_offline_hosts(db)
    if not offline_hosts:
        return

    offline_hostnames = {h.hostname.lower().strip() for h in offline_hosts}
    offline_by_hostname: dict[str, PingHost] = {h.hostname.lower().strip(): h for h in offline_hosts}

    # Get all integration configs
    configs = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.enabled == True))).scalars().all()
    all_snaps = await snap_svc.get_latest_batch_all(db)

    for cfg in configs:
        snap = all_snaps.get(cfg.type, {}).get(cfg.id)
        if not snap or snap.ok:
            continue

        # Try to extract host from config
        try:
            from services.integration import decrypt_config
            config_dict = decrypt_config(cfg.config_json)
            cfg_host = (config_dict.get("host") or "").lower().strip()
            # Strip protocol and port
            cfg_host = cfg_host.replace("https://", "").replace("http://", "").split(":")[0].split("/")[0]
        except Exception:
            continue

        if cfg_host and cfg_host in offline_hostnames:
            ping_host = offline_by_hostname[cfg_host]
            await _find_or_create_incident(
                db,
                rule="integration_host",
                title=f"{cfg.name} unreachable – host {ping_host.name} offline",
                severity="warning",
                host_ids=[ping_host.id],
                event_type="integration_error",
                summary=f"Integration '{cfg.name}' ({cfg.type}) is unreachable and its host {ping_host.name} ({cfg_host}) is also offline",
            )


# ── Rule 4: Syslog Spike ────────────────────────────────────────────────────

async def _rule_syslog_spike(db):
    """Syslog error rate 5x above 1h baseline."""
    now = datetime.utcnow()
    window_5m = now - timedelta(minutes=5)
    window_1h = now - timedelta(hours=1)

    # Count errors (severity <= 3) in last 5min
    recent_errors = (await db.execute(
        select(func.count(SyslogMessage.id)).where(
            SyslogMessage.severity <= 3,
            SyslogMessage.timestamp >= window_5m,
        )
    )).scalar() or 0

    if recent_errors < 10:  # minimum threshold
        return

    # Count errors in last hour (baseline)
    hourly_errors = (await db.execute(
        select(func.count(SyslogMessage.id)).where(
            SyslogMessage.severity <= 3,
            SyslogMessage.timestamp >= window_1h,
        )
    )).scalar() or 0

    # Expected 5min rate = hourly / 12
    baseline_5m = max(1, hourly_errors / 12)

    if recent_errors >= baseline_5m * 5:
        await _find_or_create_incident(
            db,
            rule="syslog_spike",
            title=f"Syslog error spike: {recent_errors} errors in 5min",
            severity="warning",
            host_ids=[0],  # no specific host
            event_type="syslog_error",
            summary=f"{recent_errors} syslog errors in last 5min (baseline: ~{int(baseline_5m)}/5min)",
        )


# ── Auto-Resolve ────────────────────────────────────────────────────────────

async def _auto_resolve(db):
    """Auto-resolve incidents where all affected hosts are back online."""
    open_incidents = (await db.execute(
        select(Incident).where(Incident.status.in_(["open", "acknowledged"]))
    )).scalars().all()

    if not open_incidents:
        return

    # Get current offline host IDs
    offline_hosts = await _get_offline_hosts(db)
    offline_ids = {h.id for h in offline_hosts}

    for incident in open_incidents:
        # Skip syslog_spike – auto-resolves after no new spike
        if incident.rule == "syslog_spike":
            # Resolve if last update was > 10min ago (no new spike detected)
            if incident.updated_at < datetime.utcnow() - timedelta(minutes=10):
                incident.status = "resolved"
                incident.resolved_at = datetime.utcnow()
                db.add(IncidentEvent(
                    incident_id=incident.id,
                    event_type="resolved",
                    summary="Auto-resolved: error rate returned to normal",
                ))
                try:
                    from notifications import notify
                    await notify(
                        f"✅ Resolved: {incident.title}",
                        "Auto-resolved: error rate returned to normal",
                        severity="info",
                    )
                except Exception as exc:
                    log.warning("Failed to send resolve notification: %s", exc)
            continue

        if not incident.host_ids_hash:
            continue

        # Check if ALL hosts from the original hash are back online
        # We find incidents by their hash, so we need to check current offline hosts
        # against what created this incident. Since we can't reverse the hash,
        # we check: if no offline hosts match this rule anymore, resolve it.
        should_resolve = True

        if incident.rule == "host_down_syslog":
            # If any offline host still has syslog errors, keep open
            window = datetime.utcnow() - timedelta(minutes=5)
            for host in offline_hosts:
                h = _host_ids_hash([host.id])
                if h == incident.host_ids_hash:
                    syslog_count = (await db.execute(
                        select(func.count(SyslogMessage.id)).where(
                            SyslogMessage.host_id == host.id,
                            SyslogMessage.severity <= 3,
                            SyslogMessage.timestamp >= window,
                        )
                    )).scalar() or 0
                    if syslog_count > 0:
                        should_resolve = False
                        break

        elif incident.rule == "multi_host_down":
            # Can't easily reverse the hash, so check if enough hosts recovered
            # Resolve if < 3 hosts offline now
            if len(offline_hosts) >= 3:
                should_resolve = False

        elif incident.rule == "integration_host":
            # If the host is still offline, keep open
            for host in offline_hosts:
                if _host_ids_hash([host.id]) == incident.host_ids_hash:
                    should_resolve = False
                    break

        if should_resolve:
            incident.status = "resolved"
            incident.resolved_at = datetime.utcnow()
            db.add(IncidentEvent(
                incident_id=incident.id,
                event_type="resolved",
                summary="Auto-resolved: affected hosts are back online",
            ))
            try:
                from notifications import notify
                await notify(
                    f"✅ Resolved: {incident.title}",
                    "Auto-resolved: affected hosts are back online",
                    severity="info",
                )
            except Exception as exc:
                log.warning("Failed to send resolve notification: %s", exc)


# ── Main entry point ────────────────────────────────────────────────────────

async def run_correlation():
    """Run all correlation rules. Called every 60s by scheduler."""
    async with AsyncSessionLocal() as db:
        try:
            await _rule_host_down_syslog(db)
            await _rule_multi_host_down(db)
            await _rule_integration_host(db)
            await _rule_syslog_spike(db)
            await _auto_resolve(db)
            await db.commit()
        except Exception as e:
            log.error("Correlation engine error: %s", e, exc_info=True)
            await db.rollback()
