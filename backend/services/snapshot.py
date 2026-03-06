"""
Generic snapshot service – get/save/cleanup snapshots for any integration type.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from models.integration import Snapshot


async def save(
    db: AsyncSession,
    entity_type: str,
    entity_id: int,
    ok: bool,
    data: Any = None,
    error: str | None = None,
) -> Snapshot:
    """Save a new snapshot."""
    snap = Snapshot(
        entity_type=entity_type,
        entity_id=entity_id,
        ok=ok,
        data_json=json.dumps(data) if data is not None else None,
        error=error,
    )
    db.add(snap)
    await db.flush()
    return snap


async def get_latest(
    db: AsyncSession,
    entity_type: str,
    entity_id: int,
) -> Snapshot | None:
    """Get the most recent snapshot for an entity."""
    result = await db.execute(
        select(Snapshot)
        .where(Snapshot.entity_type == entity_type, Snapshot.entity_id == entity_id)
        .order_by(Snapshot.timestamp.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_latest_batch(
    db: AsyncSession,
    entity_type: str,
) -> dict[int, Snapshot]:
    """Get the latest snapshot for ALL entities of a type. Single query."""
    # Subquery: max snapshot ID per entity
    sub = (
        select(
            Snapshot.entity_id,
            func.max(Snapshot.id).label("max_id"),
        )
        .where(Snapshot.entity_type == entity_type)
        .group_by(Snapshot.entity_id)
        .subquery()
    )
    result = await db.execute(
        select(Snapshot).join(sub, Snapshot.id == sub.c.max_id)
    )
    return {snap.entity_id: snap for snap in result.scalars().all()}


async def get_history(
    db: AsyncSession,
    entity_type: str,
    entity_id: int,
    limit: int = 100,
    since: datetime | None = None,
) -> list[Snapshot]:
    """Get snapshot history for an entity, newest first."""
    q = (
        select(Snapshot)
        .where(Snapshot.entity_type == entity_type, Snapshot.entity_id == entity_id)
    )
    if since:
        q = q.where(Snapshot.timestamp >= since)
    q = q.order_by(Snapshot.timestamp.desc()).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


async def get_previous(
    db: AsyncSession,
    entity_type: str,
    entity_id: int,
    before: datetime,
) -> Snapshot | None:
    """Get the snapshot immediately before a given timestamp."""
    result = await db.execute(
        select(Snapshot)
        .where(
            Snapshot.entity_type == entity_type,
            Snapshot.entity_id == entity_id,
            Snapshot.timestamp < before,
        )
        .order_by(Snapshot.timestamp.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def cleanup(
    db: AsyncSession,
    entity_type: str,
    retention_days: int,
) -> int:
    """Delete snapshots older than retention_days. Returns count deleted."""
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    result = await db.execute(
        delete(Snapshot).where(
            Snapshot.entity_type == entity_type,
            Snapshot.timestamp < cutoff,
        )
    )
    return result.rowcount or 0


async def cleanup_all(db: AsyncSession, retention_days: int) -> int:
    """Delete ALL snapshots older than retention_days."""
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    result = await db.execute(
        delete(Snapshot).where(Snapshot.timestamp < cutoff)
    )
    return result.rowcount or 0
