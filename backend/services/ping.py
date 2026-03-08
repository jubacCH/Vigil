"""Ping service – batch queries for host stats, uptime, heatmaps."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import cast, func, select, Integer
from sqlalchemy.ext.asyncio import AsyncSession

from database import PingHost, PingResult


async def get_latest_by_host(db: AsyncSession, host_ids: list[int]) -> dict[int, PingResult]:
    """Batch fetch the latest PingResult per host. Returns {host_id: PingResult}."""
    if not host_ids:
        return {}
    sub = (
        select(PingResult.host_id, func.max(PingResult.id).label("max_id"))
        .where(PingResult.host_id.in_(host_ids))
        .group_by(PingResult.host_id)
        .subquery()
    )
    rows = (await db.execute(
        select(PingResult).join(sub, PingResult.id == sub.c.max_id)
    )).scalars().all()
    return {r.host_id: r for r in rows}


async def get_uptime_map(
    db: AsyncSession,
    windows: list[tuple[timedelta, str]] | None = None,
) -> dict[int, dict[str, float | None]]:
    """Batch uptime stats for all hosts across multiple time windows.

    Returns {host_id: {"h24": 99.1, "d7": 98.5, "d30": 97.2}}.
    """
    if windows is None:
        windows = [
            (timedelta(hours=24), "h24"),
            (timedelta(days=7), "d7"),
            (timedelta(days=30), "d30"),
        ]
    now = datetime.utcnow()
    result: dict[int, dict] = {}
    for window, key in windows:
        rows = await db.execute(
            select(
                PingResult.host_id,
                func.count().label("total"),
                func.sum(cast(PingResult.success, Integer)).label("ok"),
            )
            .where(PingResult.timestamp >= now - window)
            .group_by(PingResult.host_id)
        )
        for host_id, total, ok in rows:
            if host_id not in result:
                result[host_id] = {}
            result[host_id][key] = round((ok or 0) / total * 100, 1) if total else None
    return result


async def get_heatmap_data(
    db: AsyncSession,
    days: int = 30,
) -> dict[int, dict[str, tuple[int, int]]]:
    """Batch fetch daily success/total aggregates for heatmap display.

    Returns {host_id: {"2026-03-01": (total, ok), ...}}.
    """
    since = datetime.utcnow() - timedelta(days=days)
    rows = (await db.execute(
        select(
            PingResult.host_id,
            func.date(PingResult.timestamp).label("day"),
            func.count().label("total"),
            func.sum(cast(PingResult.success, Integer)).label("ok"),
        )
        .where(PingResult.timestamp >= since)
        .group_by(PingResult.host_id, func.date(PingResult.timestamp))
    )).all()

    result: dict[int, dict[str, tuple]] = {}
    for row in rows:
        result.setdefault(row.host_id, {})[str(row.day)] = (row.total, row.ok or 0)
    return result


def build_heatmap(agg: dict[str, tuple[int, int]], days: int = 30) -> list[float | None]:
    """Build a heatmap list from daily aggregates. One value per day (oldest first)."""
    now = datetime.utcnow()
    heatmap = []
    for i in range(days):
        d = (now - timedelta(days=days - 1 - i)).date()
        day_data = agg.get(str(d))
        if day_data:
            total, ok = day_data
            heatmap.append(round(ok / total * 100, 1) if total > 0 else None)
        else:
            heatmap.append(None)
    return heatmap


async def get_24h_stats(
    db: AsyncSession,
    host_ids: list[int],
) -> dict[int, dict]:
    """Batch 24h stats per host: total, success, avg latency.

    Returns {host_id: {"total": N, "success": N, "avg_lat": float|None}}.
    """
    if not host_ids:
        return {}
    window = datetime.utcnow() - timedelta(hours=24)
    rows = (await db.execute(
        select(
            PingResult.host_id,
            func.count().label("total"),
            func.count().filter(PingResult.success == True).label("success"),
            func.avg(PingResult.latency_ms).filter(PingResult.success == True).label("avg_lat"),
        )
        .where(PingResult.host_id.in_(host_ids), PingResult.timestamp >= window)
        .group_by(PingResult.host_id)
    )).all()
    return {
        row.host_id: {"total": row.total, "success": row.success, "avg_lat": row.avg_lat}
        for row in rows
    }


async def get_sparklines(
    db: AsyncSession,
    host_ids: list[int],
    hours: int = 2,
    max_points: int = 60,
) -> dict[int, list[float | None]]:
    """Batch sparkline data (latency values) for all hosts.

    Returns {host_id: [latency_ms|None, ...]}.
    """
    if not host_ids:
        return {}
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = (await db.execute(
        select(PingResult.host_id, PingResult.success, PingResult.latency_ms)
        .where(PingResult.host_id.in_(host_ids), PingResult.timestamp >= since)
        .order_by(PingResult.host_id, PingResult.timestamp.asc())
    )).all()

    result: dict[int, list] = defaultdict(list)
    for row in rows:
        result[row.host_id].append(row.latency_ms if row.success else None)
    # Limit to last N points
    for hid in result:
        result[hid] = result[hid][-max_points:]
    return dict(result)
