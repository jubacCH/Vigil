"""Tests for the ping service batch queries."""
from datetime import datetime, timedelta

from database import PingHost, PingResult
from services import ping as ping_svc


async def test_get_latest_by_host(db):
    """Should return the most recent PingResult per host."""
    h = PingHost(name="srv1", hostname="10.0.0.1")
    db.add(h)
    await db.flush()

    db.add(PingResult(host_id=h.id, success=True, latency_ms=5.0, timestamp=datetime(2026, 1, 1, 10, 0)))
    db.add(PingResult(host_id=h.id, success=False, latency_ms=None, timestamp=datetime(2026, 1, 1, 11, 0)))
    await db.commit()

    result = await ping_svc.get_latest_by_host(db, [h.id])
    assert h.id in result
    assert result[h.id].success is False  # latest


async def test_get_latest_by_host_empty(db):
    """Empty list should return empty dict."""
    result = await ping_svc.get_latest_by_host(db, [])
    assert result == {}


async def test_get_24h_stats(db):
    """Should return aggregated stats for last 24h."""
    h = PingHost(name="srv2", hostname="10.0.0.2")
    db.add(h)
    await db.flush()

    now = datetime.utcnow()
    for i in range(10):
        db.add(PingResult(
            host_id=h.id,
            success=(i < 8),  # 8 ok, 2 fail
            latency_ms=5.0 if i < 8 else None,
            timestamp=now - timedelta(minutes=i * 10),
        ))
    await db.commit()

    stats = await ping_svc.get_24h_stats(db, [h.id])
    assert h.id in stats
    assert stats[h.id]["total"] == 10
    assert stats[h.id]["success"] == 8


async def test_build_heatmap():
    """Should produce a list of daily uptime percentages."""
    now = datetime.utcnow()
    today = str(now.date())
    yesterday = str((now - timedelta(days=1)).date())

    agg = {
        today: (100, 95),
        yesterday: (100, 80),
    }
    heatmap = ping_svc.build_heatmap(agg, days=3)
    assert len(heatmap) == 3
    # Most recent day (today) is last
    assert heatmap[-1] == 95.0
    assert heatmap[-2] == 80.0
    assert heatmap[-3] is None  # no data


async def test_get_sparklines(db):
    """Should return latency values grouped by host."""
    h = PingHost(name="srv3", hostname="10.0.0.3")
    db.add(h)
    await db.flush()

    now = datetime.utcnow()
    for i in range(5):
        db.add(PingResult(
            host_id=h.id, success=True,
            latency_ms=float(i),
            timestamp=now - timedelta(minutes=i),
        ))
    await db.commit()

    sparks = await ping_svc.get_sparklines(db, [h.id], hours=1)
    assert h.id in sparks
    assert len(sparks[h.id]) == 5
