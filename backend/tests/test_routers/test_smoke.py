"""Smoke tests – verify key routes return 200 and don't crash."""
import pytest
from unittest.mock import AsyncMock, patch


async def test_health(client):
    """Health endpoint bypasses middleware and returns ok."""
    with patch("main.AsyncSessionLocal") as mock_cls:
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_login_page(client):
    """Login page renders without auth."""
    resp = await client.get("/login")
    assert resp.status_code == 200
    assert "password" in resp.text.lower()


async def test_dashboard(client):
    """Dashboard renders with empty data."""
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "NODEGLOW" in resp.text or "dashboard" in resp.text.lower()


async def test_ping_list(client):
    """Ping list page renders (no hosts)."""
    resp = await client.get("/ping")
    assert resp.status_code == 200


async def test_alerts_page(client):
    """Alerts page renders."""
    resp = await client.get("/alerts")
    assert resp.status_code == 200


async def test_syslog_page(client):
    """Syslog page renders."""
    resp = await client.get("/syslog")
    assert resp.status_code == 200


async def test_incidents_page(client):
    """Incidents page renders."""
    resp = await client.get("/incidents")
    assert resp.status_code == 200


async def test_settings_page(client):
    """Settings page renders for admin user."""
    resp = await client.get("/settings")
    assert resp.status_code == 200


async def test_api_status(client):
    """Status API returns JSON list."""
    resp = await client.get("/ping/api/status")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_integration_list(client):
    """Integration list page renders."""
    resp = await client.get("/integration/proxmox")
    assert resp.status_code == 200


async def test_unknown_integration_404(client):
    """Non-existent integration type returns 404."""
    resp = await client.get("/integration/nonexistent")
    assert resp.status_code == 404
