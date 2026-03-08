"""Tests for correlation engine notification integration."""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from models.ping import PingHost, PingResult
from models.incident import Incident, IncidentEvent
from services.correlation import (
    _find_or_create_incident,
    _auto_resolve,
    run_correlation,
)


async def test_new_incident_sends_notification(db):
    """Creating a new incident should trigger a notification."""
    with patch("notifications.notify", new_callable=AsyncMock) as mock_notify:
        incident = await _find_or_create_incident(
            db,
            rule="test_rule",
            title="Test Host Offline",
            severity="critical",
            host_ids=[1],
            event_type="host_down",
            summary="Test host is down",
        )
        await db.commit()

        assert incident is not None
        assert incident.rule == "test_rule"
        mock_notify.assert_called_once()
        call_args = mock_notify.call_args
        assert "Test Host Offline" in call_args[0][0]
        assert call_args[1]["severity"] == "critical"


async def test_existing_incident_no_duplicate_notification(db):
    """Appending to existing incident should NOT send notification."""
    with patch("notifications.notify", new_callable=AsyncMock) as mock_notify:
        # Create initial incident
        inc1 = await _find_or_create_incident(
            db, rule="test_rule", title="Host Down",
            severity="critical", host_ids=[1],
            event_type="host_down", summary="Down",
        )
        await db.flush()
        mock_notify.assert_called_once()
        mock_notify.reset_mock()

        # Same rule + host → should append, not create new
        inc2 = await _find_or_create_incident(
            db, rule="test_rule", title="Host Down",
            severity="critical", host_ids=[1],
            event_type="host_down", summary="Still down",
        )
        await db.commit()

        assert inc1.id == inc2.id
        mock_notify.assert_not_called()


async def test_auto_resolve_sends_notification(db):
    """Auto-resolving an incident should send a resolve notification."""
    # Create an open incident with no matching offline hosts
    incident = Incident(
        rule="integration_host",
        title="Server offline",
        severity="warning",
        host_ids_hash="abc123",
        status="open",
        created_at=datetime.utcnow() - timedelta(minutes=30),
        updated_at=datetime.utcnow() - timedelta(minutes=5),
    )
    db.add(incident)
    await db.flush()

    with patch("notifications.notify", new_callable=AsyncMock) as mock_notify, \
         patch("services.correlation._get_offline_hosts", new_callable=AsyncMock, return_value=[]):
        await _auto_resolve(db)
        await db.commit()

        # Should have sent resolve notification
        mock_notify.assert_called_once()
        assert "Resolved" in mock_notify.call_args[0][0]


async def test_syslog_spike_auto_resolve(db):
    """Syslog spike incident auto-resolves after 10min of silence."""
    incident = Incident(
        rule="syslog_spike",
        title="Syslog spike: 50 errors",
        severity="warning",
        host_ids_hash="000",
        status="open",
        created_at=datetime.utcnow() - timedelta(minutes=20),
        updated_at=datetime.utcnow() - timedelta(minutes=15),  # >10min ago
    )
    db.add(incident)
    await db.flush()

    with patch("notifications.notify", new_callable=AsyncMock) as mock_notify, \
         patch("services.correlation._get_offline_hosts", new_callable=AsyncMock, return_value=[]):
        await _auto_resolve(db)
        await db.commit()

        assert incident.status == "resolved"
        mock_notify.assert_called_once()
