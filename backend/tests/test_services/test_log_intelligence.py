"""Tests for the log intelligence engine (template extraction, tagging, noise scoring)."""
from datetime import datetime, timedelta

from services.log_intelligence import (
    auto_tag,
    compute_noise_score,
    extract_template,
    process_message,
)


# ── Template Extraction ───────────────────────────────────────────────────────

def test_extract_template_replaces_ips():
    tpl, h = extract_template("Connection from 192.168.1.100 port 22345")
    assert "<IP>" in tpl
    assert "<NUM>" in tpl or "<PORT>" in tpl
    assert "192.168.1.100" not in tpl


def test_extract_template_replaces_timestamps():
    tpl, _ = extract_template("Event at 2026-03-07T10:30:15.123Z completed")
    assert "<TS>" in tpl
    assert "2026" not in tpl


def test_extract_template_replaces_uuids():
    tpl, _ = extract_template("Session 550e8400-e29b-41d4-a716-446655440000 started")
    assert "<UUID>" in tpl


def test_extract_template_replaces_paths():
    tpl, _ = extract_template("Error reading /var/log/syslog.1")
    assert "<PATH>" in tpl


def test_extract_template_replaces_hex():
    tpl, _ = extract_template("Memory at 0xDEADBEEF corrupted")
    assert "<HEX>" in tpl


def test_extract_template_deterministic():
    """Same message structure = same hash."""
    _, h1 = extract_template("Failed password for root from 10.0.0.1 port 22345")
    _, h2 = extract_template("Failed password for root from 10.0.0.2 port 54321")
    assert h1 == h2


def test_extract_template_different_structure():
    """Different message structure = different hash."""
    _, h1 = extract_template("Failed password for root from 10.0.0.1")
    _, h2 = extract_template("Disk I/O error on sda1 sector 12345")
    assert h1 != h2


def test_extract_template_empty():
    tpl, h = extract_template("")
    assert tpl == ""
    assert h is not None


def test_extract_template_mac_address():
    tpl, _ = extract_template("Device 00:11:22:33:44:55 connected")
    assert "<MAC>" in tpl


# ── Auto-Tagging ─────────────────────────────────────────────────────────────

def test_auto_tag_security():
    tags = auto_tag("Failed password for root from 10.0.0.1")
    assert "security" in tags


def test_auto_tag_hardware():
    tags = auto_tag("disk I/O error on sda1 sector 12345")
    assert "hardware" in tags


def test_auto_tag_network():
    tags = auto_tag("eth0: link down")
    assert "network" in tags


def test_auto_tag_service():
    tags = auto_tag("systemd: Started nginx.service")
    assert "service" in tags


def test_auto_tag_auth():
    tags = auto_tag("Accepted publickey for admin from 10.0.0.1")
    assert "auth" in tags


def test_auto_tag_storage():
    tags = auto_tag("ZFS pool tank scrub completed with 0 errors")
    assert "storage" in tags


def test_auto_tag_multiple():
    tags = auto_tag("Failed SSH login from 10.0.0.1 denied by firewall")
    assert "security" in tags
    assert "network" in tags or "auth" in tags


def test_auto_tag_no_match():
    tags = auto_tag("Just a regular message about nothing special")
    assert len(tags) == 0


# ── Noise Score ───────────────────────────────────────────────────────────────

def test_noise_score_new_template():
    """Brand new templates should have low noise score (= interesting)."""
    score = compute_noise_score(
        count=1, hours_active=0.1,
        first_seen=datetime.utcnow(),
    )
    assert score < 30


def test_noise_score_high_frequency():
    """High frequency messages should be noisy."""
    score = compute_noise_score(
        count=10000, hours_active=10,
        first_seen=datetime.utcnow() - timedelta(days=7),
    )
    assert score > 60


def test_noise_score_critical_severity():
    """Critical severity should reduce noise score."""
    score = compute_noise_score(
        count=100, hours_active=10,
        first_seen=datetime.utcnow() - timedelta(days=7),
        severity=2,  # critical
    )
    score_info = compute_noise_score(
        count=100, hours_active=10,
        first_seen=datetime.utcnow() - timedelta(days=7),
        severity=6,  # informational
    )
    assert score < score_info


def test_noise_score_security_tag():
    """Security-tagged messages should be less noisy."""
    score_with = compute_noise_score(
        count=100, hours_active=10,
        first_seen=datetime.utcnow() - timedelta(days=3),
        tags=["security"],
    )
    score_without = compute_noise_score(
        count=100, hours_active=10,
        first_seen=datetime.utcnow() - timedelta(days=3),
    )
    assert score_with < score_without


def test_noise_score_bounds():
    """Score should always be 0-100."""
    score_low = compute_noise_score(
        count=1, hours_active=0.01,
        first_seen=datetime.utcnow(),
        severity=0,
        tags=["security", "hardware"],
    )
    score_high = compute_noise_score(
        count=1000000, hours_active=100,
        first_seen=datetime.utcnow() - timedelta(days=30),
        severity=7,
    )
    assert 0 <= score_low <= 100
    assert 0 <= score_high <= 100


# ── Process Message (integration) ────────────────────────────────────────────

def test_process_message_returns_enrichment():
    result = process_message("Failed password for root from 10.0.0.1 port 22345", severity=4)
    assert "template_hash" in result
    assert "tags" in result
    assert "noise_score" in result
    assert "is_new_template" in result
    assert isinstance(result["tags"], list)


def test_process_message_detects_new_template():
    """First time seeing a template = is_new_template."""
    # Clear caches for test isolation
    from services.log_intelligence import _template_cache, _new_templates
    _template_cache.clear()
    _new_templates.clear()

    result = process_message("A very unique message 12345678 that nobody has ever seen", severity=6)
    assert result["is_new_template"] is True

    # Second time = not new
    result2 = process_message("A very unique message 87654321 that nobody has ever seen", severity=6)
    assert result2["is_new_template"] is False
    assert result2["template_hash"] == result["template_hash"]
