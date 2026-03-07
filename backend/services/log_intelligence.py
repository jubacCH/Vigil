"""
Log Intelligence Engine – template extraction, baseline learning, noise scoring,
auto-tagging, and precursor detection. Pure Python, no ML libraries.

Architecture:
- Template extraction runs on every incoming syslog message (in-memory, fast)
- Baseline computation + precursor detection run periodically (scheduler)
- Noise scores are updated periodically based on template frequency patterns
"""
import hashlib
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from models.log_template import HostBaseline, LogTemplate, PrecursorPattern
from models.syslog import SyslogMessage

log = logging.getLogger("vigil.intelligence")

# ── Drain-lite: Template Extraction ───────────────────────────────────────────

# Patterns to replace with wildcards (order matters: more specific first)
_VARIABLE_PATTERNS = [
    # UUIDs
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), '<UUID>'),
    # MAC addresses
    (re.compile(r'\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b'), '<MAC>'),
    # IPv6 (simplified)
    (re.compile(r'\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}\b'), '<IPv6>'),
    # IPv4
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '<IP>'),
    # ISO timestamps
    (re.compile(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*[Z+\-\d:]*\b'), '<TS>'),
    # Date-like patterns
    (re.compile(r'\b\d{4}[-/]\d{2}[-/]\d{2}\b'), '<DATE>'),
    # Hex strings (8+ chars)
    (re.compile(r'\b0x[0-9a-fA-F]{4,}\b'), '<HEX>'),
    (re.compile(r'\b[0-9a-fA-F]{8,}\b'), '<HEX>'),
    # File paths
    (re.compile(r'(?:/[\w.\-]+){2,}'), '<PATH>'),
    # Numbers (3+ digits, standalone)
    (re.compile(r'\b\d{3,}\b'), '<NUM>'),
    # Port-like numbers after specific keywords
    (re.compile(r'(?<=port\s)\d+'), '<PORT>'),
    (re.compile(r'(?<=pid\s)\d+'), '<PID>'),
    (re.compile(r'(?<=pid=)\d+'), '<PID>'),
]


def extract_template(message: str) -> tuple[str, str]:
    """
    Extract a template from a log message using Drain-lite algorithm.
    Returns (template_string, template_hash).
    """
    if not message:
        return ("", hashlib.md5(b"").hexdigest()[:16])

    tpl = message
    for pattern, replacement in _VARIABLE_PATTERNS:
        tpl = pattern.sub(replacement, tpl)

    # Collapse repeated wildcards
    tpl = re.sub(r'(<\w+>)(\s*\1)+', r'\1', tpl)

    # Normalize whitespace
    tpl = ' '.join(tpl.split())

    h = hashlib.md5(tpl.encode()).hexdigest()[:16]
    return tpl, h


# ── Auto-Tagging ─────────────────────────────────────────────────────────────

_TAG_RULES = [
    # (tag, compiled_regex_pattern)
    ("security", re.compile(
        r'(?i)\b(failed\s+password|unauthorized|denied|authentication|'
        r'invalid\s+user|brute.?force|attack|intrusion|forbidden|'
        r'login\s+failed|access.?denied|permission|firewall)\b'
    )),
    ("hardware", re.compile(
        r'(?i)\b(disk|memory|temperature|temp|fan|sensor|cpu|'
        r'hardware|smart|i/?o\s+error|ecc|parity|thermal|voltage|power)\b'
    )),
    ("network", re.compile(
        r'(?i)\b(link\s+down|link\s+up|unreachable|timeout|connection\s+refused|'
        r'dns|dhcp|arp|route|interface|packet|dropped|retransmit|'
        r'network|carrier|negotiat|duplex|mtu)\b'
    )),
    ("storage", re.compile(
        r'(?i)\b(zfs|zpool|raid|mdadm|lvm|mount|unmount|filesystem|'
        r'quota|inode|scrub|resilver|snapshot|backup|nfs|smb|iscsi)\b'
    )),
    ("service", re.compile(
        r'(?i)\b(started|stopped|restart|crashed|exited|failed|'
        r'systemd|service|unit|docker|container|supervisor|'
        r'enabling|disabling|loaded|activated)\b'
    )),
    ("update", re.compile(
        r'(?i)\b(upgrade|update|patch|install|dpkg|apt|yum|rpm|'
        r'package|version|firmware|release)\b'
    )),
    ("auth", re.compile(
        r'(?i)\b(login|logout|session|pam|sudo|su\b|ssh|'
        r'accepted\s+key|publickey|certificate|token|oauth)\b'
    )),
]


def auto_tag(message: str) -> list[str]:
    """Return auto-detected tags for a message."""
    tags = []
    for tag, pattern in _TAG_RULES:
        if pattern.search(message):
            tags.append(tag)
    return tags


# ── Noise Score Calculation ───────────────────────────────────────────────────

def compute_noise_score(
    count: int,
    hours_active: float,
    first_seen: datetime,
    severity: Optional[int] = None,
    tags: Optional[list[str]] = None,
) -> int:
    """
    Compute noise score 0-100 (0 = very interesting, 100 = total noise).

    Factors:
    - High frequency + consistent rate = noise
    - Low severity (info/debug) = more likely noise
    - Security/hardware tags = less likely noise
    - Recently first seen = interesting
    """
    score = 50  # neutral start

    # Frequency factor: >100/hour sustained = very noisy
    rate = count / max(hours_active, 0.1)
    if rate > 100:
        score += 30
    elif rate > 50:
        score += 20
    elif rate > 10:
        score += 10
    elif rate < 1:
        score -= 10  # rare = interesting

    # Severity factor
    if severity is not None:
        if severity <= 2:  # emergency/alert/critical
            score -= 30
        elif severity == 3:  # error
            score -= 15
        elif severity == 4:  # warning
            score -= 5
        elif severity >= 6:  # info/debug
            score += 10

    # Tag factor
    if tags:
        if "security" in tags or "hardware" in tags:
            score -= 15
        if "service" in tags and "started" not in str(tags):
            score -= 5

    # Novelty factor: first seen < 24h ago
    age_hours = (datetime.utcnow() - first_seen).total_seconds() / 3600
    if age_hours < 1:
        score -= 25  # brand new = very interesting
    elif age_hours < 24:
        score -= 10

    return max(0, min(100, score))


# ── In-Memory Template Cache (for fast per-message extraction) ────────────────

_template_cache: dict[str, int] = {}  # hash -> template_id
_template_counts: dict[str, int] = defaultdict(int)  # hash -> count since last flush
_new_templates: dict[str, tuple[str, str, list[str]]] = {}  # hash -> (template, example, tags)
_FLUSH_INTERVAL = 30  # seconds
_last_flush: float = 0.0


def process_message(message: str, severity: Optional[int] = None) -> dict:
    """
    Process a single message through the intelligence pipeline.
    Called for every incoming syslog message (must be fast).

    Returns enrichment dict: {template_hash, tags, is_new_template, noise_score}
    """
    template, h = extract_template(message)
    tags = auto_tag(message)

    is_new = h not in _template_cache and h not in _new_templates

    _template_counts[h] += 1

    if is_new:
        _new_templates[h] = (template, message, tags)

    # Rough noise estimate for immediate use (refined later by periodic job)
    noise = 50
    if is_new:
        noise = 10  # new templates are interesting
    elif h in _template_cache:
        count = _template_counts.get(h, 0)
        if count > 100:
            noise = 80

    return {
        "template_hash": h,
        "tags": tags,
        "is_new_template": is_new,
        "noise_score": noise,
    }


# ── Periodic DB Flush (called by scheduler or flush loop) ─────────────────────

async def flush_templates(db: AsyncSession):
    """Flush accumulated template counts and new templates to DB."""
    global _template_counts, _new_templates

    if not _template_counts and not _new_templates:
        return

    counts = dict(_template_counts)
    new_tpls = dict(_new_templates)
    _template_counts = defaultdict(int)
    _new_templates = {}

    now = datetime.utcnow()

    # Insert new templates
    for h, (template, example, tags) in new_tpls.items():
        existing = (await db.execute(
            select(LogTemplate).where(LogTemplate.template_hash == h)
        )).scalar_one_or_none()

        if not existing:
            tpl = LogTemplate(
                template_hash=h,
                template=template,
                example=example,
                count=counts.get(h, 1),
                first_seen=now,
                last_seen=now,
                tags=",".join(tags),
                noise_score=10,  # new = interesting
            )
            db.add(tpl)
            await db.flush()
            _template_cache[h] = tpl.id
            log.info("New log template: %s (tags: %s)", template[:80], ",".join(tags) or "none")
        else:
            _template_cache[h] = existing.id

    # Update counts for existing templates
    for h, count in counts.items():
        if h not in new_tpls:  # new ones already have their count
            await db.execute(
                update(LogTemplate)
                .where(LogTemplate.template_hash == h)
                .values(
                    count=LogTemplate.count + count,
                    last_seen=now,
                )
            )

    await db.commit()


async def load_template_cache(db: AsyncSession):
    """Load all template hashes into memory cache on startup."""
    global _template_cache
    rows = (await db.execute(select(LogTemplate.template_hash, LogTemplate.id))).all()
    _template_cache = {row.template_hash: row.id for row in rows}
    log.info("Loaded %d log templates into cache", len(_template_cache))


# ── Baseline Computation (periodic) ──────────────────────────────────────────

async def compute_baselines(db: AsyncSession):
    """
    Compute per-host hourly baselines from the last 7 days of syslog data.
    Uses source_ip as host_key.
    """
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)

    # Get hourly counts per source_ip
    rows = (await db.execute(
        select(
            SyslogMessage.source_ip,
            func.extract("dow", SyslogMessage.timestamp).label("dow"),
            func.extract("hour", SyslogMessage.timestamp).label("hour"),
            func.count(SyslogMessage.id).label("cnt"),
        )
        .where(SyslogMessage.timestamp >= week_ago)
        .group_by(
            SyslogMessage.source_ip,
            func.extract("dow", SyslogMessage.timestamp),
            func.extract("hour", SyslogMessage.timestamp),
        )
    )).all()

    if not rows:
        return

    # Group: (source_ip, dow, hour) -> [counts across weeks]
    grouped: dict[tuple, list] = defaultdict(list)
    for row in rows:
        key = (row.source_ip, int(row.dow), int(row.hour))
        grouped[key].append(row.cnt)

    # Upsert baselines
    for (host_key, dow, hour), counts in grouped.items():
        avg = sum(counts) / len(counts)
        std = (sum((c - avg) ** 2 for c in counts) / len(counts)) ** 0.5 if len(counts) > 1 else 0

        existing = (await db.execute(
            select(HostBaseline).where(
                HostBaseline.host_key == host_key,
                HostBaseline.hour_of_day == hour,
                HostBaseline.day_of_week == dow,
            )
        )).scalar_one_or_none()

        if existing:
            existing.avg_rate = avg
            existing.std_rate = std
            existing.sample_count = len(counts)
            existing.updated_at = now
        else:
            db.add(HostBaseline(
                host_key=host_key,
                hour_of_day=hour,
                day_of_week=dow,
                avg_rate=avg,
                std_rate=std,
                sample_count=len(counts),
                updated_at=now,
            ))

    await db.commit()
    log.info("Baselines computed for %d host-hour combinations", len(grouped))


async def detect_baseline_anomalies(db: AsyncSession) -> list[dict]:
    """
    Check current hour's message rate against learned baselines.
    Returns list of anomaly dicts.
    """
    now = datetime.utcnow()
    hour = now.hour
    dow = now.weekday()  # 0=Mon
    window_start = now.replace(minute=0, second=0, microsecond=0)

    # Current hour counts per source_ip
    current_counts = (await db.execute(
        select(
            SyslogMessage.source_ip,
            func.count(SyslogMessage.id).label("cnt"),
        )
        .where(SyslogMessage.timestamp >= window_start)
        .group_by(SyslogMessage.source_ip)
    )).all()

    if not current_counts:
        return []

    # Load baselines for this hour/dow
    baselines = (await db.execute(
        select(HostBaseline).where(
            HostBaseline.hour_of_day == hour,
            HostBaseline.day_of_week == dow,
        )
    )).scalars().all()
    baseline_map = {b.host_key: b for b in baselines}

    anomalies = []
    for row in current_counts:
        baseline = baseline_map.get(row.source_ip)
        if not baseline or baseline.sample_count < 3:
            continue

        # z-score: how many std devs above normal
        if baseline.std_rate > 0:
            z = (row.cnt - baseline.avg_rate) / baseline.std_rate
        elif row.cnt > baseline.avg_rate * 3:
            z = 5.0  # no variance but way above average
        else:
            continue

        if z >= 3.0:  # 3 sigma = significant
            anomalies.append({
                "source_ip": row.source_ip,
                "current_count": row.cnt,
                "expected": round(baseline.avg_rate, 1),
                "z_score": round(z, 1),
                "type": "rate_spike",
            })

        # Also detect silence (host normally sends logs but now silent)
    for host_key, baseline in baseline_map.items():
        if baseline.avg_rate > 10 and baseline.sample_count >= 3:
            current = next((r.cnt for r in current_counts if r.source_ip == host_key), 0)
            minutes_elapsed = max(1, now.minute)
            projected_rate = current * (60 / minutes_elapsed)
            if projected_rate < baseline.avg_rate * 0.1:  # <10% of normal
                anomalies.append({
                    "source_ip": host_key,
                    "current_count": current,
                    "expected": round(baseline.avg_rate, 1),
                    "z_score": 0,
                    "type": "silent",
                })

    return anomalies


# ── Precursor Detection (periodic) ───────────────────────────────────────────

async def learn_precursors(db: AsyncSession):
    """
    Analyze which log templates appeared in the 5-minute window before
    host-down events. Build confidence scores over time.
    """
    from models.ping import PingResult

    now = datetime.utcnow()
    lookback = now - timedelta(days=7)

    # Find all host-down transitions in last 7 days
    # A "down transition" = PingResult.success=False preceded by success=True
    # Simplified: find PingResults where success=False
    down_events = (await db.execute(
        select(PingResult.host_id, PingResult.timestamp)
        .where(
            PingResult.success == False,
            PingResult.timestamp >= lookback,
        )
        .order_by(PingResult.timestamp)
    )).all()

    if not down_events:
        return

    # For each down event, find syslog templates in the preceding 5 minutes
    template_before_down: dict[int, int] = defaultdict(int)  # template_id -> count
    total_down_events = 0

    for host_id, down_ts in down_events:
        window_start = down_ts - timedelta(minutes=5)
        # Get syslog messages from this host in the window
        syslog_msgs = (await db.execute(
            select(SyslogMessage.message)
            .where(
                SyslogMessage.host_id == host_id,
                SyslogMessage.timestamp >= window_start,
                SyslogMessage.timestamp <= down_ts,
                SyslogMessage.severity <= 4,  # warning and above
            )
            .limit(50)
        )).scalars().all()

        if syslog_msgs:
            total_down_events += 1
            seen_templates = set()
            for msg in syslog_msgs:
                _, h = extract_template(msg)
                tpl_id = _template_cache.get(h)
                if tpl_id and tpl_id not in seen_templates:
                    seen_templates.add(tpl_id)
                    template_before_down[tpl_id] += 1

    if not total_down_events:
        return

    # Also count total appearances of each template (for confidence calculation)
    for tpl_id, before_count in template_before_down.items():
        # Get total count of this template
        tpl = (await db.execute(
            select(LogTemplate).where(LogTemplate.id == tpl_id)
        )).scalar_one_or_none()
        if not tpl:
            continue

        confidence = before_count / total_down_events

        # Only store if confidence >= 0.3 (appeared before 30%+ of down events)
        if confidence < 0.3:
            continue

        existing = (await db.execute(
            select(PrecursorPattern).where(
                PrecursorPattern.template_id == tpl_id,
                PrecursorPattern.precedes_event == "host_down",
            )
        )).scalar_one_or_none()

        if existing:
            existing.confidence = confidence
            existing.occurrence_count = before_count
            existing.total_checked = total_down_events
            existing.updated_at = now
        else:
            db.add(PrecursorPattern(
                template_id=tpl_id,
                precedes_event="host_down",
                confidence=confidence,
                avg_lead_time_sec=150,  # ~2.5min average in 5min window
                occurrence_count=before_count,
                total_checked=total_down_events,
                updated_at=now,
            ))

    await db.commit()
    log.info("Precursor analysis: %d templates checked against %d down events",
             len(template_before_down), total_down_events)


# ── Noise Score Refresh (periodic) ───────────────────────────────────────────

async def refresh_noise_scores(db: AsyncSession):
    """Recalculate noise scores for all templates."""
    templates = (await db.execute(select(LogTemplate))).scalars().all()
    now = datetime.utcnow()

    for tpl in templates:
        hours_active = max(0.1, (now - tpl.first_seen).total_seconds() / 3600)
        tags = tpl.tags.split(",") if tpl.tags else []

        # Check if this template is a precursor (= definitely not noise)
        is_precursor = (await db.execute(
            select(func.count(PrecursorPattern.id)).where(
                PrecursorPattern.template_id == tpl.id,
                PrecursorPattern.confidence >= 0.3,
            )
        )).scalar() > 0

        score = compute_noise_score(
            count=tpl.count,
            hours_active=hours_active,
            first_seen=tpl.first_seen,
            tags=tags,
        )

        if is_precursor:
            score = max(0, score - 30)  # precursors are never noise

        tpl.noise_score = score
        tpl.avg_rate_per_hour = tpl.count / hours_active

    await db.commit()
    log.info("Noise scores refreshed for %d templates", len(templates))


# ── Main periodic job (called by scheduler) ──────────────────────────────────

async def run_intelligence():
    """Main intelligence job – flush templates, compute baselines, learn."""
    from models.base import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        try:
            await flush_templates(db)
            await compute_baselines(db)
            await learn_precursors(db)
            await refresh_noise_scores(db)
        except Exception as e:
            log.error("Intelligence engine error: %s", e, exc_info=True)
            await db.rollback()
