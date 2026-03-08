"""Syslog log viewer – filterable, searchable, sortable, paginated, live tail."""
import asyncio
import json
import re
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from templating import templates, localtime
from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import PingHost, get_db
from models.syslog import (
    FACILITY_LABELS, RETENTION_DAYS, SEVERITY_LABELS,
    SyslogMessage, SyslogView,
)

router = APIRouter(prefix="/syslog")

_PER_PAGE = 100

_SORT_COLUMNS = {
    "time": SyslogMessage.timestamp,
    "severity": SyslogMessage.severity,
    "host": SyslogMessage.hostname,
    "app": SyslogMessage.app_name,
    "source": SyslogMessage.source_ip,
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_fields(message: str) -> dict:
    """Extract structured fields from CEF or key=value messages."""
    fields = {}
    # CEF format: CEF:version|vendor|product|version|event_id|name|severity|extensions
    cef = re.match(
        r"CEF:\d+\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)",
        message,
    )
    if cef:
        fields["vendor"] = cef.group(1)
        fields["product"] = cef.group(2)
        fields["event"] = cef.group(5)
        for m in re.finditer(r"(\w[\w.-]*)=((?:\"[^\"]*\"|\S+))", cef.group(7)):
            fields[m.group(1)] = m.group(2).strip('"')
    else:
        # Generic key=value extraction
        for m in re.finditer(r"(\w[\w.-]*)=((?:\"[^\"]*\"|\S+))", message):
            key, val = m.group(1), m.group(2).strip('"')
            if len(key) > 2 and not key.isdigit():
                fields[key] = val
    return fields


def _dedup_messages(messages):
    """Group consecutive identical messages (same source_ip + message + severity)."""
    if not messages:
        return messages
    result = []
    for msg in messages:
        if (
            result
            and result[-1].source_ip == msg.source_ip
            and result[-1].message == msg.message
            and result[-1].severity == msg.severity
        ):
            result[-1]._dedup_count = getattr(result[-1], "_dedup_count", 1) + 1
            result[-1]._dedup_last = msg.timestamp
        else:
            msg._dedup_count = 1
            msg._dedup_last = None
            result.append(msg)
    return result


def _build_ip_map(ping_hosts) -> dict[str, int]:
    """Build IP/hostname → PingHost.id map for clickable links."""
    ip_to_host_id: dict[str, int] = {}
    for ph in ping_hosts:
        raw = ph.hostname
        for prefix in ("https://", "http://"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
        raw = raw.split("/")[0].split(":")[0]
        ip_to_host_id[raw] = ph.id
        if ph.name:
            ip_to_host_id[ph.name.lower()] = ph.id
    return ip_to_host_id


# ── Main page ────────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def syslog_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    severity: str = Query(""),
    facility: str = Query(""),
    host: str = Query(""),
    app: str = Query(""),
    q: str = Query(""),
    hours: int = Query(24),
    page: int = Query(1, ge=1),
    sort: str = Query("time"),
    order: str = Query("desc"),
):
    sev = int(severity) if severity not in ("", None) else None
    fac = int(facility) if facility not in ("", None) else None

    since = datetime.utcnow() - timedelta(hours=hours)

    # Base query
    query = select(SyslogMessage).where(SyslogMessage.timestamp >= since)
    count_query = select(func.count(SyslogMessage.id)).where(SyslogMessage.timestamp >= since)

    # Filters
    if sev is not None:
        query = query.where(SyslogMessage.severity == sev)
        count_query = count_query.where(SyslogMessage.severity == sev)
    if fac is not None:
        query = query.where(SyslogMessage.facility == fac)
        count_query = count_query.where(SyslogMessage.facility == fac)
    if host:
        hf = (SyslogMessage.hostname.ilike(f"%{host}%")) | (SyslogMessage.source_ip.ilike(f"%{host}%"))
        query = query.where(hf)
        count_query = count_query.where(hf)
    if app:
        query = query.where(SyslogMessage.app_name.ilike(f"%{app}%"))
        count_query = count_query.where(SyslogMessage.app_name.ilike(f"%{app}%"))
    if q:
        fts = SyslogMessage.search_vector.op("@@")(func.plainto_tsquery("english", q))
        query = query.where(fts)
        count_query = count_query.where(fts)

    # Count + paginate
    total = (await db.execute(count_query)).scalar() or 0
    total_pages = max(1, (total + _PER_PAGE - 1) // _PER_PAGE)
    page = min(page, total_pages)

    # Sort
    sort_col = _SORT_COLUMNS.get(sort, SyslogMessage.timestamp)
    query = query.order_by(sort_col.asc() if order == "asc" else sort_col.desc())

    # Fetch + dedup
    messages = (await db.execute(query.offset((page - 1) * _PER_PAGE).limit(_PER_PAGE))).scalars().all()
    messages = _dedup_messages(messages)

    # Extract structured fields + intelligence enrichment for each message
    try:
        from services.log_intelligence import extract_template, auto_tag
        from models.log_template import LogTemplate
        # Load noise scores for templates in this batch
        _tpl_hashes = set()
        for msg in messages:
            _, h = extract_template(msg.message)
            msg._template_hash = h
            _tpl_hashes.add(h)
        _noise_map = {}
        _tags_map = {}
        if _tpl_hashes:
            _tpl_rows = (await db.execute(
                select(LogTemplate.template_hash, LogTemplate.noise_score, LogTemplate.tags)
                .where(LogTemplate.template_hash.in_(_tpl_hashes))
            )).all()
            for row in _tpl_rows:
                _noise_map[row.template_hash] = row.noise_score
                _tags_map[row.template_hash] = row.tags
    except Exception:
        pass

    for msg in messages:
        msg._fields = _extract_fields(msg.message)
        h = getattr(msg, '_template_hash', None)
        msg._noise_score = _noise_map.get(h, 50) if h else 50
        db_tags = _tags_map.get(h, "") if h else ""
        msg._tags = [t.strip() for t in db_tags.split(",") if t.strip()] if db_tags else auto_tag(msg.message)

    # Severity counts for header pills
    severity_counts = dict((await db.execute(
        select(SyslogMessage.severity, func.count(SyslogMessage.id))
        .where(SyslogMessage.timestamp >= since)
        .group_by(SyslogMessage.severity)
    )).all())

    # Known hosts for filter dropdown
    known_hosts = (await db.execute(
        select(SyslogMessage.source_ip, SyslogMessage.hostname)
        .where(SyslogMessage.timestamp >= since)
        .group_by(SyslogMessage.source_ip, SyslogMessage.hostname)
        .order_by(SyslogMessage.source_ip).limit(200)
    )).all()

    # Known apps for filter dropdown
    known_apps = [r[0] for r in (await db.execute(
        select(SyslogMessage.app_name)
        .where(SyslogMessage.timestamp >= since, SyslogMessage.app_name.isnot(None))
        .group_by(SyslogMessage.app_name).order_by(SyslogMessage.app_name).limit(100)
    )).all()]

    # IP → host_id map
    ping_hosts = (await db.execute(select(PingHost))).scalars().all()
    ip_to_host_id = _build_ip_map(ping_hosts)

    # Log-rate chart data: messages per 5-min bucket for the selected time range
    # Use at most 60 buckets
    bucket_minutes = max(5, (hours * 60) // 60)
    rate_data = await _build_rate_chart(db, since, bucket_minutes)

    # Saved views
    saved_views = (await db.execute(
        select(SyslogView).order_by(SyslogView.name)
    )).scalars().all()

    # Severity alert: check if error rate is spiking
    alert_spike = await _check_severity_spike(db)

    # Intelligence: baseline anomalies + new templates
    intelligence = {"anomalies": [], "new_templates": [], "precursors": []}
    try:
        from models.log_template import LogTemplate, PrecursorPattern
        from services.log_intelligence import detect_baseline_anomalies

        # Baseline anomalies (current hour vs learned baseline)
        intelligence["anomalies"] = await detect_baseline_anomalies(db)

        # Recently discovered templates (last 24h, noise_score < 30)
        new_tpls = (await db.execute(
            select(LogTemplate)
            .where(LogTemplate.first_seen >= since, LogTemplate.noise_score < 30)
            .order_by(LogTemplate.first_seen.desc())
            .limit(5)
        )).scalars().all()
        intelligence["new_templates"] = [
            {"template": t.template[:120], "count": t.count, "tags": t.tags,
             "first_seen": localtime(t.first_seen, "%H:%M") if t.first_seen else ""}
            for t in new_tpls
        ]

        # Active precursors (high-confidence patterns)
        precs = (await db.execute(
            select(PrecursorPattern, LogTemplate)
            .join(LogTemplate, PrecursorPattern.template_id == LogTemplate.id)
            .where(PrecursorPattern.confidence >= 0.5)
            .order_by(PrecursorPattern.confidence.desc())
            .limit(5)
        )).all()
        intelligence["precursors"] = [
            {"template": tpl.template[:100], "event": p.precedes_event,
             "confidence": round(p.confidence * 100), "lead_time": p.avg_lead_time_sec}
            for p, tpl in precs
        ]
    except Exception:
        pass

    return templates.TemplateResponse("syslog.html", {
        "request": request,
        "active_page": "syslog",
        "messages": messages,
        "total": total,
        "page": page,
        "total_pages": total_pages,
        "severity_labels": SEVERITY_LABELS,
        "facility_labels": FACILITY_LABELS,
        "severity_counts": severity_counts,
        "known_hosts": known_hosts,
        "known_apps": known_apps,
        "ip_to_host_id": ip_to_host_id,
        "rate_chart": json.dumps(rate_data),
        "saved_views": saved_views,
        "retention_days": RETENTION_DAYS,
        "alert_spike": alert_spike,
        "intelligence": intelligence,
        # Current filter/sort values
        "f_severity": sev,
        "f_facility": fac,
        "f_host": host or "",
        "f_app": app or "",
        "f_q": q or "",
        "f_hours": hours,
        "f_sort": sort,
        "f_order": order,
    })


# ── Log-rate chart data ──────────────────────────────────────────────────────

async def _build_rate_chart(db: AsyncSession, since: datetime, bucket_min: int) -> dict:
    """Build rate chart data: {labels: [...], datasets: {0: [...], ...}}."""
    try:
        rows = (await db.execute(
            text("""
                SELECT
                    date_trunc('hour', timestamp)
                    + (EXTRACT(MINUTE FROM timestamp)::int / :bm * :bm) * interval '1 minute' AS bucket,
                    COALESCE(severity, 6) AS sev,
                    count(*)
                FROM syslog_messages
                WHERE timestamp >= :since
                GROUP BY 1, 2
                ORDER BY 1
            """),
            {"since": since, "bm": bucket_min},
        )).all()
    except Exception:
        return {"labels": [], "datasets": {}}

    # Build time labels and per-severity counts
    buckets = {}
    for bucket_ts, sev, cnt in rows:
        ts_str = localtime(bucket_ts, "%H:%M") if bucket_ts else "?"
        if ts_str not in buckets:
            buckets[ts_str] = {}
        buckets[ts_str][int(sev)] = buckets[ts_str].get(int(sev), 0) + cnt

    labels = list(buckets.keys())
    # Group into: errors (0-3), warnings (4), info (5-6), debug (7)
    err = [sum(buckets[l].get(s, 0) for s in range(4)) for l in labels]
    warn = [buckets[l].get(4, 0) for l in labels]
    info = [sum(buckets[l].get(s, 0) for s in (5, 6)) for l in labels]
    debug = [buckets[l].get(7, 0) for l in labels]

    return {
        "labels": labels,
        "err": err,
        "warn": warn,
        "info": info,
        "debug": debug,
    }


# ── Severity spike detection ─────────────────────────────────────────────────

async def _check_severity_spike(db: AsyncSession) -> dict | None:
    """Check if error rate in last 5min is 5x above 1h average."""
    try:
        now = datetime.utcnow()
        # Errors in last 5 minutes
        recent = (await db.execute(
            select(func.count(SyslogMessage.id))
            .where(SyslogMessage.severity <= 3, SyslogMessage.timestamp >= now - timedelta(minutes=5))
        )).scalar() or 0

        # Average errors per 5-min window in last hour
        hour_total = (await db.execute(
            select(func.count(SyslogMessage.id))
            .where(SyslogMessage.severity <= 3, SyslogMessage.timestamp >= now - timedelta(hours=1))
        )).scalar() or 0
        avg_per_5min = hour_total / 12  # 12 five-minute windows in an hour

        if avg_per_5min > 0 and recent >= 5 and recent > avg_per_5min * 5:
            return {"recent": recent, "avg": round(avg_per_5min, 1), "ratio": round(recent / avg_per_5min, 1)}
    except Exception:
        pass
    return None


# ── SSE Live tail ────────────────────────────────────────────────────────────

@router.get("/stream")
async def syslog_stream(
    severity: str = Query(""),
    host: str = Query(""),
    app: str = Query(""),
):
    """Server-Sent Events endpoint for live syslog tail."""
    from services.syslog import subscribe, unsubscribe

    sev_filter = int(severity) if severity not in ("", None) else None

    async def event_generator():
        q = subscribe()
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=30)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue

                # Apply filters
                if sev_filter is not None and msg.get("severity") != sev_filter:
                    continue
                if host and host.lower() not in (msg.get("source_ip", "").lower() + msg.get("hostname", "").lower()):
                    continue
                if app and app.lower() not in (msg.get("app_name") or "").lower():
                    continue

                # Format as SSE
                data = {
                    "timestamp": localtime(msg["timestamp"], "%m-%d %H:%M:%S") if isinstance(msg["timestamp"], datetime) else str(msg["timestamp"]),
                    "severity": msg.get("severity"),
                    "severity_label": SEVERITY_LABELS.get(msg.get("severity"), "?"),
                    "hostname": msg.get("hostname") or "",
                    "source_ip": msg.get("source_ip", ""),
                    "app_name": msg.get("app_name") or "",
                    "message": (msg.get("message") or "")[:500],
                    "host_id": msg.get("host_id"),
                    "fields": _extract_fields(msg.get("message", "")),
                    "tags": msg.get("tags", []),
                    "noise_score": msg.get("noise_score", 50),
                    "is_new_template": msg.get("is_new_template", False),
                }
                yield f"data: {json.dumps(data)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            unsubscribe(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Saved views CRUD ─────────────────────────────────────────────────────────

@router.post("/views", response_class=HTMLResponse)
async def save_view(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Save current filters as a named view."""
    form = await request.form()
    name = form.get("view_name", "").strip()
    if not name:
        return HTMLResponse("Name required", status_code=400)

    filters = {
        "severity": form.get("severity", ""),
        "facility": form.get("facility", ""),
        "host": form.get("host", ""),
        "app": form.get("app", ""),
        "q": form.get("q", ""),
        "hours": form.get("hours", "24"),
    }
    view = SyslogView(name=name, filters_json=json.dumps(filters))
    db.add(view)
    await db.commit()

    # Redirect back to syslog with current filters
    qs = "&".join(f"{k}={v}" for k, v in filters.items() if v)
    return HTMLResponse("", status_code=303, headers={"Location": f"/syslog?{qs}"})


@router.post("/views/{view_id}/delete", response_class=HTMLResponse)
async def delete_view(
    view_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete a saved view."""
    await db.execute(delete(SyslogView).where(SyslogView.id == view_id))
    await db.commit()
    return HTMLResponse("", status_code=303, headers={"Location": "/syslog"})


# ── Host detail tab ──────────────────────────────────────────────────────────

@router.get("/api/host/{host_id}", response_class=HTMLResponse)
async def syslog_by_host(
    request: Request,
    host_id: int,
    db: AsyncSession = Depends(get_db),
    hours: int = Query(24),
    page: int = Query(1, ge=1),
):
    """Return syslog messages for a specific PingHost (used in host detail tab)."""
    since = datetime.utcnow() - timedelta(hours=hours)

    # Build filter: match by host_id OR by source_ip/hostname
    host_filter = SyslogMessage.host_id == host_id
    ping_host = (await db.execute(select(PingHost).where(PingHost.id == host_id))).scalar()
    if ping_host:
        raw = ping_host.hostname
        for prefix in ("https://", "http://"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
        raw = raw.split("/")[0].split(":")[0]
        host_filter = or_(host_filter, SyslogMessage.source_ip == raw)
        if ping_host.name:
            host_filter = or_(host_filter, SyslogMessage.hostname.ilike(ping_host.name))

    query = (
        select(SyslogMessage)
        .where(host_filter, SyslogMessage.timestamp >= since)
        .order_by(SyslogMessage.timestamp.desc())
    )
    count_query = (
        select(func.count(SyslogMessage.id))
        .where(host_filter, SyslogMessage.timestamp >= since)
    )

    total = (await db.execute(count_query)).scalar() or 0
    total_pages = max(1, (total + _PER_PAGE - 1) // _PER_PAGE)
    page = min(page, total_pages)

    messages = (await db.execute(
        query.offset((page - 1) * _PER_PAGE).limit(_PER_PAGE)
    )).scalars().all()

    return templates.TemplateResponse("partials/syslog_table.html", {
        "request": request,
        "messages": messages,
        "total": total,
        "page": page,
        "total_pages": total_pages,
        "severity_labels": SEVERITY_LABELS,
    })


# ── Template Browser ─────────────────────────────────────────────────────────

@router.get("/templates", response_class=HTMLResponse)
async def template_browser(
    request: Request,
    db: AsyncSession = Depends(get_db),
    sort: str = Query("recent"),
    tag: str = Query(""),
    page: int = Query(1, ge=1),
):
    """Browse learned log templates."""
    from models.log_template import LogTemplate, PrecursorPattern

    query = select(LogTemplate)
    count_query = select(func.count(LogTemplate.id))

    if tag:
        query = query.where(LogTemplate.tags.contains(tag))
        count_query = count_query.where(LogTemplate.tags.contains(tag))

    sort_map = {
        "recent": LogTemplate.last_seen.desc(),
        "count": LogTemplate.count.desc(),
        "noise": LogTemplate.noise_score.asc(),
        "new": LogTemplate.first_seen.desc(),
    }
    query = query.order_by(sort_map.get(sort, LogTemplate.last_seen.desc()))

    per_page = 50
    total = (await db.execute(count_query)).scalar() or 0
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)

    tpls = (await db.execute(query.offset((page - 1) * per_page).limit(per_page))).scalars().all()

    # Load precursor info for these templates
    tpl_ids = [t.id for t in tpls]
    precursor_map = {}
    if tpl_ids:
        precs = (await db.execute(
            select(PrecursorPattern)
            .where(PrecursorPattern.template_id.in_(tpl_ids), PrecursorPattern.confidence >= 0.3)
        )).scalars().all()
        for p in precs:
            precursor_map[p.template_id] = p

    # All unique tags for filter
    all_tags_raw = (await db.execute(select(LogTemplate.tags).where(LogTemplate.tags != ""))).scalars().all()
    all_tags = sorted({t.strip() for raw in all_tags_raw for t in raw.split(",") if t.strip()})

    return templates.TemplateResponse("syslog_templates.html", {
        "request": request,
        "active_page": "syslog",
        "templates": tpls,
        "precursor_map": precursor_map,
        "total": total,
        "page": page,
        "total_pages": total_pages,
        "all_tags": all_tags,
        "f_sort": sort,
        "f_tag": tag,
    })


# ── Smart Feed API ───────────────────────────────────────────────────────────

@router.get("/api/smart-feed")
async def smart_feed(
    db: AsyncSession = Depends(get_db),
    hours: int = Query(24),
    min_score: int = Query(0),
    max_noise: int = Query(30),
):
    """Return interesting log messages (low noise score, high severity, new templates)."""
    from models.log_template import LogTemplate
    from services.log_intelligence import extract_template

    since = datetime.utcnow() - timedelta(hours=hours)

    # Get messages
    messages = (await db.execute(
        select(SyslogMessage)
        .where(SyslogMessage.timestamp >= since)
        .order_by(SyslogMessage.timestamp.desc())
        .limit(500)
    )).scalars().all()

    # Load template noise scores
    tpl_scores = {}
    tpls = (await db.execute(select(LogTemplate))).scalars().all()
    for t in tpls:
        tpl_scores[t.template_hash] = t.noise_score

    # Score and filter messages
    results = []
    for msg in messages:
        _, h = extract_template(msg.message)
        noise = tpl_scores.get(h, 50)
        if noise > max_noise:
            continue

        results.append({
            "id": msg.id,
            "timestamp": localtime(msg.timestamp, "%m-%d %H:%M:%S"),
            "severity": msg.severity,
            "severity_label": SEVERITY_LABELS.get(msg.severity, "?"),
            "hostname": msg.hostname or "",
            "source_ip": msg.source_ip,
            "app_name": msg.app_name or "",
            "message": msg.message[:300],
            "noise_score": noise,
            "host_id": msg.host_id,
        })

        if len(results) >= 100:
            break

    return results
