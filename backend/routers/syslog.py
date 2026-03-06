"""Syslog log viewer – filterable, searchable, paginated."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.syslog import SyslogMessage, SEVERITY_LABELS, FACILITY_LABELS

router = APIRouter(prefix="/syslog")
templates = Jinja2Templates(directory="templates")

_PER_PAGE = 100


@router.get("", response_class=HTMLResponse)
async def syslog_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    severity: int = Query(None),
    host: str = Query(None),
    app: str = Query(None),
    q: str = Query(None),
    hours: int = Query(24),
    page: int = Query(1, ge=1),
):
    since = datetime.utcnow() - timedelta(hours=hours)

    # Base query
    query = select(SyslogMessage).where(SyslogMessage.timestamp >= since)
    count_query = select(func.count(SyslogMessage.id)).where(SyslogMessage.timestamp >= since)

    # Filters
    if severity is not None:
        query = query.where(SyslogMessage.severity == severity)
        count_query = count_query.where(SyslogMessage.severity == severity)

    if host:
        host_filter = (
            (SyslogMessage.hostname.ilike(f"%{host}%")) |
            (SyslogMessage.source_ip.ilike(f"%{host}%"))
        )
        query = query.where(host_filter)
        count_query = count_query.where(host_filter)

    if app:
        query = query.where(SyslogMessage.app_name.ilike(f"%{app}%"))
        count_query = count_query.where(SyslogMessage.app_name.ilike(f"%{app}%"))

    if q:
        # PostgreSQL full-text search
        query = query.where(
            SyslogMessage.search_vector.op("@@")(func.plainto_tsquery("english", q))
        )
        count_query = count_query.where(
            SyslogMessage.search_vector.op("@@")(func.plainto_tsquery("english", q))
        )

    # Count
    total = (await db.execute(count_query)).scalar() or 0
    total_pages = max(1, (total + _PER_PAGE - 1) // _PER_PAGE)
    page = min(page, total_pages)

    # Fetch page
    query = query.order_by(SyslogMessage.timestamp.desc())
    query = query.offset((page - 1) * _PER_PAGE).limit(_PER_PAGE)
    messages = (await db.execute(query)).scalars().all()

    # Stats for header
    stats_query = (
        select(
            SyslogMessage.severity,
            func.count(SyslogMessage.id),
        )
        .where(SyslogMessage.timestamp >= since)
        .group_by(SyslogMessage.severity)
    )
    severity_counts = dict((await db.execute(stats_query)).all())

    # Unique hosts for filter dropdown
    hosts_query = (
        select(SyslogMessage.source_ip, SyslogMessage.hostname)
        .where(SyslogMessage.timestamp >= since)
        .group_by(SyslogMessage.source_ip, SyslogMessage.hostname)
        .order_by(SyslogMessage.source_ip)
        .limit(200)
    )
    known_hosts = (await db.execute(hosts_query)).all()

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
        # Current filter values
        "f_severity": severity,
        "f_host": host or "",
        "f_app": app or "",
        "f_q": q or "",
        "f_hours": hours,
    })


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

    query = (
        select(SyslogMessage)
        .where(SyslogMessage.host_id == host_id, SyslogMessage.timestamp >= since)
        .order_by(SyslogMessage.timestamp.desc())
    )
    count_query = (
        select(func.count(SyslogMessage.id))
        .where(SyslogMessage.host_id == host_id, SyslogMessage.timestamp >= since)
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
