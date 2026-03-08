"""Incidents UI – list, detail, acknowledge, resolve."""
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from templating import templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database import get_db
from models.incident import Incident, IncidentEvent

router = APIRouter(prefix="/incidents")


@router.get("", response_class=HTMLResponse)
async def incidents_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    status: str = None,
):
    from sqlalchemy import case
    status_order = case(
        (Incident.status == "open", 0),
        (Incident.status == "acknowledged", 1),
        else_=2,
    )
    query = select(Incident).order_by(status_order, Incident.updated_at.desc())

    if status:
        query = query.where(Incident.status == status)

    incidents = (await db.execute(query)).scalars().all()

    # Counts by status
    counts = {}
    for s in ("open", "acknowledged", "resolved"):
        c = (await db.execute(
            select(func.count(Incident.id)).where(Incident.status == s)
        )).scalar() or 0
        counts[s] = c

    return templates.TemplateResponse("incidents.html", {
        "request": request,
        "incidents": incidents,
        "counts": counts,
        "f_status": status,
        "active_page": "incidents",
    })


@router.get("/{incident_id}", response_class=HTMLResponse)
async def incident_detail(
    incident_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    incident = (await db.execute(
        select(Incident)
        .options(selectinload(Incident.events))
        .where(Incident.id == incident_id)
    )).scalar_one_or_none()

    if not incident:
        return RedirectResponse("/incidents", status_code=302)

    return templates.TemplateResponse("incident_detail.html", {
        "request": request,
        "incident": incident,
        "active_page": "incidents",
    })


@router.post("/{incident_id}/acknowledge")
async def acknowledge_incident(
    incident_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    incident = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()

    if incident and incident.status == "open":
        user = getattr(request.state, "current_user", None)
        username = user.username if user else "unknown"
        incident.status = "acknowledged"
        incident.acknowledged_by = username
        incident.updated_at = datetime.utcnow()
        db.add(IncidentEvent(
            incident_id=incident.id,
            event_type="acknowledged",
            summary=f"Acknowledged by {username}",
        ))
        await db.commit()

    return RedirectResponse(f"/incidents/{incident_id}", status_code=302)


@router.post("/{incident_id}/resolve")
async def resolve_incident(
    incident_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    incident = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()

    if incident and incident.status in ("open", "acknowledged"):
        user = getattr(request.state, "current_user", None)
        username = user.username if user else "unknown"
        incident.status = "resolved"
        incident.resolved_at = datetime.utcnow()
        incident.updated_at = datetime.utcnow()
        db.add(IncidentEvent(
            incident_id=incident.id,
            event_type="resolved",
            summary=f"Manually resolved by {username}",
        ))
        await db.commit()

    return RedirectResponse(f"/incidents/{incident_id}", status_code=302)
