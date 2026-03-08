"""
Generic router for all integrations.

Provides CRUD (list, detail, add, edit, delete), test-connection,
and JSON API endpoints for every registered integration.
Integration-specific custom routes can be added via BaseIntegration.get_router().
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from templating import templates
from sqlalchemy.ext.asyncio import AsyncSession

from integrations import get_registry, get_integration
from integrations._base import BaseIntegration
from models.base import get_db
from services import integration as int_svc
from services import snapshot as snap_svc

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_form_config(integration_cls: type[BaseIntegration], form: dict,
                       existing_config: dict | None = None) -> dict:
    """
    Extract config values from submitted form data based on config_fields.
    For edit operations, if a password field is empty, keep the existing value.
    """
    config = {}
    for field in integration_cls.config_fields:
        raw = form.get(field.key, "")
        if isinstance(raw, str):
            raw = raw.strip()

        if field.field_type == "checkbox":
            config[field.key] = raw in ("on", "true", "True", True, "1")
        elif field.field_type == "password":
            # Don't overwrite existing secret if form field is empty
            if not raw and existing_config:
                config[field.key] = existing_config.get(field.key, "")
            else:
                config[field.key] = raw
        elif field.field_type == "number":
            try:
                config[field.key] = int(raw) if raw else field.default
            except (ValueError, TypeError):
                config[field.key] = field.default
        else:
            config[field.key] = raw if raw else (field.default or "")
    return config


# ── List page ─────────────────────────────────────────────────────────────────


@router.get("/integration/{integration_type}", response_class=HTMLResponse)
async def list_instances(
    request: Request,
    integration_type: str,
    db: AsyncSession = Depends(get_db),
):
    integration_cls = get_integration(integration_type)
    if not integration_cls:
        return HTMLResponse("Integration not found", status_code=404)

    configs = await int_svc.get_all_configs(db, integration_type)
    snapshots = await snap_svc.get_latest_batch(db, integration_type)

    instances = []
    for cfg in configs:
        snap = snapshots.get(cfg.id)
        data = json.loads(snap.data_json) if snap and snap.data_json else None
        instances.append({
            "config": cfg,
            "snap": snap,
            "data": data,
        })

    template_name = f"integrations/{integration_type}.html"
    # Fall back to generic list template if integration-specific one doesn't exist
    try:
        templates.get_template(template_name)
    except Exception:
        template_name = "integrations/_list.html"

    return templates.TemplateResponse(template_name, {
        "request": request,
        "integration": integration_cls,
        "instances": instances,
        "active_page": integration_type,
        "saved": request.query_params.get("saved"),
    })


# ── Detail page ───────────────────────────────────────────────────────────────


@router.get("/integration/{integration_type}/{config_id}", response_class=HTMLResponse)
async def detail(
    request: Request,
    integration_type: str,
    config_id: int,
    db: AsyncSession = Depends(get_db),
):
    integration_cls = get_integration(integration_type)
    if not integration_cls:
        return HTMLResponse("Integration not found", status_code=404)

    cfg = await int_svc.get_config(db, config_id)
    if not cfg or cfg.type != integration_type:
        return HTMLResponse("Instance not found", status_code=404)

    snap = await snap_svc.get_latest(db, integration_type, config_id)
    data = None
    error = None

    if snap and snap.data_json:
        data = json.loads(snap.data_json)
    elif snap and snap.error:
        error = snap.error

    # If no snapshot exists, try a live fetch
    if data is None and error is None:
        try:
            config_dict = int_svc.decrypt_config(cfg.config_json)
            instance = integration_cls(config=config_dict)
            result = await instance.collect()
            if result.success:
                data = result.data
                await snap_svc.save(db, integration_type, config_id, True, data)
                await db.commit()
            else:
                error = result.error
        except Exception as exc:
            error = str(exc)

    config_dict = int_svc.decrypt_config(cfg.config_json)

    # Get extra context from integration
    extra_ctx = {}
    if data:
        try:
            instance = integration_cls(config=config_dict)
            extra_ctx = instance.get_detail_context(data, config_dict)
        except Exception:
            pass

    template_name = f"integrations/{integration_type}_detail.html"
    try:
        templates.get_template(template_name)
    except Exception:
        template_name = f"integrations/{integration_type}.html"
        try:
            templates.get_template(template_name)
        except Exception:
            template_name = "integrations/_detail.html"

    ctx = {
        "request": request,
        "integration": integration_cls,
        "config": cfg,
        "config_dict": config_dict,
        "snap": snap,
        "data": data,
        "error": error,
        "active_page": integration_type,
        "active_tab": request.query_params.get("tab", "overview"),
        "saved": request.query_params.get("saved"),
        **extra_ctx,
    }
    return templates.TemplateResponse(template_name, ctx)


# ── Add instance ──────────────────────────────────────────────────────────────


@router.post("/integration/{integration_type}/add")
async def add_instance(
    request: Request,
    integration_type: str,
    db: AsyncSession = Depends(get_db),
):
    integration_cls = get_integration(integration_type)
    if not integration_cls:
        return HTMLResponse("Integration not found", status_code=404)

    form = await request.form()
    name = str(form.get("name", "")).strip()
    if not name:
        name = f"{integration_cls.display_name} Instance"

    config_dict = _parse_form_config(integration_cls, dict(form))
    await int_svc.create_config(db, integration_type, name, config_dict)
    return RedirectResponse(
        url=f"/integration/{integration_type}?saved=1",
        status_code=303,
    )


# ── Edit instance ─────────────────────────────────────────────────────────────


@router.post("/integration/{integration_type}/{config_id}/edit")
async def edit_instance(
    request: Request,
    integration_type: str,
    config_id: int,
    db: AsyncSession = Depends(get_db),
):
    integration_cls = get_integration(integration_type)
    if not integration_cls:
        return HTMLResponse("Integration not found", status_code=404)

    cfg = await int_svc.get_config(db, config_id)
    if not cfg or cfg.type != integration_type:
        return HTMLResponse("Instance not found", status_code=404)

    existing_config = int_svc.decrypt_config(cfg.config_json)
    form = await request.form()
    name = str(form.get("name", "")).strip() or cfg.name
    config_dict = _parse_form_config(integration_cls, dict(form), existing_config)

    await int_svc.update_config(db, config_id, name=name, config_dict=config_dict)
    return RedirectResponse(
        url=f"/integration/{integration_type}/{config_id}?saved=1",
        status_code=303,
    )


# ── Delete instance ───────────────────────────────────────────────────────────


@router.post("/integration/{integration_type}/{config_id}/delete")
async def delete_instance(
    request: Request,
    integration_type: str,
    config_id: int,
    db: AsyncSession = Depends(get_db),
):
    await int_svc.delete_config(db, config_id)
    return RedirectResponse(
        url=f"/integration/{integration_type}?saved=deleted",
        status_code=303,
    )


# ── Test connection (JSON) ────────────────────────────────────────────────────


@router.get("/integration/{integration_type}/{config_id}/test")
async def test_connection(
    integration_type: str,
    config_id: int,
    db: AsyncSession = Depends(get_db),
):
    integration_cls = get_integration(integration_type)
    if not integration_cls:
        return JSONResponse({"ok": False, "error": "Unknown integration"}, status_code=404)

    cfg = await int_svc.get_config(db, config_id)
    if not cfg or cfg.type != integration_type:
        return JSONResponse({"ok": False, "error": "Instance not found"}, status_code=404)

    config_dict = int_svc.decrypt_config(cfg.config_json)
    instance = integration_cls(config=config_dict)

    try:
        ok = await instance.health_check()
        return JSONResponse({"ok": ok})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)})


# ── Refresh (trigger immediate re-collect) ────────────────────────────────────


@router.post("/integration/{integration_type}/{config_id}/refresh")
async def refresh_instance(
    request: Request,
    integration_type: str,
    config_id: int,
    db: AsyncSession = Depends(get_db),
):
    integration_cls = get_integration(integration_type)
    if not integration_cls:
        return HTMLResponse("Integration not found", status_code=404)

    cfg = await int_svc.get_config(db, config_id)
    if not cfg or cfg.type != integration_type:
        return HTMLResponse("Instance not found", status_code=404)

    config_dict = int_svc.decrypt_config(cfg.config_json)
    instance = integration_cls(config=config_dict)

    try:
        result = await instance.collect()
        if result.success:
            await snap_svc.save(db, integration_type, config_id, True, result.data)
        else:
            await snap_svc.save(db, integration_type, config_id, False, error=result.error)
        await db.commit()
    except Exception as exc:
        await snap_svc.save(db, integration_type, config_id, False, error=str(exc))
        await db.commit()

    return RedirectResponse(
        url=f"/integration/{integration_type}/{config_id}",
        status_code=303,
    )


# ── JSON API: latest status ───────────────────────────────────────────────────


@router.get("/api/integration/{integration_type}/{config_id}/status")
async def api_status(
    integration_type: str,
    config_id: int,
    db: AsyncSession = Depends(get_db),
):
    cfg = await int_svc.get_config(db, config_id)
    if not cfg or cfg.type != integration_type:
        return JSONResponse({"error": "not found"}, status_code=404)

    snap = await snap_svc.get_latest(db, integration_type, config_id)
    if not snap:
        return JSONResponse({"error": "no data yet"}, status_code=404)

    data = json.loads(snap.data_json) if snap.data_json else None
    return JSONResponse({
        "ok": snap.ok,
        "data": data,
        "error": snap.error,
        "timestamp": snap.timestamp.isoformat() if snap.timestamp else None,
    })


# ── JSON API: list all integrations ──────────────────────────────────────────


@router.get("/api/integrations")
async def api_list_integrations():
    """Return metadata for all registered integrations."""
    registry = get_registry()
    return JSONResponse({
        name: {
            "display_name": cls.display_name,
            "icon": cls.icon,
            "description": cls.description,
        }
        for name, cls in registry.items()
    })
