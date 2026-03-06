from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from database import encrypt_value, get_db, get_setting, set_setting

router = APIRouter(prefix="/settings")
templates = Jinja2Templates(directory="templates")


@router.get("", response_class=HTMLResponse)
async def settings_page(request: Request, db: AsyncSession = Depends(get_db)):
    site_name           = await get_setting(db, "site_name", "Vigil")
    ping_interval       = await get_setting(db, "ping_interval", "60")
    proxmox_interval    = await get_setting(db, "proxmox_interval", "60")
    ping_retention      = await get_setting(db, "ping_retention_days", "30")
    proxmox_retention   = await get_setting(db, "proxmox_retention_days", "7")
    anomaly_threshold   = await get_setting(db, "anomaly_threshold", "2.0")
    timezone            = await get_setting(db, "timezone", "UTC")

    latency_threshold   = await get_setting(db, "latency_threshold_ms", "")
    cpu_threshold       = await get_setting(db, "proxmox_cpu_threshold", "85")
    ram_threshold       = await get_setting(db, "proxmox_ram_threshold", "85")
    disk_threshold      = await get_setting(db, "proxmox_disk_threshold", "90")

    phpipam_url         = await get_setting(db, "phpipam_url", "")
    phpipam_app_id      = await get_setting(db, "phpipam_app_id", "")
    phpipam_username    = await get_setting(db, "phpipam_username", "")
    phpipam_has_pw      = bool(await get_setting(db, "phpipam_password", ""))
    phpipam_verify_ssl  = await get_setting(db, "phpipam_verify_ssl", "1")
    phpipam_sync_hours  = await get_setting(db, "phpipam_sync_hours", "0")
    integration_retention = await get_setting(db, "integration_retention_days", "7")

    syslog_port         = await get_setting(db, "syslog_port", "1514")

    notify_enabled      = await get_setting(db, "notify_enabled", "0")
    telegram_bot_token  = await get_setting(db, "telegram_bot_token", "")
    telegram_chat_id    = await get_setting(db, "telegram_chat_id", "")
    discord_webhook_url = await get_setting(db, "discord_webhook_url", "")
    smtp_host           = await get_setting(db, "smtp_host", "")
    smtp_port           = await get_setting(db, "smtp_port", "587")
    smtp_user           = await get_setting(db, "smtp_user", "")
    smtp_has_pw         = bool(await get_setting(db, "smtp_password", ""))
    smtp_from           = await get_setting(db, "smtp_from", "")
    smtp_to             = await get_setting(db, "smtp_to", "")

    return templates.TemplateResponse("settings.html", {
        "request": request,
        "site_name": site_name,
        "ping_interval": ping_interval,
        "proxmox_interval": proxmox_interval,
        "ping_retention": ping_retention,
        "proxmox_retention": proxmox_retention,
        "anomaly_threshold": anomaly_threshold,
        "timezone": timezone,
        "latency_threshold": latency_threshold,
        "cpu_threshold": cpu_threshold,
        "ram_threshold": ram_threshold,
        "disk_threshold": disk_threshold,
        "phpipam_url": phpipam_url,
        "phpipam_app_id": phpipam_app_id,
        "phpipam_username": phpipam_username,
        "phpipam_has_pw": phpipam_has_pw,
        "phpipam_verify_ssl": phpipam_verify_ssl,
        "phpipam_sync_hours": phpipam_sync_hours,
        "integration_retention": integration_retention,
        "syslog_port": syslog_port,
        "notify_enabled": notify_enabled,
        "telegram_bot_token": telegram_bot_token,
        "telegram_chat_id": telegram_chat_id,
        "discord_webhook_url": discord_webhook_url,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_has_pw": smtp_has_pw,
        "smtp_from": smtp_from,
        "smtp_to": smtp_to,
        "active_page": "settings",
        "saved": request.query_params.get("saved"),
    })


@router.post("/save")
async def save_settings(
    site_name:          str = Form("Homelab Monitor"),
    ping_interval:      str = Form("60"),
    proxmox_interval:   str = Form("60"),
    ping_retention:     str = Form("30"),
    proxmox_retention:  str = Form("7"),
    anomaly_threshold:  str = Form("2.0"),
    timezone:           str = Form("UTC"),
    latency_threshold:  str = Form(""),
    cpu_threshold:      str = Form("85"),
    ram_threshold:      str = Form("85"),
    disk_threshold:     str = Form("90"),
    integration_retention: str = Form("7"),
    syslog_port:        str = Form("1514"),
    db: AsyncSession = Depends(get_db),
):
    await set_setting(db, "site_name", site_name.strip())

    try:
        p_interval = max(10, min(3600, int(ping_interval)))
    except ValueError:
        p_interval = 60
    await set_setting(db, "ping_interval", str(p_interval))

    try:
        px_interval = max(10, min(3600, int(proxmox_interval)))
    except ValueError:
        px_interval = 60
    await set_setting(db, "proxmox_interval", str(px_interval))

    try:
        p_ret = max(1, min(365, int(ping_retention)))
    except ValueError:
        p_ret = 30
    await set_setting(db, "ping_retention_days", str(p_ret))

    try:
        px_ret = max(1, min(90, int(proxmox_retention)))
    except ValueError:
        px_ret = 7
    await set_setting(db, "proxmox_retention_days", str(px_ret))

    try:
        threshold = max(1.5, min(10.0, float(anomaly_threshold)))
    except ValueError:
        threshold = 2.0
    await set_setting(db, "anomaly_threshold", str(threshold))

    await set_setting(db, "timezone", timezone.strip() or "UTC")

    # Latency threshold (global default, empty = disabled)
    if latency_threshold.strip():
        try:
            lt = max(1, int(float(latency_threshold)))
            await set_setting(db, "latency_threshold_ms", str(lt))
        except ValueError:
            pass
    else:
        await set_setting(db, "latency_threshold_ms", "")

    try:
        int_ret = max(1, min(90, int(integration_retention)))
    except ValueError:
        int_ret = 7
    await set_setting(db, "integration_retention_days", str(int_ret))

    for key, val, lo, hi, default in [
        ("proxmox_cpu_threshold",  cpu_threshold,  1, 100, 85),
        ("proxmox_ram_threshold",  ram_threshold,  1, 100, 85),
        ("proxmox_disk_threshold", disk_threshold, 1, 100, 90),
    ]:
        try:
            pct = max(lo, min(hi, int(float(val))))
        except ValueError:
            pct = default
        await set_setting(db, key, str(pct))

    # Syslog port
    old_syslog_port = await get_setting(db, "syslog_port", "1514")
    try:
        new_sp = max(1, min(65535, int(syslog_port)))
    except ValueError:
        new_sp = 1514
    await set_setting(db, "syslog_port", str(new_sp))

    # Restart syslog server if port changed
    if str(new_sp) != old_syslog_port:
        try:
            from services.syslog import stop_syslog_server, start_syslog_server
            await stop_syslog_server()
            await start_syslog_server(udp_port=new_sp, tcp_port=new_sp)
        except Exception:
            pass  # logged internally

    # Reschedule both jobs live
    from scheduler import scheduler
    ping_job = scheduler.get_job("ping_checks")
    if ping_job:
        ping_job.reschedule(trigger="interval", seconds=p_interval)
    px_job = scheduler.get_job("proxmox_checks")
    if px_job:
        px_job.reschedule(trigger="interval", seconds=px_interval)

    return RedirectResponse(url="/settings?saved=1", status_code=303)


# ── phpIPAM ───────────────────────────────────────────────────────────────────

@router.post("/phpipam/save")
async def save_phpipam(
    phpipam_url:        str = Form(""),
    phpipam_app_id:     str = Form(""),
    phpipam_username:   str = Form(""),
    phpipam_password:   str = Form(""),
    phpipam_verify_ssl: str = Form("0"),
    phpipam_sync_hours: str = Form("0"),
    db: AsyncSession = Depends(get_db),
):
    await set_setting(db, "phpipam_url", phpipam_url.strip().rstrip("/"))
    await set_setting(db, "phpipam_app_id", phpipam_app_id.strip())
    await set_setting(db, "phpipam_username", phpipam_username.strip())
    await set_setting(db, "phpipam_verify_ssl", "1" if phpipam_verify_ssl == "on" else "0")

    if phpipam_password.strip():
        await set_setting(db, "phpipam_password", encrypt_value(phpipam_password.strip()))

    try:
        sync_h = max(0, min(168, int(phpipam_sync_hours)))
    except ValueError:
        sync_h = 0
    await set_setting(db, "phpipam_sync_hours", str(sync_h))

    # Reschedule or remove phpIPAM sync job
    from scheduler import scheduler
    from collectors.phpipam import sync_phpipam_hosts
    job = scheduler.get_job("phpipam_sync")
    if sync_h > 0:
        if job:
            job.reschedule(trigger="interval", hours=sync_h)
        else:
            async def _sync():
                from database import AsyncSessionLocal
                async with AsyncSessionLocal() as _db:
                    await sync_phpipam_hosts(_db)
            scheduler.add_job(_sync, "interval", hours=sync_h, id="phpipam_sync", replace_existing=True)
    else:
        if job:
            job.remove()

    return RedirectResponse(url="/settings?saved=1", status_code=303)


@router.post("/phpipam/sync")
async def manual_phpipam_sync(db: AsyncSession = Depends(get_db)):
    """Trigger a manual phpIPAM host import. Returns JSON result."""
    from collectors.phpipam import sync_phpipam_hosts
    result = await sync_phpipam_hosts(db)
    return JSONResponse(result)


# ── Notifications ─────────────────────────────────────────────────────────────

@router.get("/notifications", response_class=HTMLResponse)
async def notifications_settings(request: Request, db: AsyncSession = Depends(get_db)):
    # This is handled inline in the main settings page, just redirect
    return RedirectResponse(url="/settings?tab=notifications")


@router.post("/notifications/save")
async def save_notifications(
    notify_enabled:      str = Form("0"),
    telegram_bot_token:  str = Form(""),
    telegram_chat_id:    str = Form(""),
    discord_webhook_url: str = Form(""),
    smtp_host:           str = Form(""),
    smtp_port:           str = Form("587"),
    smtp_user:           str = Form(""),
    smtp_password:       str = Form(""),
    smtp_from:           str = Form(""),
    smtp_to:             str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    await set_setting(db, "notify_enabled", "1" if notify_enabled == "on" else "0")
    await set_setting(db, "telegram_bot_token", telegram_bot_token.strip())
    await set_setting(db, "telegram_chat_id", telegram_chat_id.strip())
    await set_setting(db, "discord_webhook_url", discord_webhook_url.strip())
    await set_setting(db, "smtp_host", smtp_host.strip())
    await set_setting(db, "smtp_port", smtp_port.strip() or "587")
    await set_setting(db, "smtp_user", smtp_user.strip())
    await set_setting(db, "smtp_from", smtp_from.strip())
    await set_setting(db, "smtp_to", smtp_to.strip())
    if smtp_password.strip():
        await set_setting(db, "smtp_password", encrypt_value(smtp_password.strip()))
    return RedirectResponse(url="/settings?saved=1&tab=notifications", status_code=303)


@router.post("/notifications/test")
async def test_notification(channel: str = Form(""), db: AsyncSession = Depends(get_db)):
    from notifications import _send_telegram, _send_discord, _send_email
    from database import decrypt_value, get_setting
    try:
        if channel == "telegram":
            token = await get_setting(db, "telegram_bot_token", "")
            chat  = await get_setting(db, "telegram_chat_id", "")
            await _send_telegram(token, chat, "<b>Vigil Test</b>\nBenachrichtigungen funktionieren ✓")
        elif channel == "discord":
            url = await get_setting(db, "discord_webhook_url", "")
            await _send_discord(url, "Vigil Test", "Benachrichtigungen funktionieren ✓", 0x3498db)
        elif channel == "email":
            host  = await get_setting(db, "smtp_host", "")
            port  = int(await get_setting(db, "smtp_port", "587"))
            user  = await get_setting(db, "smtp_user", "")
            pw    = decrypt_value(await get_setting(db, "smtp_password", ""))
            frm   = await get_setting(db, "smtp_from", "") or user
            to    = await get_setting(db, "smtp_to", "")
            await _send_email(host, port, user, pw, frm, to, "Vigil Test", "Benachrichtigungen funktionieren ✓")
        return JSONResponse({"ok": True, "message": "Testnachricht gesendet"})
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)
