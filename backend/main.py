import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select

from database import (
    AsyncSessionLocal, get_setting, init_db,
    ProxmoxCluster, UnifiController, UnasServer,
    PiholeInstance, AdguardInstance, PortainerInstance, TruenasServer,
    SynologyServer, FirewallInstance, HassInstance, GiteaInstance,
    PhpipamServer, SpeedtestConfig, NutInstance, RedfishServer,
)
from scheduler import start_scheduler, stop_scheduler
from routers import auth, dashboard, ping, proxmox, setup, settings, unifi, unas, pihole, adguard, portainer, truenas, synology, firewall, hass, gitea, phpipam, speedtest, nut, redfish, alerts, users
from routers import integrations as integrations_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # Create new generic tables (IntegrationConfig, Snapshot)
    from models import init_db as init_new_db
    await init_new_db()
    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(title="Vigil", lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/health")
async def health():
    from sqlalchemy import text as sa_text
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(sa_text("SELECT 1"))
        return {"status": "ok", "db": "connected"}
    except Exception as e:
        return {"status": "error", "db": str(e)}


# ── Nav counts cache (60s TTL, single GROUP BY query) ────────────────────────

_nav_cache: dict = {"counts": {}, "ts": 0.0}
_NAV_CACHE_TTL = 60  # seconds

# All integration type keys expected by templates
_NAV_KEYS = (
    "proxmox", "unifi", "unas", "pihole", "adguard", "portainer",
    "truenas", "synology", "firewall", "hass", "gitea", "phpipam",
    "speedtest", "ups", "redfish",
)


# Old table mapping for nav counts (used until data is migrated to integration_configs)
_OLD_MODELS = {
    "proxmox": ProxmoxCluster, "unifi": UnifiController, "unas": UnasServer,
    "pihole": PiholeInstance, "adguard": AdguardInstance, "portainer": PortainerInstance,
    "truenas": TruenasServer, "synology": SynologyServer, "firewall": FirewallInstance,
    "hass": HassInstance, "gitea": GiteaInstance, "phpipam": PhpipamServer,
    "speedtest": SpeedtestConfig, "ups": NutInstance, "redfish": RedfishServer,
}


async def _get_nav_counts(db) -> dict:
    now = time.time()
    if now - _nav_cache["ts"] < _NAV_CACHE_TTL and _nav_cache["counts"]:
        return _nav_cache["counts"]

    # Try new generic table first
    from services.integration import count_all_by_type
    raw = await count_all_by_type(db)
    counts = {k: raw.get(k, 0) for k in _NAV_KEYS}

    # Fall back to old tables if new table is empty
    if not any(counts.values()):
        for key, model in _OLD_MODELS.items():
            try:
                r = await db.execute(select(func.count()).select_from(model))
                counts[key] = r.scalar() or 0
            except Exception:
                counts[key] = 0

    _nav_cache["counts"] = counts
    _nav_cache["ts"] = now
    return counts


@app.middleware("http")
async def inject_globals(request: Request, call_next):
    # Skip middleware for static files and health check
    if request.url.path.startswith("/static/") or request.url.path == "/health":
        return await call_next(request)

    # Auth check – skip for public paths
    PUBLIC_PATHS = {"/login", "/logout"}
    is_public = request.url.path in PUBLIC_PATHS or request.url.path.startswith("/setup")
    if not is_public:
        from database import get_current_user, AsyncSessionLocal as _ASL
        async with _ASL() as auth_db:
            user = await get_current_user(request, auth_db)
        if user is None:
            from fastapi.responses import RedirectResponse as _RR
            return _RR(url="/login", status_code=302)
        request.state.current_user = user
        role = getattr(user, "role", "admin") or "admin"
        # Admin-only paths
        if (request.url.path.startswith("/settings") or request.url.path.startswith("/users")) \
                and role != "admin":
            from fastapi.responses import HTMLResponse as _HTML
            return _HTML(
                "<html><body style='background:#0b0d14;color:#e2e8f0;font-family:sans-serif;"
                "display:flex;align-items:center;justify-content:center;height:100vh;'>"
                "<div style='text-align:center'><p style='font-size:3rem;margin:0'>403</p>"
                "<p style='color:#94a3b8'>Admin access required.</p>"
                "<a href='/' style='color:#3b82f6;font-size:.875rem'>← Back</a></div></body></html>",
                status_code=403,
            )
        # Read-only users cannot mutate
        if role == "readonly" and request.method in ("POST", "PUT", "DELETE", "PATCH"):
            from fastapi.responses import HTMLResponse as _HTML
            return _HTML(
                "<html><body style='background:#0b0d14;color:#e2e8f0;font-family:sans-serif;"
                "display:flex;align-items:center;justify-content:center;height:100vh;'>"
                "<div style='text-align:center'><p style='font-size:3rem;margin:0'>403</p>"
                "<p style='color:#94a3b8'>Read-only access — no changes allowed.</p>"
                "<a href='/' style='color:#3b82f6;font-size:.875rem'>← Back</a></div></body></html>",
                status_code=403,
            )
    else:
        request.state.current_user = None

    async with AsyncSessionLocal() as db:
        request.state.site_name = await get_setting(db, "site_name", "Vigil")
        request.state.nav_counts = await _get_nav_counts(db)
    return await call_next(request)


# ── Old routers (backward compat – will be removed after full migration) ─────
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(setup.router)
app.include_router(ping.router)
app.include_router(settings.router)
app.include_router(proxmox.router)
app.include_router(unifi.router)
app.include_router(unas.router)
app.include_router(pihole.router)
app.include_router(adguard.router)
app.include_router(portainer.router)
app.include_router(truenas.router)
app.include_router(synology.router)
app.include_router(firewall.router)
app.include_router(hass.router)
app.include_router(gitea.router)
app.include_router(phpipam.router)
app.include_router(speedtest.router)
app.include_router(nut.router)
app.include_router(redfish.router)
app.include_router(alerts.router)
app.include_router(users.router)

# ── New generic integration router ───────────────────────────────────────────
app.include_router(integrations_router.router)
