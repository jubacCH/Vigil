"""phpIPAM integration – imports IP addresses as PingHosts."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ── API Client ────────────────────────────────────────────────────────────────


class PhpIpamClient:
    def __init__(self, base_url: str, app_id: str, app_secret: str | None = None,
                 username: str | None = None, password: str | None = None,
                 verify_ssl: bool = True):
        self.base = base_url.rstrip("/")
        self.app_id = app_id
        self.app_secret = app_secret
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self._token: str | None = None

    def _api(self, path: str) -> str:
        return f"{self.base}/api/{self.app_id}/{path.lstrip('/')}"

    async def authenticate(self) -> None:
        # App Code auth: token = app_secret, no login needed
        if self.app_secret:
            self._token = self.app_secret
            return
        # User auth: POST /user/ with basic auth
        if not self.username or not self.password:
            return
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10) as client:
            resp = await client.post(self._api("user/"), auth=(self.username, self.password))
            resp.raise_for_status()
            body = resp.json()
            if not body.get("success"):
                raise ValueError(f"phpIPAM auth failed: {body.get('message', 'unknown')}")
            self._token = body["data"]["token"]

    def _headers(self) -> dict:
        if self._token:
            return {"token": self._token, "phpipam-token": self._token}
        return {}

    async def get_addresses(self) -> list[dict]:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15) as client:
            resp = await client.get(self._api("addresses/all/"), headers=self._headers())
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            body = resp.json()
            if not body.get("success"):
                return []
            return body.get("data") or []


# ── Host Sync ─────────────────────────────────────────────────────────────────


async def sync_phpipam_hosts(db: "AsyncSession", config: dict) -> dict:
    from models.base import decrypt_value
    from models.ping import PingHost
    from sqlalchemy import select

    url = config.get("host", "")
    app_id = config.get("app_id", "")
    username = config.get("username")
    password = config.get("password")
    verify_ssl = config.get("verify_ssl", True)

    if not url or not app_id:
        return {"added": 0, "merged": 0, "skipped": 0,
                "errors": ["phpIPAM not configured (URL or App-ID missing)"]}

    app_secret = config.get("app_secret")

    client = PhpIpamClient(
        base_url=url, app_id=app_id, app_secret=app_secret or None,
        username=username or None, password=password or None,
        verify_ssl=verify_ssl,
    )

    try:
        await client.authenticate()
        addresses = await client.get_addresses()
    except Exception as exc:
        logger.error("phpIPAM fetch failed: %s", exc)
        return {"added": 0, "merged": 0, "skipped": 0, "errors": [str(exc)]}

    existing_q = await db.execute(select(PingHost))
    existing: dict[str, PingHost] = {h.hostname: h for h in existing_q.scalars().all()}

    added = merged = skipped = 0
    errors: list[str] = []
    dirty = False

    for addr in addresses:
        if str(addr.get("active", "1")) == "0":
            skipped += 1
            continue
        ip = (addr.get("ip") or "").strip()
        if not ip:
            skipped += 1
            continue
        name = (addr.get("hostname") or addr.get("description") or ip).strip() or ip

        try:
            if ip in existing:
                host = existing[ip]
                changed = False
                if host.name == host.hostname and name != ip:
                    host.name = name[:128]
                    changed = True
                if host.source == "manual":
                    host.source = "phpipam"
                    changed = True
                if changed:
                    dirty = True
                merged += 1
            else:
                db.add(PingHost(
                    name=name[:128], hostname=ip, check_type="icmp",
                    enabled=True, source="phpipam", source_detail=url,
                ))
                existing[ip] = True  # type: ignore[assignment]
                added += 1
                dirty = True
        except Exception as exc:
            errors.append(f"{ip}: {exc}")

    if dirty:
        await db.commit()

    return {"added": added, "merged": merged, "skipped": skipped, "errors": errors}


# ── Integration Plugin ────────────────────────────────────────────────────────


class PhpIpamIntegration(BaseIntegration):
    name = "phpipam"
    display_name = "phpIPAM"
    icon = "phpipam"
    icon_svg = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>'
    description = "Import IP addresses from phpIPAM as ping hosts."

    config_fields = [
        ConfigField(key="host", label="phpIPAM URL", field_type="url",
                    placeholder="https://phpipam.local"),
        ConfigField(key="app_id", label="App ID", placeholder="nodeglow"),
        ConfigField(key="app_secret", label="App Secret / API Token", field_type="password",
                    encrypted=True, required=False,
                    placeholder="For App Code auth (no username needed)"),
        ConfigField(key="username", label="Username", required=False,
                    placeholder="Only for User auth (leave empty for App Code)"),
        ConfigField(key="password", label="Password", field_type="password",
                    encrypted=True, required=False),
        ConfigField(key="verify_ssl", label="Verify SSL", field_type="checkbox",
                    required=False, default=True),
    ]

    async def collect(self) -> CollectorResult:
        try:
            client = PhpIpamClient(
                base_url=self.config.get("host", ""),
                app_id=self.config.get("app_id", ""),
                app_secret=self.config.get("app_secret"),
                username=self.config.get("username"),
                password=self.config.get("password"),
                verify_ssl=self.config.get("verify_ssl", True),
            )
            await client.authenticate()
            addresses = await client.get_addresses()

            active = [a for a in addresses if str(a.get("active", "1")) != "0"]

            # Build subnet summary
            subnets: dict[str, int] = {}
            for a in active:
                subnet_id = a.get("subnetId", "?")
                subnets[subnet_id] = subnets.get(subnet_id, 0) + 1

            # Recent addresses (last 10 added/modified)
            recent = sorted(
                [a for a in active if a.get("ip")],
                key=lambda a: a.get("editDate") or a.get("lastSeen") or "",
                reverse=True,
            )[:10]
            recent_list = []
            for a in recent:
                recent_list.append({
                    "ip": a.get("ip", ""),
                    "hostname": a.get("hostname") or a.get("description") or "",
                    "last_seen": a.get("lastSeen") or "",
                    "mac": a.get("mac") or "",
                })

            return CollectorResult(success=True, data={
                "addresses_total": len(addresses),
                "addresses_active": len(active),
                "addresses_inactive": len(addresses) - len(active),
                "subnets_count": len(subnets),
                "recent_addresses": recent_list,
            })
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))
