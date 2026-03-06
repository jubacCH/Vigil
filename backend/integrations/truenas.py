"""TrueNAS integration – pool, disk and system stats."""
from __future__ import annotations

import asyncio

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField


# ── API Client ────────────────────────────────────────────────────────────────


class TruenasAPI:
    def __init__(self, host: str, api_key: str, verify_ssl: bool = False):
        self.base = host.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    async def fetch_all(self) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0, follow_redirects=True) as client:
            info_task = client.get(f"{self.base}/api/v2.0/system/info", headers=self._headers())
            pools_task = client.get(f"{self.base}/api/v2.0/pool", headers=self._headers())
            disks_task = client.get(f"{self.base}/api/v2.0/disk", headers=self._headers())
            alerts_task = client.get(f"{self.base}/api/v2.0/alert/list", headers=self._headers())

            info_resp, pools_resp, disks_resp, alerts_resp = await asyncio.gather(
                info_task, pools_task, disks_task, alerts_task)

            info_resp.raise_for_status()
            pools_resp.raise_for_status()
            disks_resp.raise_for_status()
            alerts = alerts_resp.json() if alerts_resp.status_code == 200 else []

            return parse_truenas_data(
                info=info_resp.json(), pools=pools_resp.json(),
                disks=disks_resp.json(), alerts=alerts)

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(f"{self.base}/api/v2.0/system/info", headers=self._headers())
                return resp.status_code == 200
        except Exception:
            return False


# ── Parser ────────────────────────────────────────────────────────────────────


def _bytes_to_gb(value) -> float:
    try:
        return round(int(value) / (1024 ** 3), 2)
    except (TypeError, ValueError):
        return 0.0


def parse_truenas_data(info: dict, pools: list, disks: list, alerts: list) -> dict:
    system = {
        "hostname": info.get("hostname", ""),
        "version": info.get("version", ""),
        "uptime_s": info.get("uptime_seconds", 0),
        "platform": info.get("system_product", info.get("platform", "")),
        "model": info.get("system_product", ""),
    }

    parsed_pools = []
    total_size_bytes = 0
    total_used_bytes = 0
    pools_healthy = 0

    for p in pools:
        size_bytes = p.get("size", 0) or 0
        allocated_bytes = p.get("allocated", 0) or 0
        free_bytes = max(size_bytes - allocated_bytes, 0)
        pct = round(allocated_bytes / size_bytes * 100, 1) if size_bytes > 0 else 0.0
        status = p.get("status", "UNKNOWN")
        healthy = status == "ONLINE"
        if healthy:
            pools_healthy += 1
        total_size_bytes += size_bytes
        total_used_bytes += allocated_bytes
        parsed_pools.append({
            "name": p.get("name", ""), "guid": str(p.get("guid", "")),
            "status": status, "healthy": healthy,
            "size_gb": _bytes_to_gb(size_bytes), "used_gb": _bytes_to_gb(allocated_bytes),
            "free_gb": _bytes_to_gb(free_bytes), "pct": pct,
            "topology": p.get("topology", {}),
        })

    parsed_disks = []
    for d in disks:
        rotation = d.get("rotationrate")
        disk_type = "SSD" if rotation is None or rotation == 0 else "HDD"
        parsed_disks.append({
            "name": d.get("name", ""), "serial": d.get("serial", ""),
            "model": d.get("model", ""), "size_gb": _bytes_to_gb(d.get("size", 0)),
            "temp": d.get("temperature"), "type": disk_type,
        })
    parsed_disks.sort(key=lambda x: x["name"])

    parsed_alerts = []
    for a in alerts:
        parsed_alerts.append({
            "level": a.get("level", "INFO"),
            "message": a.get("formatted", a.get("args", {}).get("text", str(a))),
            "date": a.get("last_occurrence", ""),
        })
    level_order = {"CRITICAL": 0, "WARNING": 1, "ALERT": 1, "ERROR": 2, "INFO": 3, "NOTICE": 3}
    parsed_alerts.sort(key=lambda x: level_order.get(x["level"].upper(), 9))

    storage_total_gb = _bytes_to_gb(total_size_bytes)
    storage_used_gb = _bytes_to_gb(total_used_bytes)
    storage_pct = round(total_used_bytes / total_size_bytes * 100, 1) if total_size_bytes > 0 else 0.0

    return {
        "system": system, "pools": parsed_pools, "disks": parsed_disks,
        "alerts": parsed_alerts,
        "totals": {
            "pools_total": len(parsed_pools), "pools_healthy": pools_healthy,
            "disks_total": len(parsed_disks),
            "storage_used_gb": storage_used_gb, "storage_total_gb": storage_total_gb,
            "storage_pct": storage_pct,
        },
    }


# ── Integration Plugin ────────────────────────────────────────────────────────


class TruenasIntegration(BaseIntegration):
    name = "truenas"
    display_name = "TrueNAS"
    icon = "truenas"
    description = "Monitor TrueNAS pools, disks and system stats."

    config_fields = [
        ConfigField(key="host", label="Host URL", field_type="url",
                    placeholder="https://truenas.local"),
        ConfigField(key="api_key", label="API Key", field_type="password", encrypted=True),
        ConfigField(key="verify_ssl", label="Verify SSL", field_type="checkbox",
                    required=False, default=False),
    ]

    def _api(self) -> TruenasAPI:
        return TruenasAPI(
            host=self.config["host"],
            api_key=self.config["api_key"],
            verify_ssl=self.config.get("verify_ssl", False),
        )

    async def collect(self) -> CollectorResult:
        try:
            data = await self._api().fetch_all()
            return CollectorResult(success=True, data=data)
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))

    async def health_check(self) -> bool:
        return await self._api().health_check()
