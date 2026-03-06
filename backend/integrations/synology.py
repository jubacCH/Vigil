"""Synology DSM integration – storage and system stats."""
from __future__ import annotations

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField


# ── API Client ────────────────────────────────────────────────────────────────


class SynologyAPI:
    def __init__(self, host: str, port: int = 5001, username: str = "",
                 password: str = "", verify_ssl: bool = False):
        if not host.startswith("http://") and not host.startswith("https://"):
            scheme = "https" if port == 5001 else "http"
            host = f"{scheme}://{host}"
        self.base = f"{host.rstrip('/')}:{port}"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

    async def _login(self, client: httpx.AsyncClient) -> str:
        resp = await client.get(f"{self.base}/webapi/auth.cgi", params={
            "api": "SYNO.API.Auth", "version": "3", "method": "login",
            "account": self.username, "passwd": self.password,
            "session": "Vigil", "format": "sid",
        })
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success"):
            code = data.get("error", {}).get("code", "unknown")
            raise ValueError(f"Synology login failed (error code: {code})")
        return data["data"]["sid"]

    async def _logout(self, client: httpx.AsyncClient, sid: str) -> None:
        try:
            await client.get(f"{self.base}/webapi/auth.cgi", params={
                "api": "SYNO.API.Auth", "version": "1", "method": "logout",
                "session": "Vigil", "_sid": sid,
            })
        except Exception:
            pass

    async def _api(self, client: httpx.AsyncClient, api: str, method: str,
                   version: int, sid: str, extra_params: dict | None = None) -> dict:
        params: dict = {"api": api, "version": str(version), "method": method, "_sid": sid}
        if extra_params:
            params.update(extra_params)
        resp = await client.get(f"{self.base}/webapi/entry.cgi", params=params)
        resp.raise_for_status()
        return resp.json()

    async def fetch_all(self) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=20) as client:
            sid = await self._login(client)
            try:
                info = await self._api(client, "SYNO.DSM.Info", "getinfo", 2, sid)
                storage = await self._api(client, "SYNO.Storage.CGI.Storage", "load_info", 1, sid)
                load = await self._api(client, "SYNO.System.SystemLoad", "get", 1, sid)
            finally:
                await self._logout(client, sid)
        return {"info": info, "storage": storage, "load": load}

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10) as client:
                sid = await self._login(client)
                await self._logout(client, sid)
            return True
        except Exception:
            return False


# ── Parser ────────────────────────────────────────────────────────────────────


def _bytes_to_gb(value) -> float:
    try:
        return round(int(value) / 1_073_741_824, 2)
    except (TypeError, ValueError):
        return 0.0


def _pct(used, total) -> float:
    try:
        u, t = float(used), float(total)
        if t <= 0:
            return 0.0
        return round(u / t * 100, 1)
    except (TypeError, ValueError):
        return 0.0


def parse_synology_data(info: dict, storage: dict, load: dict) -> dict:
    info_data = info.get("data", {}) if info.get("success") else {}
    hostname = info_data.get("hostname", "unknown")
    version = info_data.get("version", "")
    uptime_s = int(info_data.get("uptime", 0))

    load_data = load.get("data", {}) if load.get("success") else {}
    cpu_list = load_data.get("cpu", [])
    cpu_pct = 0.0
    if cpu_list:
        last = cpu_list[-1]
        try:
            cpu_pct = round(float(last[0]) + float(last[1]), 1)
        except (IndexError, TypeError, ValueError):
            cpu_pct = 0.0

    mem_data = load_data.get("memory", {})
    mem_total_kb = int(mem_data.get("real_total", 0))
    mem_avail_kb = int(mem_data.get("avail_real", 0))
    mem_used_kb = mem_total_kb - mem_avail_kb
    mem_total_mb = round(mem_total_kb / 1024, 0)
    mem_used_mb = round(mem_used_kb / 1024, 0)
    mem_used_pct = _pct(mem_used_kb, mem_total_kb)

    storage_data = storage.get("data", {}) if storage.get("success") else {}
    vol_info = storage_data.get("vol_info", [])
    disk_info = storage_data.get("disk_info", [])

    volumes = []
    for vol in vol_info:
        size_bytes = int(vol.get("size_total", 0))
        used_bytes = int(vol.get("size_used", 0))
        size_gb = _bytes_to_gb(size_bytes)
        used_gb = _bytes_to_gb(used_bytes)
        free_gb = round(size_gb - used_gb, 2)
        pct = _pct(used_bytes, size_bytes)
        status = vol.get("status", "unknown")
        healthy = status in ("normal", "background_checking")
        volumes.append({
            "id": str(vol.get("vol_path", vol.get("id", ""))),
            "name": vol.get("name", vol.get("vol_path", "Unknown")),
            "status": status, "size_gb": size_gb, "used_gb": used_gb,
            "free_gb": free_gb, "pct": pct, "healthy": healthy,
            "fs_type": vol.get("fs_type", ""), "raid_type": vol.get("raid_type", ""),
        })

    disks = []
    for disk in disk_info:
        status = disk.get("status", "unknown")
        healthy = status in ("normal", "initialized", "not_exist")
        size_bytes = int(disk.get("size_total", 0))
        disks.append({
            "name": disk.get("name", ""), "model": disk.get("model", ""),
            "serial": disk.get("serial", ""), "status": status,
            "temp": int(disk.get("temp", 0)), "size_gb": _bytes_to_gb(size_bytes),
            "healthy": healthy, "type": disk.get("diskType", disk.get("type", "")),
        })

    total_storage_gb = sum(v["size_gb"] for v in volumes)
    used_storage_gb = sum(v["used_gb"] for v in volumes)
    storage_pct = _pct(used_storage_gb, total_storage_gb)

    return {
        "system": {
            "hostname": hostname, "version": version, "uptime_s": uptime_s,
            "cpu_pct": cpu_pct, "mem_used_pct": mem_used_pct,
            "mem_total_mb": int(mem_total_mb), "mem_used_mb": int(mem_used_mb),
        },
        "volumes": volumes, "disks": disks,
        "totals": {
            "volumes_total": len(volumes),
            "volumes_healthy": sum(1 for v in volumes if v["healthy"]),
            "disks_total": len(disks),
            "disks_ok": sum(1 for d in disks if d["healthy"]),
            "storage_total_gb": round(total_storage_gb, 2),
            "storage_used_gb": round(used_storage_gb, 2),
            "storage_pct": storage_pct,
        },
    }


# ── Integration Plugin ────────────────────────────────────────────────────────


class SynologyIntegration(BaseIntegration):
    name = "synology"
    display_name = "Synology DSM"
    icon = "synology"
    description = "Monitor Synology NAS storage and system stats."

    config_fields = [
        ConfigField(key="host", label="Host", placeholder="synology.local"),
        ConfigField(key="port", label="Port", field_type="number",
                    placeholder="5001", required=False, default=5001),
        ConfigField(key="username", label="Username", placeholder="admin"),
        ConfigField(key="password", label="Password", field_type="password", encrypted=True),
        ConfigField(key="verify_ssl", label="Verify SSL", field_type="checkbox",
                    required=False, default=False),
    ]

    def _api(self) -> SynologyAPI:
        return SynologyAPI(
            host=self.config["host"],
            port=int(self.config.get("port", 5001) or 5001),
            username=self.config["username"],
            password=self.config["password"],
            verify_ssl=self.config.get("verify_ssl", False),
        )

    async def collect(self) -> CollectorResult:
        try:
            api = self._api()
            raw = await api.fetch_all()
            data = parse_synology_data(raw["info"], raw["storage"], raw["load"])
            return CollectorResult(success=True, data=data)
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))

    async def health_check(self) -> bool:
        return await self._api().health_check()
