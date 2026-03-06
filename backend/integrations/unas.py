"""UniFi NAS (UNAS Pro) integration – storage, RAID, disk SMART, system stats."""
from __future__ import annotations

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField

_DISK_STATUS_LABELS: dict[str, str] = {
    "normal": "Normal", "spare": "Spare", "error": "Error",
    "failed": "Failed", "missing": "Missing", "removed": "Removed",
}

_RAID_TYPE_LABELS: dict[str, str] = {
    "raid0": "RAID 0", "raid1": "RAID 1", "raid5": "RAID 5",
    "raid6": "RAID 6", "raid10": "RAID 10", "jbod": "JBOD", "single": "Single",
}


# ── API Client ────────────────────────────────────────────────────────────────


class UnasAPI:
    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        self.base = host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

    async def fetch_all(self) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=20.0, follow_redirects=True) as client:
            resp = await client.post(
                f"{self.base}/api/auth/login",
                json={"username": self.username, "password": self.password})
            resp.raise_for_status()
            csrf = resp.headers.get("x-csrf-token", "")
            hdrs = {"x-csrf-token": csrf} if csrf else {}
            sr = await client.get(f"{self.base}/api/system", headers=hdrs)
            sr.raise_for_status()
            return parse_unas_data(sr.json())

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10.0, follow_redirects=True) as client:
                resp = await client.post(
                    f"{self.base}/api/auth/login",
                    json={"username": self.username, "password": self.password})
                resp.raise_for_status()
            return True
        except Exception:
            return False


# ── Parser ────────────────────────────────────────────────────────────────────


def parse_unas_data(raw_system: dict) -> dict:
    ustorage = raw_system.get("ustorage") or {}
    storage = raw_system.get("storage") or []
    fw = raw_system.get("firmware") or {}
    cpu_info = raw_system.get("cpu") or {}
    mem_info = raw_system.get("memory") or {}

    mem_total_kb = float(mem_info.get("total") or 0)
    mem_free_kb = float(mem_info.get("free") or 0)
    mem_used_kb = max(0.0, mem_total_kb - mem_free_kb)
    mem_total_gb = round(mem_total_kb / 1024**2, 1)
    mem_used_gb = round(mem_used_kb / 1024**2, 1)
    mem_pct = round(mem_used_gb / mem_total_gb * 100, 1) if mem_total_gb else 0

    cpu_pct = round(float(cpu_info.get("currentload") or 0), 1)
    cpu_temp = cpu_info.get("temperature")
    fw_latest = fw.get("latest") or {}
    version = fw_latest.get("version") or raw_system.get("ucore_version", "")

    system = {
        "hostname": raw_system.get("hostname", ""), "version": version,
        "uptime_s": raw_system.get("uptime", 0) or 0, "cpu_pct": cpu_pct,
        "cpu_temp": cpu_temp, "mem_used_gb": mem_used_gb,
        "mem_total_gb": mem_total_gb, "mem_pct": mem_pct,
    }

    disks = []
    for d in (ustorage.get("disks") or []):
        state = (d.get("state") or "").lower()
        healthy = (d.get("healthy") or "").lower()
        size_gb = round((d.get("size") or 0) / 1024**3, 2)
        temp = d.get("temperature")
        ok = healthy == "good" and state in ("normal", "spare", "")
        disks.append({
            "id": d.get("serial") or f"slot{d.get('slot', '')}",
            "name": f"Slot {d.get('slot', '')}", "serial": d.get("serial", ""),
            "model": (d.get("model") or "").strip(), "size_gb": size_gb,
            "size_tb": round(size_gb / 1024, 2) if size_gb >= 1024 else 0.0,
            "temp": temp, "temp_ok": temp is None or temp < 45,
            "status": state, "status_label": _DISK_STATUS_LABELS.get(state, state.title() or "Unknown"),
            "ok": ok, "smart_ok": (d.get("bad_sector") or 0) == 0,
            "type": d.get("type") or "SSD", "life_span": d.get("life_span"),
            "power_on_hrs": d.get("poweronhrs"),
        })
    disks.sort(key=lambda d: d["name"])

    raids = []
    for idx, s in enumerate(storage):
        if s.get("type") != "raid":
            continue
        r = s.get("raid") or {}
        rtype = (r.get("level") or "").lower()
        state = (r.get("state") or "").lower()
        size_gb = round((s.get("size") or 0) / 1024**3, 2)
        used_gb = round((s.get("used") or 0) / 1024**3, 2)
        pct = round(used_gb / size_gb * 100, 1) if size_gb else 0
        raids.append({
            "id": str(s.get("id", idx)),
            "name": s.get("mountPoint") or f"RAID {rtype.upper()}",
            "type": rtype, "type_label": _RAID_TYPE_LABELS.get(rtype, rtype.upper() or "RAID"),
            "state": state,
            "healthy": state in ("healthy", "clean", "active", "ok", "normal"),
            "size_gb": size_gb, "used_gb": used_gb, "pct": pct,
            "disk_ids": [dev.get("serial", "") for dev in (s.get("devices") or [])],
            "active_devices": r.get("activeDevices", ""),
            "failed_devices": r.get("failedDevices", "0"),
        })
    raids.sort(key=lambda r: r["name"])

    pools = []
    for idx, sp in enumerate(ustorage.get("space") or []):
        if sp.get("space_type") != "primary":
            continue
        total_gb = round((sp.get("total_bytes") or 0) / 1024**3, 2)
        used_gb = round((sp.get("used_bytes") or 0) / 1024**3, 2)
        pct = round(used_gb / total_gb * 100, 1) if total_gb else 0
        health = (sp.get("health") or "").lower()
        pools.append({
            "id": sp.get("device", str(idx)), "name": f"Pool {len(pools) + 1}",
            "size_gb": total_gb, "used_gb": used_gb,
            "free_gb": round(total_gb - used_gb, 2), "pct": pct,
            "healthy": health in ("health", "healthy", "ok", ""),
            "members": (sp.get("raid") or {}).get("members", []),
        })
    pools.sort(key=lambda p: p["name"])

    shares: list = []

    storage_used = sum(p["used_gb"] for p in pools)
    storage_total = sum(p["size_gb"] for p in pools)

    totals = {
        "disks_total": len(disks),
        "disks_ok": sum(1 for d in disks if d["ok"] and d["smart_ok"]),
        "disks_error": sum(1 for d in disks if not d["ok"] or not d["smart_ok"]),
        "disks_hot": sum(1 for d in disks if d["temp"] is not None and d["temp"] >= 45),
        "raids_total": len(raids),
        "raids_healthy": sum(1 for r in raids if r["healthy"]),
        "pools_total": len(pools), "shares_total": len(shares),
        "storage_used_gb": round(storage_used, 1),
        "storage_total_gb": round(storage_total, 1),
        "storage_pct": round(storage_used / storage_total * 100, 1) if storage_total else 0,
    }

    return {
        "system": system, "disks": disks, "raids": raids,
        "pools": pools, "shares": shares, "totals": totals,
    }


# ── Integration Plugin ────────────────────────────────────────────────────────


class UnasIntegration(BaseIntegration):
    name = "unas"
    display_name = "UniFi NAS"
    icon = "ubiquiti"
    description = "Monitor UniFi NAS storage, RAID, and system stats."

    config_fields = [
        ConfigField(key="host", label="Host URL", field_type="url",
                    placeholder="https://unas.local"),
        ConfigField(key="username", label="Username", placeholder="admin"),
        ConfigField(key="password", label="Password", field_type="password", encrypted=True),
        ConfigField(key="verify_ssl", label="Verify SSL", field_type="checkbox",
                    required=False, default=False),
    ]

    def _api(self) -> UnasAPI:
        return UnasAPI(
            host=self.config["host"],
            username=self.config["username"],
            password=self.config["password"],
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
