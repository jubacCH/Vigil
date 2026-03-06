"""Firewall integration – OPNsense and pfSense monitoring."""
from __future__ import annotations

import base64

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField


# ── OPNsense API Client ──────────────────────────────────────────────────────


class OPNsenseAPI:
    def __init__(self, host: str, api_key: str, api_secret: str, verify_ssl: bool = False):
        if not host.startswith("http://") and not host.startswith("https://"):
            host = f"https://{host}"
        self.base = host.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl

    def _headers(self) -> dict:
        cred = base64.b64encode(f"{self.api_key}:{self.api_secret}".encode()).decode()
        return {"Authorization": f"Basic {cred}"}

    async def _get(self, client: httpx.AsyncClient, path: str) -> dict:
        resp = await client.get(f"{self.base}{path}", headers=self._headers())
        resp.raise_for_status()
        return resp.json()

    async def fetch_all(self) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=20) as client:
            firmware: dict = {}
            status: dict = {}
            interfaces: dict = {}
            try:
                firmware = await self._get(client, "/api/core/firmware/info")
            except Exception:
                pass
            try:
                status = await self._get(client, "/api/core/system/status")
            except Exception:
                pass
            try:
                interfaces = await self._get(client, "/api/diagnostics/interface/getInterfaceNames")
            except Exception:
                pass
        return {"fw_type": "opnsense", "firmware": firmware, "status": status, "interfaces": interfaces}

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10) as client:
                resp = await client.get(f"{self.base}/api/core/firmware/info", headers=self._headers())
                return resp.status_code < 400
        except Exception:
            return False


# ── pfSense API Client ───────────────────────────────────────────────────────


class PfsenseAPI:
    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        if not host.startswith("http://") and not host.startswith("https://"):
            host = f"https://{host}"
        self.base = host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

    def _auth(self) -> tuple[str, str]:
        return (self.username, self.password)

    async def fetch_all(self) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=20) as client:
            sys_info: dict = {}
            interfaces: dict = {}
            try:
                resp = await client.get(f"{self.base}/api/v1/system/info", auth=self._auth())
                resp.raise_for_status()
                sys_info = resp.json()
            except Exception:
                pass
            try:
                resp = await client.get(f"{self.base}/api/v1/interface", auth=self._auth())
                resp.raise_for_status()
                interfaces = resp.json()
            except Exception:
                pass
        return {"fw_type": "pfsense", "sys_info": sys_info, "interfaces": interfaces}

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10) as client:
                resp = await client.get(f"{self.base}/api/v1/system/info", auth=self._auth())
                return resp.status_code < 400
        except Exception:
            return False


# ── Parsers ───────────────────────────────────────────────────────────────────


def _parse_uptime(raw) -> int:
    if raw is None:
        return 0
    if isinstance(raw, (int, float)):
        return int(raw)
    raw = str(raw).strip()
    total = 0
    try:
        if "day" in raw:
            parts = raw.split(",")
            days_part = parts[0].strip()
            days = int(days_part.split()[0])
            total += days * 86400
            raw = parts[1].strip() if len(parts) > 1 else ""
        if ":" in raw:
            hms = raw.strip().split(":")
            if len(hms) == 3:
                total += int(hms[0]) * 3600 + int(hms[1]) * 60 + int(hms[2].split(".")[0])
            elif len(hms) == 2:
                total += int(hms[0]) * 60 + int(hms[1])
        elif raw.isdigit():
            total = int(raw)
    except (ValueError, IndexError):
        pass
    return total


def parse_opnsense_data(firmware: dict, status: dict) -> dict:
    fw_data = firmware if isinstance(firmware, dict) else {}
    version = fw_data.get("product_version", fw_data.get("version", "unknown"))
    st = status if isinstance(status, dict) else {}
    hostname = st.get("hostname", "unknown")
    uptime_s = 0
    cpu_pct = 0.0
    mem_pct = 0.0
    alerts = 0

    if "kernel" in st:
        uptime_raw = st.get("kernel", {}).get("uptime", "")
        uptime_s = _parse_uptime(uptime_raw)
    elif "uptime" in st:
        uptime_s = _parse_uptime(st["uptime"])

    if "cpu" in st:
        cpu_raw = st["cpu"]
        if isinstance(cpu_raw, (int, float)):
            cpu_pct = float(cpu_raw)
        elif isinstance(cpu_raw, str):
            cpu_pct = float(cpu_raw.rstrip("%")) if cpu_raw.rstrip("%").replace(".", "", 1).isdigit() else 0.0

    if "memory" in st:
        mem_raw = st["memory"]
        if isinstance(mem_raw, dict):
            used = mem_raw.get("used", 0)
            total = mem_raw.get("total", 0)
            if total:
                mem_pct = round(float(used) / float(total) * 100, 1)
        elif isinstance(mem_raw, (int, float)):
            mem_pct = float(mem_raw)

    if "alerts" in st:
        alerts_raw = st["alerts"]
        if isinstance(alerts_raw, (int, float)):
            alerts = int(alerts_raw)

    return {
        "fw_type": "opnsense", "version": version, "hostname": hostname,
        "cpu_pct": cpu_pct, "mem_pct": mem_pct, "uptime_s": uptime_s,
        "interfaces": [], "alerts": alerts,
    }


def parse_pfsense_data(info: dict) -> dict:
    data = info.get("data", info) if isinstance(info, dict) else {}
    hostname = data.get("hostname", data.get("name", "unknown"))
    version = data.get("version", {})
    if isinstance(version, dict):
        version = version.get("version", "unknown")
    elif not isinstance(version, str):
        version = str(version)

    uptime_s = _parse_uptime(data.get("uptime", ""))
    cpu_pct = 0.0
    cpu_raw = data.get("cpu_usage", data.get("cpu", None))
    if cpu_raw is not None:
        try:
            cpu_pct = float(cpu_raw)
        except (TypeError, ValueError):
            cpu_pct = 0.0

    mem_pct = 0.0
    mem_raw = data.get("mem_usage", data.get("memory", None))
    if mem_raw is not None:
        try:
            mem_pct = float(mem_raw)
        except (TypeError, ValueError):
            mem_pct = 0.0

    return {
        "fw_type": "pfsense", "version": version, "hostname": hostname,
        "cpu_pct": cpu_pct, "mem_pct": mem_pct, "uptime_s": uptime_s,
        "interfaces": [], "alerts": 0,
    }


# ── Integration Plugin ────────────────────────────────────────────────────────


class FirewallIntegration(BaseIntegration):
    name = "firewall"
    display_name = "Firewall"
    icon = "opnsense"
    description = "Monitor OPNsense or pfSense firewalls."

    config_fields = [
        ConfigField(key="host", label="Host URL", field_type="url",
                    placeholder="https://firewall.local"),
        ConfigField(key="fw_type", label="Firewall Type", field_type="select",
                    options=[{"value": "opnsense", "label": "OPNsense"},
                             {"value": "pfsense", "label": "pfSense"}],
                    default="opnsense"),
        ConfigField(key="api_key", label="API Key / Username", encrypted=False),
        ConfigField(key="api_secret", label="API Secret / Password",
                    field_type="password", encrypted=True),
        ConfigField(key="verify_ssl", label="Verify SSL", field_type="checkbox",
                    required=False, default=False),
    ]

    def _opnsense_api(self) -> OPNsenseAPI:
        return OPNsenseAPI(
            host=self.config["host"],
            api_key=self.config["api_key"],
            api_secret=self.config["api_secret"],
            verify_ssl=self.config.get("verify_ssl", False),
        )

    def _pfsense_api(self) -> PfsenseAPI:
        return PfsenseAPI(
            host=self.config["host"],
            username=self.config["api_key"],
            password=self.config["api_secret"],
            verify_ssl=self.config.get("verify_ssl", False),
        )

    async def collect(self) -> CollectorResult:
        try:
            fw_type = self.config.get("fw_type", "opnsense")
            if fw_type == "pfsense":
                raw = await self._pfsense_api().fetch_all()
                data = parse_pfsense_data(raw.get("sys_info", {}))
            else:
                raw = await self._opnsense_api().fetch_all()
                data = parse_opnsense_data(raw.get("firmware", {}), raw.get("status", {}))
            return CollectorResult(success=True, data=data)
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))

    async def health_check(self) -> bool:
        fw_type = self.config.get("fw_type", "opnsense")
        if fw_type == "pfsense":
            return await self._pfsense_api().health_check()
        return await self._opnsense_api().health_check()
