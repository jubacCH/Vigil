"""UPS/NUT integration – connects to Network UPS Tools daemon."""
from __future__ import annotations

import asyncio

from integrations._base import BaseIntegration, CollectorResult, ConfigField

_STATUS_LABELS = {
    "OL": "On Line", "OB": "On Battery", "LB": "Low Battery",
    "HB": "High Battery", "RB": "Replace Battery", "CHRG": "Charging",
    "DISCHRG": "Discharging", "BYPASS": "Bypass", "OFF": "Offline",
    "OVER": "Overloaded", "TRIM": "Trimming", "BOOST": "Boosting",
    "FSD": "Forced Shutdown",
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _safe_float(val: str | None) -> float | None:
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


def _safe_int(val: str | None) -> int | None:
    f = _safe_float(val)
    return int(f) if f is not None else None


def parse_nut_vars(lines: list[str]) -> dict:
    raw: dict[str, str] = {}
    for line in lines:
        parts = line.split(" ", 3)
        if len(parts) == 4 and parts[0] == "VAR":
            raw[parts[2]] = parts[3].strip('"')

    status_str = raw.get("ups.status", "")
    tokens = status_str.split()
    primary = tokens[0] if tokens else ""
    status_label = " + ".join(_STATUS_LABELS.get(t, t) for t in tokens) if tokens else "Unknown"
    on_battery = "OB" in tokens

    battery_pct = _safe_float(raw.get("battery.charge"))
    runtime_s = _safe_int(raw.get("battery.runtime"))
    load_pct = _safe_float(raw.get("ups.load"))
    input_v = _safe_float(raw.get("input.voltage"))
    output_v = _safe_float(raw.get("output.voltage"))
    battery_v = _safe_float(raw.get("battery.voltage"))
    temp = _safe_float(raw.get("battery.temperature") or raw.get("ups.temperature"))
    power_w = _safe_float(raw.get("ups.power") or raw.get("ups.realpower"))

    return {
        "status": primary, "status_label": status_label, "on_battery": on_battery,
        "battery_pct": battery_pct if battery_pct is not None else 0.0,
        "runtime_s": runtime_s if runtime_s is not None else 0,
        "load_pct": load_pct if load_pct is not None else 0.0,
        "input_voltage": input_v if input_v is not None else 0.0,
        "output_voltage": output_v if output_v is not None else 0.0,
        "battery_voltage": battery_v if battery_v is not None else 0.0,
        "temp": temp, "power_w": power_w,
        "manufacturer": raw.get("ups.mfr", ""), "model": raw.get("ups.model", ""),
        "serial": raw.get("ups.serial", ""), "firmware": raw.get("ups.firmware", ""),
        "raw": raw,
    }


# ── Client ────────────────────────────────────────────────────────────────────


class NutClient:
    def __init__(self, host: str, port: int = 3493, ups_name: str = "ups",
                 username: str | None = None, password: str | None = None):
        self.host = host
        self.port = port
        self.ups_name = ups_name
        self.username = username
        self.password = password

    async def fetch_all(self) -> dict:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), timeout=10.0)
        try:
            async def send(cmd: str) -> str:
                writer.write((cmd + "\n").encode())
                await writer.drain()
                return (await reader.readline()).decode().strip()

            if self.username:
                resp = await send(f"USERNAME {self.username}")
                if resp.startswith("ERR"):
                    raise ValueError(f"NUT auth error (username): {resp}")
                resp = await send(f"PASSWORD {self.password or ''}")
                if resp.startswith("ERR"):
                    raise ValueError(f"NUT auth error (password): {resp}")

            writer.write(f"LIST VAR {self.ups_name}\n".encode())
            await writer.drain()

            lines: list[str] = []
            while True:
                line = (await asyncio.wait_for(reader.readline(), timeout=10.0)).decode().strip()
                if not line:
                    continue
                if line.startswith("END LIST VAR"):
                    break
                if line.startswith("ERR"):
                    raise ValueError(f"NUT error: {line}")
                lines.append(line)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        return parse_nut_vars(lines)

    async def health_check(self) -> bool:
        try:
            await self.fetch_all()
            return True
        except Exception:
            return False


# ── Integration Plugin ────────────────────────────────────────────────────────


class NutIntegration(BaseIntegration):
    name = "ups"
    display_name = "UPS (NUT)"
    icon = "apc"
    icon_svg = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 4h-2V2h-4v2H8C6.9 4 6 4.9 6 6v14c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 16H8V6h8v14zm-4-4c.55 0 1-.45 1-1v-3c0-.55-.45-1-1-1s-1 .45-1 1v3c0 .55.45 1 1 1z"/></svg>'
    description = "Monitor UPS devices via Network UPS Tools."

    config_fields = [
        ConfigField(key="host", label="NUT Host", placeholder="localhost"),
        ConfigField(key="port", label="Port", field_type="number",
                    placeholder="3493", required=False, default=3493),
        ConfigField(key="ups_name", label="UPS Name", placeholder="ups",
                    required=False, default="ups"),
        ConfigField(key="username", label="Username", required=False),
        ConfigField(key="password", label="Password", field_type="password",
                    encrypted=True, required=False),
    ]

    def _client(self) -> NutClient:
        return NutClient(
            host=self.config["host"],
            port=int(self.config.get("port", 3493) or 3493),
            ups_name=self.config.get("ups_name", "ups") or "ups",
            username=self.config.get("username"),
            password=self.config.get("password"),
        )

    async def collect(self) -> CollectorResult:
        try:
            data = await self._client().fetch_all()
            return CollectorResult(success=True, data=data)
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))

    async def health_check(self) -> bool:
        return await self._client().health_check()
