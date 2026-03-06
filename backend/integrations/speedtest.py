"""Speedtest integration – measures internet speed via speedtest-cli."""
from __future__ import annotations

import asyncio
import json
import subprocess

from integrations._base import BaseIntegration, CollectorResult, ConfigField


# ── Runner ────────────────────────────────────────────────────────────────────


async def run_speedtest(server_id: str | None = None) -> dict:
    cmd = ["speedtest-cli", "--json", "--secure"]
    if server_id:
        cmd += ["--server", str(server_id)]

    loop = asyncio.get_event_loop()

    def _run():
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(f"speedtest-cli failed: {result.stderr.strip()}")
        return json.loads(result.stdout)

    raw = await loop.run_in_executor(None, _run)

    return {
        "download_mbps": round(raw["download"] / 1_000_000, 2),
        "upload_mbps": round(raw["upload"] / 1_000_000, 2),
        "ping_ms": round(raw["ping"], 1),
        "server_name": f"{raw['server']['name']}, {raw['server']['country']}",
        "server_location": raw["server"].get("sponsor", ""),
        "isp": raw.get("client", {}).get("isp", ""),
        "timestamp": raw.get("timestamp", ""),
    }


async def check_speedtest_available() -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "speedtest-cli", "--version",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()
        return proc.returncode == 0
    except FileNotFoundError:
        return False


# ── Integration Plugin ────────────────────────────────────────────────────────


class SpeedtestIntegration(BaseIntegration):
    name = "speedtest"
    display_name = "Speedtest"
    icon = "speedtest"
    description = "Measure internet speed using speedtest-cli."

    config_fields = [
        ConfigField(key="server_id", label="Server ID (optional)",
                    placeholder="Leave empty for auto-select", required=False),
    ]

    async def collect(self) -> CollectorResult:
        try:
            data = await run_speedtest(self.config.get("server_id") or None)
            return CollectorResult(success=True, data=data)
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))

    async def health_check(self) -> bool:
        return await check_speedtest_available()
