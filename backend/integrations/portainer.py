"""Portainer integration – container status from all environments."""
from __future__ import annotations

import asyncio

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField


# ── API Client ────────────────────────────────────────────────────────────────


class PortainerAPI:
    def __init__(self, host: str, api_key: str | None = None, verify_ssl: bool = False):
        self.base = host.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl

    def _headers(self) -> dict:
        if self.api_key:
            return {"X-API-Key": self.api_key}
        return {}

    async def _fetch_containers(self, client: httpx.AsyncClient, endpoint_id: int) -> list:
        try:
            resp = await client.get(
                f"{self.base}/api/endpoints/{endpoint_id}/docker/containers/json",
                headers=self._headers(), params={"all": "true"})
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return []

    async def fetch_all(self) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(f"{self.base}/api/endpoints", headers=self._headers())
            resp.raise_for_status()
            raw_endpoints: list = resp.json()

            raw_containers: dict[int, list] = {}
            tasks = []
            for ep in raw_endpoints:
                ep_id = ep.get("Id")
                if ep_id is not None:
                    tasks.append(self._fetch_containers(client, ep_id))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for ep, result in zip(raw_endpoints, results):
                ep_id = ep.get("Id")
                raw_containers[ep_id] = result if not isinstance(result, Exception) else []

        return parse_portainer_data(raw_endpoints, raw_containers)

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(f"{self.base}/api/endpoints", headers=self._headers())
                return resp.status_code == 200
        except Exception:
            return False


# ── Parser ────────────────────────────────────────────────────────────────────


def parse_portainer_data(raw_endpoints: list, raw_containers: dict) -> dict:
    environments = []
    totals_containers = 0
    totals_running = 0
    totals_stopped = 0

    for ep in raw_endpoints:
        ep_id = ep.get("Id")
        ep_name = ep.get("Name", f"Environment {ep_id}")
        ep_status = ep.get("Status", 2)
        healthy = ep_status == 1

        containers_raw = raw_containers.get(ep_id, [])
        containers = []
        running = 0
        stopped = 0

        for c in containers_raw:
            names = c.get("Names", [])
            name = names[0].lstrip("/") if names else c.get("Id", "")[:12]
            state = c.get("State", "unknown")
            is_running = state == "running"
            if is_running:
                running += 1
            else:
                stopped += 1
            containers.append({
                "id": c.get("Id", "")[:12], "name": name, "image": c.get("Image", ""),
                "status": c.get("Status", ""), "state": state,
                "running": is_running, "created": c.get("Created", 0),
            })

        containers.sort(key=lambda x: (not x["running"], x["name"].lower()))
        total = len(containers)
        totals_containers += total
        totals_running += running
        totals_stopped += stopped

        environments.append({
            "id": ep_id, "name": ep_name, "status": ep_status, "healthy": healthy,
            "containers_total": total, "containers_running": running,
            "containers_stopped": stopped, "containers": containers,
        })

    return {
        "environments": environments,
        "totals": {
            "environments": len(environments), "containers": totals_containers,
            "running": totals_running, "stopped": totals_stopped,
        },
    }


# ── Integration Plugin ────────────────────────────────────────────────────────


class PortainerIntegration(BaseIntegration):
    name = "portainer"
    display_name = "Portainer"
    icon = "portainer"
    description = "Monitor Docker containers via Portainer."

    config_fields = [
        ConfigField(key="host", label="Host URL", field_type="url",
                    placeholder="https://portainer.local:9443"),
        ConfigField(key="api_key", label="API Key", field_type="password", encrypted=True),
        ConfigField(key="verify_ssl", label="Verify SSL", field_type="checkbox",
                    required=False, default=False),
    ]

    def _api(self) -> PortainerAPI:
        return PortainerAPI(
            host=self.config["host"],
            api_key=self.config.get("api_key"),
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
