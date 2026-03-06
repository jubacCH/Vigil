"""Home Assistant integration – entity states and config."""
from __future__ import annotations

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField

MONITORED_DOMAINS = {
    "sensor", "binary_sensor", "switch", "light", "person",
    "automation", "input_boolean", "climate", "cover", "media_player",
}


# ── API Client ────────────────────────────────────────────────────────────────


class HassAPI:
    def __init__(self, host: str, token: str, verify_ssl: bool = False):
        self.base = host.rstrip("/")
        self.token = token
        self.verify_ssl = verify_ssl

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    async def fetch_all(self) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15) as client:
            config_resp = await client.get(f"{self.base}/api/config", headers=self._headers())
            config_resp.raise_for_status()
            states_resp = await client.get(f"{self.base}/api/states", headers=self._headers())
            states_resp.raise_for_status()
        return {"config": config_resp.json(), "states": states_resp.json()}

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=8) as client:
                resp = await client.get(f"{self.base}/api/", headers=self._headers())
                return resp.status_code == 200
        except Exception:
            return False


# ── Parser ────────────────────────────────────────────────────────────────────


def parse_hass_data(config: dict, states: list) -> dict:
    version = config.get("version", "unknown")
    location_name = config.get("location_name", "Home")
    timezone = config.get("time_zone", config.get("timezone", "UTC"))
    components = len(config.get("components", []))

    by_domain: dict[str, int] = {}
    automations: list[dict] = []
    persons: list[dict] = []

    for entity in states:
        entity_id: str = entity.get("entity_id", "")
        domain = entity_id.split(".")[0] if "." in entity_id else ""
        if domain in MONITORED_DOMAINS:
            by_domain[domain] = by_domain.get(domain, 0) + 1
        if domain == "automation":
            attrs = entity.get("attributes", {})
            automations.append({
                "entity_id": entity_id,
                "name": attrs.get("friendly_name", entity_id),
                "state": entity.get("state", "unknown"),
                "last_triggered": attrs.get("last_triggered"),
            })
        if domain == "person":
            attrs = entity.get("attributes", {})
            persons.append({
                "name": attrs.get("friendly_name", entity_id),
                "state": entity.get("state", "unknown"),
            })

    return {
        "version": version, "location_name": location_name,
        "timezone": timezone, "components": components,
        "entities": {"total": sum(by_domain.values()), "by_domain": by_domain},
        "automations": sorted(automations, key=lambda a: a["name"]),
        "persons": persons,
    }


# ── Integration Plugin ────────────────────────────────────────────────────────


class HomeAssistantIntegration(BaseIntegration):
    name = "hass"
    display_name = "Home Assistant"
    icon = "homeassistant"
    description = "Monitor Home Assistant entities and automations."

    config_fields = [
        ConfigField(key="host", label="Host URL", field_type="url",
                    placeholder="http://homeassistant.local:8123"),
        ConfigField(key="token", label="Long-Lived Access Token",
                    field_type="password", encrypted=True),
        ConfigField(key="verify_ssl", label="Verify SSL", field_type="checkbox",
                    required=False, default=False),
    ]

    def _api(self) -> HassAPI:
        return HassAPI(
            host=self.config["host"],
            token=self.config["token"],
            verify_ssl=self.config.get("verify_ssl", False),
        )

    async def collect(self) -> CollectorResult:
        try:
            raw = await self._api().fetch_all()
            data = parse_hass_data(raw["config"], raw["states"])
            return CollectorResult(success=True, data=data)
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))

    async def health_check(self) -> bool:
        return await self._api().health_check()
