"""Pi-hole integration – DNS stats via Pi-hole API (v5 + v6 support)."""
from __future__ import annotations

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField


# ── API Client ────────────────────────────────────────────────────────────────


class PiholeAPI:
    def __init__(self, host: str, api_key: str | None = None, verify_ssl: bool = False):
        self.base = host.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl

    async def fetch_all(self) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10.0, follow_redirects=True) as client:
            # Try v6 first
            if self.api_key:
                try:
                    auth_resp = await client.post(
                        f"{self.base}/api/auth", json={"password": self.api_key})
                    if auth_resp.status_code == 200:
                        auth_data = auth_resp.json()
                        sid = (auth_data.get("session", {}) or {}).get("sid")
                        if sid:
                            headers = {"sid": sid}
                            stats_resp = await client.get(
                                f"{self.base}/api/stats/summary", headers=headers)
                            stats_resp.raise_for_status()
                            raw = stats_resp.json()

                            top_resp = await client.get(
                                f"{self.base}/api/stats/top_domains", headers=headers,
                                params={"blocked": "false", "count": 10})
                            top_blocked_resp = await client.get(
                                f"{self.base}/api/stats/top_domains", headers=headers,
                                params={"blocked": "true", "count": 10})

                            top_queries = []
                            top_blocked = []
                            if top_resp.status_code == 200:
                                domains = top_resp.json().get("domains", [])
                                top_queries = [{"domain": d.get("domain", ""), "count": d.get("count", 0)}
                                               for d in domains[:10]]
                            if top_blocked_resp.status_code == 200:
                                domains = top_blocked_resp.json().get("domains", [])
                                top_blocked = [{"domain": d.get("domain", ""), "count": d.get("count", 0)}
                                               for d in domains[:10]]

                            try:
                                await client.delete(f"{self.base}/api/auth", headers=headers)
                            except Exception:
                                pass

                            return parse_pihole_v6_data(raw, top_queries, top_blocked)
                except Exception:
                    pass

            # Fall back to v5
            params: dict = {"summaryRaw": ""}
            if self.api_key:
                params["auth"] = self.api_key

            resp = await client.get(f"{self.base}/admin/api.php", params=params)
            resp.raise_for_status()
            raw = resp.json()

            if not raw or "status" not in raw:
                raise ValueError(f"Unexpected Pi-hole v5 response: {raw}")

            top_queries = []
            top_blocked = []
            if self.api_key:
                tq_params = {"topItems": 10, "auth": self.api_key}
            else:
                tq_params = {"topItems": 10}
            try:
                tq_resp = await client.get(f"{self.base}/admin/api.php", params=tq_params)
                if tq_resp.status_code == 200:
                    tq_data = tq_resp.json()
                    tq_raw = tq_data.get("top_queries") or {}
                    tb_raw = tq_data.get("top_ads") or {}
                    top_queries = [{"domain": d, "count": c}
                                   for d, c in sorted(tq_raw.items(), key=lambda x: -x[1])][:10]
                    top_blocked = [{"domain": d, "count": c}
                                   for d, c in sorted(tb_raw.items(), key=lambda x: -x[1])][:10]
            except Exception:
                pass

            return parse_pihole_data(raw, top_queries, top_blocked)

    async def health_check(self) -> bool:
        try:
            await self.fetch_all()
            return True
        except Exception:
            return False


# ── Parsers ───────────────────────────────────────────────────────────────────


def parse_pihole_data(raw: dict, top_queries: list, top_blocked: list) -> dict:
    queries_today = int(raw.get("dns_queries_today", 0))
    blocked_today = int(raw.get("ads_blocked_today", 0))
    blocked_pct = float(raw.get("ads_percentage_today", 0.0))
    domains_blocked = int(raw.get("domains_being_blocked", 0))
    clients = int(raw.get("unique_clients", 0))
    status = str(raw.get("status", "unknown"))

    reply_types = {}
    for key, val in raw.items():
        if key.startswith("reply_"):
            reply_types[key[6:]] = val

    gravity = raw.get("gravity_last_updated", {})
    gravity_str = ""
    if isinstance(gravity, dict):
        relative = gravity.get("relative", {})
        if relative:
            days = relative.get("days", 0)
            hours = relative.get("hours", 0)
            mins = relative.get("minutes", 0)
            gravity_str = f"{days}d {hours}h {mins}m ago"
        elif gravity.get("absolute"):
            import datetime
            ts = gravity["absolute"]
            try:
                gravity_str = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
            except Exception:
                gravity_str = str(ts)

    return {
        "status": status, "queries_today": queries_today,
        "blocked_today": blocked_today, "blocked_pct": round(blocked_pct, 1),
        "domains_blocked": domains_blocked,
        "dns_queries_all_types": int(raw.get("dns_queries_all_types", 0)),
        "reply_types": reply_types, "top_queries": top_queries,
        "top_blocked": top_blocked, "clients": clients,
        "gravity_last_updated": gravity_str, "api_version": 5,
    }


def parse_pihole_v6_data(raw: dict, top_queries: list, top_blocked: list) -> dict:
    queries = raw.get("queries", {})
    gravity = raw.get("gravity", {})
    clients = raw.get("clients", {})

    queries_today = int(queries.get("total", 0))
    blocked_today = int(queries.get("blocked", 0))
    blocked_pct = float(queries.get("percent_blocked", 0.0))
    domains_blocked = int(gravity.get("domains_being_blocked", 0))
    unique_clients = int(clients.get("unique", 0))
    status = "enabled" if raw.get("blocking", {}).get("enabled", True) else "disabled"

    return {
        "status": status, "queries_today": queries_today,
        "blocked_today": blocked_today, "blocked_pct": round(blocked_pct, 1),
        "domains_blocked": domains_blocked,
        "dns_queries_all_types": queries_today,
        "reply_types": {}, "top_queries": top_queries,
        "top_blocked": top_blocked, "clients": unique_clients,
        "gravity_last_updated": "", "api_version": 6,
    }


# ── Integration Plugin ────────────────────────────────────────────────────────


class PiholeIntegration(BaseIntegration):
    name = "pihole"
    display_name = "Pi-hole"
    icon = "pihole"
    description = "Monitor Pi-hole DNS filtering (v5 + v6)."

    config_fields = [
        ConfigField(key="host", label="Host URL", field_type="url",
                    placeholder="http://pihole.local"),
        ConfigField(key="api_key", label="API Key / Password", field_type="password",
                    encrypted=True, required=False),
        ConfigField(key="verify_ssl", label="Verify SSL", field_type="checkbox",
                    required=False, default=False),
    ]

    def _api(self) -> PiholeAPI:
        return PiholeAPI(
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
