"""Gitea integration – repository and user stats."""
from __future__ import annotations

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField


# ── API Client ────────────────────────────────────────────────────────────────


class GiteaAPI:
    def __init__(self, host: str, token: str | None = None, verify_ssl: bool = False):
        self.base = host.rstrip("/")
        self.token = token
        self.verify_ssl = verify_ssl

    def _headers(self) -> dict:
        if self.token:
            return {"Authorization": f"token {self.token}"}
        return {}

    async def fetch_all(self) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15) as client:
            version_resp = await client.get(
                f"{self.base}/api/v1/version", headers=self._headers())
            version_resp.raise_for_status()

            repos_resp = await client.get(
                f"{self.base}/api/v1/repos/search",
                params={"limit": 50, "page": 1}, headers=self._headers())
            repos_resp.raise_for_status()
            repos_body = repos_resp.json()
            repos = repos_body.get("data", repos_body) if isinstance(repos_body, dict) else repos_body

            users: list = []
            orgs: list = []
            try:
                users_resp = await client.get(
                    f"{self.base}/api/v1/admin/users",
                    params={"limit": 50}, headers=self._headers())
                if users_resp.status_code == 200:
                    users = users_resp.json()
            except Exception:
                pass
            try:
                orgs_resp = await client.get(
                    f"{self.base}/api/v1/admin/orgs",
                    params={"limit": 50}, headers=self._headers())
                if orgs_resp.status_code == 200:
                    orgs = orgs_resp.json()
            except Exception:
                pass

        return {
            "version_info": version_resp.json(),
            "repos": repos if isinstance(repos, list) else [],
            "users": users if isinstance(users, list) else [],
            "orgs": orgs if isinstance(orgs, list) else [],
        }

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=8) as client:
                resp = await client.get(f"{self.base}/api/v1/version", headers=self._headers())
                return resp.status_code == 200
        except Exception:
            return False


# ── Parser ────────────────────────────────────────────────────────────────────


def parse_gitea_data(version_info: dict, repos: list, users: list, orgs: list) -> dict:
    version = version_info.get("version", "unknown")
    repo_list = []
    public_count = 0
    private_count = 0

    for repo in repos:
        is_private = repo.get("private", False)
        if is_private:
            private_count += 1
        else:
            public_count += 1
        repo_list.append({
            "name": repo.get("name", ""),
            "full_name": repo.get("full_name", ""),
            "description": repo.get("description") or "",
            "stars": repo.get("stars_count", repo.get("stargazers_count", 0)),
            "forks": repo.get("forks_count", 0),
            "open_issues": repo.get("open_issues_count", 0),
            "updated_at": repo.get("updated", repo.get("updated_at", "")),
            "private": is_private,
        })

    repo_list.sort(key=lambda r: r["updated_at"] or "", reverse=True)

    return {
        "version": version, "repos_total": len(repos),
        "repos_public": public_count, "repos_private": private_count,
        "repos": repo_list, "users_total": len(users), "orgs_total": len(orgs),
    }


# ── Integration Plugin ────────────────────────────────────────────────────────


class GiteaIntegration(BaseIntegration):
    name = "gitea"
    display_name = "Gitea"
    icon = "gitea"
    description = "Monitor Gitea repositories and users."

    config_fields = [
        ConfigField(key="host", label="Host URL", field_type="url",
                    placeholder="https://gitea.local"),
        ConfigField(key="token", label="API Token", field_type="password",
                    encrypted=True, required=False),
        ConfigField(key="verify_ssl", label="Verify SSL", field_type="checkbox",
                    required=False, default=False),
    ]

    def _api(self) -> GiteaAPI:
        return GiteaAPI(
            host=self.config["host"],
            token=self.config.get("token"),
            verify_ssl=self.config.get("verify_ssl", False),
        )

    async def collect(self) -> CollectorResult:
        try:
            raw = await self._api().fetch_all()
            data = parse_gitea_data(
                raw["version_info"], raw["repos"], raw["users"], raw["orgs"])
            return CollectorResult(success=True, data=data)
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))

    async def health_check(self) -> bool:
        return await self._api().health_check()
