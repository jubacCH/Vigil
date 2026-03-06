"""Proxmox VE integration – cluster health, node metrics, VM/LXC status."""
from __future__ import annotations

import asyncio
import re

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField


# ── API Client ────────────────────────────────────────────────────────────────


class ProxmoxAPI:
    """Thin async client for the Proxmox REST API."""

    def __init__(self, host: str, token_id: str, token_secret: str, verify_ssl: bool = False):
        self.base = host.rstrip("/")
        self._headers = {"Authorization": f"PVEAPIToken={token_id}={token_secret}"}
        self._verify_ssl = verify_ssl

    async def get(self, path: str) -> list | dict:
        url = f"{self.base}/api2/json{path}"
        async with httpx.AsyncClient(verify=self._verify_ssl, timeout=10.0) as client:
            resp = await client.get(url, headers=self._headers)
            resp.raise_for_status()
            return resp.json().get("data", [])

    async def cluster_status(self) -> list[dict]:
        return await self.get("/cluster/status")

    async def cluster_resources(self) -> list[dict]:
        return await self.get("/cluster/resources")

    async def vm_config(self, node: str, vmid: int) -> dict:
        try:
            return await self.get(f"/nodes/{node}/qemu/{vmid}/config")
        except Exception:
            return {}

    async def lxc_config(self, node: str, ctid: int) -> dict:
        try:
            return await self.get(f"/nodes/{node}/lxc/{ctid}/config")
        except Exception:
            return {}

    async def fetch_guest_macs(self, guests: list[dict]) -> dict[int, str]:
        _mac_re = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", re.I)

        async def _one(g):
            vmid = g.get("id") or g.get("vmid")
            node = g.get("node", "")
            gtype = g.get("type", "VM")
            try:
                cfg = await (self.vm_config(node, vmid) if gtype == "VM"
                             else self.lxc_config(node, vmid))
                for key in sorted(cfg.keys()):
                    if not key.startswith("net"):
                        continue
                    val = str(cfg[key])
                    m = _mac_re.search(val)
                    if m:
                        return vmid, m.group(1).upper()
            except Exception:
                pass
            return vmid, None

        results = await asyncio.gather(*[_one(g) for g in guests])
        return {vmid: mac for vmid, mac in results if mac}

    async def health_check(self) -> bool:
        try:
            await self.cluster_status()
            return True
        except Exception:
            return False


# ── Parser ────────────────────────────────────────────────────────────────────


def parse_cluster_data(resources: list[dict], cluster_status: list[dict]) -> dict:
    quorum_ok = True
    cluster_name = "Proxmox Cluster"
    for item in cluster_status:
        if item.get("type") == "cluster":
            quorum_ok = bool(item.get("quorate", 1))
            cluster_name = item.get("name", cluster_name)

    nodes = []
    vms = []
    containers = []

    for r in resources:
        rtype = r.get("type")

        if rtype == "node":
            cpu_pct = round((r.get("cpu") or 0) * 100, 1)
            mem_used = r.get("mem") or 0
            mem_total = r.get("maxmem") or 1
            mem_pct = round(mem_used / mem_total * 100, 1)
            disk_used = r.get("disk") or 0
            disk_total = r.get("maxdisk") or 1
            uptime_s = r.get("uptime") or 0
            nodes.append({
                "name": r.get("node", r.get("name", "?")),
                "status": r.get("status", "unknown"),
                "online": r.get("status") == "online",
                "cpu_pct": cpu_pct,
                "mem_pct": mem_pct,
                "mem_used_gb": round(mem_used / 1024**3, 1),
                "mem_total_gb": round(mem_total / 1024**3, 1),
                "disk_used_gb": round(disk_used / 1024**3, 1),
                "disk_total_gb": round(disk_total / 1024**3, 1),
                "disk_pct": round(disk_used / disk_total * 100, 1) if disk_total else 0,
                "netin": r.get("netin") or 0,
                "netout": r.get("netout") or 0,
                "uptime_h": round(uptime_s / 3600, 1),
            })

        elif rtype == "qemu":
            cpu_pct = round((r.get("cpu") or 0) * 100, 1)
            mem_used = r.get("mem") or 0
            mem_total = r.get("maxmem") or 1
            disk_used = r.get("disk") or 0
            disk_total = r.get("maxdisk") or 1
            vms.append({
                "id": r.get("vmid"),
                "name": r.get("name", f"vm-{r.get('vmid')}"),
                "node": r.get("node", "?"),
                "status": r.get("status", "unknown"),
                "running": r.get("status") == "running",
                "cpu_pct": cpu_pct,
                "mem_used_gb": round(mem_used / 1024**3, 2),
                "mem_total_gb": round(mem_total / 1024**3, 2),
                "disk_used_gb": round(disk_used / 1024**3, 2),
                "disk_total_gb": round(disk_total / 1024**3, 2),
                "disk_pct": round(disk_used / disk_total * 100, 1) if disk_total else 0,
                "netin": r.get("netin") or 0,
                "netout": r.get("netout") or 0,
                "diskread": r.get("diskread") or 0,
                "diskwrite": r.get("diskwrite") or 0,
                "uptime_h": round((r.get("uptime") or 0) / 3600, 1),
                "type": "VM",
            })

        elif rtype == "lxc":
            cpu_pct = round((r.get("cpu") or 0) * 100, 1)
            mem_used = r.get("mem") or 0
            mem_total = r.get("maxmem") or 1
            disk_used = r.get("disk") or 0
            disk_total = r.get("maxdisk") or 1
            containers.append({
                "id": r.get("vmid"),
                "name": r.get("name", f"ct-{r.get('vmid')}"),
                "node": r.get("node", "?"),
                "status": r.get("status", "unknown"),
                "running": r.get("status") == "running",
                "cpu_pct": cpu_pct,
                "mem_used_gb": round(mem_used / 1024**3, 2),
                "mem_total_gb": round(mem_total / 1024**3, 2),
                "disk_used_gb": round(disk_used / 1024**3, 2),
                "disk_total_gb": round(disk_total / 1024**3, 2),
                "disk_pct": round(disk_used / disk_total * 100, 1) if disk_total else 0,
                "netin": r.get("netin") or 0,
                "netout": r.get("netout") or 0,
                "diskread": r.get("diskread") or 0,
                "diskwrite": r.get("diskwrite") or 0,
                "uptime_h": round((r.get("uptime") or 0) / 3600, 1),
                "type": "LXC",
            })

    nodes.sort(key=lambda n: n["name"])
    vms.sort(key=lambda v: (v["node"], v["name"]))
    containers.sort(key=lambda c: (c["node"], c["name"]))

    online_nodes = [n for n in nodes if n["online"]]
    cpu_used = sum(n["cpu_pct"] for n in online_nodes)
    mem_used_gb = sum(n["mem_used_gb"] for n in online_nodes)
    mem_total_gb = sum(n["mem_total_gb"] for n in online_nodes)

    totals = {
        "nodes_total": len(nodes),
        "nodes_online": len(online_nodes),
        "vms_total": len(vms),
        "vms_running": sum(1 for v in vms if v["running"]),
        "lxc_total": len(containers),
        "lxc_running": sum(1 for c in containers if c["running"]),
        "cpu_avg_pct": round(cpu_used / len(online_nodes), 1) if online_nodes else 0,
        "mem_used_gb": round(mem_used_gb, 1),
        "mem_total_gb": round(mem_total_gb, 1),
        "mem_pct": round(mem_used_gb / mem_total_gb * 100, 1) if mem_total_gb else 0,
    }

    return {
        "quorum_ok": quorum_ok,
        "cluster_name": cluster_name,
        "nodes": nodes,
        "vms": vms,
        "containers": containers,
        "totals": totals,
    }


# ── Host Import ───────────────────────────────────────────────────────────────


async def import_proxmox_hosts(cluster_name: str, data: dict, db) -> dict:
    from models.ping import PingHost
    from sqlalchemy import select

    existing_q = await db.execute(select(PingHost))
    existing: dict[str, PingHost] = {h.hostname: h for h in existing_q.scalars().all()}

    guests = data.get("vms", []) + data.get("containers", [])
    added = merged = skipped = 0
    dirty = False

    for g in guests:
        hostname = (g.get("name") or "").strip()
        if not hostname:
            skipped += 1
            continue

        if hostname in existing:
            host = existing[hostname]
            changed = False
            if host.source == "manual":
                host.source = "proxmox"
                host.source_detail = cluster_name
                changed = True
            if changed:
                dirty = True
            merged += 1
        else:
            db.add(PingHost(
                name=g["name"],
                hostname=hostname,
                check_type="icmp",
                enabled=g.get("running", False),
                source="proxmox",
                source_detail=cluster_name,
            ))
            existing[hostname] = True  # type: ignore[assignment]
            added += 1
            dirty = True

    if dirty:
        await db.commit()

    return {"added": added, "merged": merged, "skipped": skipped}


# ── Integration Plugin ────────────────────────────────────────────────────────


class ProxmoxIntegration(BaseIntegration):
    name = "proxmox"
    display_name = "Proxmox VE"
    icon = "proxmox"
    description = "Monitor Proxmox VE clusters via the REST API."

    config_fields = [
        ConfigField(key="host", label="Host URL", field_type="url",
                    placeholder="https://proxmox.local:8006"),
        ConfigField(key="token_id", label="Token ID",
                    placeholder="user@realm!tokenid"),
        ConfigField(key="token_secret", label="Token Secret",
                    field_type="password", encrypted=True),
        ConfigField(key="verify_ssl", label="Verify SSL",
                    field_type="checkbox", required=False, default=False),
    ]

    def _api(self) -> ProxmoxAPI:
        return ProxmoxAPI(
            host=self.config["host"],
            token_id=self.config["token_id"],
            token_secret=self.config["token_secret"],
            verify_ssl=self.config.get("verify_ssl", False),
        )

    async def collect(self) -> CollectorResult:
        try:
            api = self._api()
            resources = await api.cluster_resources()
            status = await api.cluster_status()
            data = parse_cluster_data(resources, status)
            return CollectorResult(success=True, data=data)
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))

    async def health_check(self) -> bool:
        return await self._api().health_check()
