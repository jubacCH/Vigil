"""UniFi Network integration – device health, client stats, WAN metrics."""
from __future__ import annotations

import httpx

from integrations._base import BaseIntegration, CollectorResult, ConfigField


# ── API Client ────────────────────────────────────────────────────────────────


class UnifiAPI:
    """Async client for the UniFi Controller REST API."""

    def __init__(self, host: str, username: str, password: str,
                 site: str = "default", verify_ssl: bool = False, is_udm: bool = False):
        self.base = host.rstrip("/")
        self.username = username
        self.password = password
        self.site = site
        self.verify_ssl = verify_ssl
        self.is_udm = is_udm

    @property
    def _login_url(self) -> str:
        return f"{self.base}/api/auth/login" if self.is_udm else f"{self.base}/api/login"

    @property
    def _api_base(self) -> str:
        if self.is_udm:
            return f"{self.base}/proxy/network/api/s/{self.site}"
        return f"{self.base}/api/s/{self.site}"

    async def fetch_all(self) -> dict:
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15.0, follow_redirects=True) as client:
            resp = await client.post(
                self._login_url,
                json={"username": self.username, "password": self.password},
            )
            resp.raise_for_status()
            csrf = resp.headers.get("x-csrf-token", "")
            hdrs = {"x-csrf-token": csrf} if csrf else {}

            base = self._api_base
            devices_r = await client.get(f"{base}/stat/device", headers=hdrs)
            clients_r = await client.get(f"{base}/stat/sta", headers=hdrs)
            health_r = await client.get(f"{base}/stat/health", headers=hdrs)
            events_r = await client.get(f"{base}/stat/event", headers=hdrs,
                                        params={"_limit": 200, "_sort": "-time"})

            devices_r.raise_for_status()
            clients_r.raise_for_status()
            health_r.raise_for_status()
            raw_events = events_r.json().get("data", []) if events_r.is_success else []

            return parse_unifi_data(
                devices_r.json().get("data", []),
                clients_r.json().get("data", []),
                health_r.json().get("data", []),
                raw_events,
            )

    async def health_check(self) -> bool:
        try:
            await self.fetch_all()
            return True
        except Exception:
            return False


# ── Parser ────────────────────────────────────────────────────────────────────


_DEVICE_TYPE_LABELS = {
    "uap": "Access Point", "usw": "Switch", "ugw": "Gateway",
    "usg": "Security GW", "udm": "Dream Machine", "udmpro": "Dream Machine Pro",
    "uxg": "Express GW",
}

_EVENT_SUBSYSTEM_LABELS = {
    "wlan": "WiFi", "lan": "LAN", "wan": "WAN", "gw": "Gateway", "vpn": "VPN",
}

_EVENT_KEY_LABELS = {
    "EVT_WU_Connected": "Client connected", "EVT_WU_Disconnected": "Client disconnected",
    "EVT_WU_Roam": "Client roamed", "EVT_LU_Connected": "Wired client connected",
    "EVT_LU_Disconnected": "Wired client disconnected", "EVT_AP_Lost_Contact": "AP lost contact",
    "EVT_AP_Adopted": "AP adopted", "EVT_AP_Connected": "AP connected",
    "EVT_AP_Deleted": "AP removed", "EVT_AP_Restarted": "AP restarted",
    "EVT_AP_Upgraded": "AP firmware upgraded", "EVT_SW_Lost_Contact": "Switch lost contact",
    "EVT_SW_Connected": "Switch connected", "EVT_SW_Adopted": "Switch adopted",
    "EVT_GW_Lost_Contact": "Gateway lost contact", "EVT_GW_Connected": "Gateway connected",
    "EVT_GW_WAN_Transition": "WAN status changed", "EVT_GW_Failover": "WAN failover",
    "EVT_AD_Login": "Admin login", "EVT_AD_Logout": "Admin logout",
}


def parse_unifi_data(raw_devices: list, raw_clients: list, raw_health: list,
                     raw_events: list | None = None) -> dict:
    devices = []
    for d in raw_devices:
        sys_stats = d.get("system-stats", {})
        cpu_pct = round(float(sys_stats.get("cpu", 0)), 1)
        mem_pct = round(float(sys_stats.get("mem", 0)), 1)
        clients_wifi = sum(r.get("num_sta", 0) for r in d.get("radio_table_stats", []))
        clients_wired = d.get("num_sta", 0) - clients_wifi if d.get("num_sta") else 0
        dtype = d.get("type", "")

        port_table = []
        has_ports = dtype in ("usw", "ugw", "usg", "udm", "udmpro", "uxg")
        if has_ports:
            for p in d.get("port_table", []):
                speed = p.get("speed") or 0
                if speed >= 10000:
                    speed_label = "10G"
                elif speed >= 2500:
                    speed_label = "2.5G"
                elif speed >= 1000:
                    speed_label = "1G"
                elif speed >= 100:
                    speed_label = "100M"
                elif speed > 0:
                    speed_label = f"{speed}M"
                else:
                    speed_label = ""
                port_table.append({
                    "idx": p.get("port_idx", 0), "name": p.get("name", f"Port {p.get('port_idx', '?')}"),
                    "enable": p.get("enable", True), "up": p.get("up", False),
                    "speed": speed, "speed_label": speed_label,
                    "is_uplink": p.get("is_uplink", False),
                    "poe_enable": p.get("poe_enable", False),
                    "poe_power": round(float(p.get("poe_power") or 0), 1),
                    "rx_bytes_r": p.get("rx_bytes-r", 0) or 0, "tx_bytes_r": p.get("tx_bytes-r", 0) or 0,
                    "rx_bytes": p.get("rx_bytes", 0) or 0, "tx_bytes": p.get("tx_bytes", 0) or 0,
                    "satisfaction": p.get("satisfaction", -1), "op_mode": p.get("op_mode", ""),
                })
            port_table.sort(key=lambda p: p["idx"])

        devices.append({
            "mac": d.get("mac", ""), "name": d.get("name") or d.get("hostname") or d.get("mac", ""),
            "type": dtype, "type_label": _DEVICE_TYPE_LABELS.get(dtype, dtype.upper()),
            "model": d.get("model", ""), "state": d.get("state", 0),
            "ip": d.get("ip", ""), "uptime": d.get("uptime", 0),
            "cpu_pct": cpu_pct, "mem_pct": mem_pct,
            "clients_wifi": max(clients_wifi, 0), "clients_wired": max(clients_wired, 0),
            "rx_bytes": d.get("rx_bytes", 0) or 0, "tx_bytes": d.get("tx_bytes", 0) or 0,
            "rx_bytes_r": d.get("uplink", {}).get("rx_bytes-r", 0) or 0,
            "tx_bytes_r": d.get("uplink", {}).get("tx_bytes-r", 0) or 0,
            "satisfaction": d.get("satisfaction", -1), "version": d.get("version", ""),
            "port_table": port_table, "has_ports": has_ports and len(port_table) > 0,
        })

    ap_names = {d["mac"]: d["name"] for d in devices}
    clients = []
    for c in raw_clients:
        is_wireless = "ap_mac" in c
        ap_mac = c.get("ap_mac", "")
        clients.append({
            "mac": c.get("mac", ""), "hostname": c.get("hostname") or c.get("name") or c.get("mac", ""),
            "ip": c.get("ip", ""), "ap_mac": ap_mac, "ap_name": ap_names.get(ap_mac, ap_mac),
            "signal": c.get("signal", 0), "rssi": c.get("rssi", 0),
            "rx_bytes": c.get("rx_bytes", 0) or 0, "tx_bytes": c.get("tx_bytes", 0) or 0,
            "rx_bytes_r": c.get("rx_bytes-r", 0) or 0, "tx_bytes_r": c.get("tx_bytes-r", 0) or 0,
            "uptime": c.get("uptime", 0), "is_wireless": is_wireless,
            "vlan": c.get("vlan", 1) or 1, "ssid": c.get("essid", ""),
            "satisfaction": c.get("satisfaction", -1), "channel": c.get("channel", 0),
        })

    wan, lan, wlan = {}, {}, {}
    for h in raw_health:
        sub = h.get("subsystem", "")
        if sub == "wan":
            wan = {"status": h.get("status", "unknown"), "ip": h.get("wan_ip", ""),
                   "latency": h.get("latency_average", 0),
                   "rx_bytes_r": h.get("rx_bytes-r", 0) or 0, "tx_bytes_r": h.get("tx_bytes-r", 0) or 0}
        elif sub == "lan":
            lan = {"status": h.get("status", "unknown"), "num_adopted": h.get("num_adopted", 0),
                   "num_disconnected": h.get("num_disconnected", 0), "num_user": h.get("num_user", 0),
                   "rx_bytes_r": h.get("rx_bytes-r", 0) or 0, "tx_bytes_r": h.get("tx_bytes-r", 0) or 0}
        elif sub == "wlan":
            wlan = {"status": h.get("status", "unknown"), "num_adopted": h.get("num_adopted", 0),
                    "num_disconnected": h.get("num_disconnected", 0), "num_user": h.get("num_user", 0),
                    "satisfaction": h.get("satisfaction", -1),
                    "rx_bytes_r": h.get("rx_bytes-r", 0) or 0, "tx_bytes_r": h.get("tx_bytes-r", 0) or 0}

    events = []
    for e in (raw_events or [])[:200]:
        key = e.get("key", "")
        sub = e.get("subsystem", "")
        events.append({
            "datetime": e.get("datetime", ""), "msg": e.get("msg", ""),
            "key": key, "key_label": _EVENT_KEY_LABELS.get(key, key.replace("EVT_", "").replace("_", " ").title()),
            "subsystem": sub, "sub_label": _EVENT_SUBSYSTEM_LABELS.get(sub, sub.upper() or "System"),
            "ap": e.get("ap_name") or e.get("ap", ""),
            "hostname": e.get("hostname", ""), "ssid": e.get("ssid", ""),
        })

    devices_online = sum(1 for d in devices if d["state"] == 1)
    clients_wifi = sum(1 for c in clients if c["is_wireless"])
    clients_wired = len(clients) - clients_wifi

    return {
        "devices": devices, "clients": clients, "events": events,
        "wan": wan, "lan": lan, "wlan": wlan,
        "totals": {
            "devices": len(devices), "devices_online": devices_online,
            "clients_total": len(clients), "clients_wifi": clients_wifi,
            "clients_wired": clients_wired,
        },
    }


# ── Host Import ───────────────────────────────────────────────────────────────


async def import_unifi_devices(ctrl_name: str, data: dict, db) -> dict:
    from models.ping import PingHost
    from sqlalchemy import select

    existing_q = await db.execute(select(PingHost))
    existing_all: list[PingHost] = existing_q.scalars().all()
    by_ip = {h.hostname: h for h in existing_all if h.hostname}
    by_mac = {h.mac_address.lower(): h for h in existing_all if h.mac_address}

    added = merged = skipped = 0
    dirty = False

    for d in data.get("devices", []):
        ip = (d.get("ip") or "").strip()
        mac = (d.get("mac") or "").strip().lower()
        name = (d.get("name") or mac or "").strip()
        if not ip:
            skipped += 1
            continue

        existing = by_ip.get(ip) or by_mac.get(mac)
        if existing:
            changed = False
            if existing.source == "manual":
                existing.source = "unifi"
                existing.source_detail = ctrl_name
                changed = True
            if mac and not existing.mac_address:
                existing.mac_address = mac
                changed = True
            if changed:
                dirty = True
            merged += 1
        else:
            new_host = PingHost(
                name=name, hostname=ip, check_type="icmp",
                enabled=d.get("state", 0) == 1, source="unifi",
                source_detail=ctrl_name, mac_address=mac or None,
            )
            db.add(new_host)
            by_ip[ip] = new_host  # type: ignore[assignment]
            if mac:
                by_mac[mac] = new_host  # type: ignore[assignment]
            added += 1
            dirty = True

    if dirty:
        await db.commit()

    return {"added": added, "merged": merged, "skipped": skipped}


# ── Integration Plugin ────────────────────────────────────────────────────────


class UnifiIntegration(BaseIntegration):
    name = "unifi"
    display_name = "UniFi Network"
    icon = "ubiquiti"
    description = "Monitor UniFi network devices, clients, and WAN health."

    config_fields = [
        ConfigField(key="host", label="Controller URL", field_type="url",
                    placeholder="https://unifi.local:8443"),
        ConfigField(key="username", label="Username", placeholder="admin"),
        ConfigField(key="password", label="Password", field_type="password", encrypted=True),
        ConfigField(key="site", label="Site", placeholder="default", required=False, default="default"),
        ConfigField(key="is_udm", label="UniFi OS (UDM/UDR)", field_type="checkbox",
                    required=False, default=False),
        ConfigField(key="verify_ssl", label="Verify SSL", field_type="checkbox",
                    required=False, default=False),
    ]

    def _api(self) -> UnifiAPI:
        return UnifiAPI(
            host=self.config["host"],
            username=self.config["username"],
            password=self.config["password"],
            site=self.config.get("site", "default") or "default",
            verify_ssl=self.config.get("verify_ssl", False),
            is_udm=self.config.get("is_udm", False),
        )

    async def collect(self) -> CollectorResult:
        try:
            data = await self._api().fetch_all()
            return CollectorResult(success=True, data=data)
        except Exception as exc:
            return CollectorResult(success=False, error=str(exc))

    async def health_check(self) -> bool:
        return await self._api().health_check()
