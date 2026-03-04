# B8MON – Homelab Monitor

A self-hosted homelab monitoring dashboard built with **FastAPI**, **SQLAlchemy (async/aiosqlite)**, **Jinja2** templates and **Tailwind CSS**.

---

## Features

| Feature | Details |
|---|---|
| **Host monitoring** | ICMP Ping, HTTP/HTTPS, TCP — configurable per host |
| **30-day heatmap** | Visual uptime history per host |
| **SLA tracking** | Uptime % for 24h / 7d / 30d |
| **Maintenance mode** | Pauses checks, hides host from alarms |
| **SSL expiry** | Badge + alert when certificate expires in <30 days |
| **Latency thresholds** | Per-host or global alarm when latency exceeds limit |
| **15 integrations** | See table below |
| **Integration health grid** | Dashboard shows status of all configured integrations |
| **Global alerts page** | `/alerts` — offline hosts, integration errors, UPS on battery, SSL expiry |
| **Anomaly detection** | Proxmox VM CPU/RAM spike detection (statistical + threshold) |
| **VM history charts** | 24h CPU & RAM chart per VM on Proxmox detail page |
| **Sparklines** | 2h latency sparklines in dashboard host cards |
| **Mobile navigation** | Responsive sidebar with hamburger menu |
| **Data retention** | Configurable per integration type |

---

## Integrations

| Integration | What is monitored |
|---|---|
| **Proxmox** | Nodes, VMs, LXC containers — CPU, RAM, disk, IO rates |
| **UniFi** | APs, switches, clients, signal strength, port PoE |
| **UniFi NAS (UNAS)** | Storage, volumes, RAID |
| **Pi-hole** | Query stats, blocking %, top domains |
| **AdGuard Home** | Query stats, blocking %, filter lists |
| **Portainer** | Docker containers across all endpoints |
| **TrueNAS** | Pools, datasets, alerts, system info |
| **Synology DSM** | Volumes, shares, CPU, RAM, SMART |
| **pfSense / OPNsense** | Interface stats, rules, DHCP leases |
| **Home Assistant** | Entity states, system info |
| **Gitea** | Repos, users, issues, system stats |
| **phpIPAM** | IP subnets, address utilisation, auto-import to Hosts |
| **Speedtest** | Download, upload, latency — scheduled via `speedtest-cli` |
| **UPS / NUT** | Battery charge, status (on-line / on-battery), runtime |
| **Redfish / iDRAC** | Server hardware temps, fans, power, system info |

---

## Quick start

### Requirements

- Docker & Docker Compose
- `NET_RAW` capability for ICMP ping (already set in `docker-compose.yml`)

### Run

```bash
git clone https://github.com/jubacCH/B8MON.git
cd B8MON
docker compose up -d
```

Open **http://localhost:8000** — the setup wizard runs on first start.

> Data (SQLite DB) is persisted in `./data/monitor.db`.

### Live reload (development)

The `docker-compose.yml` mounts `./backend` into the container and runs Uvicorn with `--reload`, so code changes take effect immediately without rebuilding.

---

## Configuration

All settings are available at **`/settings`**:

| Setting | Default | Description |
|---|---|---|
| Site name | Homelab Monitor | Shown in page title and sidebar |
| Timezone | UTC | Display timezone |
| Ping interval | 60 s | How often hosts are checked |
| Proxmox interval | 60 s | How often Proxmox is polled |
| Ping retention | 30 days | How long ping results are kept |
| Proxmox retention | 7 days | How long Proxmox snapshots are kept |
| Integration retention | 7 days | How long all other integration snapshots are kept |
| Latency threshold (global) | — | Alarm when latency exceeds this (ms) |
| Proxmox CPU/RAM/Disk threshold | 85 / 85 / 90 % | Absolute threshold for anomaly alerts |
| Anomaly multiplier | 2.0× | Spike detection: alert when metric > N× 24h avg |

phpIPAM credentials are also configured in Settings (separate form, auto-sync available).

---

## Architecture

```
B8MON/
├── backend/
│   ├── main.py               # FastAPI app, middleware, router registration
│   ├── database.py           # SQLAlchemy models, async session, helpers
│   ├── scheduler.py          # APScheduler background jobs
│   ├── collectors/           # One file per integration (async HTTP / TCP)
│   │   ├── ping.py           # ICMP, HTTP, HTTPS, TCP, SSL expiry
│   │   ├── proxmox.py
│   │   ├── unifi.py
│   │   └── ...
│   ├── routers/              # FastAPI routers (HTML + JSON endpoints)
│   │   ├── dashboard.py
│   │   ├── ping.py
│   │   ├── alerts.py
│   │   └── ...
│   └── templates/            # Jinja2 HTML templates
│       ├── base.html         # Shared layout, sidebar, mobile nav
│       ├── dashboard.html
│       └── ...
├── data/                     # Persisted SQLite DB (docker volume)
└── docker-compose.yml
```

### Data flow

1. **Scheduler** (APScheduler, async) runs collector functions on a configurable interval.
2. Each collector stores a **snapshot** row in SQLite (`data_json` column holds full JSON).
3. **Routers** read the latest snapshot on page load — no live API calls on every request.
4. Background **cleanup job** (daily at 03:00) prunes snapshots older than the configured retention.

---

## Host check types

Each host supports one or more check types (combinable):

| Type | How it works |
|---|---|
| `icmp` | Raw ICMP ping via `icmplib` |
| `http` | HTTP GET, success = 2xx/3xx |
| `https` | HTTPS GET, additionally tracks SSL expiry |
| `tcp` | TCP connect to host:port |

Per-host latency threshold and a global fallback threshold are both supported.

---

## License

MIT
