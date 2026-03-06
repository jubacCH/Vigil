#!/usr/bin/env python3
"""
One-time migration: copy data from old per-integration tables to the new
generic IntegrationConfig + Snapshot tables.

Run inside the backend/ directory:
    python migrate_to_generic.py

Safe to run multiple times – skips integration types that already have rows
in the new table.
"""
import asyncio
import json
import sys
from datetime import datetime

from sqlalchemy import text

from config import DATABASE_URL, SECRET_KEY
from database import AsyncSessionLocal, decrypt_value
from models.base import encrypt_value as new_encrypt
from models.integration import IntegrationConfig, Snapshot
from services.integration import encrypt_config


# ── Mapping: old table → new integration type + field extraction ─────────────

MIGRATIONS = [
    {
        "type": "proxmox",
        "config_table": "proxmox_clusters",
        "snapshot_table": "proxmox_snapshots",
        "snapshot_fk": "cluster_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "token_id": row["token_id"],
            "token_secret": _decrypt_safe(row["token_secret"]),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "unifi",
        "config_table": "unifi_controllers",
        "snapshot_table": "unifi_snapshots",
        "snapshot_fk": "controller_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "username": row["username"],
            "password": _decrypt_safe(row["password_enc"]),
            "site": row["site"] or "default",
            "is_udm": bool(row.get("is_udm", False)),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "unas",
        "config_table": "unas_servers",
        "snapshot_table": "unas_snapshots",
        "snapshot_fk": "server_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "username": row["username"],
            "password": _decrypt_safe(row["password_enc"]),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "pihole",
        "config_table": "pihole_instances",
        "snapshot_table": "pihole_snapshots",
        "snapshot_fk": "instance_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "api_key": _decrypt_safe(row.get("api_key_enc", "")),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "adguard",
        "config_table": "adguard_instances",
        "snapshot_table": "adguard_snapshots",
        "snapshot_fk": "instance_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "username": row.get("username", ""),
            "password": _decrypt_safe(row.get("password_enc", "")),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "portainer",
        "config_table": "portainer_instances",
        "snapshot_table": "portainer_snapshots",
        "snapshot_fk": "instance_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "api_key": _decrypt_safe(row.get("api_key_enc", "")),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "truenas",
        "config_table": "truenas_servers",
        "snapshot_table": "truenas_snapshots",
        "snapshot_fk": "server_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "api_key": _decrypt_safe(row.get("api_key_enc", "")),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "synology",
        "config_table": "synology_servers",
        "snapshot_table": "synology_snapshots",
        "snapshot_fk": "server_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "port": row.get("port", 5001),
            "username": row["username"],
            "password": _decrypt_safe(row["password_enc"]),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "firewall",
        "config_table": "firewall_instances",
        "snapshot_table": "firewall_snapshots",
        "snapshot_fk": "instance_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "fw_type": row.get("fw_type", "opnsense"),
            "api_key": _decrypt_safe(row.get("api_key_enc", "")),
            "api_secret": _decrypt_safe(row.get("api_secret_enc", "")),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "hass",
        "config_table": "hass_instances",
        "snapshot_table": "hass_snapshots",
        "snapshot_fk": "instance_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "token": _decrypt_safe(row.get("token_enc", "")),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "gitea",
        "config_table": "gitea_instances",
        "snapshot_table": "gitea_snapshots",
        "snapshot_fk": "instance_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "token": _decrypt_safe(row.get("token_enc", "")),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
    {
        "type": "phpipam",
        "config_table": "phpipam_servers",
        "snapshot_table": "phpipam_snapshots",
        "snapshot_fk": "server_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "app_id": row.get("app_id", ""),
            "username": row.get("username", ""),
            "password": _decrypt_safe(row.get("password_enc", "")),
            "verify_ssl": bool(row.get("verify_ssl", True)),
        },
    },
    {
        "type": "speedtest",
        "config_table": "speedtest_configs",
        "snapshot_table": "speedtest_results",
        "snapshot_fk": "config_id",
        "extract_config": lambda row: {
            "server_id": row.get("server_id", ""),
        },
        # Speedtest results have different columns — convert to data_json
        "convert_snapshot": lambda row: {
            "download_mbps": row.get("download_mbps"),
            "upload_mbps": row.get("upload_mbps"),
            "ping_ms": row.get("ping_ms"),
            "server_name": row.get("server_name", ""),
            "server_location": row.get("server_location", ""),
        },
    },
    {
        "type": "ups",
        "config_table": "nut_instances",
        "snapshot_table": "nut_snapshots",
        "snapshot_fk": "instance_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "port": row.get("port", 3493),
            "ups_name": row.get("ups_name", "ups"),
            "username": row.get("username", ""),
            "password": _decrypt_safe(row.get("password_enc", "")),
        },
    },
    {
        "type": "redfish",
        "config_table": "redfish_servers",
        "snapshot_table": "redfish_snapshots",
        "snapshot_fk": "server_id",
        "extract_config": lambda row: {
            "host": row["host"],
            "username": row["username"],
            "password": _decrypt_safe(row["password_enc"]),
            "verify_ssl": bool(row["verify_ssl"]),
        },
    },
]


def _decrypt_safe(val: str) -> str:
    """Decrypt a value, returning empty string if blank or invalid."""
    if not val:
        return ""
    try:
        return decrypt_value(val)
    except Exception:
        return val  # already plaintext or corrupted — keep as-is


def _table_exists(conn, table_name: str) -> bool:
    """Check if a table exists (SQLite)."""
    result = conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name=:t"),
        {"t": table_name},
    )
    return result.fetchone() is not None


async def migrate():
    # Ensure new tables exist
    from models import init_db
    await init_db()

    async with AsyncSessionLocal() as db:
        # Check if already migrated
        result = await db.execute(
            text("SELECT COUNT(*) FROM integration_configs")
        )
        existing = result.scalar()
        if existing > 0:
            print(f"integration_configs already has {existing} rows. Skipping.")
            print("To re-run, delete all rows first: DELETE FROM integration_configs;")
            return

    total_configs = 0
    total_snaps = 0

    for m in MIGRATIONS:
        int_type = m["type"]
        config_table = m["config_table"]
        snap_table = m["snapshot_table"]
        snap_fk = m["snapshot_fk"]

        async with AsyncSessionLocal() as db:
            # Check if old table exists
            exists = await db.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name=:t"),
                {"t": config_table},
            )
            if not exists.fetchone():
                print(f"  [{int_type}] table '{config_table}' not found — skipping")
                continue

            # Read old configs
            rows = await db.execute(text(f"SELECT * FROM {config_table}"))
            old_configs = [dict(row._mapping) for row in rows]

            if not old_configs:
                print(f"  [{int_type}] no configs — skipping")
                continue

            # Map old_id → new IntegrationConfig
            id_map: dict[int, int] = {}  # old_id → new_id

            for old in old_configs:
                try:
                    config_dict = m["extract_config"](old)
                except Exception as e:
                    print(f"  [{int_type}] error extracting config id={old['id']}: {e}")
                    continue

                new_cfg = IntegrationConfig(
                    type=int_type,
                    name=old.get("name", int_type),
                    config_json=encrypt_config(config_dict),
                    enabled=True,
                    created_at=old.get("created_at", datetime.utcnow()),
                )
                db.add(new_cfg)
                await db.flush()  # get new_cfg.id
                id_map[old["id"]] = new_cfg.id
                total_configs += 1

            # Migrate snapshots
            snap_exists = await db.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name=:t"),
                {"t": snap_table},
            )
            if snap_exists.fetchone():
                snap_rows = await db.execute(text(f"SELECT * FROM {snap_table}"))
                for snap in snap_rows:
                    snap_dict = dict(snap._mapping)
                    old_parent_id = snap_dict.get(snap_fk)
                    new_parent_id = id_map.get(old_parent_id)
                    if not new_parent_id:
                        continue

                    # Get data_json — either from column or via converter
                    if "convert_snapshot" in m:
                        data_json = json.dumps(m["convert_snapshot"](snap_dict))
                    else:
                        data_json = snap_dict.get("data_json")

                    new_snap = Snapshot(
                        entity_type=int_type,
                        entity_id=new_parent_id,
                        timestamp=snap_dict.get("timestamp", datetime.utcnow()),
                        ok=bool(snap_dict.get("ok", True)),
                        data_json=data_json,
                        error=snap_dict.get("error"),
                    )
                    db.add(new_snap)
                    total_snaps += 1

            await db.commit()
            print(f"  [{int_type}] migrated {len(id_map)} configs, snapshots from {snap_table}")

    print(f"\nDone! Migrated {total_configs} configs and {total_snaps} snapshots.")


if __name__ == "__main__":
    asyncio.run(migrate())
