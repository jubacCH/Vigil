"""
Generic CRUD and config helpers for integrations.
Handles encryption/decryption of config_json.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import encrypt_value, decrypt_value
from models.integration import IntegrationConfig, Snapshot


# ── Config CRUD ──────────────────────────────────────────────────────────────

def encrypt_config(config_dict: dict[str, Any]) -> str:
    """Serialize config dict to encrypted JSON string."""
    return encrypt_value(json.dumps(config_dict))


def decrypt_config(encrypted_json: str) -> dict[str, Any]:
    """Decrypt JSON string back to config dict."""
    return json.loads(decrypt_value(encrypted_json))


async def get_configs(db: AsyncSession, integration_type: str) -> list[IntegrationConfig]:
    """Get all configs for an integration type."""
    result = await db.execute(
        select(IntegrationConfig)
        .where(IntegrationConfig.type == integration_type, IntegrationConfig.enabled == True)
        .order_by(IntegrationConfig.name)
    )
    return list(result.scalars().all())


async def get_all_configs(db: AsyncSession, integration_type: str) -> list[IntegrationConfig]:
    """Get all configs for an integration type (including disabled)."""
    result = await db.execute(
        select(IntegrationConfig)
        .where(IntegrationConfig.type == integration_type)
        .order_by(IntegrationConfig.name)
    )
    return list(result.scalars().all())


async def get_config(db: AsyncSession, config_id: int) -> IntegrationConfig | None:
    """Get a single config by ID."""
    return await db.get(IntegrationConfig, config_id)


async def create_config(
    db: AsyncSession,
    integration_type: str,
    name: str,
    config_dict: dict[str, Any],
) -> IntegrationConfig:
    """Create a new integration config."""
    cfg = IntegrationConfig(
        type=integration_type,
        name=name,
        config_json=encrypt_config(config_dict),
    )
    db.add(cfg)
    await db.commit()
    await db.refresh(cfg)
    return cfg


async def update_config(
    db: AsyncSession,
    config_id: int,
    name: str | None = None,
    config_dict: dict[str, Any] | None = None,
) -> IntegrationConfig | None:
    """Update an existing config."""
    cfg = await db.get(IntegrationConfig, config_id)
    if not cfg:
        return None
    if name is not None:
        cfg.name = name
    if config_dict is not None:
        cfg.config_json = encrypt_config(config_dict)
    await db.commit()
    return cfg


async def delete_config(db: AsyncSession, config_id: int) -> bool:
    """Delete a config and its snapshots."""
    cfg = await db.get(IntegrationConfig, config_id)
    if not cfg:
        return False
    # Delete associated snapshots
    await db.execute(
        delete(Snapshot).where(
            Snapshot.entity_type == cfg.type,
            Snapshot.entity_id == cfg.id,
        )
    )
    await db.delete(cfg)
    await db.commit()
    return True


async def count_configs(db: AsyncSession, integration_type: str) -> int:
    """Count configs for a type (for nav counts)."""
    result = await db.execute(
        select(func.count()).select_from(IntegrationConfig)
        .where(IntegrationConfig.type == integration_type)
    )
    return result.scalar() or 0


async def count_all_by_type(db: AsyncSession) -> dict[str, int]:
    """Count all configs grouped by type. Single query for nav counts."""
    result = await db.execute(
        select(IntegrationConfig.type, func.count())
        .group_by(IntegrationConfig.type)
    )
    return {row[0]: row[1] for row in result.all()}
