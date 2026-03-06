"""
Models package – re-exports all models and helpers for easy importing.

Usage:
    from models import Base, IntegrationConfig, Snapshot, PingHost, ...
    from models import get_setting, set_setting, encrypt_value, decrypt_value
"""
from models.base import (
    Base,
    AsyncSessionLocal,
    engine,
    encrypt_value,
    decrypt_value,
    get_db,
)
from models.settings import (
    Setting,
    User,
    Session,
    get_current_user,
    get_setting,
    set_setting,
    is_setup_complete,
)
from models.ping import PingHost, PingResult
from models.integration import IntegrationConfig, Snapshot


async def init_db():
    """Create all tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


__all__ = [
    "Base", "AsyncSessionLocal", "engine",
    "encrypt_value", "decrypt_value", "get_db",
    "Setting", "User", "Session",
    "get_current_user", "get_setting", "set_setting", "is_setup_complete",
    "PingHost", "PingResult",
    "IntegrationConfig", "Snapshot",
    "init_db",
]
