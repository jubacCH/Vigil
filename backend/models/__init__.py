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
from models.syslog import SyslogMessage


async def init_db():
    """Create all tables and PostgreSQL-specific objects (triggers, etc.)."""
    from sqlalchemy import text
    from config import DATABASE_URL

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # PostgreSQL: create tsvector trigger for syslog FTS
    if "postgresql" in (DATABASE_URL or ""):
        async with engine.begin() as conn:
            await conn.execute(text("""
                CREATE OR REPLACE FUNCTION syslog_search_vector_update() RETURNS trigger AS $$
                BEGIN
                    NEW.search_vector :=
                        setweight(to_tsvector('english', COALESCE(NEW.hostname, '')), 'A') ||
                        setweight(to_tsvector('english', COALESCE(NEW.app_name, '')), 'B') ||
                        setweight(to_tsvector('english', COALESCE(NEW.message, '')), 'C');
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
            """))
            await conn.execute(text("""
                DO $$ BEGIN
                    CREATE TRIGGER syslog_search_vector_trigger
                        BEFORE INSERT OR UPDATE ON syslog_messages
                        FOR EACH ROW EXECUTE FUNCTION syslog_search_vector_update();
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$;
            """))


__all__ = [
    "Base", "AsyncSessionLocal", "engine",
    "encrypt_value", "decrypt_value", "get_db",
    "Setting", "User", "Session",
    "get_current_user", "get_setting", "set_setting", "is_setup_complete",
    "PingHost", "PingResult",
    "IntegrationConfig", "Snapshot",
    "SyslogMessage",
    "init_db",
]
