"""Shared fixtures for router smoke tests."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", ".test_data"))

import pytest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch
from httpx import ASGITransport, AsyncClient
from sqlalchemy import String
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from models.base import Base as ModelsBase
from database import Base as DbBase


class FakeUser:
    id = 1
    username = "admin"
    role = "admin"


@pytest.fixture
async def client():
    """Provide an httpx AsyncClient wired to the FastAPI app with auth bypassed."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    # SQLite compat: replace TSVECTOR, remove GIN indexes
    from sqlalchemy.dialects.postgresql import TSVECTOR
    for base in (DbBase, ModelsBase):
        for table in base.metadata.tables.values():
            for col in table.columns:
                if isinstance(col.type, TSVECTOR):
                    col.type = String()
            table.indexes = {
                idx for idx in table.indexes
                if not getattr(idx, 'dialect_options', {}).get('postgresql', {}).get('using')
                and 'gin' not in str(getattr(idx, 'kwargs', {}))
            }

    async with engine.begin() as conn:
        await conn.run_sync(DbBase.metadata.create_all)
        await conn.run_sync(ModelsBase.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    # Seed minimal settings
    async with session_factory() as seed_db:
        from database import Setting
        seed_db.add(Setting(key="setup_complete", value="true"))
        seed_db.add(Setting(key="site_name", value="NODEGLOW"))
        seed_db.add(Setting(key="timezone", value="UTC"))
        seed_db.add(Setting(key="syslog_port", value="1514"))
        await seed_db.commit()

    @asynccontextmanager
    async def fake_session():
        async with session_factory() as session:
            yield session

    with patch("main.start_scheduler", new_callable=AsyncMock), \
         patch("main.stop_scheduler"), \
         patch("main.init_db", new_callable=AsyncMock), \
         patch("models.init_db", new_callable=AsyncMock), \
         patch("services.syslog.start_syslog_server", new_callable=AsyncMock), \
         patch("services.syslog.stop_syslog_server", new_callable=AsyncMock), \
         patch("database.AsyncSessionLocal", side_effect=fake_session), \
         patch("main.AsyncSessionLocal", side_effect=fake_session), \
         patch("models.base.AsyncSessionLocal", side_effect=fake_session), \
         patch("database.get_current_user", new_callable=AsyncMock, return_value=FakeUser()):

        from main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

    await engine.dispose()
