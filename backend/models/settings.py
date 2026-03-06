"""Settings, User, and Session models."""
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.base import Base, decrypt_value, encrypt_value


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String, primary_key=True)
    value = Column(Text, nullable=True)
    encrypted = Column(Boolean, default=False)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(16), default="admin")   # admin | editor | readonly
    created_at = Column(DateTime, default=datetime.utcnow)


class Session(Base):
    __tablename__ = "sessions"
    token = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)


# ── Helpers ──────────────────────────────────────────────────────────────────

async def get_current_user(request, db: AsyncSession):
    token = request.cookies.get("vigil_session")
    if not token:
        return None
    now = datetime.utcnow()
    result = await db.execute(
        select(Session).where(Session.token == token, Session.expires_at > now)
    )
    session = result.scalar_one_or_none()
    if not session:
        return None
    result = await db.execute(select(User).where(User.id == session.user_id))
    return result.scalar_one_or_none()


async def get_setting(db: AsyncSession, key: str, default=None):
    row = await db.get(Setting, key)
    if row is None:
        return default
    if row.encrypted and row.value:
        return decrypt_value(row.value)
    return row.value


async def set_setting(db: AsyncSession, key: str, value: str, encrypted: bool = False):
    row = await db.get(Setting, key)
    stored = encrypt_value(value) if encrypted else value
    if row:
        row.value = stored
        row.encrypted = encrypted
    else:
        db.add(Setting(key=key, value=stored, encrypted=encrypted))
    await db.commit()


async def is_setup_complete(db: AsyncSession) -> bool:
    val = await get_setting(db, "setup_complete")
    return val == "true"
