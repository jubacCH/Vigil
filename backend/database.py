"""
Legacy database module – kept for backward compatibility with old routers.

New code should import from:
  - models.base (engine, session, crypto)
  - models.integration (IntegrationConfig, Snapshot)
  - models.settings (Setting, User, Session)
  - models.ping (PingHost, PingResult)
  - services.integration / services.snapshot

Old per-integration config + snapshot tables below will be removed once
all routers are migrated to the generic integration system.
"""
import base64
import hashlib
import json
from datetime import datetime
from typing import TYPE_CHECKING, AsyncGenerator

if TYPE_CHECKING:
    from fastapi import Request

from cryptography.fernet import Fernet
from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, select, text
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship

from config import DATABASE_URL, SECRET_KEY


engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String, primary_key=True)
    value = Column(Text, nullable=True)
    encrypted = Column(Boolean, default=False)


class PingHost(Base):
    __tablename__ = "ping_hosts"
    id                   = Column(Integer, primary_key=True, autoincrement=True)
    name                 = Column(String, nullable=False)
    hostname             = Column(String, nullable=False)
    enabled              = Column(Boolean, default=True)
    check_type           = Column(String, default="icmp")   # icmp | http | https | tcp
    port                 = Column(Integer, nullable=True)   # override for tcp/http/https
    latency_threshold_ms = Column(Float, nullable=True)     # alert if avg latency exceeds this
    maintenance          = Column(Boolean, default=False)   # suppress alerts, skip downtime count
    ssl_expiry_days      = Column(Integer, nullable=True)   # days until SSL cert expires (https only)
    source               = Column(String, default="manual") # manual | phpipam | proxmox | unifi
    source_detail        = Column(String, nullable=True)    # e.g. cluster name or phpIPAM subnet
    mac_address          = Column(String, nullable=True)    # optional MAC, populated by auto-import
    parent_id            = Column(Integer, ForeignKey("ping_hosts.id"), nullable=True)  # topology: parent device
    created_at           = Column(DateTime, default=datetime.utcnow)
    results = relationship("PingResult", back_populates="host", cascade="all, delete-orphan")
    children = relationship("PingHost", foreign_keys="PingHost.parent_id", viewonly=True)


class PingResult(Base):
    __tablename__ = "ping_results"
    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("ping_hosts.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    success = Column(Boolean, nullable=False)
    latency_ms = Column(Float, nullable=True)
    host = relationship("PingHost", back_populates="results")


class ProxmoxCluster(Base):
    __tablename__ = "proxmox_clusters"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String, nullable=False)
    host         = Column(String, nullable=False)   # e.g. https://proxmox.local:8006
    verify_ssl   = Column(Boolean, default=False)
    token_id     = Column(String, nullable=False)   # user@realm!tokenid
    token_secret = Column(String, nullable=False)   # stored encrypted
    created_at   = Column(DateTime, default=datetime.utcnow)
    snapshots    = relationship("ProxmoxSnapshot", back_populates="cluster",
                                cascade="all, delete-orphan")


class ProxmoxSnapshot(Base):
    """Latest cached status per Proxmox cluster, written by the background scheduler."""
    __tablename__ = "proxmox_snapshots"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    cluster_id = Column(Integer, ForeignKey("proxmox_clusters.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, index=True)
    ok         = Column(Boolean, nullable=False)
    data_json  = Column(Text, nullable=True)   # JSON-encoded parse_cluster_data result
    error      = Column(Text, nullable=True)
    cluster    = relationship("ProxmoxCluster", back_populates="snapshots")


class UnifiController(Base):
    __tablename__ = "unifi_controllers"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String, nullable=False)
    host         = Column(String, nullable=False)   # e.g. https://unifi.local:8443
    username     = Column(String, nullable=False)
    password_enc = Column(String, nullable=False)   # stored encrypted
    site         = Column(String, default="default")
    verify_ssl   = Column(Boolean, default=False)
    is_udm       = Column(Boolean, default=False)   # UniFi OS / Dream Machine API
    created_at   = Column(DateTime, default=datetime.utcnow)
    snapshots    = relationship("UnifiSnapshot", back_populates="controller",
                                cascade="all, delete-orphan")


class UnifiSnapshot(Base):
    """Periodic status snapshot per UniFi controller, written by the background scheduler."""
    __tablename__ = "unifi_snapshots"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    controller_id = Column(Integer, ForeignKey("unifi_controllers.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)
    ok            = Column(Boolean, nullable=False)
    data_json     = Column(Text, nullable=True)   # JSON-encoded parse_unifi_data result
    error         = Column(Text, nullable=True)
    controller    = relationship("UnifiController", back_populates="snapshots")


class UnasServer(Base):
    __tablename__ = "unas_servers"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String, nullable=False)
    host         = Column(String, nullable=False)   # e.g. https://unas.local
    username     = Column(String, nullable=False)
    password_enc = Column(String, nullable=False)   # stored encrypted
    verify_ssl   = Column(Boolean, default=False)
    created_at   = Column(DateTime, default=datetime.utcnow)
    snapshots    = relationship("UnasSnapshot", back_populates="server",
                                cascade="all, delete-orphan")


class UnasSnapshot(Base):
    """Periodic status snapshot per UniFi NAS, written by the background scheduler."""
    __tablename__ = "unas_snapshots"
    id        = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(Integer, ForeignKey("unas_servers.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ok        = Column(Boolean, nullable=False)
    data_json = Column(Text, nullable=True)
    error     = Column(Text, nullable=True)
    server    = relationship("UnasServer", back_populates="snapshots")


# ── phpIPAM ───────────────────────────────────────────────────────────────────
class PhpipamServer(Base):
    __tablename__ = "phpipam_servers"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String, nullable=False)
    host         = Column(String, nullable=False)
    app_id       = Column(String, nullable=False)
    username     = Column(String, nullable=True)
    password_enc = Column(String, nullable=True)
    verify_ssl   = Column(Boolean, default=True)
    created_at   = Column(DateTime, default=datetime.utcnow)
    snapshots    = relationship("PhpipamSnapshot", back_populates="server", cascade="all, delete-orphan")

class PhpipamSnapshot(Base):
    __tablename__ = "phpipam_snapshots"
    id        = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(Integer, ForeignKey("phpipam_servers.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ok        = Column(Boolean, nullable=False)
    data_json = Column(Text, nullable=True)
    error     = Column(Text, nullable=True)
    server    = relationship("PhpipamServer", back_populates="snapshots")


# ── Pi-hole ───────────────────────────────────────────────────────────────────
class PiholeInstance(Base):
    __tablename__ = "pihole_instances"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    name        = Column(String, nullable=False)
    host        = Column(String, nullable=False)
    api_key_enc = Column(String, nullable=True)
    verify_ssl  = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)
    snapshots   = relationship("PiholeSnapshot", back_populates="instance", cascade="all, delete-orphan")

class PiholeSnapshot(Base):
    __tablename__ = "pihole_snapshots"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(Integer, ForeignKey("pihole_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    ok          = Column(Boolean, nullable=False)
    data_json   = Column(Text, nullable=True)
    error       = Column(Text, nullable=True)
    instance    = relationship("PiholeInstance", back_populates="snapshots")


# ── AdGuard Home ──────────────────────────────────────────────────────────────
class AdguardInstance(Base):
    __tablename__ = "adguard_instances"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String, nullable=False)
    host         = Column(String, nullable=False)
    username     = Column(String, nullable=True)
    password_enc = Column(String, nullable=True)
    verify_ssl   = Column(Boolean, default=False)
    created_at   = Column(DateTime, default=datetime.utcnow)
    snapshots    = relationship("AdguardSnapshot", back_populates="instance", cascade="all, delete-orphan")

class AdguardSnapshot(Base):
    __tablename__ = "adguard_snapshots"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(Integer, ForeignKey("adguard_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    ok          = Column(Boolean, nullable=False)
    data_json   = Column(Text, nullable=True)
    error       = Column(Text, nullable=True)
    instance    = relationship("AdguardInstance", back_populates="snapshots")


# ── Portainer ─────────────────────────────────────────────────────────────────
class PortainerInstance(Base):
    __tablename__ = "portainer_instances"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    name        = Column(String, nullable=False)
    host        = Column(String, nullable=False)
    api_key_enc = Column(String, nullable=True)
    verify_ssl  = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)
    snapshots   = relationship("PortainerSnapshot", back_populates="instance", cascade="all, delete-orphan")

class PortainerSnapshot(Base):
    __tablename__ = "portainer_snapshots"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(Integer, ForeignKey("portainer_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    ok          = Column(Boolean, nullable=False)
    data_json   = Column(Text, nullable=True)
    error       = Column(Text, nullable=True)
    instance    = relationship("PortainerInstance", back_populates="snapshots")


# ── TrueNAS ───────────────────────────────────────────────────────────────────
class TruenasServer(Base):
    __tablename__ = "truenas_servers"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    name        = Column(String, nullable=False)
    host        = Column(String, nullable=False)
    api_key_enc = Column(String, nullable=False)
    verify_ssl  = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)
    snapshots   = relationship("TruenasSnapshot", back_populates="server", cascade="all, delete-orphan")

class TruenasSnapshot(Base):
    __tablename__ = "truenas_snapshots"
    id        = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(Integer, ForeignKey("truenas_servers.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ok        = Column(Boolean, nullable=False)
    data_json = Column(Text, nullable=True)
    error     = Column(Text, nullable=True)
    server    = relationship("TruenasServer", back_populates="snapshots")


# ── Synology DSM ──────────────────────────────────────────────────────────────
class SynologyServer(Base):
    __tablename__ = "synology_servers"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String, nullable=False)
    host         = Column(String, nullable=False)
    port         = Column(Integer, default=5001)
    username     = Column(String, nullable=False)
    password_enc = Column(String, nullable=False)
    verify_ssl   = Column(Boolean, default=False)
    created_at   = Column(DateTime, default=datetime.utcnow)
    snapshots    = relationship("SynologySnapshot", back_populates="server", cascade="all, delete-orphan")

class SynologySnapshot(Base):
    __tablename__ = "synology_snapshots"
    id        = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(Integer, ForeignKey("synology_servers.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ok        = Column(Boolean, nullable=False)
    data_json = Column(Text, nullable=True)
    error     = Column(Text, nullable=True)
    server    = relationship("SynologyServer", back_populates="snapshots")


# ── pfSense / OPNsense ────────────────────────────────────────────────────────
class FirewallInstance(Base):
    __tablename__ = "firewall_instances"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String, nullable=False)
    host         = Column(String, nullable=False)
    fw_type      = Column(String, default="opnsense")   # pfsense | opnsense
    username     = Column(String, nullable=True)
    password_enc = Column(String, nullable=True)
    api_key_enc  = Column(String, nullable=True)    # OPNsense key
    api_secret_enc = Column(String, nullable=True)  # OPNsense secret
    verify_ssl   = Column(Boolean, default=False)
    created_at   = Column(DateTime, default=datetime.utcnow)
    snapshots    = relationship("FirewallSnapshot", back_populates="instance", cascade="all, delete-orphan")

class FirewallSnapshot(Base):
    __tablename__ = "firewall_snapshots"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(Integer, ForeignKey("firewall_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    ok          = Column(Boolean, nullable=False)
    data_json   = Column(Text, nullable=True)
    error       = Column(Text, nullable=True)
    instance    = relationship("FirewallInstance", back_populates="snapshots")


# ── Home Assistant ────────────────────────────────────────────────────────────
class HassInstance(Base):
    __tablename__ = "hass_instances"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    name        = Column(String, nullable=False)
    host        = Column(String, nullable=False)
    token_enc   = Column(String, nullable=False)   # Long-lived access token
    verify_ssl  = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)
    snapshots   = relationship("HassSnapshot", back_populates="instance", cascade="all, delete-orphan")

class HassSnapshot(Base):
    __tablename__ = "hass_snapshots"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(Integer, ForeignKey("hass_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    ok          = Column(Boolean, nullable=False)
    data_json   = Column(Text, nullable=True)
    error       = Column(Text, nullable=True)
    instance    = relationship("HassInstance", back_populates="snapshots")


# ── Speedtest ─────────────────────────────────────────────────────────────────
class SpeedtestConfig(Base):
    __tablename__ = "speedtest_configs"
    id               = Column(Integer, primary_key=True, autoincrement=True)
    name             = Column(String, nullable=False, default="Speedtest")
    schedule_minutes = Column(Integer, default=60)
    server_id        = Column(String, nullable=True)   # optional Speedtest server ID
    created_at       = Column(DateTime, default=datetime.utcnow)
    results          = relationship("SpeedtestResult", back_populates="config", cascade="all, delete-orphan")

class SpeedtestResult(Base):
    __tablename__ = "speedtest_results"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    config_id     = Column(Integer, ForeignKey("speedtest_configs.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)
    ok            = Column(Boolean, nullable=False)
    download_mbps = Column(Float, nullable=True)
    upload_mbps   = Column(Float, nullable=True)
    ping_ms       = Column(Float, nullable=True)
    server_name   = Column(String, nullable=True)
    error         = Column(Text, nullable=True)
    config        = relationship("SpeedtestConfig", back_populates="results")


# ── UPS / NUT ─────────────────────────────────────────────────────────────────
class NutInstance(Base):
    __tablename__ = "nut_instances"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String, nullable=False)
    host         = Column(String, nullable=False)
    port         = Column(Integer, default=3493)
    ups_name     = Column(String, default="ups")
    username     = Column(String, nullable=True)
    password_enc = Column(String, nullable=True)
    created_at   = Column(DateTime, default=datetime.utcnow)
    snapshots    = relationship("NutSnapshot", back_populates="instance", cascade="all, delete-orphan")

class NutSnapshot(Base):
    __tablename__ = "nut_snapshots"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(Integer, ForeignKey("nut_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    ok          = Column(Boolean, nullable=False)
    data_json   = Column(Text, nullable=True)
    error       = Column(Text, nullable=True)
    instance    = relationship("NutInstance", back_populates="snapshots")


# ── iDRAC / Redfish ───────────────────────────────────────────────────────────
class RedfishServer(Base):
    __tablename__ = "redfish_servers"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String, nullable=False)
    host         = Column(String, nullable=False)
    username     = Column(String, nullable=False)
    password_enc = Column(String, nullable=False)
    verify_ssl   = Column(Boolean, default=False)
    created_at   = Column(DateTime, default=datetime.utcnow)
    snapshots    = relationship("RedfishSnapshot", back_populates="server", cascade="all, delete-orphan")

class RedfishSnapshot(Base):
    __tablename__ = "redfish_snapshots"
    id        = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(Integer, ForeignKey("redfish_servers.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ok        = Column(Boolean, nullable=False)
    data_json = Column(Text, nullable=True)
    error     = Column(Text, nullable=True)
    server    = relationship("RedfishServer", back_populates="snapshots")


# ── Gitea ─────────────────────────────────────────────────────────────────────
class GiteaInstance(Base):
    __tablename__ = "gitea_instances"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    name        = Column(String, nullable=False)
    host        = Column(String, nullable=False)
    token_enc   = Column(String, nullable=True)
    verify_ssl  = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)
    snapshots   = relationship("GiteaSnapshot", back_populates="instance", cascade="all, delete-orphan")

class GiteaSnapshot(Base):
    __tablename__ = "gitea_snapshots"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(Integer, ForeignKey("gitea_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    ok          = Column(Boolean, nullable=False)
    data_json   = Column(Text, nullable=True)
    error       = Column(Text, nullable=True)
    instance    = relationship("GiteaInstance", back_populates="snapshots")


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


async def get_current_user(request: "Request", db: AsyncSession) -> "User | None":
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


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Safe migration: add new columns to existing ping_hosts table
        # Add role column to existing users table
        try:
            await conn.execute(text("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'admin'"))
        except Exception:
            pass
        migrations = [
            ("check_type",           "TEXT DEFAULT 'icmp'"),
            ("port",                 "INTEGER"),
            ("latency_threshold_ms", "REAL"),
            ("maintenance",          "INTEGER DEFAULT 0"),
            ("ssl_expiry_days",      "INTEGER"),
            ("source",               "TEXT DEFAULT 'manual'"),
            ("source_detail",        "TEXT"),
            ("mac_address",          "TEXT"),
            ("parent_id",            "INTEGER REFERENCES ping_hosts(id)"),
        ]
        for col, definition in migrations:
            try:
                await conn.execute(text(f"ALTER TABLE ping_hosts ADD COLUMN {col} {definition}"))
            except Exception:
                pass  # column already exists


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


# ── Settings helpers ──────────────────────────────────────────────────────────

def _fernet() -> Fernet:
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_value(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_value(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()


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
