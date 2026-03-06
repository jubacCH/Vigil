"""Generic IntegrationConfig and Snapshot models for all integrations."""
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text

from models.base import Base


class IntegrationConfig(Base):
    """
    Single table for all integration configurations.
    Each row stores one integration instance (e.g. one Proxmox cluster, one UniFi controller).
    The config_json field holds all config fields as encrypted JSON.
    """
    __tablename__ = "integration_configs"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    type        = Column(String(32), nullable=False, index=True)
    name        = Column(String(128), nullable=False)
    config_json = Column(Text, nullable=False)    # encrypted JSON with all fields
    enabled     = Column(Boolean, default=True)
    created_at  = Column(DateTime, default=datetime.utcnow)


class Snapshot(Base):
    """
    Generic snapshot table for all integration types.
    Stores the latest collected data as JSON.
    """
    __tablename__ = "snapshots"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    entity_type = Column(String(32), nullable=False)
    entity_id   = Column(Integer, nullable=False)
    timestamp   = Column(DateTime, default=datetime.utcnow)
    ok          = Column(Boolean, nullable=False, default=True)
    data_json   = Column(Text, nullable=True)
    error       = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_snap_type_entity_ts", "entity_type", "entity_id", timestamp.desc()),
        Index("ix_snap_entity_id", "entity_id"),
    )
