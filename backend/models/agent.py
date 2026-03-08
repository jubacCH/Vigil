"""Agent model — stores registered agent hosts and their metric snapshots."""
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Index, Integer, String, Text, func

from models.base import Base


class Agent(Base):
    """A registered agent host that reports metrics."""
    __tablename__ = "agents"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    name       = Column(String(128), nullable=False)
    hostname   = Column(String(256), nullable=True)
    token      = Column(String(64), nullable=False, unique=True, index=True)
    platform   = Column(String(32), nullable=True)
    arch       = Column(String(32), nullable=True)
    agent_version = Column(String(16), nullable=True)
    enabled    = Column(Boolean, default=True)
    log_levels = Column(String(32), nullable=True, default="1,2,3")  # Windows Event Log levels to collect
    last_seen  = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_agents_hostname_lower", func.lower(hostname), unique=True),
    )


class AgentSnapshot(Base):
    """One metric report from an agent."""
    __tablename__ = "agent_snapshots"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    agent_id   = Column(Integer, nullable=False, index=True)
    timestamp  = Column(DateTime, default=datetime.utcnow)
    cpu_pct    = Column(Float, nullable=True)
    mem_pct    = Column(Float, nullable=True)
    mem_used_mb = Column(Float, nullable=True)
    mem_total_mb = Column(Float, nullable=True)
    disk_pct   = Column(Float, nullable=True)       # primary disk usage %
    load_1     = Column(Float, nullable=True)
    load_5     = Column(Float, nullable=True)
    load_15    = Column(Float, nullable=True)
    uptime_s   = Column(Integer, nullable=True)
    rx_bytes   = Column(Float, nullable=True)        # cumulative
    tx_bytes   = Column(Float, nullable=True)        # cumulative
    data_json  = Column(Text, nullable=True)         # full payload (disks, processes etc.)

    __table_args__ = (
        Index("ix_agent_snap_ts", "agent_id", timestamp.desc()),
    )
