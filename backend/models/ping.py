"""PingHost and PingResult models – high-volume time-series, kept separate."""
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import relationship

from models.base import Base


class PingHost(Base):
    __tablename__ = "ping_hosts"
    id                   = Column(Integer, primary_key=True, autoincrement=True)
    name                 = Column(String, nullable=False)
    hostname             = Column(String, nullable=False)
    enabled              = Column(Boolean, default=True)
    check_type           = Column(String, default="icmp")   # icmp | http | https | tcp
    port                 = Column(Integer, nullable=True)
    latency_threshold_ms = Column(Float, nullable=True)
    maintenance          = Column(Boolean, default=False)
    ssl_expiry_days      = Column(Integer, nullable=True)
    source               = Column(String, default="manual") # manual | phpipam | proxmox | unifi
    source_detail        = Column(String, nullable=True)
    mac_address          = Column(String, nullable=True)
    parent_id            = Column(Integer, ForeignKey("ping_hosts.id"), nullable=True)
    created_at           = Column(DateTime, default=datetime.utcnow)
    results = relationship("PingResult", back_populates="host", cascade="all, delete-orphan")
    children = relationship("PingHost", foreign_keys=[parent_id], viewonly=True)


class PingResult(Base):
    __tablename__ = "ping_results"
    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("ping_hosts.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    success = Column(Boolean, nullable=False)
    latency_ms = Column(Float, nullable=True)
    host = relationship("PingHost", back_populates="results")

    __table_args__ = (
        Index("ix_ping_results_host_ts", "host_id", timestamp.desc()),
        Index("ix_ping_results_host_success_ts", "host_id", "success", "timestamp"),
    )
