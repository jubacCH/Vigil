"""Log intelligence models – templates, baselines, precursor patterns."""
from datetime import datetime

from sqlalchemy import (
    Column, DateTime, Float, ForeignKey, Index, Integer,
    SmallInteger, String, Text,
)

from models.base import Base


class LogTemplate(Base):
    """A learned log message template (skeleton with wildcards)."""
    __tablename__ = "log_templates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    template_hash = Column(String(32), unique=True, nullable=False, index=True)
    template = Column(Text, nullable=False)          # "Failed password for <*> from <*> port <*>"
    example = Column(Text)                           # One real message
    count = Column(Integer, default=1)               # Total occurrences
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    noise_score = Column(SmallInteger, default=50)   # 0=very interesting, 100=total noise
    tags = Column(String(256), default="")           # comma-separated auto-tags
    avg_rate_per_hour = Column(Float, default=0.0)   # learned average rate


class HostBaseline(Base):
    """Per-host hourly message rate baseline (7-day rolling)."""
    __tablename__ = "host_baselines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_key = Column(String(64), nullable=False)    # source_ip or "host:<host_id>"
    hour_of_day = Column(SmallInteger, nullable=False)  # 0-23
    day_of_week = Column(SmallInteger, nullable=False)  # 0=Mon, 6=Sun
    avg_rate = Column(Float, default=0.0)            # messages per hour
    std_rate = Column(Float, default=0.0)            # standard deviation
    sample_count = Column(Integer, default=0)        # how many weeks of data
    updated_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_baseline_host_time", "host_key", "hour_of_day", "day_of_week", unique=True),
    )


class PrecursorPattern(Base):
    """Learned pattern: template X often precedes event Y."""
    __tablename__ = "precursor_patterns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    template_id = Column(Integer, ForeignKey("log_templates.id"), nullable=False)
    precedes_event = Column(String(64), nullable=False)  # "host_down", "high_latency"
    confidence = Column(Float, default=0.0)          # 0.0 - 1.0
    avg_lead_time_sec = Column(Integer, default=0)   # seconds before event
    occurrence_count = Column(Integer, default=0)     # how often observed
    total_checked = Column(Integer, default=0)        # total times template appeared
    updated_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_precursor_tpl_event", "template_id", "precedes_event", unique=True),
    )
