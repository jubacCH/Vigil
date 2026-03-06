"""SyslogMessage model – stores parsed syslog messages with PostgreSQL FTS."""
from datetime import datetime

from sqlalchemy import (
    Column, DateTime, ForeignKey, Index, Integer, SmallInteger, String, Text,
)
from sqlalchemy.dialects.postgresql import TSVECTOR

from models.base import Base


# RFC 5424 severity levels
SEVERITY_LABELS = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Informational",
    7: "Debug",
}

SEVERITY_COLORS = {
    0: "red",
    1: "red",
    2: "red",
    3: "orange",
    4: "yellow",
    5: "blue",
    6: "green",
    7: "gray",
}

FACILITY_LABELS = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}


class SyslogMessage(Base):
    __tablename__ = "syslog_messages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    received_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    source_ip = Column(String(45), nullable=False)           # IPv4 or IPv6
    hostname = Column(String(255), nullable=True)             # parsed hostname
    facility = Column(SmallInteger, nullable=True)            # 0-23
    severity = Column(SmallInteger, nullable=True)            # 0-7
    app_name = Column(String(128), nullable=True)             # process/app name
    message = Column(Text, nullable=False)
    host_id = Column(Integer, ForeignKey("ping_hosts.id"), nullable=True)  # auto-assigned

    # PostgreSQL full-text search vector (auto-maintained via trigger)
    search_vector = Column(TSVECTOR)

    __table_args__ = (
        Index("ix_syslog_ts", timestamp.desc()),
        Index("ix_syslog_host_ts", "host_id", timestamp.desc()),
        Index("ix_syslog_severity_ts", "severity", timestamp.desc()),
        Index("ix_syslog_source_ip", "source_ip"),
        Index("ix_syslog_fts", "search_vector", postgresql_using="gin"),
    )
