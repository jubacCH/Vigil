"""
Syslog receiver – asyncio UDP + TCP server with RFC 3164/5424 parsing,
write-buffered DB inserts, and auto-host assignment.
"""
import asyncio
import logging
import re
from datetime import datetime
from typing import Optional

from sqlalchemy import select, text

from models.base import AsyncSessionLocal
from models.ping import PingHost
from models.syslog import SyslogMessage

log = logging.getLogger("vigil.syslog")

# ── RFC 3164 (BSD syslog) parser ────────────────────────────────────────────

# <PRI>TIMESTAMP HOSTNAME APP[PID]: MESSAGE
_RFC3164_RE = re.compile(
    r"<(\d{1,3})>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # Mon DD HH:MM:SS
    r"(\S+)\s+"                                      # hostname
    r"(.+)"                                           # rest (app + message)
)

_RFC3164_TS_FMTS = [
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",
]


def _parse_3164_ts(ts_str: str) -> datetime:
    now = datetime.utcnow()
    for fmt in _RFC3164_TS_FMTS:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(year=now.year)
        except ValueError:
            continue
    return now


def _split_app_message(rest: str) -> tuple[Optional[str], str]:
    """Split 'app[pid]: message' or 'app: message' into (app_name, message)."""
    m = re.match(r"(\S+?)(?:\[\d+\])?:\s*(.*)", rest, re.DOTALL)
    if m:
        return m.group(1), m.group(2)
    return None, rest


# ── RFC 5424 parser ─────────────────────────────────────────────────────────

# <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
_RFC5424_RE = re.compile(
    r"<(\d{1,3})>"
    r"(\d+)\s+"                                      # version
    r"(\S+)\s+"                                      # timestamp (ISO 8601)
    r"(\S+)\s+"                                      # hostname
    r"(\S+)\s+"                                      # app-name
    r"(\S+)\s+"                                      # procid
    r"(\S+)\s*"                                      # msgid
    r"(?:\[.*?\]\s*)?"                               # structured data (skip)
    r"(.*)"                                           # message
)


def _parse_5424_ts(ts_str: str) -> datetime:
    if ts_str == "-":
        return datetime.utcnow()
    # ISO 8601 with optional fractional seconds and timezone
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return datetime.utcnow()


# ── Unified parser ──────────────────────────────────────────────────────────

def parse_syslog(raw: str, source_ip: str) -> dict:
    """Parse a raw syslog message. Returns dict ready for SyslogMessage fields."""
    raw = raw.strip()
    if not raw:
        return None

    # Try RFC 5424 first (has version number after PRI)
    m = _RFC5424_RE.match(raw)
    if m:
        pri = int(m.group(1))
        facility = pri >> 3
        severity = pri & 7
        ts = _parse_5424_ts(m.group(3))
        hostname = m.group(4) if m.group(4) != "-" else None
        app_name = m.group(5) if m.group(5) != "-" else None
        message = m.group(8) or ""
        return {
            "timestamp": ts,
            "source_ip": source_ip,
            "hostname": hostname,
            "facility": facility,
            "severity": severity,
            "app_name": app_name,
            "message": message.strip(),
        }

    # Try RFC 3164
    m = _RFC3164_RE.match(raw)
    if m:
        pri = int(m.group(1))
        facility = pri >> 3
        severity = pri & 7
        ts = _parse_3164_ts(m.group(2))
        hostname = m.group(3)
        app_name, message = _split_app_message(m.group(4))
        return {
            "timestamp": ts,
            "source_ip": source_ip,
            "hostname": hostname,
            "facility": facility,
            "severity": severity,
            "app_name": app_name,
            "message": message.strip(),
        }

    # Fallback: just PRI + message
    pri_match = re.match(r"<(\d{1,3})>(.*)", raw, re.DOTALL)
    if pri_match:
        pri = int(pri_match.group(1))
        return {
            "timestamp": datetime.utcnow(),
            "source_ip": source_ip,
            "hostname": None,
            "facility": pri >> 3,
            "severity": pri & 7,
            "app_name": None,
            "message": pri_match.group(2).strip(),
        }

    # No PRI at all
    return {
        "timestamp": datetime.utcnow(),
        "source_ip": source_ip,
        "hostname": None,
        "facility": None,
        "severity": 6,  # informational
        "app_name": None,
        "message": raw,
    }


# ── Host cache for auto-assignment ──────────────────────────────────────────

_host_cache: dict[str, int] = {}  # ip_or_hostname -> host_id
_host_cache_ts: float = 0.0
_HOST_CACHE_TTL = 120  # seconds


async def _refresh_host_cache():
    global _host_cache, _host_cache_ts
    import time
    now = time.time()
    if now - _host_cache_ts < _HOST_CACHE_TTL and _host_cache:
        return
    try:
        async with AsyncSessionLocal() as db:
            hosts = (await db.execute(select(PingHost))).scalars().all()
        cache: dict[str, int] = {}
        for h in hosts:
            cache[h.hostname.lower()] = h.id
            if h.name:
                cache[h.name.lower()] = h.id
        _host_cache = cache
        _host_cache_ts = now
    except Exception as e:
        log.warning("Failed to refresh host cache: %s", e)


def _resolve_host_id(source_ip: str, hostname: Optional[str]) -> Optional[int]:
    """Try to match source_ip or hostname to a PingHost."""
    if hostname and hostname.lower() in _host_cache:
        return _host_cache[hostname.lower()]
    if source_ip in _host_cache:
        return _host_cache[source_ip]
    return None


# ── Write buffer ────────────────────────────────────────────────────────────

_buffer: list[dict] = []
_buffer_lock = asyncio.Lock()
_BUFFER_SIZE = 100
_FLUSH_INTERVAL = 2.0  # seconds


async def _enqueue(parsed: dict):
    async with _buffer_lock:
        _buffer.append(parsed)
        if len(_buffer) >= _BUFFER_SIZE:
            await _flush_buffer()


async def _flush_buffer():
    """Write buffered messages to DB. Called with lock held or from flush task."""
    global _buffer
    if not _buffer:
        return
    batch = _buffer[:]
    _buffer = []

    try:
        async with AsyncSessionLocal() as db:
            for msg in batch:
                db.add(SyslogMessage(**msg))
            await db.commit()
    except Exception as e:
        log.error("Failed to flush syslog buffer (%d msgs): %s", len(batch), e)


async def _flush_loop():
    """Periodically flush the write buffer."""
    while True:
        await asyncio.sleep(_FLUSH_INTERVAL)
        async with _buffer_lock:
            await _flush_buffer()


# ── Protocol handlers ───────────────────────────────────────────────────────

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple):
        source_ip = addr[0]
        try:
            raw = data.decode("utf-8", errors="replace")
        except Exception:
            return
        parsed = parse_syslog(raw, source_ip)
        if not parsed:
            return
        parsed["host_id"] = _resolve_host_id(source_ip, parsed.get("hostname"))
        asyncio.ensure_future(_enqueue(parsed))


class SyslogTCPHandler:
    """Handle one TCP connection (one message per line)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer

    async def handle(self):
        addr = self.writer.get_extra_info("peername")
        source_ip = addr[0] if addr else "0.0.0.0"
        try:
            while True:
                line = await asyncio.wait_for(self.reader.readline(), timeout=300)
                if not line:
                    break
                raw = line.decode("utf-8", errors="replace").strip()
                if not raw:
                    continue
                parsed = parse_syslog(raw, source_ip)
                if not parsed:
                    continue
                parsed["host_id"] = _resolve_host_id(source_ip, parsed.get("hostname"))
                await _enqueue(parsed)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self.writer.close()


# ── Server lifecycle ────────────────────────────────────────────────────────

_udp_transport = None
_tcp_server = None
_flush_task = None
_cache_task = None


async def _cache_refresh_loop():
    """Periodically refresh the host cache."""
    while True:
        await _refresh_host_cache()
        await asyncio.sleep(_HOST_CACHE_TTL)


async def start_syslog_server(udp_port: int = 1514, tcp_port: int = 1514):
    """Start UDP + TCP syslog listeners."""
    global _udp_transport, _tcp_server, _flush_task, _cache_task

    loop = asyncio.get_running_loop()

    # Initial host cache load
    await _refresh_host_cache()

    # UDP
    _udp_transport, _ = await loop.create_datagram_endpoint(
        SyslogUDPProtocol, local_addr=("0.0.0.0", udp_port)
    )
    log.info("Syslog UDP listening on port %d", udp_port)

    # TCP
    async def _tcp_client_connected(reader, writer):
        handler = SyslogTCPHandler(reader, writer)
        await handler.handle()

    _tcp_server = await asyncio.start_server(
        _tcp_client_connected, "0.0.0.0", tcp_port
    )
    log.info("Syslog TCP listening on port %d", tcp_port)

    # Background tasks
    _flush_task = asyncio.create_task(_flush_loop())
    _cache_task = asyncio.create_task(_cache_refresh_loop())


async def stop_syslog_server():
    """Stop syslog listeners and flush remaining buffer."""
    global _udp_transport, _tcp_server, _flush_task, _cache_task

    if _flush_task:
        _flush_task.cancel()
    if _cache_task:
        _cache_task.cancel()
    if _udp_transport:
        _udp_transport.close()
    if _tcp_server:
        _tcp_server.close()
        await _tcp_server.wait_closed()

    # Final flush
    async with _buffer_lock:
        await _flush_buffer()

    log.info("Syslog server stopped")
