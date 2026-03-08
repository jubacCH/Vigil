"""Structured JSON logging configuration for Nodeglow."""
import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Format log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exc"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_data"):
            entry.update(record.extra_data)
        return json.dumps(entry, default=str, ensure_ascii=False)


def setup_logging(*, level: str = "INFO", json_output: bool = True):
    """Configure root logger. Call once at startup."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    if json_output:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
    root.addHandler(handler)

    # Quiet noisy libraries
    for name in ("uvicorn.access", "httpx", "httpcore", "asyncio",
                 "aiosqlite", "sqlalchemy.engine"):
        logging.getLogger(name).setLevel(logging.WARNING)
