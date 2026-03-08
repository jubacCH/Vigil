"""Shared Jinja2 templates with timezone-aware filters."""

import contextvars
from datetime import datetime, timezone as _tz

from fastapi.templating import Jinja2Templates

try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo  # Python 3.8

# Current timezone name — set by middleware on each request
current_tz = contextvars.ContextVar("timezone", default="UTC")

templates = Jinja2Templates(directory="templates")


def localtime(dt, fmt=None):
    """Convert naive UTC datetime to the configured timezone.

    Usage in templates:
        {{ dt|localtime }}                  → "2026-03-08 11:30:45"
        {{ dt|localtime("%H:%M:%S") }}      → "11:30:45"
        {{ dt|localtime("%d.%m.%Y %H:%M") }}→ "08.03.2026 11:30"
    """
    if dt is None:
        return "—"
    if fmt is None:
        fmt = "%Y-%m-%d %H:%M:%S"
    try:
        tzname = current_tz.get()
        if tzname and tzname != "UTC":
            # Handle both naive (UTC assumed) and aware datetimes
            if dt.tzinfo is None:
                utc_dt = dt.replace(tzinfo=_tz.utc)
            else:
                utc_dt = dt
            local_dt = utc_dt.astimezone(ZoneInfo(tzname))
            return local_dt.strftime(fmt)
    except Exception:
        pass
    return dt.strftime(fmt)


templates.env.filters["localtime"] = localtime
