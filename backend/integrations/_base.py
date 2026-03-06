"""
Base class for all integrations.

Each integration is a single file in backend/integrations/ that subclasses
BaseIntegration. The file contains everything: API client, parser, collector,
config field definitions, and optional custom routes.

To add a new integration:
1. Create integrations/<name>.py
2. Subclass BaseIntegration
3. Done – auto-discovery handles registration
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from fastapi import APIRouter


@dataclass
class ConfigField:
    """Definition of a single configuration field shown in the UI."""
    key: str
    label: str
    field_type: str = "text"      # text | password | number | checkbox | url | select
    placeholder: str = ""
    required: bool = True
    encrypted: bool = False       # store encrypted in config_json
    default: Any = None
    options: list[dict] = field(default_factory=list)  # for select: [{"value": "x", "label": "X"}]


@dataclass
class CollectorResult:
    """Result from a collect() call."""
    success: bool
    data: Any = None
    error: Optional[str] = None


@dataclass
class Alert:
    """An alert extracted from snapshot data."""
    severity: str = "warning"     # critical | warning | info
    title: str = ""
    detail: str = ""
    entity: str = ""              # e.g. "node: pve01" or "VM: 100"


class BaseIntegration(ABC):
    """
    Base class for all integrations.

    Class attributes define metadata; methods define behavior.
    """
    # ── Metadata (override in subclass) ──────────────────────────────────────
    name: str = ""                # URL slug + entity_type, e.g. "proxmox"
    display_name: str = ""        # Human-readable, e.g. "Proxmox VE"
    icon: str = ""                # Simple Icons slug, e.g. "proxmox"
    icon_svg: str = ""            # Optional custom SVG (used if icon is empty)
    description: str = ""

    # ── Config fields (override in subclass) ─────────────────────────────────
    config_fields: list[ConfigField] = []

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize with decrypted config dict."""
        self.config = config or {}

    # ── Required methods ─────────────────────────────────────────────────────

    @abstractmethod
    async def collect(self) -> CollectorResult:
        """
        Collect data from the external service.
        Returns CollectorResult with structured data dict on success.
        """
        ...

    # ── Optional methods (override if needed) ────────────────────────────────

    async def health_check(self) -> bool:
        """Quick connectivity test for 'Test Connection' button."""
        try:
            result = await self.collect()
            return result.success
        except Exception:
            return False

    def parse_alerts(self, data: dict) -> list[Alert]:
        """Extract alerts from snapshot data. Override per integration."""
        return []

    def get_dashboard_summary(self, data: dict) -> dict | None:
        """Return summary dict for dashboard card. Override per integration."""
        return None

    def get_detail_context(self, data: dict, config: dict) -> dict:
        """Return extra template context for the detail page. Override if needed."""
        return {}

    def get_router(self) -> APIRouter | None:
        """Return custom APIRouter if this integration needs non-standard routes."""
        return None

    async def on_snapshot(self, data: dict, config: dict, db) -> None:
        """
        Hook called after a successful snapshot is saved.
        Use for auto-import of hosts, etc.
        """
        pass
