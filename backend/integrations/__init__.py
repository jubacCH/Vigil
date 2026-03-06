"""
Integration registry with auto-discovery.

All .py files in this package (except _base.py) are scanned for
BaseIntegration subclasses and registered automatically.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from integrations._base import BaseIntegration

logger = logging.getLogger(__name__)

_registry: dict[str, type[BaseIntegration]] = {}


def _discover():
    """Import all integration modules and register BaseIntegration subclasses."""
    from integrations._base import BaseIntegration as _Base

    pkg_dir = str(Path(__file__).parent)
    for _, module_name, _ in pkgutil.iter_modules([pkg_dir]):
        if module_name.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f"integrations.{module_name}")
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, _Base)
                    and obj is not _Base
                    and obj.name  # skip incomplete stubs
                ):
                    _registry[obj.name] = obj
                    logger.debug("Registered integration: %s (%s)", obj.name, obj.display_name)
        except Exception:
            logger.exception("Failed to load integration module: %s", module_name)


def get_registry() -> dict[str, type[BaseIntegration]]:
    """Return the integration registry. Auto-discovers on first call."""
    if not _registry:
        _discover()
    return _registry


def get_integration(name: str) -> type[BaseIntegration] | None:
    """Get a specific integration class by name."""
    return get_registry().get(name)
