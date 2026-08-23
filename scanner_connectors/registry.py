"""
Connector registry — discovers, loads, and manages scanner connectors.
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from .base import ScannerConnector, ScanResult


class ConnectorRegistry:
    """Central registry for all scanner connectors."""

    def __init__(self):
        self._connectors: dict[str, type[ScannerConnector]] = {}
        self._instances: dict[str, ScannerConnector] = {}
        self._discover()

    def _discover(self):
        """Auto-discover connectors in this package."""
        import sys
        pkg_name = __package__
        if not pkg_name or pkg_name not in sys.modules:
            return
        pkg_path = getattr(sys.modules[pkg_name], "__path__", None)
        if not pkg_path:
            return
        for mod_info in pkgutil.iter_modules(pkg_path):
            if mod_info.name in ("base", "registry", "__init__"):
                continue
            try:
                mod = importlib.import_module(f"{pkg_name}.{mod_info.name}")
                for attr in dir(mod):
                    obj = getattr(mod, attr)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, ScannerConnector)
                        and obj is not ScannerConnector
                        and hasattr(obj, "name")
                    ):
                        self._connectors[obj.name] = obj
            except Exception as e:
                print(f"[connectors] failed to load {mod_info.name}: {e}")

    def register(self, connector_cls: type[ScannerConnector]):
        """Manually register a connector class."""
        self._connectors[connector_cls.name] = connector_cls

    def get(self, name: str) -> type[ScannerConnector] | None:
        return self._connectors.get(name)

    def get_instance(self, name: str, config: dict | None = None) -> ScannerConnector | None:
        """Return (cached) instance, creating it if needed."""
        if name not in self._connectors:
            return None
        if name not in self._instances:
            self._instances[name] = self._connectors[name](config)
        return self._instances[name]

    def list_available(self) -> list[dict]:
        """List all connectors with their connection status."""
        out = []
        for name, cls in self._connectors.items():
            try:
                inst = cls()
                ok = inst.is_available()
            except Exception:
                ok = False
            out.append({
                "name": name,
                "display_name": cls.display_name,
                "description": cls.description,
                "available": ok,
                "requires_auth": cls.requires_auth,
            })
        return out

    @property
    def names(self) -> list[str]:
        return list(self._connectors.keys())


def get_registry() -> ConnectorRegistry:
    """Singleton accessor."""
    if not hasattr(get_registry, "_instance"):
        get_registry._instance = ConnectorRegistry()  # type: ignore
    return get_registry._instance  # type: ignore
