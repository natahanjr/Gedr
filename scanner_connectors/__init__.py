"""
Gədr — External Scanner Connector Framework

Provides a pluggable interface for integrating external security scanners:
  - OpenVAS (GVM) — full vulnerability assessment
  - Nmap — network discovery and port scanning
  - Nessus — commercial vulnerability scanner
  - Custom Scanner — user-defined external tool integration

Each connector normalizes its output to the Gədr finding format
so results merge seamlessly with the heuristic engine.
"""
from .base import ScannerConnector, ScanResult, FindingNormalizer
from .registry import ConnectorRegistry, get_registry
from .openvas import OpenVASConnector
from .nmap import NmapConnector
from .nessus import NessusConnector
from .custom import CustomScannerConnector

__all__ = [
    "ScannerConnector",
    "ScanResult",
    "FindingNormalizer",
    "ConnectorRegistry",
    "get_registry",
    "OpenVASConnector",
    "NmapConnector",
    "NessusConnector",
    "CustomScannerConnector",
]
