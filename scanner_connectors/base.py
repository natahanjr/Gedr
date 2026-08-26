"""
Base connector interface and normalization utilities.

Every external scanner connector must inherit from ScannerConnector and
implement the scan() method, returning a ScanResult with normalized findings.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path


@dataclass
class ScanResult:
    """Normalized output from any scanner connector."""

    scanner_name: str
    success: bool
    findings: list[dict] = field(default_factory=list)
    raw_output: Any = None
    error: str | None = None
    metadata: dict = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class FindingNormalizer:
    """Maps external scanner output formats to CCI finding dicts."""

    @staticmethod
    def normalize(finding: dict, scanner_name: str, source: str = "external") -> dict:
        """Map any scanner's finding format to the CCI internal format."""
        return {
            "file": finding.get("file", finding.get("path", finding.get("host", ""))),
            "line": finding.get("line", finding.get("port", 0)),
            "code": finding.get("code", finding.get("description", finding.get("summary", "")))[:300],
            "scanner": scanner_name,
            "rule_id": finding.get("rule_id", finding.get("plugin_id", finding.get("nvt_oid", ""))),
            "title": finding.get("title", finding.get("name", finding.get("script", ""))),
            "severity_score": finding.get("severity_score", finding.get("cvss_base", 5)),
            "severity": finding.get("severity", _score_to_sev(finding.get("severity_score", 5))),
            "cwe": finding.get("cwe", finding.get("cwe_id", "CWE-20")),
            "owasp": finding.get("owasp", "Security Misconfiguration"),
            "description": finding.get("description", finding.get("summary", "")),
            "raw": finding,
            "source": source,
        }


def _score_to_sev(score: int | float) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


class ScannerConnector(ABC):
    """Abstract base class for all external scanner connectors."""

    name: str = "base"
    display_name: str = "Base Connector"
    description: str = "Abstract scanner connector"
    requires_auth: bool = False
    config_keys: list[str] = []

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self._validate_config()

    def _validate_config(self):
        """Ensure required config keys are present."""
        missing = [k for k in self.config_keys if k not in self.config]
        if missing:
            raise ValueError(f"{self.name} connector missing required config: {', '.join(missing)}")

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the scanner tool/service is reachable."""

    @abstractmethod
    def scan(self, target: str | Path) -> ScanResult:
        """Execute the scanner against target and return normalized results."""

    def test_connection(self) -> dict:
        """Quick health check. Returns {'ok': bool, 'info': str}."""
        return {"ok": self.is_available(), "info": self.display_name}
