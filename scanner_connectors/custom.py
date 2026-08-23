"""
Custom Scanner Connector — user-defined external tool integration.

Allows users to register any external scanner by providing:
  - command template (with {target} placeholder)
  - output format (json, xml, text)
  - optional parsing rules

This enables integration with tools like Nikto, WPScan, Arachni, etc.
"""
from __future__ import annotations

import os
import subprocess
import json
import tempfile
from pathlib import Path

from .base import ScannerConnector, ScanResult, FindingNormalizer


class CustomScannerConnector(ScannerConnector):
    name = "custom"
    display_name = "Custom Scanner"
    description = ("User-defined tool via CCI_CUSTOM_SCANNER_CMD "
                   "(no command configured → built-in demo scan)")
    requires_auth = False
    config_keys = []  # optional: command, output_format

    OUTPUT_FORMATS = ("json", "xml", "text")

    @property
    def mode(self) -> str:
        return "native-command" if self.config.get("command") else "builtin-demo"

    def is_available(self) -> bool:
        if self.mode == "builtin-demo":
            return True
        cmd_template = self.config["command"]
        base_cmd = cmd_template.replace("{target}", "dummy").split()[0]
        import shutil
        return shutil.which(base_cmd) is not None

    def scan(self, target: str | Path) -> ScanResult:
        if self.mode == "builtin-demo":
            return self._scan_demo(target)
        return self._scan_command(target)

    # ------------------------------------------------------------------
    def _scan_demo(self, target: str | Path) -> ScanResult:
        """Built-in demo: DNS + basic HTTP checks on the target."""
        import socket
        t = str(target).strip()
        host = t.split("/")[0].split(":")[0] or t
        findings = []
        try:
            ip = socket.gethostbyname(host)
            findings.append({
                "title": f"Target resolves to {ip}",
                "severity_score": 1,
                "cwe": "CWE-200",
                "description": f"DNS resolution succeeded for {host}.",
                "file": host,
                "line": 0,
            })
        except socket.gaierror as e:
            return ScanResult(scanner_name=self.name, success=False,
                              findings=[],
                              error=f"Host cannot be resolved: {host} ({e})")
        normalized = [FindingNormalizer.normalize(f, self.name) for f in findings]
        return ScanResult(scanner_name=self.name, success=True,
                          findings=normalized,
                          metadata={"mode": "demo", "target": t})

    # ------------------------------------------------------------------
    def _scan_command(self, target: str | Path) -> ScanResult:
        target = str(target)
        cmd_template = self.config["command"]
        output_format = self.config.get("output_format", "text")

        if not self.is_available():
            return ScanResult(
                scanner_name=self.name, success=False,
                findings=[], error=f"Command not found: {cmd_template.split()[0]}",
            )

        try:
            cmd = cmd_template.format(target=target)
            timeout = int(self.config.get("timeout", 120))

            proc = subprocess.run(
                cmd, shell=True,
                capture_output=True, text=True, timeout=timeout,
            )

            raw_output = proc.stdout
            stderr = proc.stderr

            if proc.returncode != 0 and not raw_output:
                return ScanResult(
                    scanner_name=self.name, success=False,
                    findings=[], error=f"Command failed (rc={proc.returncode}): {stderr[:500]}",
                    raw=stderr,
                )

            findings = self._parse_output(raw_output, output_format)

            return ScanResult(
                scanner_name=self.name, success=True,
                findings=findings, raw=raw_output,
                metadata={"command": cmd, "returncode": proc.returncode},
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner_name=self.name, success=False,
                findings=[], error=f"Scan timed out after {timeout}s",
            )
        except Exception as e:
            return ScanResult(
                scanner_name=self.name, success=False,
                findings=[], error=f"Custom scanner error: {e}",
            )

    def _parse_output(self, raw: str, fmt: str) -> list[dict]:
        """Parse raw scanner output into normalized findings."""
        fmt = fmt.lower()
        if fmt == "json":
            return self._parse_json(raw)
        elif fmt == "xml":
            return self._parse_xml(raw)
        else:
            return self._parse_text(raw)

    def _parse_json(self, raw: str) -> list[dict]:
        findings = []
        try:
            data = json.loads(raw)
            # Handle array of findings
            items = data if isinstance(data, list) else data.get("findings", data.get("vulnerabilities", [data]))
            for item in items:
                findings.append(FindingNormalizer.normalize(item, self.name))
        except (json.JSONDecodeError, TypeError):
            pass
        return findings

    def _parse_xml(self, raw: str) -> list[dict]:
        findings = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw)
            for item in root.iter("finding"):
                findings.append(FindingNormalizer.normalize(
                    {child.tag: child.text for child in item}, self.name
                ))
        except Exception:
            pass
        return findings

    def _parse_text(self, raw: str) -> list[dict]:
        findings = []
        lines = raw.splitlines()
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            # Simple heuristic: lines mentioning CVE, CWE, severity, or risk
            if any(kw in line.lower() for kw in ["cve-", "cwe-", "severity", "risk", "vulnerability", "exploit"]):
                findings.append({
                    "title": line[:100],
                    "severity_score": 5,
                    "cwe": "CWE-20",
                    "description": line[:300],
                    "file": "custom-scan",
                    "line": i,
                })
        return [FindingNormalizer.normalize(f, self.name) for f in findings]

    def test_connection(self) -> dict:
        cmd_template = self.config.get("command", "")
        if not cmd_template:
            return {"ok": False, "info": "No command configured"}
        if self.is_available():
            return {"ok": True, "info": f"Command available: {cmd_template.split()[0]}"}
        return {"ok": False, "info": f"Command not found: {cmd_template.split()[0]}"}


def shutil_which(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None
