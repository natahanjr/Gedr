"""
OpenVAS (Greenbone Vulnerability Management) connector.

Dual mode:
  1. If gvmd/ospd-openvas tools or a GMP listener are available → real OpenVAS.
  2. Otherwise → built-in network exposure assessment with pure Python:
       - Well-known vulnerable service ports
       - Banner grabbing for version disclosure
       - Common admin-interface exposure checks
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import ScannerConnector, ScanResult, FindingNormalizer


class OpenVASConnector(ScannerConnector):
    name = "openvas"
    display_name = "OpenVAS (GVM)"
    description = "Greenbone OpenVAS (real if available, else built-in exposure scan)"
    requires_auth = False
    config_keys = []  # optional: host, port, username, password enable native mode

    # Default GMP port
    DEFAULT_PORT = 9390
    DEFAULT_SCAN_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast

    # ------------------------------------------------------------------
    @property
    def mode(self) -> str:
        if shutil.which("gvmd") or shutil.which("ospd-openvas"):
            return "native-openvas"
        try:
            with socket.create_connection(
                (self.config.get("host", "localhost"), self.DEFAULT_PORT), timeout=2
            ):
                return "native-openvas"
        except Exception:
            return "builtin-exposure"

    def is_available(self) -> bool:
        return True  # built-in mode always works

    # ------------------------------------------------------------------
    def scan(self, target: str | Path) -> ScanResult:
        target = str(target).strip()
        result = (
            self._scan_native(target)
            if self.mode == "native-openvas"
            else self._scan_builtin(target)
        )
        result.metadata["target"] = target
        result.metadata["mode"] = self.mode
        return result

    # ------------------------------------------------------------------
    def _scan_native(self, target: str) -> ScanResult:
        findings: list[dict] = []
        if shutil.which("gvmd"):
            return self._scan_with_gvmd(target, findings)
        if shutil.which("ospd-openvas"):
            return self._scan_with_ospd(target, findings)
        return ScanResult(
            scanner_name=self.name,
            success=False,
            findings=[],
            error="GMP listener detected but no gvmd CLI to drive it",
        )

    # ------------------------------------------------------------------
    # Built-in exposure assessment
    # ------------------------------------------------------------------
    EXPOSURE_PORTS = {
        21: ("FTP service exposed - check anonymous access", "CWE-284", 6),
        22: ("SSH exposed - verify key-only auth and version", "CWE-16", 3),
        23: ("Telnet exposed - cleartext remote administration", "CWE-319", 9),
        25: ("SMTP exposed - check open relay status", "CWE-16", 4),
        80: ("HTTP exposed - assess TLS migration", "CWE-319", 3),
        110: ("POP3 cleartext exposed", "CWE-319", 5),
        135: ("MSRPC exposed - Windows enumeration vector", "CWE-284", 7),
        139: ("NetBIOS exposed - information disclosure", "CWE-200", 7),
        143: ("IMAP cleartext exposed", "CWE-319", 5),
        443: ("HTTPS exposed - verify TLS configuration", "CWE-16", 2),
        445: ("SMB exposed - EternalBlue-class risk", "CWE-284", 8),
        3306: ("MySQL exposed - should be firewalled", "CWE-284", 8),
        3389: ("RDP exposed - brute-force target", "CWE-284", 8),
        5432: ("PostgreSQL exposed - should be firewalled", "CWE-284", 8),
        5900: ("VNC exposed - weak auth common", "CWE-284", 9),
        6379: ("Redis exposed - often unauthenticated", "CWE-306", 9),
        8080: ("HTTP alt exposed - check proxy misconfig", "CWE-16", 4),
        8443: ("HTTPS alt exposed - verify certificate", "CWE-16", 3),
        9200: ("Elasticsearch exposed - data at risk", "CWE-306", 9),
        27017: ("MongoDB exposed - often unauthenticated", "CWE-306", 9),
        11211: ("Memcached exposed - amplification DDoS vector", "CWE-406", 9),
        161: ("SNMP exposed - default community strings common", "CWE-798", 8),
        1900: ("UPnP exposed - device discovery risk", "CWE-284", 5),
        5000: ("Port 5000 exposed - identify service", "CWE-16", 4),
    }

    BANNER_VERSION_PATTERNS = [
        (re.compile(r"OpenSSH[_ ](\d+\.\d+)", re.I), "OpenSSH"),
        (re.compile(r"Apache[/ ](\d+\.\d+[\.\d]*)", re.I), "Apache"),
        (re.compile(r"nginx[/ ](\d+\.\d+[\.\d]*)", re.I), "nginx"),
        (re.compile(r"vsftpd[/ ]?(\d+\.\d+[\.\d]*)", re.I), "vsftpd"),
        (re.compile(r"Postfix", re.I), "Postfix"),
        (re.compile(r"MySQL", re.I), "MySQL"),
        (re.compile(r"Redis", re.I), "Redis"),
    ]

    def _scan_builtin(self, target: str) -> ScanResult:
        host = self._normalize_host(target)
        if not host:
            return ScanResult(scanner_name=self.name, success=False,
                              findings=[], error=f"Cannot parse host from: {target}")
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            return ScanResult(scanner_name=self.name, success=False,
                              findings=[], error=f"Host cannot be resolved: {host}")

        open_ports = []
        ports = sorted(self.EXPOSURE_PORTS.keys())

        def probe(port: int):
            try:
                with socket.create_connection((host, port), timeout=1.5) as s:
                    banner = ""
                    try:
                        s.settimeout(1.0)
                        banner = s.recv(256).decode("utf-8", errors="replace").strip()
                    except (socket.timeout, OSError):
                        pass
                    open_ports.append((port, banner))
            except (ConnectionRefusedError, socket.timeout, OSError):
                pass

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=25) as pool:
            list(pool.map(probe, ports))

        findings = []
        for port, banner in sorted(open_ports):
            title, cwe, score = self.EXPOSURE_PORTS[port]
            desc = f"{title}. Port {port} is open on {host}."
            # Version disclosure via banner
            for pat, product in self.BANNER_VERSION_PATTERNS:
                m = pat.search(banner)
                if m:
                    ver = m.group(1) if m.lastindex else ""
                    findings.append({
                        "title": f"{product}{' ' + ver if ver else ''} version disclosed in banner",
                        "severity_score": 3,
                        "cwe": "CWE-200",
                        "description": f"Banner on {host}:{port} reveals software version, aiding targeted attacks.",
                        "file": host,
                        "line": port,
                    })
                    break
            findings.append({
                "title": f"{title} (port {port})",
                "severity_score": score,
                "cwe": cwe,
                "description": desc,
                "file": host,
                "line": port,
            })

        if not open_ports:
            findings.append({
                "title": "No exposed services found on scanned ports",
                "severity_score": 1,
                "cwe": "CWE-20",
                "description": f"None of the {len(ports)} well-known ports were reachable on {host}.",
                "file": host,
                "line": 0,
            })

        normalized = [FindingNormalizer.normalize(f, self.name) for f in findings]
        return ScanResult(scanner_name=self.name, success=True,
                          findings=normalized,
                          metadata={"ports_open": len(open_ports)})

    @staticmethod
    def _normalize_host(target: str) -> str | None:
        t = target.strip()
        if "://" in t:
            from urllib.parse import urlparse
            t = urlparse(t).hostname or ""
        t = t.split("/")[0].split(":")[0].strip()
        return t or None

    # ------------------------------------------------------------------
    # Native paths (unchanged)
    # ------------------------------------------------------------------

    def _scan_with_gvmd(self, target: str, findings: list[dict]) -> ScanResult:
        host = self.config.get("host", "localhost")
        port = str(self.config.get("port", self.DEFAULT_PORT))
        username = self.config.get("username", "")
        password = self.config.get("password", "")
        scan_name = f"cci-scan-{int(time.time())}"

        try:
            # Create target
            t_out = subprocess.run(
                [
                    "gvmd", "--gmp", "--host", host, "--port", port,
                    "--username", username, "--password", password,
                    "--xml", "<create_target><name>cci-target</name><hosts>"
                    + target + "</hosts></create_target>",
                ],
                capture_output=True, text=True, timeout=30,
            )
            target_id = self._extract_gmp_id(t_out.stdout)

            if not target_id:
                return ScanResult(
                    scanner_name=self.name, success=False,
                    findings=[], error="Failed to create OpenVAS target",
                    raw=t_out.stdout,
                )

            # Create task
            config_id = self.DEFAULT_SCAN_CONFIG
            t_out = subprocess.run(
                [
                    "gvmd", "--gmp", "--host", host, "--port", port,
                    "--username", username, "--password", password,
                    "--xml",
                    f"<create_task><name>{scan_name}</name><config id='{config_id}'/><target id='{target_id}'/></create_task>",
                ],
                capture_output=True, text=True, timeout=30,
            )
            task_id = self._extract_gmp_id(t_out.stdout)

            if not task_id:
                return ScanResult(
                    scanner_name=self.name, success=False,
                    findings=[], error="Failed to create OpenVAS task",
                    raw=t_out.stdout,
                )

            # Start task
            subprocess.run(
                [
                    "gvmd", "--gmp", "--host", host, "--port", port,
                    "--username", username, "--password", password,
                    "--xml", f"<start_task task_id='{task_id}'/>",
                ],
                capture_output=True, text=True, timeout=30,
            )

            # Poll for completion (simplified — in production use GMP events)
            time.sleep(10)

            # Get results
            r_out = subprocess.run(
                [
                    "gvmd", "--gmp", "--host", host, "--port", port,
                    "--username", username, "--password", password,
                    "--xml",
                    f"<get_reports><report_id>results/{task_id}</report_id><format_id>c6573abb-9387-4c0b-aa86-58dcbed60ad3</format_id></get_reports>",
                ],
                capture_output=True, text=True, timeout=60,
            )

            findings = self._parse_gmp_results(r_out.stdout)

            return ScanResult(
                scanner_name=self.name,
                success=True,
                findings=findings,
                raw=r_out.stdout,
                metadata={"task_id": task_id, "target_id": target_id},
            )

        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner_name=self.name, success=False,
                findings=[], error="OpenVAS scan timed out",
            )
        except Exception as e:
            return ScanResult(
                scanner_name=self.name, success=False,
                findings=[], error=f"OpenVAS error: {e}",
            )

    def _scan_with_ospd(self, target: str, findings: list[dict]) -> ScanResult:
        """Use ospd-openvas client if available."""
        try:
            from gvm.connections import TLSConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform

            host = self.config.get("host", "localhost")
            port = int(self.config.get("port", self.DEFAULT_PORT))
            username = self.config.get("username", "")
            password = self.config.get("password", "")

            conn = TLSConnection(hostname=host, port=port)
            with Gmp(conn, transform=EtreeTransform()) as gmp:
                gmp.authenticate(username, password)

                # Create target
                target_resp = gmp.create_target(
                    name=f"cci-target-{int(time.time())}",
                    hosts=[target],
                )
                target_id = target_resp.get("id")

                # Create and start task
                task_resp = gmp.create_task(
                    name=f"cci-scan-{int(time.time())}",
                    config_id=self.DEFAULT_SCAN_CONFIG,
                    target_id=target_id,
                )
                task_id = task_resp.get("id")
                gmp.start_task(task_id)

                # Get results (simplified)
                time.sleep(10)
                report = gmp.get_reports()
                findings = self._parse_gmp_results(ET.tostring(report))

            return ScanResult(
                scanner_name=self.name, success=True,
                findings=findings, metadata={"task_id": task_id},
            )
        except ImportError:
            return ScanResult(
                scanner_name=self.name, success=False,
                findings=[], error="python-gvm library not installed. Run: pip install python-gvm",
            )
        except Exception as e:
            return ScanResult(
                scanner_name=self.name, success=False,
                findings=[], error=f"OpenVAS GMP error: {e}",
            )

    def _extract_gmp_id(self, xml_text: str) -> str | None:
        """Extract an entity ID from GMP XML response."""
        try:
            root = ET.fromstring(xml_text)
            return root.attrib.get("id")
        except Exception:
            return None

    def _parse_gmp_results(self, xml_text: str) -> list[dict]:
        """Parse OpenVAS report XML into normalized findings."""
        findings = []
        try:
            root = ET.fromstring(xml_text)
            for result in root.iter("result"):
                finding = {
                    "title": self._text(result, "name"),
                    "severity_score": self._cvss(result),
                    "cwe": self._text(result, "cwe") or "CWE-20",
                    "description": self._text(result, "description"),
                    "file": self._text(result, "host"),
                    "port": self._text(result, "port"),
                }
                findings.append(FindingNormalizer.normalize(finding, self.name))
        except Exception:
            pass
        return findings

    def _text(self, parent, tag: str) -> str | None:
        el = parent.find(tag)
        return el.text if el is not None and el.text else None

    def _cvss(self, result) -> float:
        """Extract CVSS base score from OpenVAS result."""
        el = result.find("cvss_base")
        try:
            return float(el.text) if el is not None and el.text else 5.0
        except (ValueError, TypeError):
            return 5.0


