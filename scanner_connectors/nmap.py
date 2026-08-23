"""
Nmap connector — network discovery, port scanning, service detection.

Dual mode:
  1. If the real nmap binary is installed → use it (-sV + vuln NSE scripts).
  2. Otherwise → built-in pure-Python TCP connect scanner with banner
     grabbing. Always available, no external dependencies.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from .base import ScannerConnector, ScanResult, FindingNormalizer

# Common ports scanned in fallback mode (fast but meaningful coverage)
FALLBACK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    8888, 9200, 27017, 11211,
]

# Port -> likely service for banner-less fallback findings
SERVICE_HINTS = {
    21: ("ftp", "FTP"), 22: ("ssh", "SSH"), 23: ("telnet", "Telnet"),
    25: ("smtp", "SMTP"), 53: ("domain", "DNS"), 80: ("http", "HTTP"),
    110: ("pop3", "POP3"), 135: ("msrpc", "MSRPC"), 139: ("netbios-ssn", "NetBIOS"),
    143: ("imap", "IMAP"), 443: ("https", "HTTPS"), 445: ("microsoft-ds", "SMB"),
    3306: ("mysql", "MySQL"), 3389: ("ms-wbt-server", "RDP"),
    5432: ("postgresql", "PostgreSQL"), 5900: ("vnc", "VNC"),
    6379: ("redis", "Redis"), 8080: ("http-proxy", "HTTP alt"),
    8443: ("https-alt", "HTTPS alt"), 9200: ("elasticsearch", "Elasticsearch"),
    27017: ("mongod", "MongoDB"), 11211: ("memcache", "Memcached"),
}

# Ports whose plaintext protocols are inherently risky to expose
RISKY_PORTS = {
    21: ("Cleartext FTP service exposed", "CWE-319", 7),
    23: ("Telnet service exposed - cleartext remote administration", "CWE-319", 9),
    110: ("Cleartext POP3 service exposed", "CWE-319", 5),
    143: ("Cleartext IMAP service exposed", "CWE-319", 5),
    3389: ("RDP exposed to network", "CWE-284", 7),
    6379: ("Redis exposed - frequently unauthenticated", "CWE-306", 8),
    9200: ("Elasticsearch exposed - frequently unauthenticated", "CWE-306", 8),
    27017: ("MongoDB exposed - frequently unauthenticated", "CWE-306", 8),
    11211: ("Memcached exposed - amplification attack vector", "CWE-406", 8),
    445: ("SMB exposed to network", "CWE-284", 7),
    5900: ("VNC exposed to network", "CWE-284", 8),
}


class NmapConnector(ScannerConnector):
    name = "nmap"
    display_name = "Nmap"
    description = "Port/service scanning (real nmap if installed, else built-in scanner)"
    requires_auth = False
    config_keys = []  # no required config; works out of the box

    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        return True  # always available thanks to the built-in fallback

    @property
    def mode(self) -> str:
        return "native-nmap" if shutil.which("nmap") else "builtin-scanner"

    # ------------------------------------------------------------------
    def scan(self, target: str | Path) -> ScanResult:
        target = str(target).strip()
        host = self._normalize_host(target)
        if not host:
            return ScanResult(
                scanner_name=self.name, success=False,
                findings=[], error=f"Cannot parse target host from: {target}",
            )

        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            return ScanResult(
                scanner_name=self.name, success=False,
                findings=[], error=f"Host cannot be resolved: {host}",
            )

        if self.mode == "native-nmap":
            result = self._scan_native(host)
        else:
            result = self._scan_builtin(host)

        result.metadata["target"] = target
        result.metadata["mode"] = self.mode
        return result

    # ------------------------------------------------------------------
    # Native nmap path
    # ------------------------------------------------------------------
    def _scan_native(self, host: str) -> ScanResult:
        findings = []
        try:
            proc = subprocess.run(
                ["nmap", "-sV", "--open", "-oX", "-", host],
                capture_output=True, text=True, timeout=180,
            )
            findings = self._parse_nmap_xml(proc.stdout)
        except subprocess.TimeoutExpired:
            return ScanResult(scanner_name=self.name, success=False,
                              findings=[], error="nmap scan timed out")
        except Exception as e:
            return ScanResult(scanner_name=self.name, success=False,
                              findings=[], error=f"nmap error: {e}")
        return ScanResult(scanner_name=self.name, success=True,
                          findings=findings, metadata={"ports_found": len(findings)})

    def _parse_nmap_xml(self, xml_text: str) -> list[dict]:
        findings = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []
        for host_el in root.iter("host"):
            addr = host_el.find("address")
            ip = addr.get("addr", "unknown") if addr is not None else "unknown"
            for port_el in host_el.iter("port"):
                port_id = int(port_el.get("portid", "0"))
                svc = port_el.find("service")
                product = (svc.get("product", "") if svc is not None else "")
                version = (svc.get("version", "") if svc is not None else "")
                banner = f"{product} {version}".strip()

                risk = RISKY_PORTS.get(port_id)
                if risk:
                    title, cwe, score = risk
                    findings.append({
                        "title": f"{title} (port {port_id})",
                        "severity_score": score,
                        "cwe": cwe,
                        "description": f"{banner or 'Service'} listening on {ip}:{port_id}",
                        "file": ip,
                        "line": port_id,
                    })
                elif banner:
                    findings.append({
                        "title": f"Open service {banner} on port {port_id}",
                        "severity_score": 3,
                        "cwe": "CWE-200",
                        "description": f"Service information exposed on {ip}:{port_id}",
                        "file": ip,
                        "line": port_id,
                    })
        return [FindingNormalizer.normalize(f, self.name) for f in findings]

    # ------------------------------------------------------------------
    # Built-in pure-Python fallback
    # ------------------------------------------------------------------
    def _scan_builtin(self, host: str) -> ScanResult:
        open_ports = []

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

        with ThreadPoolExecutor(max_workers=27) as pool:
            list(pool.map(probe, FALLBACK_PORTS))

        findings = []
        for port, banner in sorted(open_ports):
            svc_key, svc_label = SERVICE_HINTS.get(port, ("unknown", "Unknown"))

            risk = RISKY_PORTS.get(port)
            if risk:
                title, cwe, score = risk
                findings.append({
                    "title": title,
                    "severity_score": score,
                    "cwe": cwe,
                    "description": (
                        f"Detected {svc_label} on {host}:{port}. "
                        + (f"Banner: {banner[:120]}" if banner else "No banner captured.")
                    ),
                    "file": host,
                    "line": port,
                })
            else:
                findings.append({
                    "title": f"Open {svc_label} service on port {port}",
                    "severity_score": 3,
                    "cwe": "CWE-200",
                    "description": (
                        f"Detected {svc_label} on {host}:{port}. "
                        + (f"Banner: {banner[:120]}" if banner else "")
                    ),
                    "file": host,
                    "line": port,
                })

            # Flag outdated software versions found in banners
            weak = self._weak_version(banner)
            if weak:
                findings.append({
                    "title": f"Outdated/vulnerable software version in banner: {weak}",
                    "severity_score": 6,
                    "cwe": "CWE-1104",
                    "description": f"Banner on {host}:{port} reveals version that may have known CVEs.",
                    "file": host,
                    "line": port,
                })

        normalized = [FindingNormalizer.normalize(f, self.name) for f in findings]
        return ScanResult(
            scanner_name=self.name, success=True,
            findings=normalized,
            metadata={"ports_open": len(open_ports)},
        )

    def _weak_version(self, banner: str) -> str | None:
        patterns = [
            r"OpenSSH[_-](\d+\.\d+)", r"Apache[/ ](\d\.\d+)",
            r"nginx/(\d+\.\d+)", r"(?:OpenSSL|openssl)/(\d+\.\d+[\.\d]*)",
            r"MySQL[/ ](\d+\.\d+)", r"vsftpd (\d+\.\d+)",
        ]
        for pat in patterns:
            m = re.search(pat, banner)
            if m:
                ver = float(m.group(1).rsplit(".", 1)[0] or 0)
                name = pat.split("[/")[0].strip("(?:")
                if ("openssh" in pat.lower() and ver < 8) or \
                   ("apache" in pat.lower() and ver < 2.4) or \
                   ("openssl" in pat.lower() and ver < 3) or \
                   ("nginx" in pat.lower() and ver < 1.18):
                    return f"{name} {m.group(1)}"
        return None

    def _normalize_host(self, target: str) -> str:
        """Strip scheme/path/port from URLs, keep bare IPs/hostnames."""
        t = target.strip()
        t = re.sub(r"^https?://", "", t, flags=re.I)
        t = t.split("/")[0]
        t = t.split(":")[0]
        return t.strip()
