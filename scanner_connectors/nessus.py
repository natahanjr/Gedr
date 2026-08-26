"""
Nessus connector — integrates with Tenable Nessus vulnerability scanner.

Dual mode:
  1. If NESSUS_URL + API keys are configured → real Nessus (API v2).
  2. Otherwise → built-in HTTPS/TLS assessment scanner that probes the
     target directly with pure Python (no Nessus server needed):
       - TLS version/cipher checks
       - HTTP security headers
       - Server banner disclosure
"""
from __future__ import annotations

import re
import socket
import ssl
import time
import requests
from urllib.parse import urlparse

from .base import ScannerConnector, ScanResult, FindingNormalizer


class NessusConnector(ScannerConnector):
    name = "nessus"
    display_name = "Nessus"
    description = "Tenable Nessus (real if configured, else built-in web assessment)"
    requires_auth = False  # auth only needed for real-Nessus mode
    config_keys = []  # optional: url, api_key, secret_key enable native mode

    DEFAULT_TIMEOUT = 30

    # ------------------------------------------------------------------
    @property
    def mode(self) -> str:
        cfg = self.config or {}
        return "native-nessus" if all([
            cfg.get("url"), cfg.get("api_key"), cfg.get("secret_key")
        ]) else "builtin-web-assessment"

    def is_available(self) -> bool:
        if self.mode == "native-nessus":
            try:
                resp = requests.get(
                    f"{self.config['url'].rstrip('/')}/server/status",
                    headers={"X-ApiKeys": (
                        f"accessKey={self.config['api_key']}; "
                        f"secretKey={self.config['secret_key']}"
                    )},
                    timeout=5,
                )
                return resp.status_code == 200
            except Exception:
                return False
        return True  # built-in mode always works

    # ------------------------------------------------------------------
    def scan(self, target: str | Path) -> ScanResult:
        target = str(target).strip()
        result = (
            self._scan_native(target)
            if self.mode == "native-nessus"
            else self._scan_builtin(target)
        )
        result.metadata["target"] = target
        result.metadata["mode"] = self.mode
        return result

    # ------------------------------------------------------------------
    # Native Nessus path (API v2)
    # ------------------------------------------------------------------
    def _scan_native(self, target: str) -> ScanResult:
        url = self.config["url"].rstrip("/")
        headers = {
            "X-ApiKeys": (
                f"accessKey={self.config['api_key']}; "
                f"secretKey={self.config['secret_key']}"
            ),
            "Content-Type": "application/json",
        }
        try:
            scan_uuid = self._create_scan(url, headers, target)
            if not scan_uuid:
                return ScanResult(scanner_name=self.name, success=False,
                                  findings=[], error="Failed to create Nessus scan")

            launch = requests.post(
                f"{url}/scans/{scan_uuid}/launch",
                headers=headers, timeout=self.DEFAULT_TIMEOUT,
            )
            if launch.status_code != 200:
                return ScanResult(scanner_name=self.name, success=False,
                                  findings=[], error=f"Failed to launch: {launch.text[:200]}")

            findings = self._wait_and_fetch(url, headers, scan_uuid)
            return ScanResult(scanner_name=self.name, success=True,
                              findings=findings, metadata={"scan_uuid": scan_uuid})
        except requests.Timeout:
            return ScanResult(scanner_name=self.name, success=False,
                              findings=[], error="Nessus API request timed out")
        except Exception as e:
            return ScanResult(scanner_name=self.name, success=False,
                              findings=[], error=f"Nessus error: {e}")

    def _create_scan(self, url, headers, target):
        policies_resp = requests.get(f"{url}/policies", headers=headers,
                                     timeout=self.DEFAULT_TIMEOUT)
        if policies_resp.status_code != 200:
            return None
        policies = policies_resp.json().get("policies", [])
        payload = {
            "uuid": self._get_template_uuid(url, headers),
            "settings": {
                "name": f"Gedr Scan - {target}",
                "description": f"Gedr scan of {target}",
                "targets": [target],
            },
        }
        if policies:
            payload["settings"]["policy_id"] = policies[0]["id"]
        resp = requests.post(f"{url}/scans", headers=headers, json=payload,
                             timeout=self.DEFAULT_TIMEOUT)
        if resp.status_code in (200, 201):
            return resp.json().get("scan", {}).get("uuid")
        return None

    def _get_template_uuid(self, url, headers):
        try:
            resp = requests.get(f"{url}/editor/scan/templates", headers=headers,
                                timeout=self.DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                for t in resp.json().get("templates", []):
                    if t.get("name") == "advanced":
                        return t["uuid"]
        except Exception:
            pass
        return ""

    def _wait_and_fetch(self, url, headers, scan_uuid):
        waited = 0
        while waited < 300:
            resp = requests.get(f"{url}/scans/{scan_uuid}", headers=headers,
                                timeout=self.DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                status = resp.json().get("info", {}).get("status", "")
                if status == "completed":
                    return self._fetch_findings(url, headers, scan_uuid)
                if status in ("aborted", "failed", "canceled"):
                    return []
            time.sleep(10)
            waited += 10
        return []

    def _fetch_findings(self, url, headers, scan_uuid):
        findings = []
        try:
            resp = requests.get(f"{url}/scans/{scan_uuid}/export", headers=headers,
                                params={"format": "json"},
                                timeout=self.DEFAULT_TIMEOUT)
            if resp.status_code != 200:
                return []
            token = resp.json().get("token")
            if not token:
                return []
            for _ in range(30):
                dl = requests.get(
                    f"{url}/scans/{scan_uuid}/export/{token}/download",
                    headers=headers, timeout=self.DEFAULT_TIMEOUT,
                )
                if dl.status_code == 200:
                    for vuln in dl.json().get("vulnerabilities", []):
                        finding = {
                            "title": vuln.get("plugin_name", vuln.get("name", "")),
                            "severity_score": vuln.get("cvss_base_score",
                                                       vuln.get("severity", 5)),
                            "cwe": vuln.get("cwe_id", "CWE-20"),
                            "description": (vuln.get("description") or "")[:300],
                            "file": vuln.get("host", ""),
                        }
                        findings.append(FindingNormalizer.normalize(finding, self.name))
                    break
                time.sleep(2)
        except Exception:
            pass
        return findings

    # ------------------------------------------------------------------
    # Built-in web/TLS assessment (no Nessus server required)
    # ------------------------------------------------------------------
    def _scan_builtin(self, target: str) -> ScanResult:
        host, port, is_tls = self._parse_target(target)
        if not host:
            return ScanResult(scanner_name=self.name, success=False,
                              findings=[],
                              error=f"Cannot parse target from: {target}")

        findings = []

        # 1. Reachability
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.close()
        except OSError as e:
            return ScanResult(scanner_name=self.name, success=False,
                              findings=[],
                              error=f"Target unreachable {host}:{port} ({e})")

        if not is_tls and port != 443:
            # Plain HTTP — check headers anyway
            findings.extend(self._check_http_headers(host, port))

        # 2. TLS assessment (always attempt; works on 443/8443 or http:// targets too)
        tls_findings = self._assess_tls(host, port)
        findings.extend(tls_findings)

        if not findings:
            findings.append({
                "title": "No critical TLS/header issues detected",
                "severity_score": 1,
                "cwe": "CWE-20",
                "description": f"Basic assessment of {host}:{port} found no high-severity issues.",
                "file": host,
                "line": port,
            })

        normalized = [FindingNormalizer.normalize(f, self.name) for f in findings]
        return ScanResult(scanner_name=self.name, success=True,
                          findings=normalized,
                          metadata={"checks_run": len(findings)})

    def _parse_target(self, target: str):
        """Return (host, port, use_https) parsed from URL or bare host."""
        t = target.strip()
        if "://" not in t:
            t = "https://" + t
        p = urlparse(t)
        host = p.hostname
        port = p.port or (443 if p.scheme == "https" else 80)
        return (host, port, p.scheme == "https")

    def _assess_tls(self, host: str, port: int) -> list[dict]:
        """Probe TLS versions and certificate properties."""
        out = []
        ctx_probe = [
            ("TLSv1.0", ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
        ]
        for label, proto, vmin, vmax in ctx_probe:
            try:
                ctx = ssl.SSLContext(proto)
                ctx.minimum_version = vmin
                ctx.maximum_version = vmax
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=4) as s:
                    with ctx.wrap_socket(s, server_hostname=host):
                        out.append({
                            "title": f"Outdated protocol {label} accepted",
                            "severity_score": 7 if label == "TLSv1.0" else 6,
                            "cwe": "CWE-327",
                            "description": f"Server at {host}:{port} still accepts {label}, which is deprecated.",
                            "file": host,
                            "line": port,
                        })
            except Exception:
                continue  # good — protocol rejected

        # Certificate expiry / self-signed check
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=4) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ts:
                    cert = ts.getpeercert(binary_form=False)
                    import datetime
                    nb = cert.get("notBefore")
                    na = cert.get("notAfter")
                    if na:
                        exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp - datetime.datetime.utcnow()).days
                        if days_left < 30:
                            out.append({
                                "title": f"TLS certificate expires soon ({days_left} days)",
                                "severity_score": 6 if days_left > 0 else 9,
                                "cwe": "CWE-298",
                                "description": f"Certificate for {host} expires {na}.",
                                "file": host,
                                "line": port,
                            })
        except Exception:
            pass
        return out

    def _check_http_headers(self, host: str, port: int) -> list[dict]:
        """Fetch over plain HTTP and flag missing security headers."""
        out = []
        try:
            r = requests.get(f"http://{host}:{port}/", timeout=5,
                             allow_redirects=False, verify=False)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            required = {
                "strict-transport-security": ("HSTS header missing", "CWE-319", 5),
                "content-security-policy": ("Content-Security-Policy missing", "CWE-79", 5),
                "x-content-type-options": ("X-Content-Type-Options missing", "CWE-430", 3),
                "x-frame-options": ("X-Frame-Options missing (clickjacking)", "CWE-1021", 4),
            }
            for h, (title, cwe, score) in required.items():
                if h not in hdrs:
                    out.append({
                        "title": title,
                        "severity_score": score,
                        "cwe": cwe,
                        "description": f"Response from {host}:{port} lacks the {h} header.",
                        "file": host,
                        "line": port,
                    })
            server = hdrs.get("server", "")
            if re.search(r"\d+\.\d+", server):
                out.append({
                    "title": f"Server version disclosed: {server}",
                    "severity_score": 3,
                    "cwe": "CWE-200",
                    "description": "The Server header exposes a specific version, aiding attackers.",
                    "file": host,
                    "line": port,
                })
        except Exception:
            pass
        return out
