"""
Dependency vulnerability scanner.

Detects known vulnerabilities in project dependencies:
- Python: pip audit, poetry audit
- JavaScript/Node: npm audit, yarn audit
- PHP: composer audit
- Java: dependency check
"""
import re
import json
from pathlib import Path

from . import resolve_cwe


class DependencyScanner:
    name = "dependency-scanner"

    def scan_path(self, path: Path) -> list[dict]:
        findings = []
        
        # Python dependencies
        findings.extend(self._scan_python_deps(path))
        
        # JavaScript/Node dependencies
        findings.extend(self._scan_npm_deps(path))
        
        # PHP Composer dependencies
        findings.extend(self._scan_composer_deps(path))
        
        # Java dependencies
        findings.extend(self._scan_java_deps(path))
        
        return _dedupe(findings)

    def _scan_python_deps(self, path: Path) -> list[dict]:
        """Run pip audit on Python dependencies."""
        import subprocess
        
        requirements_files = list(path.rglob("requirements*.txt")) + list(path.rglob("Pipfile")) + list(path.rglob("pyproject.toml"))
        if not requirements_files:
            return []
        
        try:
            proc = subprocess.run(
                ["pip", "audit", "--json"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(path),
            )
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, ValueError, OSError):
            return []
        
        findings = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cve", "CWE-1026")  # Untrusted dependency
            # Extract CWE from CVE if available
            if "CWE" in str(vuln):
                cwe_match = re.search(r"CWE-(\d+)", str(vuln))
                if cwe_match:
                    cve_id = f"CWE-{cwe_match.group(1)}"
            
            severity_map = {"critical": 10, "high": 8, "medium": 6, "low": 3}
            score = severity_map.get(vuln.get("vulnerability_type", "").lower(), 5)
            
            findings.append({
                "file": "requirements.txt / pyproject.toml / Pipfile",
                "line": 0,
                "code": f"{vuln.get('package_name', 'unknown')} {vuln.get('current_version', 'unknown')}",
                "scanner": self.name,
                "rule_id": f"PIP-{vuln.get('id', 'unknown')}",
                "title": f"Vulnerable Python package: {vuln.get('package_name', 'unknown')}",
                "severity_score": score,
                "severity": _sev(score),
                **resolve_cwe(cve_id),
                "description": vuln.get("description", "Known vulnerability in dependency"),
                "raw": {
                    "package": vuln.get("package_name"),
                    "version": vuln.get("current_version"),
                    "advisory": vuln.get("id"),
                    "language": "python",
                },
            })
        
        return findings

    def _scan_npm_deps(self, path: Path) -> list[dict]:
        """Run npm audit on JavaScript dependencies."""
        import subprocess
        
        if not (path / "package.json").exists():
            return []
        
        try:
            proc = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(path),
            )
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, ValueError, OSError):
            return []
        
        findings = []
        for pkg_name, vuln_data in data.get("vulnerabilities", {}).items():
            if isinstance(vuln_data, dict) and "severity" in vuln_data:
                severity_map = {"critical": 10, "high": 8, "medium": 6, "low": 3}
                score = severity_map.get(vuln_data.get("severity", "").lower(), 5)
                
                findings.append({
                    "file": "package.json",
                    "line": 0,
                    "code": f"{pkg_name} {vuln_data.get('current_version', 'unknown')}",
                    "scanner": self.name,
                    "rule_id": f"NPM-{pkg_name}",
                    "title": f"Vulnerable npm package: {pkg_name}",
                    "severity_score": score,
                    "severity": _sev(score),
                    **resolve_cwe("CWE-1026"),
                    "description": vuln_data.get("via", [{}])[0].get("title", "Known vulnerability in dependency"),
                    "raw": {
                        "package": pkg_name,
                        "severity": vuln_data.get("severity"),
                        "language": "javascript",
                    },
                })
        
        return findings

    def _scan_composer_deps(self, path: Path) -> list[dict]:
        """Run composer audit on PHP dependencies."""
        import subprocess
        
        if not (path / "composer.json").exists():
            return []
        
        try:
            proc = subprocess.run(
                ["composer", "audit", "--format=json"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(path),
            )
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, ValueError, OSError):
            return []
        
        findings = []
        for vuln in data.get("vulnerabilities", []):
            severity_map = {"critical": 10, "high": 8, "medium": 6, "low": 3}
            score = severity_map.get(vuln.get("severity", "").lower(), 5)
            
            findings.append({
                "file": "composer.json",
                "line": 0,
                "code": f"{vuln.get('package', 'unknown')} {vuln.get('version', 'unknown')}",
                "scanner": self.name,
                "rule_id": f"COMPOSER-{vuln.get('id', 'unknown')}",
                "title": f"Vulnerable Composer package: {vuln.get('package', 'unknown')}",
                "severity_score": score,
                "severity": _sev(score),
                **resolve_cwe("CWE-1026"),
                "description": vuln.get("description", "Known vulnerability in dependency"),
                "raw": {
                    "package": vuln.get("package"),
                    "language": "php",
                },
            })
        
        return findings

    def _scan_java_deps(self, path: Path) -> list[dict]:
        """Run dependency-check on Java/Maven/Gradle dependencies."""
        import subprocess
        
        # Check for Maven or Gradle files
        if not ((path / "pom.xml").exists() or (path / "build.gradle").exists()):
            return []
        
        try:
            proc = subprocess.run(
                ["dependency-check", "--project", "Gədr", "--scan", str(path), "--format", "JSON", "--out", "/tmp"],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (subprocess.SubprocessError, OSError):
            return []
        
        # Parse JSON report if generated
        findings = []
        try:
            report_path = Path("/tmp/dependency-check-report.json")
            if report_path.exists():
                data = json.loads(report_path.read_text())
                for dependency in data.get("reportSchema", {}).get("dependencies", []):
                    for vuln in dependency.get("vulnerabilities", []):
                        severity_map = {"critical": 10, "high": 8, "medium": 6, "low": 3}
                        score = severity_map.get(vuln.get("severity", "").lower(), 5)
                        
                        findings.append({
                            "file": "pom.xml / build.gradle",
                            "line": 0,
                            "code": dependency.get("name", "unknown"),
                            "scanner": self.name,
                            "rule_id": f"DEPCHECK-{vuln.get('cve', 'unknown')}",
                            "title": f"Vulnerable Java dependency: {dependency.get('name', 'unknown')}",
                            "severity_score": score,
                            "severity": _sev(score),
                            **resolve_cwe("CWE-1026"),
                            "description": vuln.get("description", "Known vulnerability in dependency"),
                            "raw": {
                                "package": dependency.get("name"),
                                "cve": vuln.get("cve"),
                                "language": "java",
                            },
                        })
        except (json.JSONDecodeError, OSError):
            pass
        
        return findings


def _dedupe(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in findings:
        key = (f["file"], f.get("code", ""), f["rule_id"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _sev(score: int) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"
