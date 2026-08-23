"""
Python security scanner.

Two layers:
  1. Built-in heuristic scanner (regex/pattern based) - always available,
     zero external dependencies. Catches hardcoded secrets, SQL/command
     injection sinks, dangerous functions (eval, exec, pickle, subprocess shell).
  2. Optional integration with Bandit and Semgrep when installed on the host.

Each finding is normalized to a dict consumed by the risk engine.
"""
import re
from pathlib import Path

from . import resolve_cwe

EXTERNAL_TOOLS = ("bandit", "semgrep")

def _is_comment_or_string(line: str) -> bool:
    """Check if line is primarily a comment or documentation string."""
    stripped = line.strip()
    # Skip pure comment lines
    if stripped.startswith("#"):
        return True
    # Skip docstring-like lines
    if stripped.startswith(('"""', "'''", 'r"""', "r'''", "f\"\"\"", "f'''")):
        return True
    return False

def _exclude_comment_suffix(line: str) -> str:
    """Remove inline comments for pattern matching."""
    # Skip lines where pattern is in a comment
    if "#" in line:
        code_part = line.split("#")[0]
        return code_part
    return line

def _is_safe_password_assignment(line: str) -> bool:
    """Check for safe password patterns (tests, examples, docs)."""
    safe_keywords = ("test", "example", "demo", "mock", "fake", "dummy", "placeholder")
    lower_line = line.lower()
    if not any(kw in lower_line for kw in safe_keywords):
        return False
    # Only treat it as a safe *credential assignment*. Without this guard a
    # line like `requests.get("http://example.com")` would be skipped too,
    # silently hiding cleartext-traffic findings.
    return bool(re.search(r"\b(password|passwd|secret|api[_-]?key|token)\s*=", lower_line))

# (pattern, rule_id, title, cwe, score)
RULES = [
    (re.compile(r"password\s*=\s*['\"][^'\"]{3,}['\"]", re.I), "S-HARDCODE-1", "Hardcoded password in source", "CWE-259", 8),
    (re.compile(r"secret\s*=\s*['\"][^'\"]{8,}['\"]", re.I), "S-HARDCODE-2", "Hardcoded secret in source", "CWE-798", 8),
    (re.compile(r"api[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]", re.I), "S-HARDCODE-3", "Hardcoded API key", "CWE-798", 8),
    (re.compile(r"token\s*=\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]", re.I), "S-HARDCODE-4", "Hardcoded token", "CWE-798", 7),
    (re.compile(r"execute\s*\(\s*f?['\"][^'\"]*?(?:['\"]\s*\+|\{)(?!\s*#)"), "S-SQLI-1", "Possible SQL injection (string concatenation in execute)", "CWE-89", 9),
    (re.compile(r"cursor\.execute\s*\([^)]*%\s+[A-Za-z(]"), "S-SQLI-2", "SQL query built with unsafe % formatting", "CWE-89", 8),
    (re.compile(r"\.format\s*\([^)]*\).*SELECT|SELECT.*\.format\s*\("), "S-SQLI-3", "SQL query built with .format()", "CWE-89", 8),
    # Command injection: exclude safe uses like shell=False
    (re.compile(r"subprocess\.(run|Popen|call|check_output|check_call)\s*\([^)]*shell\s*=\s*True"), "S-CMDI-1", "Shell=True allows command injection", "CWE-78", 9),
    (re.compile(r"os\.system\s*\("), "S-CMDI-2", "os.system() with untrusted input risk", "CWE-78", 7),
    (re.compile(r"\beval\s*\("), "S-CMDI-3", "Use of eval() - code injection risk", "CWE-95", 9),
    (re.compile(r"\bexec\s*\("), "S-CMDI-4", "Use of exec() - code injection risk", "CWE-95", 9),
    (re.compile(r"pickle\.(loads|load)\s*\("), "S-DESER-1", "Unsafe pickle deserialization", "CWE-502", 9),
    (re.compile(r"yaml\.load\s*\([^)]*(?!Loader)"), "S-DESER-2", "yaml.load without safe Loader", "CWE-502", 8),
    (re.compile(r"paramiko|ftp|smtplib|poplib|imaplib"), "S-CLEAR-1", "Possible cleartext network usage", "CWE-319", 4),
    (re.compile(r"requests\.get\s*\(\s*['\"]http://"), "S-CLEAR-2", "HTTP (not HTTPS) request", "CWE-319", 4),
    (re.compile(r"urlopen\s*\(\s*['\"]http://"), "S-CLEAR-3", "HTTP (not HTTPS) urlopen", "CWE-319", 4),
    (re.compile(r"\bmd5\s*\("), "S-CRYPTO-1", "Insecure MD5 hashing", "CWE-327", 5),
    (re.compile(r"\bsha1\s*\("), "S-CRYPTO-2", "Weak SHA-1 hashing", "CWE-327", 4),
    (re.compile(r"random\.(random|randint|choice|uniform)\s*\("), "S-CRYPTO-3", "Non-cryptographic random for security", "CWE-330", 6),
    (re.compile(r"assert\s+.*\b(is_admin|is_authenticated|is_superuser|is_staff|has_permission|has_role|logged_in|authenticated)\b"), "S-AUTH-1", "assert used for authorization (disabled with -O)", "CWE-287", 8),
    (re.compile(r"exec\s*\(\s*['\"]rm\s+-rf|os\.remove|shutil\.rmtree"), "S-DELETE-1", "Destructive file operation", "CWE-20", 6),
]


class PythonScanner:
    """Bandit-compatible heuristic scanner for Python source code."""

    name = "python-heuristic"

    def scan_text(self, filename: str, code: str) -> list[dict]:
        findings = []
        lines = code.splitlines()
        
        for line_no, line in enumerate(lines, start=1):
            # Filter: skip comment-only lines
            if _is_comment_or_string(line):
                continue
            
            # Filter: skip test/example code
            if _is_safe_password_assignment(line):
                continue
            
            # Remove inline comments for pattern matching
            clean_line = _exclude_comment_suffix(line)
            
            for pattern, rule_id, title, cwe_id, score in RULES:
                if pattern.search(clean_line):
                    findings.append(
                        {
                            "file": filename,
                            "line": line_no,
                            "code": line.strip()[:300],
                            "scanner": self.name,
                            "rule_id": rule_id,
                            "title": title,
                            "severity_score": score,
                            "severity": _sev(score),
                            **resolve_cwe(cwe_id),
                            "description": f"{title} detected on line {line_no}.",
                            "raw": {"rule_id": rule_id, "language": "python"},
                        }
                    )
        
        # Add taint tracking for multi-step injection patterns
        findings.extend(self._scan_taint_flow(filename, lines))
        return _dedupe(findings)

    def _scan_taint_flow(self, filename: str, lines: list[str]) -> list[dict]:
        """Detect multi-step injection patterns via basic taint tracking."""
        findings = []
        taint_sources = {}  # var_name -> line_no where it's tainted
        
        for line_no, line in enumerate(lines, start=1):
            if _is_comment_or_string(line):
                continue
            
            clean_line = _exclude_comment_suffix(line)
            
            # Detect taint sources: user input assignment
            if any(src in clean_line for src in ["input(", "sys.argv", "request.args", "request.form", "os.environ", "sys.stdin"]):
                # Extract variable name
                var_match = re.search(r"(\w+)\s*=.*(?:input|argv|args|form|environ|stdin)", clean_line)
                if var_match:
                    taint_sources[var_match.group(1)] = line_no
            
            # Check if tainted var is used in dangerous sink
            for var_name, source_line in list(taint_sources.items()):
                # SQL injection via tainted variable
                if var_name in clean_line and re.search(rf"(execute|query|SELECT).*{re.escape(var_name)}", clean_line, re.I):
                    findings.append({
                        "file": filename,
                        "line": line_no,
                        "code": line.strip()[:300],
                        "scanner": self.name,
                        "rule_id": "S-SQLI-TAINT",
                        "title": f"SQL injection via tainted variable '{var_name}' (sourced at line {source_line})",
                        "severity_score": 9,
                        "severity": "Critical",
                        **resolve_cwe("CWE-89"),
                        "description": f"Variable '{var_name}' tainted at line {source_line}, used unsafely in query at line {line_no}.",
                        "raw": {"rule_id": "S-SQLI-TAINT", "language": "python"},
                    })
                
                # Command injection via tainted variable
                if var_name in clean_line and re.search(rf"(subprocess|os\.system|exec|shell_exec).*{re.escape(var_name)}", clean_line, re.I):
                    findings.append({
                        "file": filename,
                        "line": line_no,
                        "code": line.strip()[:300],
                        "scanner": self.name,
                        "rule_id": "S-CMDI-TAINT",
                        "title": f"Command injection via tainted variable '{var_name}' (sourced at line {source_line})",
                        "severity_score": 9,
                        "severity": "Critical",
                        **resolve_cwe("CWE-78"),
                        "description": f"Variable '{var_name}' tainted at line {source_line}, used unsafely in command execution at line {line_no}.",
                        "raw": {"rule_id": "S-CMDI-TAINT", "language": "python"},
                    })
        
        return findings

    def scan_path(self, path: Path) -> list[dict]:
        findings = []
        for file in _iter_python_files(path):
            try:
                code = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self.scan_text(str(file.relative_to(path)), code))
        return findings

    # Optional external tool integration -------------------------------
    def run_bandit(self, path: Path) -> list[dict]:
        import json
        import subprocess

        try:
            proc = subprocess.run(
                ["bandit", "-r", str(path), "-f", "json", "-q"],
                capture_output=True, text=True, timeout=120,
            )
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, ValueError, OSError, ImportError):
            return []

        findings = []
        for item in data.get("results", []):
            score = item.get("issue_severity", "LOW") and _tool_sev_to_score(
                item.get("issue_severity", "LOW")
            )
            findings.append(
                {
                    "file": item.get("filename", ""),
                    "line": int(item.get("line_number", 0)),
                    "code": (item.get("code", "") or "")[:300],
                    "scanner": "bandit",
                    "rule_id": item.get("test_id"),
                    "title": item.get("test_name", "Bandit issue"),
                    "severity_score": score,
                    "severity": _sev(score),
                    **resolve_cwe("CWE-20"),
                    "description": item.get("issue_text", ""),
                    "raw": {"rule_id": item.get("test_id"), "language": "python"},
                }
            )
        return findings

    def run_semgrep(self, path: Path) -> list[dict]:
        import json
        import subprocess

        try:
            proc = subprocess.run(
                ["semgrep", "scan", "--json", "--quiet", str(path)],
                capture_output=True, text=True, timeout=300,
            )
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, ValueError, OSError, ImportError):
            return []

        findings = []
        for res in data.get("results", []):
            sev_map = {"ERROR": 10, "WARNING": 6, "INFO": 3}
            score = sev_map.get(res.get("extra", {}).get("severity", "WARNING"), 5)
            findings.append(
                {
                    "file": res.get("path", ""),
                    "line": int(res.get("start", {}).get("line", 0)),
                    "code": (res.get("extra", {}).get("lines", "") or "")[:300],
                    "scanner": "semgrep",
                    "rule_id": res.get("check_id"),
                    "title": res.get("extra", {}).get("message", "Semgrep finding")[:200],
                    "severity_score": score,
                    "severity": _sev(score),
                    **resolve_cwe("CWE-20"),
                    "description": res.get("extra", {}).get("message", ""),
                    "raw": {"check_id": res.get("check_id"), "language": "python"},
                }
            )
        return findings


# ----------------------------------------------------------------------
def _iter_python_files(path: Path):
    for p in path.rglob("*"):
        if p.is_file() and p.suffix in {".py", ".pyw"}:
            yield p


def _dedupe(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in findings:
        key = (f["file"], f["line"], f["rule_id"])
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


def _tool_sev_to_score(sev: str) -> int:
    return {"LOW": 3, "MEDIUM": 6, "HIGH": 8}.get(sev.upper(), 5)
