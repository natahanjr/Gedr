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
# Word boundaries on the identifier avoid matching words like
# "passwordless" or "application/json" substrings.
RULES = [
    (re.compile(r"\bpassword\s*=\s*['\"][^'\"]{3,}['\"]", re.I), "S-HARDCODE-1", "Hardcoded password in source", "CWE-259", 8),
    (re.compile(r"\bsecret\s*=\s*['\"][^'\"]{8,}['\"]", re.I), "S-HARDCODE-2", "Hardcoded secret in source", "CWE-798", 8),
    (re.compile(r"\bapi[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]", re.I), "S-HARDCODE-3", "Hardcoded API key", "CWE-798", 8),
    (re.compile(r"\btoken\s*=\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]", re.I), "S-HARDCODE-4", "Hardcoded token", "CWE-798", 7),
    (re.compile(r"\bexecute\s*\(\s*f?['\"][^'\"]*?(?:['\"]\s*\+|\{)(?!\s*#)"), "S-SQLI-1", "Possible SQL injection (string concatenation in execute)", "CWE-89", 9),
    (re.compile(r"\bcursor\.execute\s*\([^)]*%\s+[A-Za-z(]"), "S-SQLI-2", "SQL query built with unsafe % formatting", "CWE-89", 8),
    (re.compile(r"\.format\s*\([^)]*\).*SELECT|SELECT.*\.format\s*\("), "S-SQLI-3", "SQL query built with .format()", "CWE-89", 8),
    # Command injection: exclude safe uses like shell=False
    (re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)]*\bshell\s*=\s*True"), "S-CMDI-1", "Shell=True allows command injection", "CWE-78", 9),
    (re.compile(r"\bos\.system\s*\("), "S-CMDI-2", "os.system() with untrusted input risk", "CWE-78", 7),
    (re.compile(r"\beval\s*\("), "S-CMDI-3", "Use of eval() - code injection risk", "CWE-95", 9),
    (re.compile(r"\bexec\s*\("), "S-CMDI-4", "Use of exec() - code injection risk", "CWE-95", 9),
    (re.compile(r"\bpickle\.(?:loads|load)\s*\("), "S-DESER-1", "Unsafe pickle deserialization", "CWE-502", 9),
    (re.compile(r"\byaml\.load\s*\([^)]*(?!Loader)"), "S-DESER-2", "yaml.load without safe Loader", "CWE-502", 8),
    (re.compile(r"\b(?:paramiko|ftp|ftplib|smtplib|poplib|imaplib)\b"), "S-CLEAR-1", "Possible cleartext network usage", "CWE-319", 4),
    (re.compile(r"\brequests\.get\s*\(\s*['\"]http://"), "S-CLEAR-2", "HTTP (not HTTPS) request", "CWE-319", 4),
    (re.compile(r"\burlopen\s*\(\s*['\"]http://"), "S-CLEAR-3", "HTTP (not HTTPS) urlopen", "CWE-319", 4),
    (re.compile(r"\bmd5\s*\("), "S-CRYPTO-1", "Insecure MD5 hashing", "CWE-327", 5),
    (re.compile(r"\bsha1\s*\("), "S-CRYPTO-2", "Weak SHA-1 hashing", "CWE-327", 4),
    (re.compile(r"\brandom\.(?:random|randint|choice|uniform)\s*\("), "S-CRYPTO-3", "Non-cryptographic random for security", "CWE-330", 6),
    (re.compile(r"\bassert\s+.*\b(?:is_admin|is_authenticated|is_superuser|is_staff|has_permission|has_role|logged_in|authenticated)\b"), "S-AUTH-1", "assert used for authorization (disabled with -O)", "CWE-287", 8),
    (re.compile(r"\bexec\s*\(\s*['\"]rm\s+-rf|\bos\.remove|\bshutil\.rmtree\b"), "S-DELETE-1", "Destructive file operation", "CWE-20", 6),
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
        """Detect multi-step injection patterns via basic taint tracking.

        Improvements over the previous version:
          - Uses word boundaries (``\\b``) instead of substring ``in``
            so short names like ``x``, ``cmd``, ``i`` no longer produce
            a finding on every other line.
          - Clears the taint set at every function boundary so taint
            never leaks across scopes.
          - Dedupes by (source_line, var_name, rule_id) so a single
            vulnerability no longer yields N findings.
        """
        findings = []
        # Tracks var_name -> source_line for the current function scope only.
        scope_taint: dict[str, int] = {}
        # Dedup keys per finding to avoid duplicate taint findings on the same sink.
        seen: set[tuple[str, str]] = set()
        TAINT_PATTERN = re.compile(
            r"\b(?:input\b|sys\.argv\b|request\.(?:args|form)|os\.environ\b|sys\.stdin\b|\w+\.args\.\w+)"
        )

        def reset_scope():
            scope_taint.clear()

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if _is_comment_or_string(line):
                continue

            clean_line = _exclude_comment_suffix(line)

            # Function boundary (top-level `def` / `async def`) — reset scope.
            if re.match(r"^(?:async\s+)?def\s+\w+\s*\(", clean_line):
                reset_scope()
                continue

            # Taint source: a variable assignment from a known user-input API.
            if re.match(r"^\s*([A-Za-z_]\w*)\s*=", clean_line) and TAINT_PATTERN.search(clean_line):
                var_match = re.match(r"^\s*([A-Za-z_]\w*)\s*=", clean_line)
                if var_match:
                    scope_taint[var_match.group(1)] = line_no

            # Taint propagation: x = y (or y.func()) — if y is tainted, x is too.
            prop_match = re.match(r"^\s*([A-Za-z_]\w*)\s*=", clean_line)
            if prop_match and scope_taint:
                rhs = clean_line[prop_match.end():]
                for tainted_var in list(scope_taint.keys()):
                    if re.search(rf"\b{re.escape(tainted_var)}\b", rhs):
                        scope_taint[prop_match.group(1)] = scope_taint[tainted_var]
                        break

            # Sinks: check each tainted var against SQL / command sinks with
            # word-boundary matching on the variable name.
            for var_name, source_line in list(scope_taint.items()):
                if not re.search(rf"\b{re.escape(var_name)}\b", clean_line):
                    continue
                # SQL sink
                if re.search(r"\b(?:execute|query)\s*\(", clean_line) or re.search(
                    r"\bSELECT\b", clean_line, re.I
                ):
                    key = (f"S-SQLI-TAINT-{source_line}-{var_name}", filename)
                    if key not in seen:
                        seen.add(key)
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
                            "raw": {"rule_id": "S-SQLI-TAINT", "language": "python", "source_line": source_line},
                        })
                # Command sink
                if re.search(r"\b(?:subprocess|os\.system|exec)\b", clean_line):
                    key = (f"S-CMDI-TAINT-{source_line}-{var_name}", filename)
                    if key not in seen:
                        seen.add(key)
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
                            "raw": {"rule_id": "S-CMDI-TAINT", "language": "python", "source_line": source_line},
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
