"""
Taint Analysis Engine for Gədr.

Tracks user-controlled input (sources) to dangerous functions (sinks).

Improvements over the previous version:
  - Uses word-boundary (``\\b``) matching so a tainted variable named
    ``cmd`` no longer matches inside ``subprocess.run(...)`` arbitrarily.
  - Resets the taint set at function/method boundaries so taint never
    leaks across scopes.
  - Dedupes findings by (file, sink_kind, source_var) so the same
    vulnerability no longer yields N findings.
"""
import re
from pathlib import Path


class TaintAnalyzer:
    def __init__(self):
        # Sources: Where user input enters the system
        self.sources = {
            "python": [
                r"\brequest\.(?:args|form|json|headers|cookies)\b",
                r"\binput\s*\(",
                r"\bsys\.argv\b",
                r"\bsys\.stdin\b",
                r"\bos\.environ\b",
            ],
            "php": [r"\$_GET\b", r"\$_POST\b", r"\$_REQUEST\b", r"\$_COOKIE\b"],
            "java": [r"\bgetParameter\b", r"\bgetHeader\b", r"\breadLine\b"],
            "js": [
                r"\breq\.(?:body|params|query|cookies|headers)\b",
                r"\blocation\.search\b",
                r"\bdocument\.cookie\b",
            ],
        }

        # Sinks: Where untrusted data causes a vulnerability
        self.sinks = {
            "sql": [r"\bexecute\s*\(", r"\bquery\s*\(", r"\bmysqli_query\b"],
            "cmd": [
                r"\bsystem\s*\(",
                r"\bpopen\s*\(",
                r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\b",
                r"\bexec\s*\(",
                r"\bos\.system\s*\(",
            ],
            "xss": [r"\binnerHTML\b", r"\bdocument\.write\b", r"\becho\b", r"\bprint\s*\("],
            "file": [r"\bopen\s*\(", r"\bfile_get_contents\b", r"\bread_file\b"],
        }

    @staticmethod
    def _is_scope_boundary(clean_line: str, language: str) -> bool:
        """Detect the start of a new function/method body."""
        if language in ("python",):
            return bool(re.match(r"^(?:async\s+)?def\s+\w+\s*\(", clean_line))
        if language in ("php",):
            return bool(re.match(r"^\s*function\s+\w+\s*\(", clean_line))
        if language in ("java", "js"):
            # function/method header at zero or some indent
            return bool(
                re.match(
                    r"^\s*(?:public|private|protected|static|async|function|export)?\s*"
                    r"(?:function\s+\w+|\w+\s*\([^)]*\)\s*\{)",
                    clean_line,
                )
            )
        return False

    def analyze_file(self, file_path: Path, content: str, language: str) -> list:
        """Perform basic intra-procedural data-flow taint analysis.

        Returns a list of taint-flow findings. Findings are deduped by
        (file, sink_kind, source_var) so the same vulnerability is
        reported once even when it reaches multiple sinks.
        """
        findings = []
        lang_sources = self.sources.get(language, [])
        if not lang_sources:
            return []

        lines = content.splitlines()
        tainted_vars: dict[str, int] = {}  # var -> source line
        seen_findings: set[tuple[str, str, str]] = set()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue

            # Detect and reset scope boundaries (function/method entry).
            if self._is_scope_boundary(line, language):
                tainted_vars.clear()

            # Strip JS/C-like variable declarations so the assignment
            # regex captures the actual variable, not the keyword.
            normalised = re.sub(
                r"^\s*(?:var|let|const|final)\b\s*",
                "",
                line,
            )

            # 1. Identify taint sources: variable assignments from user input.
            assign_match = re.match(r"^\s*([A-Za-z_][\w.]*)\s*=", normalised)
            if assign_match and any(re.search(p, normalised) for p in lang_sources):
                tainted_vars[assign_match.group(1)] = i

            # 2. Taint propagation: x = ... y ... (if y is tainted, x is too).
            if assign_match and tainted_vars:
                rhs = normalised[assign_match.end():]
                for tainted_var in list(tainted_vars.keys()):
                    if re.search(rf"\b{re.escape(tainted_var)}\b", rhs):
                        tainted_vars[assign_match.group(1)] = tainted_vars[tainted_var]
                        break

            # 3. Check for tainted-variable usage inside any sink.
            for sink_type, sink_patterns in self.sinks.items():
                if not any(re.search(p, line) for p in sink_patterns):
                    continue
                for var, source_line in list(tainted_vars.items()):
                    if not re.search(rf"\b{re.escape(var)}\b", line):
                        continue
                    dedup_key = (str(file_path), sink_type, var)
                    if dedup_key in seen_findings:
                        continue
                    seen_findings.add(dedup_key)
                    findings.append({
                        "file": str(file_path),
                        "line": i,
                        "code": stripped[:300],
                        "scanner": "TaintAnalyzer",
                        "rule_id": f"TAINT-{sink_type.upper()}",
                        "title": f"Unsanitized user input flowing to {sink_type} sink",
                        "severity": "Critical",
                        "severity_score": 9,
                        "cwe": "CWE-20",
                        "owasp": "A03:2021-Injection",
                        "description": (
                            f"Variable '{var}' tainted at line {source_line}, "
                            f"flows into {sink_type} sink at line {i}."
                        ),
                        "raw": {"sink": sink_type, "var": var, "source_line": source_line},
                    })
        return findings