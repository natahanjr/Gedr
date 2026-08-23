"""
C / C++ security scanner.

Layer 1: built-in heuristic scanner for memory-unsafe functions
         (strcpy, gets, sprintf, scanf, memcpy with static sizes),
         pointer arithmetic risks, use-after-free patterns and
         missing null checks.
Layer 2: optional integration with the Clang Static Analyzer
         (clang --analyze), used if clang is available on PATH.
"""
import re
from pathlib import Path

from . import resolve_cwe

RULES = [
    (re.compile(r"\bgets\s*\("), "C-OVERFLOW-1", "gets() - unbounded buffer read", "CWE-242", 10),
    (re.compile(r"\bstrcpy\s*\("), "C-OVERFLOW-2", "strcpy() - no bounds checking", "CWE-120", 8),
    (re.compile(r"\bstrcat\s*\("), "C-OVERFLOW-3", "strcat() - no bounds checking", "CWE-120", 8),
    (re.compile(r"\bsprintf\s*\("), "C-OVERFLOW-4", "sprintf() - potential buffer overflow", "CWE-120", 8),
    (re.compile(r"\bvsprintf\s*\("), "C-OVERFLOW-5", "vsprintf() - potential buffer overflow", "CWE-120", 8),
    (re.compile(r"\bscanf\s*\(\s*['\"][^'\"]*%s"), "C-OVERFLOW-6", "scanf with %s - no length limit", "CWE-120", 8),
    (re.compile(r"\bstrncpy\s*\([^,]+,[^,]+,\s*sizeof\s*\([^)]*\)"), "C-MEM-1", "strncpy with sizeof(pointer) - truncation/overflow", "CWE-121", 6),
    (re.compile(r"\bmemcpy\s*\([^,]+,[^,]+,\s*sizeof\s*\([^)]*\)"), "C-MEM-2", "memcpy with sizeof(pointer) instead of array size", "CWE-121", 6),
    (re.compile(r"malloc\s*\([^)]*\)\s*\)\s*;"), "C-MEM-3", "malloc() result not checked for NULL", "CWE-476", 5),
    (re.compile(r"new\s+\w+\s*(\[\d+\])?\s*;"), "C-MEM-4", "new allocation without null/exception handling", "CWE-476", 4),
    (re.compile(r"delete\s+\w+;\s*.*\b\w+\b\s*->|\buse\s+after\s+delete"), "C-UAF-1", "Possible use-after-free pattern", "CWE-416", 9),
    (re.compile(r"free\s*\(\s*(\w+)\s*\)\s*;"), "C-UAF-2", "free() call - verify no later dereference", "CWE-416", 6),
    (re.compile(r"char\s+\w+\s*\[\s*\d+\s*\]\s*;\s*(?!.*strncpy|.*snprintf|.*memcpy_s|.*strcpy_s)", re.I), "C-BUF-1", "Fixed-size stack buffer", "CWE-787", 5),
    (re.compile(r"\bstrlen\s*\(\s*[^)]*input|strlen\s*\(\s*argv"), "C-INPUT-1", "Untrusted input length used without bounds", "CWE-20", 6),
    (re.compile(r"atof\s*\(|atoi\s*\(|atol\s*\("), "C-NUM-1", "Unsafe numeric conversion (no error check)", "CWE-20", 4),
    (re.compile(r"system\s*\("), "C-CMDI-1", "system() call - command injection risk", "CWE-78", 9),
    (re.compile(r"strcmp\s*\(\s*[^,]+,\s*[^)]*password|strcmp\s*\(\s*[^,]+,\s*[^)]*passwd", re.I), "C-AUTH-1", "Password comparison with strcmp (timing attack)", "CWE-287", 6),
    (re.compile(r"\balloc\s*\([^)]*\*\s*\w+\s*\+|alloc\s*\([^)]*\+\s*\w+"), "C-OFF-1", "Integer overflow in allocation size", "CWE-190", 7),
    (re.compile(r"\batoi\s*\([^)]*argv"), "C-INPUT-2", "argv parsed without validation", "CWE-20", 5),
]

# Clang analyzer findings that indicate memory issues
CLANG_CHECKER_CWE = {
    "DeadStores": ("CWE-20", "Dead store"),
    "core.CallAndMessage": ("CWE-120", "Bad function call"),
    "core.DivideZero": ("CWE-369", "Divide by zero"),
    "unix.Malloc": ("CWE-416", "Memory leak / UAF"),
    "unix.MallocSizeof": ("CWE-121", "Malloc sizeof bug"),
    "core.NullDereference": ("CWE-476", "Null pointer dereference"),
    "core.StackAddressEscape": ("CWE-664", "Stack address escape"),
    "core.UndefinedBinaryOperatorResult": ("CWE-190", "Undefined operation"),
    "security.insecureAPI": ("CWE-120", "Insecure API usage"),
    "security.insecureAPI.strcpy": ("CWE-120", "strcpy is insecure"),
    "security.insecureAPI.gets": ("CWE-242", "gets is insecure"),
}


class CppScanner:
    name = "cpp-heuristic"

    def scan_text(self, filename: str, code: str) -> list[dict]:
        findings = []
        for line_no, line in enumerate(code.splitlines(), start=1):
            for pattern, rule_id, title, cwe_id, score in RULES:
                if pattern.search(line):
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
                            "description": f"{title} on line {line_no}.",
                            "raw": {"rule_id": rule_id, "language": "cpp"},
                        }
                    )
        return _dedupe(findings)

    def scan_path(self, path: Path) -> list[dict]:
        findings = []
        for file in _iter_files(path, (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")):
            try:
                code = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self.scan_text(str(file.relative_to(path)), code))
        return findings

    def run_clang_analyzer(self, path: Path) -> list[dict]:
        """Run Clang Static Analyzer on each translation unit."""
        import subprocess
        import tempfile

        findings = []
        for file in _iter_files(path, (".c", ".cc", ".cpp", ".cxx")):
            try:
                proc = subprocess.run(
                    ["clang", "--analyze", "-Xanalyzer", "-analyzer-output=text", str(file)],
                    capture_output=True, text=True, timeout=180,
                )
                text = proc.stderr + proc.stdout
            except (subprocess.SubprocessError, OSError):
                continue

            # Parse: warning: Path [diagnostic id]
            for m in re.finditer(
                r"^([^:]+):(\d+):(\d+):\s+warning:\s+(.*?)\s*\[(.*?)\]", text, re.M
            ):
                _, line, _col, msg, check = m.groups()
                cwe_id, base = CLANG_CHECKER_CWE.get(check, ("CWE-20", "Clang analyzer finding"))
                findings.append(
                    {
                        "file": _basename(m.group(1)),
                        "line": int(line),
                        "code": "",
                        "scanner": "clang-analyzer",
                        "rule_id": check,
                        "title": base,
                        "severity_score": 7,
                        "severity": "High",
                        **resolve_cwe(cwe_id),
                        "description": msg.strip(),
                        "raw": {"checker": check, "language": "cpp"},
                    }
                )
        return findings


def _iter_files(path: Path, suffixes: tuple):
    for p in path.rglob("*"):
        if p.is_file() and p.suffix in suffixes:
            yield p


def _basename(p: str) -> str:
    return p.split("\\")[-1].split("/")[-1]


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
