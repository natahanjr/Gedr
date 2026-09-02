"""
Java security scanner.

Layer 1: built-in heuristic scanner for common Java weakness patterns
         (SQL injection, command injection, XSS sinks, hardcoded secrets,
         insecure crypto, deserialization, dangerous reflection).
Layer 2: optional integration with SpotBugs and PMD if installed.
"""
import re
from pathlib import Path

from . import resolve_cwe

RULES = [
    (re.compile(r'Statement\s+\w+\s*=|createStatement\s*\(\s*\)'), "J-SQLI-1", "Raw JDBC Statement (use PreparedStatement)", "CWE-89", 9),
    (re.compile(r"\.executeQuery\s*\(\s*[^)]*\+[^)]*\)"), "J-SQLI-2", "SQL query concatenation", "CWE-89", 9),
    (re.compile(r"\.execute\s*\(\s*[^)]*\+[^)]*\)"), "J-SQLI-3", "SQL statement concatenation", "CWE-89", 9),
    (re.compile(r"['\"][^'\"]*SELECT[^'\"]*['\"]\s*\+\s*\w+", re.I), "J-SQLI-4", "SQL query string concatenation with variable", "CWE-89", 9),
    (re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('), "J-CMDI-1", "Runtime.exec() command injection risk", "CWE-78", 8),
    (re.compile(r'ProcessBuilder\s*\([^)]*\)\s*\.\s*command\s*\(\s*[^)]*\+'), "J-CMDI-2", "ProcessBuilder with concatenated command", "CWE-78", 8),
    (re.compile(r"getParameter\s*\(\s*['\"][^'\"]+['\"]\s*\)\s*.*\bout\.println\b|out\.println\s*\([^)]*getParameter"), "J-XSS-1", "Reflected XSS: request parameter written to response", "CWE-79", 8),
    (re.compile(r"printWriter\s*\([^)]*\)\s*;\s*.*\.println\s*\([^)]*getParameter|\.println\s*\(\s*[^)]*request\.getParameter"), "J-XSS-2", "Unescaped request data written to output", "CWE-79", 7),
    (re.compile(r"password\s*=\s*['\"][^'\"]{3,}['\"]|secret\s*=\s*['\"][^'\"]{8,}['\"]|apiKey\s*=\s*['\"][^'\"]{8,}['\"]", re.I), "J-HARDCODE-1", "Hardcoded credential in source", "CWE-798", 8),
    (re.compile(r"@RequestMapping\s*\([^)]*\)\s*[^{]*\{|@GetMapping|@PostMapping", re.I), "J-AUTH-1", "Endpoint without visible authorization annotation", "CWE-862", 6),
    (re.compile(r"ObjectInputStream\s*\(|\.readObject\s*\("), "J-DESER-1", "Unsafe Java deserialization", "CWE-502", 9),
    (re.compile(r"MessageDigest\.getInstance\s*\(\s*['\"]MD5|['\"]SHA-1"), "J-CRYPTO-1", "Weak hash algorithm", "CWE-327", 5),
    (re.compile(r"DESKeySpec|DESedeKeySpec|[\"']DES[\"']\s*[,)]"), "J-CRYPTO-2", "Weak DES encryption", "CWE-327", 7),
    (re.compile(r"getBytes\s*\(\s*\)\s*[^\"]*Cipher|cipher\.doFinal\s*\(\s*\w+\.getBytes\s*\(\s*\)"), "J-CRYPTO-3", "Incorrect charset in crypto operations", "CWE-327", 4),
    (re.compile(r"Math\.random\s*\(\s*\)"), "J-CRYPTO-4", "Math.random() not cryptographically secure", "CWE-330", 5),
    (re.compile(r"\bnew\s+java\.util\.Random\s*\(|\bnew\s+Random\s*\(\s*\)"), "J-CRYPTO-4b", "java.util.Random is not cryptographically secure (use SecureRandom)", "CWE-330", 5),
    (re.compile(r"System\.getenv\s*\([^)]*\)\s*\+|getenv\s*\([^)]*\)\s*.*print|\.println\s*\([^)]*getenv"), "J-INFO-1", "Environment variable in output (info leak)", "CWE-200", 4),
    (re.compile(r"Class\.forName\s*\([^)]*getParameter|URLClassLoader"), "J-INJECT-1", "Reflection / dynamic class loading from input", "CWE-470", 7),
]

# PMD rules that map to security issues
PMD_SECURITY_RULES = {
    "AvoidCallingFinalize": ("J-DESER-2", "Avoid calling finalize()", "CWE-20"),
    "InsecureCrypto": ("J-CRYPTO-5", "Insecure cryptographic usage", "CWE-327"),
}


class JavaScanner:
    name = "java-heuristic"

    def scan_text(self, filename: str, code: str) -> list[dict]:
        findings = []
        for line_no, line in enumerate(code.splitlines(), start=1):
            for pattern, rule_id, title, cwe_id, score in RULES:
                if pattern.search(line):
                    findings.append(self._finding(filename, line_no, line, rule_id, title, cwe_id, score))
        return _dedupe(findings)

    def scan_path(self, path: Path) -> list[dict]:
        findings = []
        for file in _iter_files(path, ".java"):
            try:
                code = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self.scan_text(str(file.relative_to(path)), code))
        return findings

    def run_spotbugs(self, path: Path) -> list[dict]:
        import subprocess
        import xml.etree.ElementTree as ET

        try:
            proc = subprocess.run(
                ["spotbugs", "-textui", "-xml:withMessages", "-exitcode", str(path)],
                capture_output=True, text=True, timeout=600,
            )
        except (subprocess.SubprocessError, OSError):
            return []
        return self._parse_spotbugs_xml(proc.stdout)

    def _parse_spotbugs_xml(self, xml_text: str) -> list[dict]:
        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []

        sev_map = {"1": 9, "2": 7, "3": 4}
        findings = []
        for bug in root.iter("BugInstance"):
            score = sev_map.get(bug.get("priority", "2"), 4)
            cwe = bug.get("cweid")
            cwe_id = f"CWE-{cwe}" if cwe else "CWE-20"
            findings.append(
                {
                    "file": (bug.findtext("Class/classname") or "").replace(".", "/") + ".java",
                    "line": int(bug.findtext("SourceLine/start", "0") or 0),
                    "code": "",
                    "scanner": "spotbugs",
                    "rule_id": bug.get("type"),
                    "title": (bug.get("shortMessage") or "SpotBugs issue")[:200],
                    "severity_score": score,
                    "severity": _sev(score),
                    **resolve_cwe(cwe_id),
                    "description": bug.findtext("LongMessage") or "",
                    "raw": {"type": bug.get("type"), "language": "java"},
                }
            )
        return findings

    def run_pmd(self, path: Path) -> list[dict]:
        import subprocess

        try:
            proc = subprocess.run(
                ["pmd", "check", "-d", str(path), "-R", "category/java/security.xml"],
                capture_output=True, text=True, timeout=600,
            )
            out = proc.stdout + proc.stderr
        except (subprocess.SubprocessError, OSError):
            return []

        findings = []
        line_re = re.compile(r"([^\s]+\.java):(\d+):\s+(\w+):\s+(.*)")
        for m in line_re.finditer(out):
            _, line, rule, msg = m.groups()
            rule_id, title, cwe_id = PMD_SECURITY_RULES.get(rule, (f"PMD-{rule}", rule, "CWE-20"))
            findings.append(
                {
                    "file": _basename(m.group(1)),
                    "line": int(line),
                    "code": "",
                    "scanner": "pmd",
                    "rule_id": rule_id,
                    "title": title,
                    "severity_score": 6,
                    "severity": "Medium",
                    **resolve_cwe(cwe_id),
                    "description": msg,
                    "raw": {"pmd_rule": rule, "language": "java"},
                }
            )
        return findings

    @staticmethod
    def _finding(filename, line_no, line, rule_id, title, cwe_id, score):
        return {
            "file": filename,
            "line": line_no,
            "code": line.strip()[:300],
            "scanner": JavaScanner.name,
            "rule_id": rule_id,
            "title": title,
            "severity_score": score,
            "severity": _sev(score),
            **resolve_cwe(cwe_id),
            "description": f"{title} on line {line_no}.",
            "raw": {"rule_id": rule_id, "language": "java"},
        }


def _iter_files(path: Path, suffix: str):
    for p in path.rglob(f"*{suffix}"):
        if p.is_file():
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
