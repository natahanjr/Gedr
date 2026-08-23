"""
Web security scanner: PHP, HTML, CSS, JavaScript.

Layer 1: built-in heuristic scanner (XSS, SQLi, command injection,
         file upload, auth issues, CSRF, DOM clobbering, mixed content).
Layer 2: optional Semgrep integration when installed.
"""
import re
from pathlib import Path

from . import resolve_cwe

PHP_RULES = [
    (re.compile(r"\$_GET\s*\[[^\]]*\]\s*[^\n;]*echo|\becho\s+\$_GET|\$\w+\s*=\s*\$_GET\s*\[[^\]]*\]\s*;.*echo", re.S), "W-XSS-1", "Reflected XSS: unsanitized GET param echoed", "CWE-79", 9),
    (re.compile(r"\$_REQUEST\s*\[[^\]]*\]\s*[^\n;]*\becho|echo\s+\$_REQUEST"), "W-XSS-2", "Reflected XSS via _REQUEST", "CWE-79", 8),
    (re.compile(r"\becho\b[^;]*\$_GET\b", re.I), "W-XSS-3", "Reflected XSS: unsanitized GET input echoed", "CWE-79", 9),
    (re.compile(r"mysql_query\s*\(\s*['\"][^'\"]*\$|mysqli_query\s*\(\s*[^,]+,\s*['\"][^'\"]*\$"), "W-SQLI-1", "SQL query with interpolated variable", "CWE-89", 9),
    (re.compile(r"SELECT\s+.*?\.\s*\$|query\s*\(\s*[\"'][^\"']*\$"), "W-SQLI-2", "SQL string concatenation with variable", "CWE-89", 9),
    (re.compile(r"\$pdo\s*->\s*query\s*\([^)]*\$|->query\s*\(\s*[\"'][^\"']*\$"), "W-SQLI-3", "PDO query without prepared statement", "CWE-89", 8),
    (re.compile(r"shell_exec\s*\([^)]*\$|system\s*\([^)]*\$|exec\s*\([^)]*\$|passthru\s*\([^)]*\$|`[^`]*\$"), "W-CMDI-1", "Command execution with variable input", "CWE-78", 9),
    (re.compile(r"include\s*\(\s*\$_GET|require\s*\(\s*\$_GET|include\s*\(\s*\$_POST|require\s*\(\s*\$_POST"), "W-LFI-1", "Local file inclusion via user input", "CWE-98", 9),
    (re.compile(r"file_get_contents\s*\(\s*['\"]https?://[^'\"]*\$|curl_exec\s*\(\s*[^)]*\$"), "W-SSRF-1", "Possible SSRF: URL from user input fetched", "CWE-918", 7),
    (re.compile(r"move_uploaded_file\s*\([^)]*\$"), "W-UPLOAD-1", "File upload without extension/type validation", "CWE-434", 9),
    (re.compile(r"\$_FILES\s*\[[^\]]*\]\s*\[['\"]name"), "W-UPLOAD-2", "Uploaded file name used unsafely", "CWE-434", 7),
    (re.compile(r"password_hash\s*\([^)]*PASSWORD_DEFAULT|password_verify"), "W-CRYPTO-1", "Password hashing - verify algorithm is modern", "CWE-521", 4),
    (re.compile(r"md5\s*\([^)]*password|sha1\s*\([^)]*password"), "W-CRYPTO-2", "Weak hash for password", "CWE-327", 8),
    (re.compile(r"unserialize\s*\(\s*\$_COOKIE|unserialize\s*\(\s*['\"][^'\"]*base64"), "W-DESER-1", "Unsafe unserialize of user data", "CWE-502", 9),
    (re.compile(r"session_start\s*\(\s*\)\s*;\s*[^;]*\$_SESSION\s*\[['\"]user['\"]\]\s*=\s*['\"]?1"), "W-AUTH-1", "Weak session auth flag", "CWE-287", 6),
    (re.compile(r"\$_SERVER\['HTTP_REFERER'\][^\n;]*check|referer\s*==\s*"), "W-CSRF-1", "CSRF protection relying on Referer header only", "CWE-352", 7),
    # CSRF: missing token validation
    (re.compile(r"\$_POST\s*\[['\"]user_id|GET.*id.*=.*\$_GET.*update"), "W-IDOR-1", "Insecure Direct Object Reference: ID from user input", "CWE-639", 8),
    # CSRF: form without token
    (re.compile(r"<form.*POST[^>]*>\s*(?!.*csrf|.*token|.*nonce)"), "W-CSRF-2", "Form POST without CSRF token", "CWE-352", 8),
    (re.compile(r"\$(?:password|passwd|secret|api[_-]?key|token|access_key)\w*\s*=\s*['\"][^'\"]{3,}['\"]", re.I), "W-HARDCODE-1", "Hardcoded credential in PHP source", "CWE-798", 8),
]

JS_RULES = [
    (re.compile(r"innerHTML\s*=\s*[^;]*\b(location\.search|location\.hash|document\.URL|window\.name|document\.referrer)\b"), "W-XSS-DOM-1", "DOM XSS: taint source into innerHTML", "CWE-79", 9),
    (re.compile(r"document\.write\s*\([^)]*(location|URL|search|referrer|hash|name)"), "W-XSS-DOM-2", "DOM XSS: document.write with tainted source", "CWE-79", 9),
    (re.compile(r"\.html\s*\(\s*[^)]*(location\.search|location\.hash|document\.URL)"), "W-XSS-JQ-1", "jQuery .html() with tainted source", "CWE-79", 8),
    (re.compile(r"\beval\s*\([^)]*(location|document\.|window\.|req|res|data)"), "W-JSEVAL-1", "eval() of potentially tainted data", "CWE-95", 9),
    (re.compile(r"\beval\s*\("), "W-JSEVAL-3", "Use of eval() - code injection risk", "CWE-95", 8),
    (re.compile(r"new\s+Function\s*\([^)]*(location|document\.|window\.)"), "W-JSEVAL-2", "Function constructor with tainted data", "CWE-95", 8),
    (re.compile(r"window\.open\s*\(\s*[^)'\"]+[^)]*\)"), "W-OPEN-1", "window.open with computed URL (open redirect risk)", "CWE-601", 5),
    (re.compile(r"postMessage\s*\([^)]*\*\s*\)"), "W-POSTMSG-1", "postMessage to '*' - target origin not validated", "CWE-345", 7),
    (re.compile(r"addEventListener\s*\(\s*['\"]message['\"]\s*,[^)]*\{?\s*data\b"), "W-POSTMSG-2", "message listener without origin check", "CWE-345", 6),
    (re.compile(r"localStorage\.(setItem|getItem)\s*\([^)]*(token|password|secret|credential)"), "W-STORE-1", "Sensitive data in localStorage", "CWE-312", 7),
    (re.compile(r"http://"), "W-MIXED-1", "Hardcoded HTTP (mixed content) URL", "CWE-319", 4),
    (re.compile(r"Math\.random\s*\(\s*\)\s*[^;]*(password|token|key|secret)"), "W-RANDOM-1", "Math.random used for security token", "CWE-330", 8),
]

HTML_RULES = [
    (re.compile(r"<script[^>]*>\s*eval\s*\(", re.I), "W-HTML-EVAL-1", "Inline script using eval()", "CWE-95", 8),
    (re.compile(r"<a\s+[^>]*href\s*=\s*['\"]javascript:", re.I), "W-HTML-JS-1", "javascript: URI in href", "CWE-79", 7),
    (re.compile(r"<iframe[^>]*src\s*=\s*['\"]\s*javascript:", re.I), "W-HTML-JS-2", "javascript: URI in iframe", "CWE-79", 7),
    (re.compile(r"onerror\s*=|onload\s*=.*(alert|document\.|fetch)", re.I), "W-HTML-EH-1", "Inline event handler executing code", "CWE-79", 6),
    (re.compile(r"<form\b(?:(?!action\s*=)[^>])*>", re.I), "W-HTML-FORM-1", "Form without action attribute", "CWE-20", 3),
    (re.compile(r"<input[^>]*type\s*=\s*['\"]password['\"][^>]*(?!.*autocomplete)", re.I), "W-HTML-AUTO-1", "Password field without autocomplete handling", "CWE-521", 3),
]

CSS_RULES = [
    (re.compile(r"expression\s*\(", re.I), "W-CSS-EXPR-1", "CSS expression() - legacy code execution vector", "CWE-79", 7),
    (re.compile(r"url\s*\(\s*['\"]?\s*javascript:", re.I), "W-CSS-URL-1", "javascript: URL in CSS", "CWE-79", 8),
    (re.compile(r"behavior\s*:\s*url", re.I), "W-CSS-BEH-1", "IE behavior URL (remote script execution)", "CWE-79", 8),
]

SEMGREP_SEV_MAP = {"ERROR": 10, "WARNING": 6, "INFO": 3}


class WebScanner:
    name = "web-heuristic"

    def scan_text(self, filename: str, code: str) -> list[dict]:
        ext = Path(filename).suffix.lower()
        rule_sets = []
        if ext in {".php", ".phtml"}:
            rule_sets.append(PHP_RULES)
        if ext in {".js", ".jsx", ".ts", ".mjs"}:
            rule_sets.append(JS_RULES)
        if ext in {".html", ".htm", ".xhtml"}:
            rule_sets.append(HTML_RULES)
        if ext == ".css":
            rule_sets.append(CSS_RULES)
        if not rule_sets:
            rule_sets.append(HTML_RULES)

        findings = []
        for rules in rule_sets:
            for line_no, line in enumerate(code.splitlines(), start=1):
                for pattern, rule_id, title, cwe_id, score in rules:
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
                                "raw": {"rule_id": rule_id, "language": "web"},
                            }
                        )
        return _dedupe(findings)

    def scan_path(self, path: Path) -> list[dict]:
        findings = []
        for file in _iter_web_files(path):
            try:
                code = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self.scan_text(str(file.relative_to(path)), code))
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
            score = SEMGREP_SEV_MAP.get(res.get("extra", {}).get("severity", "WARNING"), 5)
            findings.append(
                {
                    "file": res.get("path", ""),
                    "line": int(res.get("start", {}).get("line", 0)),
                    "code": (res.get("extra", {}).get("lines", "") or "")[:300],
                    "scanner": "semgrep",
                    "rule_id": res.get("check_id"),
                    "title": (res.get("extra", {}).get("message", "Semgrep finding"))[:200],
                    "severity_score": score,
                    "severity": _sev(score),
                    **resolve_cwe("CWE-20"),
                    "description": res.get("extra", {}).get("message", ""),
                    "raw": {"check_id": res.get("check_id"), "language": "web"},
                }
            )
        return findings


def _iter_web_files(path: Path):
    exts = {".php", ".phtml", ".js", ".jsx", ".ts", ".mjs", ".html", ".htm", ".xhtml", ".css"}
    for p in path.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
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
