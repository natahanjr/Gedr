"""
Generic security scanner for additional languages:
Go, Ruby, Rust, C#, Kotlin, Swift, Shell/Bash, SQL.

Same two-layer contract as the other scanners: line-based heuristics,
normalized findings for the risk engine.
"""
import re
from pathlib import Path

from . import resolve_cwe


def _rules_go() -> list[tuple]:
    return [
        (re.compile(r"\bexec\.Command\s*\(\s*['\"]?(?:/bin/)?(?:ba)?sh['\"]"), "G-CMDI-1", "Shell invocation via exec.Command allows command injection", "CWE-78", 8),
        (re.compile(r"\bos/exec\.[A-Za-z]*Command\s*\([^)]*\.\.\."), "G-CMDI-2", "exec.Command built from variable arguments", "CWE-78", 7),
        # Word boundaries on identifier + value so 'json' / 'application/json' no
        # longer match 'api_key'/'token' substrings inside URL/headers.
        (re.compile(r"(?i)\b(?:password|passwd|secret|apikey|api[_-]key|token)\b\s*[:=]\s*[\"'][^\"']{6,}[\"']"), "G-HARDCODE-1", "Hardcoded credential in Go source", "CWE-798", 8),
        (re.compile(r"\bcrypto/(?:md5|sha1)\b"), "G-CRYPTO-1", "Weak hash algorithm (MD5/SHA-1) imported", "CWE-327", 6),
        (re.compile(r"(?i)\bhttp://(?!localhost|127\.0\.0\.1)"), "G-CLEAR-1", "Cleartext HTTP URL in Go code", "CWE-319", 4),
        (re.compile(r"\btls\.Config\s*\{[^}]*InsecureSkipVerify\s*:\s*true"), "G-TLS-1", "TLS certificate verification disabled", "CWE-295", 8),
        (re.compile(r"\bfmt\.Sprintf\s*\(\s*['\"](?:SELECT|INSERT|UPDATE)"), "G-SQLI-1", "SQL query built with fmt.Sprintf", "CWE-89", 8),
        (re.compile(r"\btemplate\.HTML\s*\("), "G-XSS-1", "template.HTML bypasses auto-escaping", "CWE-79", 7),
    ]


def _rules_ruby() -> list[tuple]:
    return [
        (re.compile(r"\beval\s*\(|instance_eval\b|class_eval\b"), "R-CMDI-1", "eval() usage enables code injection", "CWE-95", 9),
        (re.compile(r"`[^`]*#\{|\bsystem\s*\(|%x\(|\bexec\s*\(|IO\.popen\b"), "R-CMDI-2", "Shell command with interpolated input", "CWE-78", 9),
        (re.compile(r"(?i)\b(?:password|secret|api[_-]key|token)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]"), "R-HARDCODE-1", "Hardcoded credential in Ruby source", "CWE-798", 8),
        (re.compile(r"\bActiveRecord::Base\.connection\.execute\b|\bfind_by_sql\s*\("), "R-SQLI-1", "Raw SQL with interpolation", "CWE-89", 9),
        (re.compile(r"\brender\s+text\s*=>|\brender\s+:text\s*=>"), "R-XSS-1", "render :text may output unsanitized data", "CWE-79", 6),
        (re.compile(r"\bverify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE\b"), "R-TLS-1", "SSL certificate verification disabled", "CWE-295", 8),
        (re.compile(r"\bDigest::(?:MD5|SHA1)\b"), "R-CRYPTO-1", "Weak hash (MD5/SHA-1)", "CWE-327", 6),
        (re.compile(r"\bYAML\.load\s*\((?!.*safe)"), "R-DESER-1", "Unsafe YAML.load deserialization", "CWE-502", 8),
    ]


def _rules_rust() -> list[tuple]:
    return [
        (re.compile(r"\bunsafe\s*\{"), "RS-UNSAFE-1", "unsafe block disables memory safety guarantees", "CWE-120", 6),
        (re.compile(r"\bstd::process::Command::new\s*\(\s*[\"']?(?:sh|bash|cmd)[\"']"), "RS-CMDI-1", "Spawning a shell via Command::new", "CWE-78", 8),
        (re.compile(r"(?i)\b(?:password|secret|api[_-]key|token)\b\s*[:=]\s*[\"'][^\"']{6,}[\"']"), "RS-HARDCODE-1", "Hardcoded credential in Rust source", "CWE-798", 8),
        (re.compile(r"\bunwrap\s*\(\s*\)\s*;?\s*$"), "RS-ERR-1", "unwrap() can panic on untrusted input (DoS)", "CWE-20", 3),
        (re.compile(r"\b(?:md5|sha1)::"), "RS-CRYPTO-1", "Weak hash crate (md5/sha1)", "CWE-327", 6),
    ]


def _rules_csharp() -> list[tuple]:
    return [
        (re.compile(r"\bProcess\.Start\s*\([^)]*(?:cmd|powershell)|\bUseShellExecute\s*=\s*true"), "C-CMDI-1", "Process.Start via shell allows command injection", "CWE-78", 8),
        (re.compile(r"\b(?:new\s+)?(?:Sql(?:Client\.)?)?Sql(?:Client\.)?Command(?:Builder)?\s*\([^)]*\+\s*\w+|\b(?:new\s+)?SqlCommand\s*\([^)]*\+\s*\w+"), "C-SQLI-1", "SqlCommand built with string concatenation", "CWE-89", 9),
        (re.compile(r"(?i)\b(?:string\s+)?(?:password|passwd|pwd|secret|apikey|api[_-]key|access[_-]?key|token)\w*\s*=\s*\"[^\"]{6,}\""), "C-HARDCODE-1", "Hardcoded credential in C# source", "CWE-798", 8),
        (re.compile(r"\b(?:MD5|SHA1)\.Create\b|\bnew\s+MD5CryptoServiceProvider\b"), "C-CRYPTO-1", "Weak hash algorithm (MD5/SHA-1)", "CWE-327", 6),
        (re.compile(r"\bResponse\.Write\s*\(\s*Request[.\[]|<%=\s*Request\[", re.I), "C-XSS-1", "Reflected request value written to response", "CWE-79", 9),
        (re.compile(r"\bDns\.GetHostAddresses\b|\bWebRequest\.Create\s*\(\s*\w+\s*\)"), "C-SSRF-1", "Possible SSRF: URL taken from variable", "CWE-918", 6),
        (re.compile(r"\bRandom\s+\w+\s*=\s*new\s+Random\s*\(\s*\)"), "C-RANDOM-1", "System.Random is not cryptographically secure", "CWE-330", 6),
        (re.compile(r"\bValidateRequest\s*=\s*false\b|\bvalidateIntegratedModeConfiguration\b"), "C-VALID-1", "ASP.NET request validation disabled", "CWE-20", 6),
    ]


def _rules_kotlin() -> list[tuple]:
    return [
        (re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\("), "K-CMDI-1", "Runtime.exec with dynamic command", "CWE-78", 8),
        (re.compile(r"(?i)\b(?:password|secret|api[_-]key|apikey|token)\b\s*=\s*\"[^\"]{6,}\""), "K-HARDCODE-1", "Hardcoded credential in Kotlin source", "CWE-798", 8),
        (re.compile(r"\brawQuery\s*\(|\bexecSQL\s*\([^)]*\$"), "K-SQLI-1", "SQLite raw query with interpolated value", "CWE-89", 8),
        (re.compile(r"\ballowBackup\s*=\s*true\b|\bexported\s*=\s*true\b"), "K-ANDROID-1", "Android component exported/backup enabled - review exposure", "CWE-926", 4),
        (re.compile(r"\bMessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\""), "K-CRYPTO-1", "Weak hash algorithm (MD5/SHA-1)", "CWE-327", 6),
        (re.compile(r"\bWebView[a-zA-Z]*\.setJavaScriptEnabled\s*\(\s*true"), "K-WEBVIEW-1", "JavaScript enabled in WebView", "CWE-79", 6),
    ]


def _rules_swift() -> list[tuple]:
    return [
        (re.compile(r"(?i)\b(?:password|secret|api[_-]key|apikey|token)\b\s*[:=]\s*\"[^\"]{6,}\""), "S-HARDCODE-1", "Hardcoded credential in Swift source", "CWE-798", 8),
        (re.compile(r"\bProcess\s*\(\s*\)|\bposix_spawn\b"), "S-CMDI-1", "Process spawned from Swift code", "CWE-78", 7),
        (re.compile(r"\bkSecTrustSettings\b|\bURLSession\.shared\.delegate\b|\ballowsArbitraryLoads\b"), "S-TLS-1", "ATS/TLS restrictions relaxed", "CWE-295", 7),
        (re.compile(r"\bInsecure\.(?:MD5|SHA1)\b"), "S-CRYPTO-1", "Weak hash algorithm (MD5/SHA-1)", "CWE-327", 6),
        (re.compile(r"\bevaluateJavaScript\s*\(\s*(?!.*static)"), "S-JSINJ-1", "WKWebView evaluateJavaScript with dynamic content", "CWE-95", 6),
    ]


def _rules_shell() -> list[tuple]:
    return [
        (re.compile(r"\beval\s+[\$\"]"), "SH-EVAL-1", "eval on expanded variables enables code injection", "CWE-95", 9),
        (re.compile(r"\bcurl[^|]*\|\s*(?:ba)?sh\b|\bwget[^|]*\|\s*(?:ba)?sh\b"), "SH-DL-1", "Remote script piped directly into shell", "CWE-494", 9),
        (re.compile(r"(?i)\b(?:password|passwd|secret|token)\b\s*=\s*['\"][^'\"]{4,}['\"]"), "SH-HARDCODE-1", "Hardcoded credential in shell script", "CWE-798", 8),
        (re.compile(r"\brm\s+-rf?\s+[\"\$]"), "SH-DESTR-1", "rm -rf with variable path is dangerous", "CWE-78", 7),
        (re.compile(r"\bchmod\s+(?:777|666)\b"), "SH-PERM-1", "World-writable permissions set", "CWE-732", 6),
        (re.compile(r"\bnc\s+-[el]\b|\bmkfifo\b.*\bnc\b"), "SH-REV-1", "Possible reverse-shell primitive (nc listener)", "CWE-78", 8),
        (re.compile(r"\bsshpass\b|\bssh\b[^\n]*-oStrictHostKeyChecking=no\b"), "SH-SSH-1", "SSH host-key checking disabled or cleartext password tool", "CWE-322", 7),
    ]


def _rules_sql() -> list[tuple]:
    return [
        (re.compile(r"(?i)\bGRANT\s+ALL\s+PRIVILEGES\b"), "Q-GRANT-1", "GRANT ALL PRIVILEGES - excessive permissions", "CWE-250", 7),
        (re.compile(r"(?i)\bCREATE\s+(?:USER|LOGIN)\s+\w+\s+WITH\s+PASSWORD\s*=\s*'[^']{1,7}'"), "Q-PASS-1", "Weak password in CREATE USER", "CWE-521", 7),
        (re.compile(r"(?i)\bIDENTIFIED\s+BY\s+'[^']{1,7}'"), "Q-PASS-2", "Short password in IDENTIFIED BY clause", "CWE-521", 7),
        (re.compile(r"(?i)\bEXECUTE\s+IMMEDIATE\s*\|\||\bsp_executesql\s*@sql\b"), "Q-DYN-1", "Dynamic SQL execution", "CWE-89", 6),
        (re.compile(r"(?i)\bENCRYPTION\s*=\s*NO\b|\bsslmode\s*=\s*disable\b"), "Q-TLS-1", "Connection encryption disabled", "CWE-319", 6),
    ]


LANGUAGE_RULES = {
    "go": (_rules_go, {"name": "go-heuristic"}),
    "ruby": (_rules_ruby, {"name": "ruby-heuristic"}),
    "rust": (_rules_rust, {"name": "rust-heuristic"}),
    "csharp": (_rules_csharp, {"name": "csharp-heuristic"}),
    "kotlin": (_rules_kotlin, {"name": "kotlin-heuristic"}),
    "swift": (_rules_swift, {"name": "swift-heuristic"}),
    "shell": (_rules_shell, {"name": "shell-heuristic"}),
    "sql": (_rules_sql, {"name": "sql-heuristic"}),
}


def _sev(score: int) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


class GenericScanner:
    """Heuristic scanner driven by per-language rule tables."""

    def __init__(self, lang: str):
        builder, meta = LANGUAGE_RULES[lang]
        self.lang = lang
        self.name = meta["name"]
        self._rules = builder()

    def scan_text(self, filename: str, code: str) -> list[dict]:
        findings = []
        for line_no, line in enumerate(code.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                # still allow SQL/XML-style comments handled below
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue
                if not stripped:
                    continue
            clean = stripped
            if "#" in line and self.lang in ("go", "ruby", "shell"):
                clean = line.split("#")[0]
            elif "//" in line and self.lang in ("go", "rust", "csharp", "kotlin", "swift"):
                clean = line.split("//")[0]
            for pattern, rule_id, title, cwe_id, score in self._rules:
                try:
                    if pattern.search(clean):
                        findings.append({
                            "file": filename,
                            "line": line_no,
                            "code": stripped[:300],
                            "scanner": self.name,
                            "rule_id": rule_id,
                            "title": title,
                            "severity_score": score,
                            "severity": _sev(score),
                            **resolve_cwe(cwe_id),
                            "description": f"{title} (line {line_no}).",
                            "raw": {"rule_id": rule_id, "language": self.lang},
                        })
                except Exception:
                    continue
        return self._dedupe(findings)

    @staticmethod
    def _dedupe(findings: list[dict]) -> list[dict]:
        seen, out = set(), []
        for f in findings:
            key = (f["file"], f["line"], f["rule_id"])
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out


# Pre-built instances, one per language (mirrors SCANNER_INSTANCES shape)
GENERIC_SCANNERS = {lang: GenericScanner(lang) for lang in LANGUAGE_RULES}
