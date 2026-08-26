"""
Scanner Manager: orchestrates the whole scan pipeline.

Responsibilities:
  - Detect programming language from file extensions.
  - Dispatch files to the correct language scanner.
  - Merge heuristic + external tool findings.
  - Run the risk engine: severity classification and security score.
  - Persist results through the SQLite manager.

Design decision: the heuristic layer always runs (zero external
dependencies), while external tools (Bandit, Semgrep, Clang, SpotBugs,
PMD) are probed on PATH and only invoked when present - keeping the
system light on a 12GB RAM laptop.
"""
import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from database.sqlite_manager import PostgresManager
from backend.path_security import is_safe_symlink
from scanners.cpp_scanner import CppScanner
from scanners.java_scanner import JavaScanner
from scanners.python_scanner import PythonScanner
from scanners.web_scanner import WebScanner
from scanners.dependency_scanner import DependencyScanner
from backend.docker_orchestrator import DockerScannerManager
from backend.custom_rule_engine import CustomRuleEngine
from backend.taint_analyzer import TaintAnalyzer
from scanners.generic_scanner import GENERIC_SCANNERS
from scanner_connectors import get_registry, ScanResult as ConnectorScanResult

# Optional external scanner connectors (OpenVAS, Nmap, Nessus, Custom)
CONNECTOR_CONFIGS: dict[str, dict] = {
    "openvas": {
        "host": os.getenv("OPENVAS_HOST", "localhost"),
        "port": int(os.getenv("OPENVAS_PORT", "9390")),
        "username": os.getenv("OPENVAS_USERNAME", ""),
        "password": os.getenv("OPENVAS_PASSWORD", ""),
    },
    "nmap": {},
    "nessus": {
        "url": os.getenv("NESSUS_URL", ""),
        "api_key": os.getenv("NESSUS_API_KEY", ""),
        "secret_key": os.getenv("NESSUS_SECRET_KEY", ""),
    },
    "custom": {
        "command": os.getenv("CCI_CUSTOM_SCANNER_CMD", ""),
        "output_format": os.getenv("CCI_CUSTOM_SCANNER_FORMAT", "text"),
    },
}

LANGUAGE_EXTENSIONS = {
    "python": {".py", ".pyw", ".pyi"},
    "java": {".java"},
    "cpp": {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"},
    "web": {".php", ".phtml", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".html", ".htm", ".xhtml", ".css"},
    # Additional languages (generic heuristic scanners)
    "go": {".go"},
    "ruby": {".rb", ".erb", ".rake", ".gemspec"},
    "rust": {".rs"},
    "csharp": {".cs"},
    "kotlin": {".kt", ".kts"},
    "swift": {".swift"},
    "shell": {".sh", ".bash", ".zsh", ".bashrc", ".bash_profile"},
    "sql": {".sql"},
}

# Directories never worth scanning: vendored deps, build output, VCS.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    "node_modules", "bower_components", ".venv", "venv", "env", "site-packages",
    "dist", "build", "target", ".gradle", ".idea", ".vscode", ".next", ".nuxt",
    "coverage", "htmlcov", ".tox", ".nox", "vendor",
}

# Heuristic scanners can't parse CSS well for these, but our rules handle it.

SCANNER_INSTANCES = {
    "python": PythonScanner(),
    "java": JavaScanner(),
    "cpp": CppScanner(),
    "web": WebScanner(),
    **GENERIC_SCANNERS,  # go, ruby, rust, csharp, kotlin, swift, shell, sql
}

MAX_FILE_BYTES = 2 * 1024 * 1024  # skip minified bundles / binaries


def detect_language(filename: str) -> str | None:
    ext = Path(filename).suffix.lower()
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        if ext in exts:
            return lang
    return None


class RiskEngine:
    """Maps findings to severities and computes the project security score.

    Score model: 100 - sum(weighted finding penalties), floored at 0.
    Critical=30, High=15, Medium=6, Low=2. The formula is deliberately
    transparent so thesis reviewers can reproduce the math.
    """

    PENALTY = {"Critical": 30, "High": 15, "Medium": 6, "Low": 2}

    @staticmethod
    def classify(score: int) -> str:
        if score >= 9:
            return "Critical"
        if score >= 7:
            return "High"
        if score >= 4:
            return "Medium"
        return "Low"

    def compute_security_score(self, findings: list[dict], total_files: int) -> int:
        if not findings:
            return 100
        penalty = sum(self.PENALTY.get(f.get("severity", "Low"), 2) for f in findings)
        # Scale penalty by project size so a single file with one medium issue
        # is not unfairly graded against a large codebase.
        scale = 1.0 if total_files <= 1 else max(0.4, 10.0 / total_files)
        return max(0, 100 - round(penalty * scale))

    def grade(self, score: int) -> str:
        if score >= 90:
            return "A+ (Secure)"
        if score >= 80:
            return "A (Good)"
        if score >= 70:
            return "B (Acceptable)"
        if score >= 50:
            return "C (At Risk)"
        if score >= 30:
            return "D (High Risk)"
        return "F (Critical)"


class ScannerManager:
    def __init__(self, db: PostgresManager | None = None):
        self.db = db or PostgresManager()
        self.risk = RiskEngine()
        self._lock = threading.Lock()
        self.custom_rules = CustomRuleEngine()
        self.taint_analyzer = TaintAnalyzer()
        self.connector_registry = get_registry()

    # ------------------------------------------------------------------
    def run_connector(self, connector_name: str, target: str) -> ConnectorScanResult:
        """Run an external scanner connector by name."""
        inst = self.connector_registry.get_instance(connector_name, CONNECTOR_CONFIGS.get(connector_name))
        if not inst:
            return ConnectorScanResult(
                scanner_name=connector_name, success=False,
                findings=[], error=f"Unknown connector: {connector_name}",
            )
        return inst.scan(target)

    # ------------------------------------------------------------------
    def list_connectors(self) -> list[dict]:
        """List all registered connectors with availability status."""
        out = []
        for info in self.connector_registry.list_available():
            cfg = CONNECTOR_CONFIGS.get(info["name"], {})
            configured = bool(cfg.get("command") or cfg.get("url") or cfg.get("api_key"))
            out.append({**info, "configured": configured})
        return out

    # ------------------------------------------------------------------
    def collect_files(self, source: Path) -> list[Path]:
        files = []
        source_resolved = source.resolve()
        for root, dirs, names in source.walk():
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in names:
                fpath = Path(root) / name
                if not detect_language(name):
                    continue
                # Reject symlinks pointing outside scan root
                if not is_safe_symlink(fpath, follow=False):
                    continue
                # Reject symlinks that resolve outside scan root
                try:
                    fpath_resolved = fpath.resolve()
                    if not str(fpath_resolved).startswith(str(source_resolved)):
                        continue
                except (OSError, RuntimeError):
                    continue
                files.append(fpath)
        return files

    def scan_path(self, source: Path, use_ai: bool = True, max_findings: int = 500) -> dict:
        """Run a full scan over a directory (or single file) and persist it."""
        source = Path(source)
        if source.is_file():
            source = source.parent  # scan the containing dir, but limit below

        files = self.collect_files(source)
        project_name = source.name
        language = self._dominant_language(files) or "unknown"

        project_id = self.db.create_project(project_name, language, str(source))
        scan_id = self.db.create_scan(project_id)

        findings: list[dict] = []
        with self._lock:

            def _scan_file(f: Path):
                rel = str(f.relative_to(source))
                lang = detect_language(f.name)
                if lang is None:
                    return []
                try:
                    stat = f.stat()
                    if stat.st_size > MAX_FILE_BYTES:
                        return []
                    # TOCTOU mitigation: snapshot mtime before and after read
                    mtime_before = stat.st_mtime
                    text = f.read_text(encoding="utf-8", errors="replace")
                    mtime_after = f.stat().st_mtime
                    if mtime_before != mtime_after:
                        return []  # File changed during read, skip
                    return SCANNER_INSTANCES[lang].scan_text(rel, text)
                except OSError:
                    return []

            with ThreadPoolExecutor(max_workers=4) as pool:
                for chunk in pool.map(_scan_file, files, chunksize=8):
                    findings.extend(chunk)
            
            # Run Custom User-Defined Rules
            for f in files:
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                    findings.extend(self.custom_rules.scan_file(f, text))
                    
                    # Run Taint Analysis
                    lang = detect_language(f.name)
                    if lang:
                        findings.extend(self.taint_analyzer.analyze_file(f, text, lang))
                except OSError:
                    pass

            # External tools (best effort, only if installed)
            findings.extend(self._run_external_tools(source, language))
            
            # Dependency vulnerability scanning
            try:
                dep_scanner = DependencyScanner()
                findings.extend(dep_scanner.scan_path(source))
            except Exception:
                pass

        findings = _dedupe_all(findings)
        findings.sort(key=lambda x: x.get("severity_score", 0), reverse=True)
        findings = findings[:max_findings]

        finding_ids = self.db.insert_findings(scan_id, findings)

        score = self.risk.compute_security_score(findings, len(files))
        summary = self._build_summary(findings, score)
        self.db.finish_scan(scan_id, len(files), score, bool(use_ai), summary)

        return {
            "scan_id": scan_id,
            "project_id": project_id,
            "score": score,
            "grade": self.risk.grade(score),
            "files_scanned": len(files),
            "findings": findings,
            "finding_ids": finding_ids,
            "summary": summary,
            "ai_enabled": use_ai,
        }

    # ------------------------------------------------------------------
    def _run_external_tools(self, source: Path, language: str) -> list[dict]:
        out = []
        try:
            if language == "python":
                if shutil.which("bandit"):
                    out += SCANNER_INSTANCES["python"].run_bandit(source)
                if shutil.which("semgrep"):
                    out += SCANNER_INSTANCES["python"].run_semgrep(source)
            elif language == "java":
                if shutil.which("spotbugs"):
                    out += SCANNER_INSTANCES["java"].run_spotbugs(source)
                if shutil.which("pmd"):
                    out += SCANNER_INSTANCES["java"].run_pmd(source)
            elif language == "cpp":
                if shutil.which("clang"):
                    out += SCANNER_INSTANCES["cpp"].run_clang_analyzer(source)
            elif language == "web":
                if shutil.which("semgrep"):
                    out += SCANNER_INSTANCES["web"].run_semgrep(source)
        except Exception:
            # External tools must never break the core scan.
            pass
        return out

    @staticmethod
    def _dominant_language(files: list[Path]) -> str:
        counts: dict[str, int] = {}
        for f in files:
            lang = detect_language(f.name)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
        if not counts:
            return "unknown"
        return max(counts, key=counts.get)

    @staticmethod
    def _build_summary(findings: list[dict], score: int) -> str:
        if not findings:
            return f"Scan complete. No vulnerabilities detected. Security score: {score}/100."
        sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev[f.get("severity", "Low")] += 1
        return (
            f"Found {len(findings)} findings: {sev['Critical']} critical, {sev['High']} high, "
            f"{sev['Medium']} medium, {sev['Low']} low. Security score: {score}/100."
        )


def _dedupe_all(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in findings:
        key = (f.get("file", ""), f.get("line", 0), f.get("rule_id", ""))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


class ScanSummary:
    """Structured summary of scan results for reporting."""
    
    def __init__(self, findings: list[dict], score: int, scan_time: float):
        self.findings = findings
        self.score = score
        self.scan_time = scan_time
        self.total = len(findings)
        self.by_severity = self._count_by_severity()
        self.by_cwe = self._count_by_cwe()
        self.affected_files = self._count_files()
    
    def _count_by_severity(self) -> dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in self.findings:
            sev = f.get("severity", "Low")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _count_by_cwe(self) -> dict[str, int]:
        counts = {}
        for f in self.findings:
            cwe = f.get("cwe", "Unknown")
            counts[cwe] = counts.get(cwe, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))
    
    def _count_files(self) -> int:
        return len({f.get("file") for f in self.findings if f.get("file")})
    
    def to_dict(self) -> dict:
        return {
            "total_findings": self.total,
            "security_score": self.score,
            "scan_time_seconds": round(self.scan_time, 2),
            "by_severity": self.by_severity,
            "by_cwe": self.by_cwe,
            "affected_files": self.affected_files,
        }
