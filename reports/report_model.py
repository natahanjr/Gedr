"""
Gədr Reporting Engine - report model.

The data layer of the reporting pipeline. It converts raw platform records
(project / scan / findings / AI recommendations) into a normalised,
presentation-agnostic ReportModel.

Rules enforced here:
- Nothing is invented: aggregates are computed strictly from the supplied
  records; sections that lack data are flagged absent so the layout layer
  can omit them.
- Everything is sanitised: no credential-bearing text survives to the
  presentation layer.
- Findings receive stable human-readable identifiers (GDR-F-001 ...) used
  for cross-referencing between the overview table, finding pages and the
  remediation plan.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .sanitizer import clean, strip_ai_headings
from .theme import SEVERITY_ORDER, grade_for, severity_of

ENGINE_NAME = "Gedr Reporting Engine"
ENGINE_VERSION = "3.0"
PLATFORM_NAME = "Gedr"

SEVERITY_RANK: dict[str, int] = {name: i for i, name in enumerate(SEVERITY_ORDER)}


def _parse_ts(value: Any) -> datetime | None:
    """Parse timestamps as stored by the platform (ISO-8601 variants)."""
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    dt = None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s[:19], fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _fmt_ts(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "Not available"


@dataclass(frozen=True)
class FindingModel:
    uid: str                  # GDR-F-001
    index: int                # 1-based position in this report
    db_id: Any
    title: str
    severity: str             # Critical | High | Medium | Low | Informational
    score: int                # 1-10
    file: str
    line: int
    code: str                 # evidence snippet (sanitised)
    scanner: str
    rule_id: str
    cwe: str
    owasp: str
    description: str

    @property
    def location(self) -> str:
        loc = self.file or "unknown location"
        if self.line:
            loc = f"{loc}:{self.line}"
        return loc

    @property
    def short_location(self) -> str:
        """Compact location for tables/captions: filename(+line) when deep."""
        loc = self.file or "unknown"
        if len(loc) > 34 and ("\\" in loc or "/" in loc):
            loc = re.split(r"[\\/]", loc)[-1]
        if self.line:
            loc = f"{loc}:{self.line}"
        return loc


@dataclass(frozen=True)
class RecommendationModel:
    explanation: str
    impact: str
    attack_scenario: str
    root_cause: str
    recommended_fix: str
    secure_code: str
    model: str


@dataclass
class Aggregates:
    total: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_scanner: dict[str, int] = field(default_factory=dict)
    by_cwe: list[tuple[str, int]] = field(default_factory=list)
    by_owasp: list[tuple[str, int]] = field(default_factory=list)
    top_files: list[tuple[str, int]] = field(default_factory=list)
    max_score: int = 0
    files_scanned: int = 0
    duration_minutes: float | None = None


@dataclass
class ReportMeta:
    report_id: str
    filename_date: str
    generated_at: datetime
    generated_at_s: str
    report_type: str
    classification: str
    document_version: str
    project_name: str
    project_language: str
    project_path: str
    scan_id: str
    scan_status: str
    started_at: datetime | None
    finished_at: datetime | None
    started_at_s: str
    finished_at_s: str
    security_score: int
    grade: str
    ai_enabled: bool
    summary_text: str
    data_digest: str


def _cwe_family(cwe: str) -> str:
    """Group raw CWE ids (CWE-089, CWE-89, CWE-79 XSS variants) for aggregation."""
    m = re.search(r"(\d+)", cwe or "")
    return f"CWE-{int(m.group(1))}" if m else ""


class ReportModel:
    """Normalised, validated and sanitised view of one analysis."""

    def __init__(self, project: dict, scan: dict, findings: list[dict],
                 recommendations: dict[Any, dict], *,
                 report_type: str, classification: str):
        now = datetime.now(timezone.utc)

        # ---- identity ----------------------------------------------------
        scan_raw_id = str(scan.get("id") or "UNKNOWN")
        scan_token = re.sub(r"[^A-Za-z0-9]", "", scan_raw_id).upper()[:8] or "SCAN"
        date_token = now.strftime("%Y%m%d")
        self.meta = ReportMeta(
            report_id=f"GDR-{scan_token}",
            filename_date=date_token,
            generated_at=now,
            generated_at_s=_fmt_ts(now),
            report_type=report_type,
            classification=classification,
            document_version="1.0",
            project_name=clean(project.get("name")) or "Untitled Project",
            project_language=clean(project.get("language")) or "Not recorded",
            project_path=clean(project.get("source_path"), max_length=120) or "Not recorded",
            scan_id=scan_raw_id,
            scan_status=clean(scan.get("status")) or "unknown",
            started_at=_parse_ts(scan.get("started_at")),
            finished_at=_parse_ts(scan.get("finished_at")),
            started_at_s="", finished_at_s="",   # filled below
            security_score=self._safe_int(scan.get("security_score"), default=100, lo=0, hi=100),
            grade=grade_for(self._safe_int(scan.get("security_score"), default=100, lo=0, hi=100)),
            ai_enabled=bool(scan.get("ai_enabled")),
            summary_text=clean(scan.get("summary"), max_length=2000),
            data_digest="",
        )
        self.meta.started_at_s = _fmt_ts(self.meta.started_at)
        self.meta.finished_at_s = _fmt_ts(self.meta.finished_at)

        # ---- findings ------------------------------------------------------
        recs_by_key: dict[str, dict] = {}
        for key, rec in (recommendations or {}).items():
            recs_by_key[str(key)] = rec or {}

        ordered = sorted(
            findings or [],
            key=lambda f: (
                -self._safe_int(f.get("severity_score"), default=0, lo=0, hi=10),
                clean(f.get("file")),
                self._safe_int(f.get("line"), default=0, lo=0, hi=10**9),
            ),
        )
        self.findings: list[FindingModel] = []
        self.recommendations: dict[str, RecommendationModel] = {}
        for i, f in enumerate(ordered, start=1):
            score = self._safe_int(f.get("severity_score"), default=1, lo=0, hi=10)
            sev = severity_of(f.get("severity"), score if score else None)
            fm = FindingModel(
                uid=f"GDR-F-{i:03d}",
                index=i,
                db_id=f.get("id"),
                title=clean(f.get("title"), max_length=180) or "Untitled finding",
                severity=sev,
                score=max(1, score) or 1,
                file=clean(f.get("file"), max_length=160) or "",
                line=self._safe_int(f.get("line"), default=0, lo=0, hi=10**9),
                code=clean(f.get("code"), max_length=1200),
                scanner=clean(f.get("scanner"), max_length=40) or "heuristic",
                rule_id=clean(f.get("rule_id"), max_length=60),
                cwe=_cwe_family(clean(f.get("cwe"), max_length=24)),
                owasp=clean(f.get("owasp"), max_length=60),
                description=clean(f.get("description"), max_length=1500),
            )
            self.findings.append(fm)

            raw_rec = recs_by_key.get(str(fm.db_id)) or recs_by_key.get(fm.uid)
            if raw_rec:
                self.recommendations[fm.uid] = RecommendationModel(
                    explanation=strip_ai_headings(clean(raw_rec.get("explanation"), max_length=2500)),
                    impact=strip_ai_headings(clean(raw_rec.get("impact"), max_length=2000)),
                    attack_scenario=strip_ai_headings(clean(raw_rec.get("attack_scenario"), max_length=2000)),
                    root_cause=strip_ai_headings(clean(raw_rec.get("root_cause"), max_length=2000)),
                    recommended_fix=strip_ai_headings(clean(raw_rec.get("recommended_fix"), max_length=2500)),
                    secure_code=clean(raw_rec.get("secure_code"), max_length=800),
                    model=clean(raw_rec.get("model"), max_length=60),
                )

        # ---- aggregates -----------------------------------------------------
        self.agg = Aggregates(
            total=len(self.findings),
            files_scanned=self._safe_int(scan.get("files_scanned"), default=0, lo=0, hi=10**9),
        )
        self._compute_aggregates()

        # ---- integrity digest over the normalised inputs -------------------
        canonical = json.dumps({
            "project": {k: self.meta.__dict__.get(k) for k in ()},
            "scan": {k: scan.get(k) for k in ("id", "security_score", "files_scanned",
                                              "status", "ai_enabled")},
            "findings": [
                [fm.title, fm.severity, fm.score, fm.file, fm.line,
                 fm.scanner, fm.rule_id, fm.cwe, fm.owasp]
                for fm in self.findings
            ],
            "recommendation_count": len(self.recommendations),
        }, sort_keys=True, default=str)
        self.meta.data_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ #
    @staticmethod
    def _safe_int(value: Any, *, default: int, lo: int, hi: int) -> int:
        try:
            n = int(value)
        except (TypeError, ValueError):
            return default
        return max(lo, min(hi, n))

    def _compute_aggregates(self) -> None:
        agg = self.agg
        counts = {name: 0 for name in SEVERITY_ORDER}
        scanners: dict[str, int] = {}
        cwe_counts: dict[str, int] = {}
        owasp_counts: dict[str, int] = {}
        file_counts: dict[str, int] = {}

        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            scanners[f.scanner] = scanners.get(f.scanner, 0) + 1
            if f.cwe:
                cwe_counts[f.cwe] = cwe_counts.get(f.cwe, 0) + 1
            if f.owasp:
                owasp_counts[f.owasp] = owasp_counts.get(f.owasp, 0) + 1
            key = f.file or "(no path recorded)"
            file_counts[key] = file_counts.get(key, 0) + 1
            agg.max_score = max(agg.max_score, f.score)

        agg.by_severity = counts
        agg.by_scanner = dict(sorted(scanners.items(), key=lambda kv: (-kv[1], kv[0])))
        agg.by_cwe = sorted(cwe_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        agg.by_owasp = sorted(owasp_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
        agg.top_files = sorted(file_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:8]

        if self.meta.started_at and self.meta.finished_at:
            delta = self.meta.finished_at - self.meta.started_at
            agg.duration_minutes = round(max(delta.total_seconds(), 0) / 60.0, 1)

    # ------------------------------------------------------------------ #
    @property
    def analysis_window(self) -> str:
        start, end = self.meta.started_at, self.meta.finished_at
        if start and end:
            return f"{self.meta.started_at_s}  \u2192  {self.meta.finished_at_s}"
        if start:
            return f"{self.meta.started_at_s}  \u2192  in progress"
        return "Not recorded"

    @property
    def has_findings(self) -> bool:
        return self.agg.total > 0

    @property
    def has_recommendations(self) -> bool:
        return bool(self.recommendations)

    def present_severities(self) -> list[tuple[str, int]]:
        return [(name, self.agg.by_severity.get(name, 0)) for name in SEVERITY_ORDER]

    def top_findings(self, limit: int = 5) -> list[FindingModel]:
        return self.findings[:limit]

    def remediation_tiers(self) -> list[tuple[str, str, list[FindingModel]]]:
        """Priority tiers derived purely from observed severities."""
        tiers: dict[str, list[FindingModel]] = {
            "Immediate": [], "Scheduled": [], "Hygiene": [],
        }
        for f in self.findings:
            if f.severity == "Critical":
                tiers["Immediate"].append(f)
            elif f.severity == "High":
                tiers["Immediate"].append(f)
            elif f.severity == "Medium":
                tiers["Scheduled"].append(f)
            else:
                tiers["Hygiene"].append(f)
        window = {
            "Immediate": "Address before release / within days",
            "Scheduled": "Address within the regular development cycle",
            "Hygiene": "Fold into routine maintenance",
        }
        out = []
        for name in ("Immediate", "Scheduled", "Hygiene"):
            if tiers[name]:
                out.append((name, window[name], tiers[name]))
        return out


# --------------------------------------------------------------------------- #

def build_report_model(project: dict, scan: dict, findings: list[dict],
                       recommendations: dict[Any, dict], *,
                       report_type: str = "Security Analysis Report",
                       classification: str = "Confidential - Internal Use Only") -> ReportModel:
    return ReportModel(project, scan, findings, recommendations,
                       report_type=report_type, classification=classification)
