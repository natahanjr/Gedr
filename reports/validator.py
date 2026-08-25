"""
Gedr Reporting Engine - report validation / automated quality control.

A PDF is not "generated" merely because a file exists. Every report passes
through this QC layer before delivery:

  structural checks   - valid PDF header/trailer, sane file size
  content checks      - cover contains the report identity, every finding
                        appears in the rendered text, no blank pages
  metadata checks     - document title/author set correctly
  consistency checks  - declared page count matches the physical file

Checks marked CRITICAL abort delivery; warnings are recorded on the
generator for diagnostics but do not block the report.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


CRITICAL = "critical"
WARNING = "warning"


@dataclass
class ReportValidation:
    ok: bool = True
    issues: list[tuple[str, str]] = field(default_factory=list)
    pages: int | None = None
    size_bytes: int = 0

    @property
    def critical_issues(self) -> list[str]:
        return [msg for level, msg in self.issues if level == CRITICAL]

    @property
    def warnings(self) -> list[str]:
        return [msg for level, msg in self.issues if level == WARNING]

    def summary(self) -> str:
        status = "PASS" if self.ok else "FAIL"
        return (f"{status} - pages={self.pages} size={self.size_bytes}B "
                f"warnings={len(self.warnings)}")


class ValidationError(RuntimeError):
    """Raised when a generated report fails a critical quality gate."""


def _try_pypdf():
    try:
        import pypdf  # noqa: F401
        return pypdf
    except Exception:
        return None


def validate_report(pdf_path: Path, *, expected_report_id: str,
                    expected_tokens: list[str] | None = None,
                    declared_pages: int | None = None) -> ReportValidation:
    """Run all quality gates against a freshly generated PDF."""
    result = ReportValidation()

    # ---------------- structural ----------------
    try:
        raw = Path(pdf_path).read_bytes()
    except OSError as exc:
        result.ok = False
        result.issues.append((CRITICAL, f"report unreadable: {exc}"))
        return result
    result.size_bytes = len(raw)
    if not raw.startswith(b"%PDF-"):
        result.ok = False
        result.issues.append((CRITICAL, "missing %PDF header"))
    if b"%%EOF" not in raw[-2048:]:
        result.ok = False
        result.issues.append((CRITICAL, "missing %%EOF trailer"))
    if result.size_bytes < 1024:
        result.ok = False
        result.issues.append((CRITICAL, "suspiciously small PDF (<1KB)"))

    pypdf = _try_pypdf()
    if pypdf is None:
        result.issues.append((
            WARNING,
            "pypdf not installed - deep layout/content checks skipped "
            "(pip install pypdf to enable full validation)",
        ))
        return result

    # ---------------- deep checks ----------------
    reader = None
    try:
        reader = pypdf.PdfReader(str(pdf_path))
        result.pages = len(reader.pages)
    except Exception as exc:
        result.ok = False
        result.issues.append((CRITICAL, f"PDF cannot be parsed: {exc}"))
        return result

    if result.pages == 0:
        result.ok = False
        result.issues.append((CRITICAL, "document has zero pages"))

    if declared_pages is not None and result.pages != declared_pages:
        result.issues.append((
            WARNING,
            f"declared page count {declared_pages} != actual {result.pages}",
        ))

    text_by_page: list[str] = []
    try:
        text_by_page = [(page.extract_text() or "") for page in reader.pages]
    except Exception as exc:
        result.issues.append((WARNING, f"text extraction failed ({exc}); content checks skipped"))

    full_text = "\n".join(text_by_page)

    if text_by_page:
        first_page = text_by_page[0]
        rid_token = expected_report_id.split("-")[-1] if expected_report_id else ""
        if rid_token and rid_token not in first_page:
            result.issues.append((WARNING, "cover page missing report identity"))
        for i, ptext in enumerate(text_by_page, start=1):
            if i > 1 and len(ptext.strip()) < 5:
                result.issues.append((WARNING, f"page {i} appears blank"))

    if expected_tokens:
        missing = [tok for tok in expected_tokens if tok and tok not in full_text]
        if missing:
            result.ok = False
            preview = ", ".join(missing[:5])
            result.issues.append((
                CRITICAL,
                f"required content missing from report: {preview}"
                + (" ..." if len(missing) > 5 else ""),
            ))

    # ---------------- metadata ----------------
    try:
        meta_title = str(reader.metadata.get("/Title", "")) if reader.metadata else ""
        if expected_report_id and expected_report_id not in meta_title:
            result.issues.append((WARNING, "document title metadata missing report id"))
    except Exception:
        result.issues.append((WARNING, "document metadata unreadable"))

    return result
