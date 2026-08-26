"""
Gedr Reporting Engine - pipeline orchestrator and section builders.

Pipeline:  DATA -> REPORT MODEL -> SECTION GENERATION -> VISUALISATION
           -> PDF LAYOUT -> VALIDATION -> DELIVERY

The generator is data-driven: sections appear only when the underlying
analysis contains meaningful data for them, so a 3-finding scan produces a
concise report, a 300-finding scan a structured large one, and an empty
scan a meaningful "No Significant Findings" report - never blank pages or
empty tables.
"""
from __future__ import annotations

from pathlib import Path

from .charts import donut, hbars, legend, mini_tiles, score_meter
from .layout import GedrPDF
from .report_model import (
    ENGINE_NAME,
    ENGINE_VERSION,
    FindingModel,
    ReportModel,
    build_report_model,
)
from .theme import (
    FAINT,
    GRADE_BAND,
    GRADE_COLOR,
    INK,
    MARGIN_L,
    MARGIN_R,
    MUTED,
    NAVY,
    PAGE_W,
    SEVERITY_COLORS,
    SEVERITY_DEFINITIONS,
    SEVERITY_ORDER,
    SEVERITY_TINTS,
    STEEL,
    SURFACE,
    TYPE,
)
from .validator import validate_report

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports" / "output"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

REPORT_TYPE_SECURITY = "Security Analysis Report"

# CWE-specific hardening guidance used ONLY when no AI recommendation is
# stored for a finding. Clearly presented as general guidance in the report.
_CWE_GUIDANCE: dict[str, str] = {
    "CWE-89": "Use parameterised queries / prepared statements for every SQL statement; "
              "never build SQL through string concatenation with untrusted values.",
    "CWE-79": "Apply context-aware output encoding when rendering user-controlled data "
              "(HTML escaping, URL encoding) and deploy a Content-Security-Policy.",
    "CWE-78": "Avoid invoking shell commands with untrusted input; prefer argument lists "
              "without a shell and validate input against strict allowlists.",
    "CWE-120": "Replace unsafe memory operations with bounds-checked alternatives and "
               "verify buffer capacities before every copy.",
    "CWE-502": "Do not deserialise untrusted data with object-capable formats; prefer JSON "
               "or restrict deserialisation to explicit class allowlists.",
    "CWE-798": "Remove embedded credentials from source, move them to environment-based "
               "secrets management, and rotate any credential that has been exposed.",
    "CWE-434": "Validate uploads server-side (content type, size, extension), store files "
               "outside the web root, and never execute uploaded content.",
    "CWE-22": "Canonicalise file paths and validate against an allowlist of permitted "
              "directories; reject path components containing '..' or symbolic links.",
    "CWE-611": "Disable external entity processing in XML parsers; use safe parser "
               "configurations that reject DTDs and external entities.",
    "CWE-918": "Validate and sanitise all URLs before server-side requests; block access "
               "to internal network ranges (RFC 1918) and require explicit allowlists.",
    "CWE-601": "Validate redirect targets against a strict allowlist of trusted domains; "
               "never redirect to user-supplied URLs without verification.",
    "CWE-799": "Rate-limit outgoing network connections per source; monitor for abnormal "
               "volumes of outbound traffic that may indicate data exfiltration.",
    "CWE-917": "Avoid embedding user input directly into code strings; use parameterised "
               "templates or strict allowlists if dynamic expression evaluation is required.",
    "CWE-327": "Use only well-vetted cryptographic algorithms (AES-256-GCM, SHA-256+); "
               "never implement custom cryptography or use deprecated ciphers.",
    "CWE-330": "Generate cryptographic random values using cryptographically secure "
               "pseudo-random number generators (CSPRNGs); avoid Math.random() or rand().",
    "CWE-522": "Transport credentials only over encrypted channels (TLS 1.2+); store "
               "passwords using adaptive hashing (Argon2, bcrypt) with unique salts.",
    "CWE-862": "Enforce authorization checks on every request; never rely solely on "
               "client-side access control or obscurity for protection.",
    "CWE-863": "Verify authorization server-side on every operation; apply principle of "
               "least privilege and deny by default when permissions are ambiguous.",
    "CWE-200": "Avoid exposing internal system details (stack traces, versions, paths) "
               "in error messages; return generic errors to untrusted callers.",
    "CWE-287": "Implement multi-factor authentication for sensitive operations; enforce "
               "account lockout and credential complexity policies.",
    "CWE-306": "Perform all critical authentication and authorization checks server-side; "
               "never trust client-supplied authentication state or flags.",
    "CWE-362": "Use atomic operations or proper locking for shared resources; design "
               "concurrent access patterns to avoid race conditions.",
    "CWE-400": "Implement resource limits and rate limiting; validate request size and "
               "complexity before processing to prevent resource exhaustion.",
    "CWE-476": "Check all pointer/reference dereferences for NULL before use; use "
               "optional types or defensive checks in critical code paths.",
    "CWE-693": "Use a whitelist approach for plugin/extension loading; validate integrity "
               "of loaded components and apply sandboxing where possible.",
    "CWE-770": "Set explicit limits on collection sizes, recursion depth, and processing "
               "time; reject or truncate inputs that exceed defined thresholds.",
    "CWE-776": "Restrict XML parser configuration to disable external entity resolution "
               "and DTD processing; use JSON instead of XML where possible.",
    "CWE-918": "Restrict outbound network requests to trusted destinations; implement "
               "server-side request forgery protections with network segmentation.",
}


class SecurityReportGenerator:
    """Builds intelligence-grade PDF security reports from Gedr analysis data."""

    def __init__(self):
        self.last_validation = None
        self.report_id: str = ""
        self.model: ReportModel | None = None

    # ------------------------------------------------------------------ #
    # Public entry point (interface compatible with previous versions)
    # ------------------------------------------------------------------ #
    def generate(self, project: dict | None, scan: dict | None,
                 findings: list[dict] | None, recommendations: dict | None,
                 output_path: Path | None = None, *,
                 report_type: str = REPORT_TYPE_SECURITY,
                 classification: str = "Confidential - Internal Use Only") -> Path:
        model = build_report_model(
            project or {}, scan or {}, findings or [], recommendations or {},
            report_type=report_type, classification=classification,
        )
        self.model = model
        self.report_id = model.meta.report_id

        pdf = GedrPDF(classification=model.meta.classification,
                      report_id=model.meta.report_id)

        self._cover(pdf, model)
        self._document_information(pdf, model)
        self._executive_summary(pdf, model)
        self._security_posture(pdf, model)
        self._risk_analysis(pdf, model)
        self._mitre_attack(pdf, model)
        self._timeline(pdf, model)

        if model.has_findings:
            self._findings_overview(pdf, model)
            self._detailed_findings(pdf, model)
            self._remediation_plan(pdf, model)
        else:
            self._no_findings(pdf, model)

        self._appendix_methodology(pdf, model)
        self._appendix_metadata(pdf, model)

        # Generate TOC after all sections are recorded (page numbers are final)
        pdf.table_of_contents()

        if output_path is None:
            output_path = REPORTS_DIR / (
                f"GDR_Security_Analysis_Report_{model.meta.report_id}"
                f"_{model.meta.filename_date}.pdf"
            )
        output_path = Path(output_path)
        pdf.output(str(output_path))

        declared_pages = getattr(pdf, "pages_count", None) or pdf.page_no()
        expected_tokens = [fm.uid for fm in model.findings]
        validation = validate_report(
            output_path,
            expected_report_id=model.meta.report_id,
            expected_tokens=expected_tokens or None,
            declared_pages=declared_pages,
        )
        self.last_validation = validation
        if validation.critical_issues:
            raise RuntimeError(
                "Generated report failed critical quality control: "
                + "; ".join(validation.critical_issues)
            )
        return output_path

    @staticmethod
    def suggested_filename(model: ReportModel) -> str:
        return (f"GDR_Security_Analysis_Report_{model.meta.report_id}"
                f"_{model.meta.filename_date}.pdf")

    # ------------------------------------------------------------------ #
    # Cover  (section 3 of the design brief)
    # ------------------------------------------------------------------ #
    def _cover(self, pdf: GedrPDF, m: ReportModel) -> None:
        pdf.add_page()

        # Masthead band
        pdf.set_fill_color(*NAVY)
        pdf.rect(0, 0, PAGE_W, 62, "F")

        # Logo (if available)
        logo_path = Path(__file__).parent / "assets" / "gedr_logo_transparent.png"
        if logo_path.exists():
            try:
                pdf.image(str(logo_path), x=16, y=10, w=32)
            except Exception:
                pass  # fallback to text-only masthead

        # Brand wordmark
        brand_wordmark = "G\u0259dr" if pdf.font_sans == "gedr" else "Gedr"
        pdf.sans("B", 32)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(16, 16)
        pdf.cell(80, 12, brand_wordmark)

        # Platform tagline
        pdf.sans("B", 8.4)
        pdf.set_text_color(206, 216, 226)
        pdf.set_xy(96, 18.5)
        pdf.cell(98, 4.6, "AUTOMATED SECURITY ANALYSIS PLATFORM", align="R")

        # Classification badge
        pdf.sans("B", 7.4)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(96, 24.0)
        class_text = m.meta.classification.upper()
        class_w = pdf.get_string_width(class_text) + 8
        pdf.set_fill_color(43, 84, 124)  # STEEL
        pdf.rect(PAGE_W - MARGIN_R - class_w, 23.2, class_w, 5.6, "F")
        pdf.set_xy(PAGE_W - MARGIN_R - class_w + 4, 23.2)
        pdf.cell(class_w - 8, 5.6, class_text)

        # Brand accent bar
        pdf.set_fill_color(*STEEL)
        pdf.rect(16, 44.5, 26, 1.4, "F")

        # Title block
        y = 78.0
        pdf.sans("B", TYPE.display)
        pdf.set_text_color(*NAVY)
        pdf.set_xy(16, y)
        pdf.cell(178, 14, m.meta.report_type)

        # Project name
        pdf.sans("B", 14)
        pdf.set_text_color(*STEEL)
        pdf.set_xy(16, y + 16)
        project_title = m.meta.project_name
        while pdf.get_string_width(project_title) > 176 and len(project_title) > 10:
            project_title = project_title[:-2]
        pdf.cell(178, 8, project_title)

        # Decorative rule
        pdf.set_draw_color(*NAVY)
        pdf.set_line_width(0.4)
        pdf.line(16, y + 28, PAGE_W - 16, y + 28)

        # Identity grid
        pdf.set_y(y + 34)
        pdf.kv_grid([
            ("Report ID", m.meta.report_id),
            ("Document version", m.meta.document_version),
            ("Generated (UTC)", m.meta.generated_at_s),
            ("Analysis window", m.meta.started_at_s if m.meta.started_at else "Not recorded"),
            ("Security score", f"{m.meta.security_score} / 100   \u00b7   Grade {m.meta.grade}"),
            ("Findings reported", str(m.agg.total)),
            ("Files analysed", str(m.agg.files_scanned)),
            ("Target language", m.meta.project_language),
        ], cols=2)

        # Severity snapshot strip
        pdf.ln(2)
        tiles = [
            (name, m.agg.by_severity.get(name, 0), SEVERITY_COLORS[name], SEVERITY_TINTS[name])
            for name in ("Critical", "High", "Medium", "Low")
        ]
        tile_w = (PAGE_W - 32 - 9) / 4
        mini_tiles(pdf, 16, pdf.get_y(), tile_w, 17.5, tiles)

        # Footer note
        pdf.sans("", 7.0)
        pdf.set_text_color(*FAINT)
        pdf.set_xy(16, 268)
        pdf.multi_cell(178, 3.8, pdf._disp(
            "This document was automatically generated from the recorded results of scan "
            f"{m.meta.scan_id}. It contains security-sensitive information and is distributed "
            f"under the classification: {m.meta.classification}."
        ), align="C")

    # ------------------------------------------------------------------ #
    # Document information
    # ------------------------------------------------------------------ #
    def _document_information(self, pdf: GedrPDF, m: ReportModel) -> None:
        pdf.open_section("Document Information")

        pdf.subsection("Report identity")
        pdf.kv_grid([
            ("Report ID", m.meta.report_id),
            ("Report type", m.meta.report_type),
            ("Document version", m.meta.document_version),
            ("Classification", m.meta.classification),
            ("Generated (UTC)", m.meta.generated_at_s),
            ("Reporting engine", f"{ENGINE_NAME} {ENGINE_VERSION}"),
        ], cols=2)

        pdf.subsection("Analysis scope")
        duration = "-"
        if m.agg.duration_minutes is not None:
            duration = f"{m.agg.duration_minutes:.1f} minutes"
        pdf.kv_grid([
            ("Target project", m.meta.project_name),
            ("Language / platform", m.meta.project_language),
            ("Source path", m.meta.project_path),
            ("Scan identifier", m.meta.scan_id),
            ("Scan status", m.meta.scan_status),
            ("Analysis window", m.analysis_window),
            ("Analysis duration", duration),
            ("Files analysed", str(m.agg.files_scanned)),
            ("AI reasoning layer", "Applied" if m.meta.ai_enabled else
             "Not applied for this scan"),
            ("Findings reported", str(m.agg.total)),
        ], cols=2)

        pdf.subsection("Intended audience")
        pdf.para(
            "This report is written for security analysts, researchers, system "
            "administrators, developers, security managers and technical leadership. "
            "Sections 1-2 provide non-specialist context and overall posture; sections "
            "3 onward contain progressively deeper technical detail."
        )

        pdf.callout(
            "info",
            "Data provenance",
            "Every figure, finding and recommendation in this document derives exclusively "
            f"from the recorded results of Gedr analysis {m.meta.report_id}. Where "
            "information was not captured by the analysis, it is explicitly marked as "
            "unavailable rather than estimated. Data integrity digest (SHA-256): "
            f"{m.meta.data_digest[:32]}\u2026",
        )

    # ------------------------------------------------------------------ #
    # Executive summary
    # ------------------------------------------------------------------ #
    def _executive_summary(self, pdf: GedrPDF, m: ReportModel) -> None:
        pdf.open_section("Executive Summary")

        counts = ", ".join(f"{n} {name.lower()}" for name, n in m.present_severities() if n) \
            or "no findings"
        opening = (
            f"On {m.meta.generated_at_s}, Gedr completed a static security analysis of "
            f"\u201c{m.meta.project_name}\u201d covering {m.agg.files_scanned} file(s). "
        )
        if m.has_findings:
            opening += (
                f"The analysis reported {m.agg.total} finding(s): {counts}. The resulting "
                f"security score is {m.meta.security_score}/100 (grade {m.meta.grade}), "
                f"indicating {GRADE_BAND[m.meta.grade].lower()}."
            )
        else:
            opening += (
                f"The analysis completed without reporting findings. The resulting security "
                f"score is {m.meta.security_score}/100 (grade {m.meta.grade})."
            )
        pdf.para(opening, size=TYPE.lead)

        highest = next((s for s in SEVERITY_ORDER if m.agg.by_severity.get(s)), None)
        pdf.kpi_tiles([
            ("Findings", str(m.agg.total), "total observations"),
            ("Security score", f"{m.meta.security_score}", "out of 100"),
            ("Grade", m.meta.grade, GRADE_BAND[m.meta.grade]),
            ("Highest severity", highest if highest else "None",
             SEVERITY_DEFINITIONS[highest].split(".")[0] if highest else "clean result"),
        ])

        if m.has_findings:
            top = m.top_findings(3)
            if top:
                names = "; ".join(f"{f.title} ({f.location})" for f in top[:2])
                pdf.para(
                    f"The most urgent item{'' if len(top) == 1 else 's'} identified: "
                    f"{names}. Full technical detail, evidence and remediation guidance are "
                    "provided in section 4."
                )
            if m.agg.top_files:
                worst_file, worst_count = m.agg.top_files[0]
                plural = "area carries" if worst_count == 1 else "areas carry"
                pdf.para(
                    f"Concentration analysis shows that {worst_file} accounts for "
                    f"{worst_count} finding(s); remediation effort focused there will yield "
                    "the largest early risk reduction." if worst_count > 1 else
                    f"{worst_file} is the only component with a recorded finding."
                )
            tiers = m.remediation_tiers()
            if tiers and tiers[0][0] == "Immediate":
                pdf.callout(
                    "warn",
                    "Immediate attention required",
                    f"{len(tiers[0][2])} finding(s) are classified Critical or High and are "
                    "listed under Immediate priorities in section 5.",
                )
        else:
            pdf.callout(
                "ok",
                "Clean result",
                "No weaknesses were identified by the enabled detection layers for this "
                "scope. This does not constitute a guarantee of security; see Appendix A "
                "for methodology and limitations.",
            )

    # ------------------------------------------------------------------ #
    # Security posture
    # ------------------------------------------------------------------ #
    def _security_posture(self, pdf: GedrPDF, m: ReportModel) -> None:
        pdf.open_section("Security Posture")

        pdf.subsection("Overall assessment")
        grade_color = GRADE_COLOR[m.meta.grade]
        y_start = pdf.get_y()
        after = score_meter(pdf, MARGIN_L, y_start, 120, m.meta.security_score,
                            fill_color=grade_color)
        pdf.sans("B", 20)
        pdf.set_text_color(*grade_color)
        pdf.set_xy(MARGIN_L + 126, y_start - 2.0)
        pdf.cell(52, 9.5, f"{m.meta.security_score}/100", align="R")
        pdf.sans("B", 10)
        pdf.set_text_color(*INK)
        pdf.set_xy(MARGIN_L + 126, y_start + 7.5)
        pdf.cell(52, 6.5, f"Grade {m.meta.grade}", align="R")
        pdf.sans("", 8.4)
        pdf.set_text_color(*MUTED)
        pdf.set_y(after + 1.5)
        pdf.para(GRADE_BAND[m.meta.grade] + ".", color=MUTED)

        # Distribution ring + legend side by side
        pdf.subsection("Severity distribution")
        pdf.ensure_space(46)
        ring_cx = MARGIN_L + 21
        ring_cy = pdf.get_y() + 19
        values = [(name, m.agg.by_severity.get(name, 0), SEVERITY_COLORS[name])
                  for name in SEVERITY_ORDER if name != "Informational"]
        donut(pdf, ring_cx, ring_cy, 17.0, 10.5, values,
              total=m.agg.total if m.has_findings else None,
              center_label="findings" if m.has_findings else "")
        lx = MARGIN_L + 48
        ly = ring_cy - 13.5
        legend(pdf, lx, ly, 60, [(n, c, col) for n, c, col in values],
               show_share_of=m.agg.total or None)
        if m.agg.by_severity.get("Informational"):
            legend(pdf, lx, ly + 29, 60,
                   [("Informational", m.agg.by_severity["Informational"],
                     SEVERITY_COLORS["Informational"])], show_share_of=m.agg.total or None)
        pdf.set_y(ring_cy + 22)

        rows = []
        for name, count in m.present_severities():
            share = f"{count / m.agg.total * 100:.0f}%" if m.agg.total else "0%"
            rows.append([name, str(count), share, name and SEVERITY_DEFINITIONS[name].split(".")[0]])
        pdf.data_table(["Severity", "Count", "Share", "Definition"],
                  rows, widths=(28, 20, 22, 108),
                  aligns=("LEFT", "CENTER", "CENTER", "LEFT"), font_size=8.0)

        if m.agg.by_cwe:
            pdf.subsection("Findings by weakness category")
            items = m.agg.by_cwe[:6]
            end = hbars(pdf, MARGIN_L, pdf.get_y(), 178, items, color=STEEL)
            pdf.set_y(end + 2.5)

        if m.agg.by_owasp:
            pdf.subsection("Findings by OWASP Top 10 category")
            end = hbars(pdf, MARGIN_L, pdf.get_y(), 178, m.agg.by_owasp[:6], color=NAVY)
            pdf.set_y(end + 2.5)

        if len(m.agg.by_scanner) > 1:
            pdf.subsection("Detection sources")
            end = hbars(pdf, MARGIN_L, pdf.get_y(), 178, list(m.agg.by_scanner.items())[:6],
                        color=(96, 125, 155))
            pdf.set_y(end + 2.5)

        if m.agg.top_files and m.agg.total > 1:
            pdf.subsection("Most affected components")
            rows = [[f, str(n)] for f, n in m.agg.top_files]
            pdf.data_table(["Component / file", "Findings"], rows, widths=(148, 30),
                      aligns=("LEFT", "CENTER"), font_size=7.8)

    # ------------------------------------------------------------------ #
    # Risk analysis
    # ------------------------------------------------------------------ #
    def _risk_analysis(self, pdf: GedrPDF, m: ReportModel) -> None:
        if not m.has_findings:
            return
        pdf.open_section("Risk Analysis")

        # Calculate risk metrics
        critical = m.agg.by_severity.get("Critical", 0)
        high = m.agg.by_severity.get("High", 0)
        medium = m.agg.by_severity.get("Medium", 0)
        low = m.agg.by_severity.get("Low", 0)

        # Risk score: weighted sum
        risk_score = min(100, critical * 25 + high * 15 + medium * 5 + low * 1)
        risk_level = ("Critical" if risk_score >= 75 else
                      "High" if risk_score >= 50 else
                      "Medium" if risk_score >= 25 else "Low")

        pdf.subsection("Overall risk assessment")
        pdf.ensure_space(24)
        tiles = [
            ("Risk Score", f"{risk_score}/100", risk_level),
            ("Critical", str(critical), "findings"),
            ("High", str(high), "findings"),
            ("Exposure", f"{m.agg.files_scanned}", "files analysed"),
        ]
        pdf.kpi_tiles(tiles, cols=4, tile_h=18)

        pdf.subsection("Risk interpretation")
        pdf.para(
            f"The overall risk score of {risk_score}/100 reflects a {risk_level.lower()} risk "
            f"posture. This is derived from {critical} critical, {high} high, {medium} medium, "
            f"and {low} low severity findings across {m.agg.files_scanned} analysed files."
        )

        if critical > 0:
            pdf.callout("warn", "Immediate action required",
                        f"{critical} critical finding(s) require immediate remediation. "
                        "These represent directly exploitable weaknesses with severe impact.")

        if high > 0:
            pdf.callout("info", "High-priority remediation",
                        f"{high} high severity finding(s) should be addressed in the current "
                        "sprint. These weaknesses are likely exploitable with significant impact.")

    # ------------------------------------------------------------------ #
    # MITRE ATT&CK mapping
    # ------------------------------------------------------------------ #
    def _mitre_attack(self, pdf: GedrPDF, m: ReportModel) -> None:
        if not m.agg.by_owasp:
            return
        pdf.open_section("MITRE ATT&CK Mapping")

        pdf.para(
            "This section maps detected weaknesses to MITRE ATT&CK tactics and techniques "
            "based on observed OWASP Top 10 categories. Mappings are derived from the "
            "relationship between web application security weaknesses and adversary behaviour."
        )

        # OWASP to ATT&CK mapping
        owasp_to_attack = {
            "A01:2021": ("T1190", "Exploit Public-Facing Application", "Initial Access",
                         "Broken access control allows unauthorised access to protected resources."),
            "A02:2021": ("T1195", "Supply Chain Compromise", "Initial Access",
                         "Cryptographic failures may expose sensitive data during transit."),
            "A03:2021": ("T1059", "Command and Scripting Interpreter", "Execution",
                         "Injection vulnerabilities enable execution of arbitrary code."),
            "A04:2021": ("T1078", "Valid Accounts", "Initial Access",
                         "Insecure design may allow authentication bypass."),
            "A05:2021": ("T1190", "Exploit Public-Facing Application", "Initial Access",
                         "Security misconfiguration exposes attack surface."),
            "A06:2021": ("T1195", "Supply Chain Compromise", "Initial Access",
                         "Vulnerable components introduce known exploitable weaknesses."),
            "A07:2021": ("T1110", "Brute Force", "Credential Access",
                         "Authentication failures allow credential stuffing or brute force."),
            "A08:2021": ("T1190", "Exploit Public-Facing Application", "Initial Access",
                         "Software and data integrity failures enable code injection."),
            "A09:2021": ("T1046", "Network Service Scanning", "Discovery",
                         "Security logging gaps allow attacker reconnaissance."),
            "A10:2021": ("T1078", "Valid Accounts", "Initial Access",
                         "Server-side request forgery enables internal network access."),
        }

        pdf.subsection("ATT&CK technique mapping")
        rows = []
        for owasp_cat, count in m.agg.by_owasp[:8]:
            if owasp_cat in owasp_to_attack:
                tid, technique, tactic, desc = owasp_to_attack[owasp_cat]
                rows.append([tid, technique, tactic, str(count), desc[:60] + "..." if len(desc) > 60 else desc])
            else:
                rows.append(["--", "Mapping unavailable", "--", str(count), "No ATT&CK mapping for this category"])

        if rows:
            pdf.data_table(
                ["Technique ID", "Technique", "Tactic", "Count", "Description"],
                rows, widths=(24, 44, 28, 16, 66),
                aligns=("LEFT", "LEFT", "LEFT", "CENTER", "LEFT"), font_size=7.4
            )
        else:
            pdf.callout("note", "No ATT&CK mappings available",
                        "No OWASP categories were detected in this scan to map to ATT&CK techniques.")

    # ------------------------------------------------------------------ #
    # Timeline
    # ------------------------------------------------------------------ #
    def _timeline(self, pdf: GedrPDF, m: ReportModel) -> None:
        if not m.meta.started_at:
            return
        pdf.open_section("Analysis Timeline")

        pdf.para(
            "Chronological view of the analysis session, showing key events and their "
            "sequence. Timestamps are in Coordinated Universal Time (UTC)."
        )

        events = []
        if m.meta.started_at_s:
            events.append(("Analysis started", m.meta.started_at_s, STEEL))
        if m.meta.finished_at_s and m.meta.started_at_s != m.meta.finished_at_s:
            events.append(("Analysis completed", m.meta.finished_at_s, NAVY))
        if m.meta.generated_at_s:
            events.append(("Report generated", m.meta.generated_at_s, MUTED))

        if m.has_findings:
            events.append((f"Identified {m.agg.total} finding(s)", m.meta.finished_at_s or m.meta.generated_at_s, SEVERITY_COLORS.get("High", INK)))

        if not events:
            pdf.callout("note", "No timeline data", "Timestamp information was not recorded for this scan.")
            return

        pdf.subsection("Key events")
        rows = [[name, ts] for name, ts, _ in events]
        pdf.data_table(["Event", "Timestamp (UTC)"], rows, widths=(100, 78),
                       aligns=("LEFT", "LEFT"), font_size=8.2)

        if m.agg.total > 0 and m.meta.started_at_s:
            pdf.subsection("Analysis duration")
            if m.agg.duration_minutes:
                pdf.para(f"Total analysis time: {m.agg.duration_minutes:.1f} minutes "
                         f"({m.agg.files_scanned} files analysed).")
            else:
                pdf.para(f"Analysis covered {m.agg.files_scanned} files.")

    # ------------------------------------------------------------------ #
    # Findings overview table
    # ------------------------------------------------------------------ #
    def _findings_overview(self, pdf: GedrPDF, m: ReportModel) -> None:
        pdf.open_section("Key Findings Overview")
        pdf.para(
            f"All {m.agg.total} finding(s) recorded by this analysis, ordered by severity "
            "score. Each identifier (GDR-F-nnn) is stable within this report and is "
            "referenced again in the detailed write-ups and the remediation plan."
        )
        rows = []
        for f in m.findings:
            rows.append([f.uid, f.severity, f"{f.score}/10", f.title, f.short_location, f.scanner])
        pdf.data_table(["ID", "Severity", "Score", "Title", "Location", "Detector"],
                       rows,
                       widths=(21, 19, 13, 59, 42, 24),
                       aligns=("LEFT", "CENTER", "CENTER", "LEFT", "LEFT", "LEFT"),
                       font_size=7.4)

    # ------------------------------------------------------------------ #
    # Detailed findings
    # ------------------------------------------------------------------ #
    def _detailed_findings(self, pdf: GedrPDF, m: ReportModel) -> None:
        pdf.open_section("Detailed Findings")
        pdf.para(
            "Each finding below follows a fixed structure: identification metadata, "
            "description, evidence, analysis where produced by the reasoning layer, and "
            "remediation. Evidence is reproduced verbatim apart from automatic redaction "
            "of credential-like strings."
        )

        for f in m.findings:
            pdf.ensure_space(48)
            rec = m.recommendations.get(f.uid)
            self._finding_card(pdf, f, rec)
            pdf.ln(1.5)
            pdf.set_draw_color(*SEVERITY_TINTS[f.severity])
            pdf.set_line_width(0.4)
            y = pdf.get_y()
            pdf.line(MARGIN_L, y, PAGE_W - 16, y)
            pdf.ln(4.5)

    def _finding_card(self, pdf: GedrPDF, f: FindingModel, rec) -> None:
        color = SEVERITY_COLORS[f.severity]

        # Header strip
        head_h = 13.0
        y0 = pdf.get_y()
        pdf.set_fill_color(*SEVERITY_TINTS[f.severity])
        pdf.rect(MARGIN_L, y0, PAGE_W - 32, head_h, "F")
        pdf.set_fill_color(*color)
        pdf.rect(MARGIN_L, y0, 1.8, head_h, "F")
        pdf.mono("B", 7.4)
        pdf.set_text_color(*MUTED)
        pdf.set_xy(MARGIN_L + 5, y0 + 1.8)
        pdf.cell(30, 3.4, f.uid)
        pdf.sans("B", 11.2)
        pdf.set_text_color(*INK)
        title = f.title
        while pdf.get_string_width(title) > PAGE_W - 32 - 46 and len(title) > 12:
            title = title[:-2]
        pdf.set_xy(MARGIN_L + 5, y0 + 5.4)
        pdf.cell(PAGE_W - 32 - 44, 6.2, title)
        # Score badge right-aligned inside the strip
        pdf.sans("B", 9.5)
        pdf.set_text_color(*color)
        pdf.set_xy(MARGIN_L + PAGE_W - 32 - 36, y0 + 4.4)
        pdf.cell(33, 6.0, f"{f.score}/10", align="R")
        pdf.set_y(y0 + head_h + 2.4)

        chip_w = pdf.severity_chip(MARGIN_L, pdf.get_y(), f.severity, None)
        meta_bits = [f"Location: {f.short_location}", f"Detector: {f.scanner}"]
        if f.rule_id:
            meta_bits.append(f"Rule: {f.rule_id}")
        if f.cwe:
            meta_bits.append(f"CWE: {f.cwe}")
        if f.owasp:
            meta_bits.append(f"OWASP: {f.owasp}")
        pdf.sans("", 7.4)
        pdf.set_text_color(*MUTED)
        avail = PAGE_W - 32 - chip_w - 6
        # Prefer dropping trailing metadata over truncating mid-word; only the
        # full location in the evidence caption carries the complete path.
        while len(meta_bits) > 2 and \
                pdf.get_string_width("   \u00b7   ".join(meta_bits)) > avail:
            meta_bits.pop()
        meta_line = "   \u00b7   ".join(meta_bits)
        if pdf.get_string_width(meta_line) > avail:
            while meta_line and pdf.get_string_width(meta_line + "\u2026") > avail:
                meta_line = meta_line[:-2]
            meta_line += "\u2026"
        pdf.set_xy(MARGIN_L + chip_w + 5, pdf.get_y())
        pdf.cell(avail, 5.0, pdf._disp(meta_line))
        pdf.ln(4.2)

        if f.description:
            pdf.para(f.description, size=8.8, line_h=4.3)

        if f.code:
            pdf.code_block(f.code, caption=f"EVIDENCE \u00b7 {f.short_location}")

        if rec:
            blocks = [
                ("ANALYSIS", rec.explanation),
                ("POTENTIAL IMPACT", rec.impact),
                ("ATTACK SCENARIO", rec.attack_scenario),
                ("ROOT CAUSE", rec.root_cause),
                ("REMEDIATION", rec.recommended_fix),
            ]
            for label, body in blocks:
                if body:
                    pdf.ln(1.4)
                    pdf.ensure_space(16)
                    pdf.sans("B", 8.2)
                    pdf.set_text_color(*STEEL)
                    pdf.set_x(MARGIN_L)
                    pdf.cell(0, 4.4, label)
                    pdf.ln(6.0)
                    pdf.para(body, size=8.8, line_h=4.3)
            if rec.secure_code:
                src = f"AI reasoning layer ({rec.model})" if rec.model else "AI reasoning layer"
                pdf.code_block(rec.secure_code, caption=f"SUGGESTED SECURE PATTERN \u00b7 {src}")
        elif f.cwe and f.cwe in _CWE_GUIDANCE:
            pdf.callout(
                "note",
                f"General hardening guidance \u00b7 {f.cwe}",
                _CWE_GUIDANCE[f.cwe]
                + " (General guidance for this weakness class; detailed AI-generated "
                  "remediation was not produced for this finding.)",
            )

    # ------------------------------------------------------------------ #
    # Remediation plan
    # ------------------------------------------------------------------ #
    def _remediation_plan(self, pdf: GedrPDF, m: ReportModel) -> None:
        pdf.open_section("Remediation Plan")
        sourced = m.has_recommendations
        if sourced and len(m.recommendations) < m.agg.total:
            intro = (
                "Priorities below are derived strictly from observed severities. "
                "Remediation text is produced by the AI reasoning layer where available "
                "and is tied to its finding by identifier; findings without a stored "
                "recommendation fall back to general hardening guidance for their "
                "weakness class, labelled as such."
            )
        elif sourced:
            intro = (
                "Priorities below are derived strictly from observed severities. "
                "Remediation text is produced by the AI reasoning layer and is tied to "
                "its finding by identifier."
            )
        else:
            intro = (
                "Priorities below are derived strictly from observed severities. No "
                "AI-generated recommendations were stored for this scan, so each item "
                "references general hardening guidance for its weakness class."
            )
        pdf.para(intro, size=8.8)

        for tier_name, tier_window, items in m.remediation_tiers():
            pdf.subsection(f"{tier_name} priorities \u2014 {tier_window}")
            for f in items:
                pdf.bullet_list([f"[{f.uid}] {f.title} \u2014 {f.location}"], size=8.8)
                rec = m.recommendations.get(f.uid)
                fix = rec.recommended_fix if rec else (
                    _CWE_GUIDANCE.get(f.cwe) if f.cwe else None)
                if fix:
                    text = fix if len(fix) <= 320 else fix[:319].rstrip() + "\u2026"
                    pdf.para(text, size=8.2, indent=6.4, line_h=4.1,
                             color=(90, 99, 113))

    # ------------------------------------------------------------------ #
    # Clean-scan variant
    # ------------------------------------------------------------------ #
    def _no_findings(self, pdf: GedrPDF, m: ReportModel) -> None:
        pdf.open_section("No Significant Findings")
        pdf.para(
            f"Gedr analysed {m.agg.files_scanned} file(s) of \u201c{m.meta.project_name}\u201d "
            "and recorded no findings. No weaknesses were identified by the detection "
            "layers that were active during this scan.",
            size=TYPE.lead,
        )
        pdf.callout(
            "ok",
            "Interpretation",
            "A clean result reflects the scope, languages and detection layers applied "
            "during this analysis. Static analysis cannot prove the absence of "
            "vulnerabilities; periodic re-scanning and complementary testing remain "
            "recommended.",
        )
        pdf.subsection("Scope recap")
        pdf.kv_grid([
            ("Files analysed", str(m.agg.files_scanned)),
            ("Language / platform", m.meta.project_language),
            ("Analysis window", m.analysis_window),
            ("Detection layers", "Heuristic engine + auto-detected external tools"),
        ], cols=2)

    # ------------------------------------------------------------------ #
    # Appendix A - methodology
    # ------------------------------------------------------------------ #
    def _appendix_methodology(self, pdf: GedrPDF, m: ReportModel) -> None:
        pdf.open_section("Appendix A \u00b7 Methodology")

        pdf.subsection("Detection architecture")
        pdf.data_table(
            ["Layer", "Engine", "Role"],
            [
                ["1", "Heuristic engine", "Built-in pattern matching across all supported "
                 "languages; always available, zero external dependencies"],
                ["2", "External analysers", "Bandit, Semgrep, SpotBugs, PMD, Clang Static "
                 "Analyzer - used automatically when present on PATH"],
                ["3", "Dependency scanning", "Known-vulnerability checks for Python, Node.js "
                 "and PHP dependency manifests"],
                ["4", "AI reasoning layer", "Post-detection explanation, impact analysis and "
                 "remediation guidance over structured findings"],
            ],
            widths=(14, 42, 122), aligns=("CENTER", "LEFT", "LEFT"), font_size=7.8,
        )

        pdf.subsection("Scoring model")
        pdf.para(
            "The security score starts at 100 and deducts weighted penalties per finding: "
            "Critical 30, High 15, Medium 6, Low 2, floored at 0. Grades map from the "
            "final score as follows:"
        )
        pdf.data_table(
            ["Grade", "Score range", "Band"],
            [
                ["A+", "90-100", GRADE_BAND["A+"]],
                ["A", "80-89", GRADE_BAND["A"]],
                ["B", "70-79", GRADE_BAND["B"]],
                ["C", "50-69", GRADE_BAND["C"]],
                ["D", "30-49", GRADE_BAND["D"]],
                ["F", "0-29", GRADE_BAND["F"]],
            ],
            widths=(22, 34, 122), aligns=("CENTER", "CENTER", "LEFT"), font_size=7.8,
        )

        pdf.subsection("Severity definitions")
        pdf.data_table(
            ["Severity", "Score range", "Definition"],
            [[name, rng, SEVERITY_DEFINITIONS[name]]
             for name, rng in (("Critical", "9-10"), ("High", "7-8"), ("Medium", "4-6"),
                               ("Low", "1-3"), ("Informational", "-"))],
            widths=(26, 24, 128), aligns=("LEFT", "CENTER", "LEFT"), font_size=7.8,
        )

        pdf.subsection("Limitations")
        pdf.callout(
            "note",
            "Reading this report correctly",
            "Gedr performs static analysis: it inspects source code without executing it. "
            "Heuristic rules can produce false positives, and some vulnerability classes "
            "(configuration drift, runtime behaviour, cryptographic strength of keys in "
            "use) may be invisible to static tooling. Scores quantify detected findings "
            "only and are not a probability of exploitation.",
        )

    # ------------------------------------------------------------------ #
    # Appendix B - report metadata
    # ------------------------------------------------------------------ #
    def _appendix_metadata(self, pdf: GedrPDF, m: ReportModel) -> None:
        pdf.open_section("Appendix B \u00b7 Report Metadata")
        pdf.kv_grid([
            ("Report ID", m.meta.report_id),
            ("Report type", m.meta.report_type),
            ("Document version", m.meta.document_version),
            ("Classification", m.meta.classification),
            ("Generated (UTC)", m.meta.generated_at_s),
            ("Scan identifier", m.meta.scan_id),
            ("Records ingested", f"{m.agg.total} findings, "
                                 f"{len(m.recommendations)} recommendations"),
            ("Data integrity digest", m.meta.data_digest[:32] + "\u2026 (SHA-256)"),
            ("Reporting engine", f"{ENGINE_NAME} {ENGINE_VERSION}"),
            ("Rendering library", "fpdf2 (vector output)"),
        ], cols=2)
        pdf.subsection("Point of contact")
        pdf.bullet_list([
            "Project: https://github.com/natahanjr",
            "Email: gedr21@hotmail.com",
        ])
        pdf.ln(2)
        pdf.callout(
            "info",
            "Handling instructions",
            f"This report is classified \u201c{m.meta.classification}\u201d. Distribute only "
            "to recipients with a legitimate need to act on its contents. Evidence "
            "snippets were automatically screened for credential material before "
            "inclusion; treat all included code excerpts as sensitive nonetheless.",
        )
