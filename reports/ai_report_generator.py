"""
AI Report Generator - Builds premium HTML reports using our CSS template,
then converts to PDF via weasyprint. Uses AI only for summary narrative.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from .html_to_pdf import html_to_pdf
from .report_model import (
    ENGINE_NAME,
    ENGINE_VERSION,
    ReportModel,
    build_report_model,
)

REPORT_TYPE_SECURITY = "Security Analysis Report"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_ICONS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
SEVERITY_CLASSES = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}


class AIReportGenerator:
    def __init__(self, ai_agent=None):
        self.ai_agent = ai_agent
        self.report_id: str = ""
        self.model: ReportModel | None = None
        self._css_path = Path(__file__).parent / "templates" / "report_style.css"
        self._logo_path = Path(__file__).parent / "assets" / "gedr_logo_transparent.png"

    def _get_ai_agent(self):
        if self.ai_agent is not None:
            return self.ai_agent
        try:
            from ai.ai_agent import GedrAgent
            self.ai_agent = GedrAgent()
            return self.ai_agent
        except Exception as e:
            print(f"[AI Report] Failed to initialize AI agent: {e}")
            return None

    def _generate_ai_summary(self, project, scan, findings, recs) -> str:
        agent = self._get_ai_agent()
        if agent is None or not agent.enabled:
            return self._fallback_summary(findings, recs)

        prompt = f"""Analyze these security scan results and write a 2-3 sentence executive summary.
Be concise and professional. Only return the summary text, no HTML or markdown.

Project: {project.get('name', 'Unknown')} ({project.get('language', 'Unknown')})
Findings: {len(findings)} total
Severity: {', '.join(f'{s}: {sum(1 for f in findings if f.get("severity") == s)}' for s in SEVERITY_ORDER if sum(1 for f in findings if f.get('severity') == s))}
Top CWEs: {', '.join(set(f.get('cwe', '') for f in findings if f.get('cwe')))}

Critical findings: {', '.join(f.get('title', '') for f in findings if f.get('severity') == 'Critical')}
High findings: {', '.join(f.get('title', '') for f in findings if f.get('severity') == 'High')}
"""
        try:
            return agent.generate(prompt)
        except Exception as e:
            print(f"[AI Report] AI summary failed: {e}")
            return self._fallback_summary(findings, recs)

    def _fallback_summary(self, findings, recs) -> str:
        crit = sum(1 for f in findings if f.get("severity") == "Critical")
        high = sum(1 for f in findings if f.get("severity") == "High")
        total = len(findings)

        lines = [f"The scan identified {total} security finding(s)"]
        if crit:
            lines.append(f"{crit} critical")
        if high:
            lines.append(f"{high} high severity")

        action_items = []
        for f in findings:
            if f.get("severity") in ("Critical", "High"):
                rec = recs.get(str(f.get("id", ""))) or recs.get(f.get("uid", ""), {})
                fix = rec.get("recommended_fix", "")
                if fix:
                    action_items.append(f"{f.get('title', 'Unknown')}: {fix}")

        if action_items:
            lines.append("Immediate action required: " + "; ".join(action_items[:3]))

        return ". ".join(lines) + "."

    def _get_default_solution(self, finding: dict) -> str:
        """Generate a default solution based on finding title and CWE."""
        title = finding.get('title', '').lower()
        cwe = finding.get('cwe', '').lower()
        
        solutions = {
            'sql injection': 'Use parameterized queries or prepared statements instead of string concatenation. Validate and sanitize all user inputs before using them in SQL queries.',
            'xss': 'Encode all output data using context-appropriate encoding. Use Content Security Policy (CSP) headers. Sanitize user input before rendering.',
            'command injection': 'Avoid using system commands with user input. Use language-specific APIs instead of shell commands. Validate and sanitize inputs.',
            'path traversal': 'Validate file paths against a whitelist of allowed directories. Use path canonicalization. Avoid constructing paths from user input.',
            'deserialization': 'Avoid deserializing untrusted data. Use safe serialization formats like JSON. Implement integrity checks.',
            'buffer overflow': 'Use safe string handling functions. Implement bounds checking. Use languages with built-in memory safety.',
            'weak cryptographic': 'Use strong, up-to-date cryptographic algorithms (AES-256, SHA-256). Avoid MD5, SHA-1, DES.',
            'hardcoded': 'Store secrets in environment variables or secure vaults. Never commit credentials to source code.',
            'ssrf': 'Validate and sanitize URLs. Use allowlists for permitted domains. Avoid fetching user-controlled URLs.',
            'xxe': 'Disable external entity processing in XML parsers. Use JSON instead of XML when possible.',
        }
        
        for pattern, solution in solutions.items():
            if pattern in title or pattern in cwe:
                return solution
        
        return 'Review the code for security vulnerabilities. Apply input validation, output encoding, and follow secure coding best practices.'

    def _get_default_secure_code(self, finding: dict) -> str:
        """Generate a default secure code example based on finding type."""
        title = finding.get('title', '').lower()
        cwe = finding.get('cwe', '').lower()
        code = finding.get('code', '')
        
        if 'sql injection' in title or 'sql' in cwe:
            return '-- INSECURE:\nSELECT * FROM users WHERE id = \'\' + user_input + \'\'\n\n-- SECURE (use parameterized query):\nSELECT * FROM users WHERE id = ?'
        elif 'xss' in title or 'cross-site' in title:
            return '// INSECURE:\nelement.innerHTML = userInput\n\n// SECURE:\nelement.textContent = userInput'
        elif 'command injection' in title or 'os command' in title:
            return '# INSECURE:\nimport os\nos.system("ping " + user_input)\n\n# SECURE:\nimport subprocess\nsubprocess.run(["ping", "-c", "1", user_input], shell=False)'
        elif 'path traversal' in title or 'directory traversal' in title:
            return '# INSECURE:\nopen("/app/" + user_input)\n\n# SECURE:\nimport os\nsafe = os.path.normpath(os.path.join("/app/", user_input))\nif safe.startswith("/app/"):\n    open(safe)'
        elif 'hardcoded' in title or 'credential' in title or 'password' in title:
            return '# INSECURE:\npassword = "admin123"\n\n# SECURE:\nimport os\npassword = os.environ.get("APP_PASSWORD")'
        elif 'deserialization' in title or 'unsafe deserialization' in title:
            return '# INSECURE:\nimport pickle\ndata = pickle.loads(user_data)\n\n# SECURE:\nimport json\ndata = json.loads(user_data)'
        elif 'ssrf' in title:
            return '# INSECURE:\nrequests.get(user_url)\n\n# SECURE:\nfrom urllib.parse import urlparse\nparsed = urlparse(user_url)\nif parsed.hostname in ALLOWED_HOSTS:\n    requests.get(user_url)'
        elif 'xxe' in title or 'xml external' in title:
            return '# INSECURE:\nimport xml.etree.ElementTree as ET\ntree = ET.parse(user_file)\n\n# SECURE:\nimport defusedxml.ElementTree as ET\ntree = defusedxml.ElementTree.parse(user_file)'
        elif 'buffer overflow' in title:
            return '// INSECURE:\nchar buf[8];\ngets(buf);  // No bounds checking\n\n// SECURE:\nchar buf[8];\nfgets(buf, sizeof(buf), stdin);  // Limits input'
        elif 'weak' in title and ('hash' in title or 'crypto' in title or 'md5' in title or 'sha' in title):
            return '# INSECURE:\nimport hashlib\nh = hashlib.md5(password).hexdigest()\n\n# SECURE:\nimport hashlib\nh = hashlib.pbkdf2_hmac("sha256", password, salt, 100000)'
        elif 'open redirect' in title:
            return '# INSECURE:\nredirect(user_input)\n\n# SECURE:\nfrom urllib.parse import urlparse\nif urlparse(user_input).netloc == "":\n    redirect(user_input)\nelse:\n    redirect("/")'
        elif 'csrf' in title:
            return '# INSECURE:\n# No CSRF protection\n\n# SECURE:\nfrom flask_wtf.csrf import CSRFProtect\ncsrf = CSRFProtect(app)'
        elif 'insecure' in title and 'random' in title:
            return '# INSECURE:\nimport random\ntoken = random.randint(100000, 999999)\n\n# SECURE:\nimport secrets\ntoken = secrets.token_urlsafe(32)'
        
        # Generic secure coding example based on finding code
        if code:
            return f'# Review and fix the security issue in this code:\n# {code.strip()[:100]}'
        
        return ''

    def _build_html(self, project, scan, findings, recs, model, ai_summary: str) -> str:
        m = model
        agg = m.agg

        css = ""
        if self._css_path.exists():
            css = self._css_path.read_text(encoding="utf-8")

        severity_counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "Low")
            if sev in severity_counts:
                severity_counts[sev] += 1

        severity_tiles = ""
        for sev in SEVERITY_ORDER:
            count = severity_counts[sev]
            if count > 0:
                severity_tiles += f"""
                <div class="severity-tile {SEVERITY_CLASSES[sev]}">
                    <div class="severity-count">{count}</div>
                    <div class="severity-label">{sev}</div>
                </div>"""

        findings_html = ""
        for i, f in enumerate(findings, 1):
            fid = f.get("uid", f"GDR-F-{f.get('id', i):03d}")
            sev = f.get("severity", "Low")
            sev_cls = SEVERITY_CLASSES.get(sev, "low")
            rec = recs.get(str(f.get("id", ""))) or recs.get(fid, {})

            code_html = ""
            code = f.get("code", "")
            if code:
                code_lines = code.strip().split("\n")
                code_lines_html = ""
                for ln, line in enumerate(code_lines, 1):
                    code_lines_html += f'<div class="code-line"><span class="code-number">{ln}</span><span class="code-text">{_esc(line)}</span></div>\n'
                code_html = f'<div class="code-block">{code_lines_html}</div>'

            analysis_sections = ""
            for label, key in [("Analysis", "explanation"), ("Potential Impact", "impact"),
                               ("Attack Scenario", "attack_scenario"), ("Root Cause", "root_cause")]:
                val = rec.get(key, "")
                if val:
                    analysis_sections += f'<div class="finding-section"><div class="finding-section-title">{label}</div><p>{_esc(val)}</p></div>\n'

            solution = rec.get('recommended_fix', '')
            secure_code = rec.get('secure_code', '')
            if not solution:
                solution = self._get_default_solution(f)
            if not secure_code:
                secure_code = self._get_default_secure_code(f)

            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <div class="finding-id">{_esc(fid)}</div>
                    <div class="severity-badge {sev_cls}">{sev} ({f.get('score', 0)}/10)</div>
                </div>
                <h3 class="finding-title">{_esc(f.get('title', 'Unknown Finding'))}</h3>
                <div class="finding-location">
                    <div class="location-icon">📍</div>
                    <div class="location-details">
                        <div class="location-file">{_esc(f.get('file', 'unknown'))}</div>
                        <div class="location-line">Line {f.get('line', 0)}</div>
                    </div>
                </div>
                <div class="finding-meta">
                    <span>🔍 {_esc(f.get('scanner', 'unknown'))}</span>
                    <span>📋 {_esc(f.get('rule_id', 'N/A'))}</span>
                    <span>🔗 {_esc(f.get('cwe', 'N/A'))}</span>
                    <span>🛡️ {_esc(f.get('owasp', 'N/A'))}</span>
                </div>
                <p class="finding-desc">{_esc(f.get('description', 'No description available.'))}</p>
                {code_html}
                {analysis_sections}
            </div>"""

        remediation_html = ""
        for sev in SEVERITY_ORDER:
            sev_findings = [f for f in findings if f.get("severity") == sev]
            if sev_findings:
                items = ""
                for f in sev_findings:
                    rec = recs.get(str(f.get("id", ""))) or recs.get(f.get("uid", ""), {})
                    fix = rec.get("recommended_fix", "")
                    if not fix:
                        fix = self._get_default_solution(f)
                    file_path = f.get('file', 'unknown')
                    line_num = f.get('line', 0)
                    items += f'''<li>
                        <div class="remediation-item">
                            <div class="remediation-header">
                                <strong>{_esc(f.get("title", "Unknown"))}</strong>
                                <span class="remediation-location">📍 {_esc(file_path)}:{line_num}</span>
                            </div>
                            <div class="remediation-fix">{_esc(fix)}</div>
                        </div>
                    </li>\n'''
                remediation_html += f"""
                <div class="remediation-group">
                    <h4 class="severity-badge {SEVERITY_CLASSES[sev]}">{sev}</h4>
                    <ul>{items}</ul>
                </div>"""

        cwe_items = ""
        for cwe, count in agg.by_cwe[:10]:
            cwe_items += f'<div class="chart-row"><div class="chart-label-group"><span>{_esc(cwe)}</span><span>{count}</span></div><div class="chart-bar"><div class="bar-fill high" style="width: {min(100, count * 100 // max(1, agg.total))}%"></div></div></div>\n'

        owasp_items = ""
        for cat, count in agg.by_owasp[:10]:
            owasp_items += f'<div class="chart-row"><div class="chart-label-group"><span>{_esc(cat)}</span><span>{count}</span></div><div class="chart-bar"><div class="bar-fill medium" style="width: {min(100, count * 100 // max(1, agg.total))}%"></div></div></div>\n'

        severity_chart = ""
        for sev in SEVERITY_ORDER:
            count = severity_counts[sev]
            if count > 0:
                pct = (count * 100 // max(1, agg.total))
                severity_chart += f'<div class="chart-row"><div class="chart-label-group"><span>{sev}</span><span>{count}</span></div><div class="chart-bar"><div class="bar-fill {SEVERITY_CLASSES[sev]}" style="width: {pct}%"></div></div></div>\n'

        logo_tag = ""
        logo_b64 = ""
        if self._logo_path.exists():
            import base64
            logo_b64 = base64.b64encode(self._logo_path.read_bytes()).decode()
            logo_tag = f'<img src="data:image/png;base64,{logo_b64}" class="cover-logo" alt="Gedr">'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Report - {_esc(project.get('name', 'Project'))}</title>
<style>{css}</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover-page" style="background-image: url('data:image/png;base64,{logo_b64}');">
    <div class="cover-overlay"></div>
    <div class="cover-content">
        <img src="data:image/png;base64,{logo_b64}" class="cover-logo" alt="Gedr">
        <h1 class="cover-title">Security Assessment Report</h1>
        <p class="cover-subtitle">{_esc(project.get('name', 'Unknown Project'))}</p>
        <div class="cover-meta-grid">
            <div class="meta-item"><div class="meta-label">Report ID</div><div class="meta-value">{_esc(m.meta.report_id)}</div></div>
            <div class="meta-item"><div class="meta-label">Language</div><div class="meta-value">{_esc(project.get('language', 'Unknown'))}</div></div>
            <div class="meta-item"><div class="meta-label">Generated</div><div class="meta-value">{_esc(m.meta.filename_date)}</div></div>
            <div class="meta-item"><div class="meta-label">Files Scanned</div><div class="meta-value">{agg.files_scanned}</div></div>
        </div>
        <div class="severity-tiles">{severity_tiles}</div>
    </div>
</div>

<!-- TABLE OF CONTENTS -->
<div class="toc">
    <h2 class="toc-title">Table of Contents</h2>
    <ul class="toc-list">
        <li class="toc-item"><span class="toc-number">01</span><span class="toc-text">Executive Summary</span><span class="toc-dots"></span></li>
        <li class="toc-item"><span class="toc-number">02</span><span class="toc-text">Security Posture</span><span class="toc-dots"></span></li>
        <li class="toc-item"><span class="toc-number">03</span><span class="toc-text">Detailed Findings ({agg.total})</span><span class="toc-dots"></span></li>
        <li class="toc-item"><span class="toc-number">04</span><span class="toc-text">Remediation Plan</span><span class="toc-dots"></span></li>
        <li class="toc-item"><span class="toc-number">05</span><span class="toc-text">Appendix: Methodology</span><span class="toc-dots"></span></li>
    </ul>
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="section">
    <h2 class="section-title">Executive Summary</h2>
    <div class="summary-metrics">
        <div class="metric-card"><div class="metric-value">{agg.total}</div><div class="metric-label">Total Findings</div></div>
        <div class="metric-card"><div class="metric-value">{severity_counts.get('Critical', 0)}</div><div class="metric-label">Critical</div></div>
        <div class="metric-card"><div class="metric-value">{severity_counts.get('High', 0)}</div><div class="metric-label">High</div></div>
        <div class="metric-card"><div class="metric-value">{severity_counts.get('Medium', 0)}</div><div class="metric-label">Medium</div></div>
        <div class="metric-card"><div class="metric-value">{severity_counts.get('Low', 0)}</div><div class="metric-label">Low</div></div>
    </div>
    <div class="ai-summary">
        <p>{_esc(ai_summary)}</p>
    </div>
</div>

<!-- SECURITY POSTURE -->
<div class="section">
    <h2 class="section-title">Security Posture</h2>
    <div class="two-col">
        <div class="card">
            <h3 class="card-title">Severity Distribution</h3>
            {severity_chart}
        </div>
        <div class="card">
            <h3 class="card-title">Findings by Weakness (CWE)</h3>
            {cwe_items}
        </div>
    </div>
    <div class="card" style="margin-top: 16px;">
        <h3 class="card-title">Findings by OWASP Top 10</h3>
        {owasp_items}
    </div>
</div>

<!-- DETAILED FINDINGS -->
<div class="section">
    <h2 class="section-title">Detailed Findings ({agg.total})</h2>
    {findings_html}
</div>

<!-- REMEDIATION PLAN -->
<div class="section">
    <h2 class="section-title">Remediation Plan</h2>
    {remediation_html}
</div>

<!-- APPENDIX -->
<div class="section appendix">
    <h2 class="section-title">Appendix: Methodology</h2>
    <div class="card">
        <h3 class="card-title">Detection</h3>
        <p>Gedr uses a combination of heuristic pattern matching and optional external scanners (Bandit, Semgrep, SpotBugs, PMD, Clang) to identify security vulnerabilities.</p>
        <h3 class="card-title" style="margin-top: 16px;">Scoring</h3>
        <p>Findings are scored on a 1-10 scale based on CVSS-like factors: exploitability, impact, and prevalence.</p>
        <h3 class="card-title" style="margin-top: 16px;">Severity Definitions</h3>
        <table class="severity-table">
            <tr><th>Severity</th><th>Score Range</th><th>Description</th></tr>
            <tr><td><span class="severity-badge critical">Critical</span></td><td>9-10</td><td>Immediate exploitation risk, severe impact</td></tr>
            <tr><td><span class="severity-badge high">High</span></td><td>7-8</td><td>Easily exploitable, significant impact</td></tr>
            <tr><td><span class="severity-badge medium">Medium</span></td><td>4-6</td><td>Exploitable under certain conditions</td></tr>
            <tr><td><span class="severity-badge low">Low</span></td><td>1-3</td><td>Limited impact or difficult to exploit</td></tr>
        </table>
    </div>
</div>

<!-- FOOTER -->
<div class="report-footer">
    <span>Generated by {ENGINE_NAME} v{ENGINE_VERSION}</span>
    <span>Confidential — Internal Use Only</span>
</div>

</body>
</html>"""
        return html

    def generate(
        self,
        project: dict | None,
        scan: dict | None,
        findings: list[dict] | None,
        recommendations: dict | None,
        output_path: Path | None = None,
        *,
        report_type: str = REPORT_TYPE_SECURITY,
        classification: str = "Confidential - Internal Use Only",
        use_ai: bool = True,
    ) -> Path:
        model = build_report_model(
            project or {}, scan or {}, findings or [], recommendations or {},
            report_type=report_type, classification=classification,
        )
        self.model = model
        self.report_id = model.meta.report_id

        if output_path is None:
            from .generator import REPORTS_DIR
            output_path = REPORTS_DIR / (
                f"GDR_AI_Report_{model.meta.report_id}"
                f"_{model.meta.filename_date}.pdf"
            )
        else:
            output_path = Path(output_path)

        # Generate AI summary (optional)
        ai_summary = ""
        if use_ai:
            print("[AI Report] Generating AI summary...")
            ai_summary = self._generate_ai_summary(project or {}, scan or {}, findings or [], recommendations or {})
            print(f"[AI Report] Summary generated ({len(ai_summary)} chars)")

        # Build HTML from template
        print("[AI Report] Building HTML report...")
        html = self._build_html(project or {}, scan or {}, findings or [], recommendations or {}, model, ai_summary)

        # Convert to PDF
        print("[AI Report] Converting HTML to PDF via weasyprint...")
        try:
            result = html_to_pdf(html, output_path)
            size = result.stat().st_size
            print(f"[AI Report] PDF generated: {result} ({size} bytes)")
            return result
        except Exception as e:
            print(f"[AI Report] PDF conversion failed: {e}")
            print("[AI Report] Falling back to Python fpdf2 engine...")
            from .generator import SecurityReportGenerator
            return SecurityReportGenerator().generate(
                project, scan, findings, recommendations, output_path=output_path
            )

    def generate_html_only(
        self,
        project: dict | None,
        scan: dict | None,
        findings: list[dict] | None,
        recommendations: dict | None,
    ) -> str:
        model = build_report_model(
            project or {}, scan or {}, findings or [], recommendations or {},
            report_type=REPORT_TYPE_SECURITY, classification="Confidential",
        )
        ai_summary = self._generate_ai_summary(project or {}, scan or {}, findings or [], recommendations or {})
        return self._build_html(project or {}, scan or {}, findings or [], recommendations or {}, model, ai_summary)


def _esc(text) -> str:
    """Escape HTML entities."""
    if not text:
        return ""
    s = str(text)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
