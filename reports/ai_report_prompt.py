"""
AI Report Prompt - Instructs the AI to generate premium HTML security reports.
"""

REPORT_SYSTEM_PROMPT = """You are a document designer creating a security report for Gədr cybersecurity platform.

OUTPUT: Return ONLY a complete HTML document. Start with <!DOCTYPE html>, end with </html>.

IMPORTANT: Do NOT include a <style> tag or any CSS. A professional CSS stylesheet will be injected automatically after you generate the HTML. Focus ONLY on the HTML structure and content.

HTML STRUCTURE (use semantic HTML, no inline styles):
- Cover page: <div class="cover"> with project name, report ID, metadata, severity tiles
- Executive summary: <div class="summary"> with key metrics
- Severity chart: <div class="chart"> with bar elements
- Findings: <div class="finding"> cards for each finding with severity badge, location, code block, analysis
- Remediation: grouped by severity
- Appendix: methodology

RULES:
1. Only use data provided below
2. Include ALL findings as HTML cards
3. Use semantic HTML divs with class names
4. DO NOT include any CSS or style tags
5. Keep HTML structure clean and simple
"""


def build_report_prompt(
    project: dict,
    scan: dict,
    findings: list[dict],
    recommendations: dict,
    aggregates: dict,
) -> str:
    """Build the complete prompt for AI report generation."""
    
    # Format findings
    findings_text = ""
    for f in findings:
        uid = f.get("uid", f"GDR-F-{f.get('id', 0):03d}")
        rec = recommendations.get(str(f.get("id", ""))) or recommendations.get(uid, {})
        
        findings_text += f"""
FINDING {uid}:
- Title: {f.get('title', 'Unknown')}
- Severity: {f.get('severity', 'Low')} (Score: {f.get('score', 1)}/10)
- File: {f.get('file', 'unknown')}:{f.get('line', 0)}
- Scanner: {f.get('scanner', 'unknown')}
- Rule: {f.get('rule_id', 'N/A')}
- CWE: {f.get('cwe', 'N/A')}
- OWASP: {f.get('owasp', 'N/A')}
- Description: {f.get('description', 'No description')}
- Code: 
```
{f.get('code', 'No code available')}
```
- Analysis: {rec.get('explanation', 'No analysis available')}
- Impact: {rec.get('impact', 'No impact analysis')}
- Attack Scenario: {rec.get('attack_scenario', 'No attack scenario')}
- Root Cause: {rec.get('root_cause', 'No root cause identified')}
- Remediation: {rec.get('recommended_fix', 'No remediation available')}
- Secure Code: {rec.get('secure_code', 'No secure code suggestion')}
"""
    
    # Format aggregates
    severity_dist = aggregates.get("by_severity", {})
    if isinstance(severity_dist, dict):
        severity_text = ", ".join(f"{k}: {v}" for k, v in severity_dist.items() if v > 0)
    else:
        severity_text = str(severity_dist)
    
    cwe_data = aggregates.get("by_cwe", {})
    if isinstance(cwe_data, dict):
        cwe_sorted = sorted(cwe_data.items(), key=lambda x: x[1], reverse=True)[:6]
    elif isinstance(cwe_data, list):
        cwe_sorted = cwe_data[:6]
    else:
        cwe_sorted = []
    cwe_text = ", ".join(f"{cwe} ({count})" for cwe, count in cwe_sorted)
    
    owasp_data = aggregates.get("by_owasp", {})
    if isinstance(owasp_data, dict):
        owasp_sorted = sorted(owasp_data.items(), key=lambda x: x[1], reverse=True)[:6]
    elif isinstance(owasp_data, list):
        owasp_sorted = owasp_data[:6]
    else:
        owasp_sorted = []
    owasp_text = ", ".join(f"{cat} ({count})" for cat, count in owasp_sorted)
    
    files_data = aggregates.get("top_files", {})
    if isinstance(files_data, dict):
        files_sorted = sorted(files_data.items(), key=lambda x: x[1], reverse=True)[:8]
    elif isinstance(files_data, list):
        files_sorted = files_data[:8]
    else:
        files_sorted = []
    files_text = ", ".join(f"{f} ({n})" for f, n in files_sorted)
    
    prompt = f"""{REPORT_SYSTEM_PROMPT}

=== REPORT DATA ===

PROJECT:
- Name: {project.get('name', 'Unknown Project')}
- Language: {project.get('language', 'Not specified')}
- Description: {project.get('description', 'No description')}

SCAN:
- Report ID: GDR-{scan.get('id', 0)}
- Generated: {scan.get('created_at', 'Unknown')}
- Files Scanned: {scan.get('files_scanned', 0)}
- Security Score: {scan.get('score', 0)}/100 (Grade: {scan.get('grade', 'N/A')})
- Analysis Window: {scan.get('started_at', 'N/A')} to {scan.get('finished_at', 'N/A')}

AGGREGATES:
- Total Findings: {aggregates.get('total', 0)}
- Severity Distribution: {severity_text}
- Top CWEs: {cwe_text}
- Top OWASP: {owasp_text}
- Most Affected Files: {files_text}
- Duration: {round(aggregates.get('duration_minutes') or 0, 1)} minutes

FINDINGS ({len(findings)} total):
{findings_text}

=== END DATA ===

Generate the complete HTML report now. Remember: ONLY the HTML document, nothing else."""
    
    return prompt
