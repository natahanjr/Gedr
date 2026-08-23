"""
Gədr — AI Microservice

Standalone FastAPI service for AI-powered security analysis.
Runs on its own port (default 8002) and can be deployed independently.

Endpoints:
  POST /ai/analyze        - analyze a single finding
  POST /ai/analyze-many   - analyze up to N findings from a scan
  POST /ai/summarize      - generate an executive summary of a scan report
  GET  /ai/health         - health check + model info
"""
import os
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load .env from project root
_env = Path(__file__).resolve().parent.parent / ".env"
if _env.exists():
    load_dotenv(_env)

try:
    from ai_service.gemini_client import GeminiClient, get_fallback
except ImportError:
    from gemini_client import GeminiClient, get_fallback

app = FastAPI(
    title="Gədr — AI Service",
    description="Gemini-powered security reasoning microservice",
    version="1.0.0",
)

client = GeminiClient()


# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    finding: dict = Field(..., description="A single scanner finding")
    language: str = Field("unknown", description="Programming language")

class AnalyzeManyRequest(BaseModel):
    findings: list[dict] = Field(..., max_length=50, description="List of findings (max 50)")
    scan_summary: str = Field("", description="Optional scan-level summary for context")

class SummarizeRequest(BaseModel):
    scan_summary: str = Field(..., description="Scan summary text")
    findings: list[dict] = Field(..., description="Findings to summarize")
    grade: str = Field("", description="Security grade")
    score: int = Field(0, description="Security score")


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------
@app.get("/ai/health")
def health():
    return {
        "status": "ok",
        "ai_enabled": client.available,
        "model": client.model_name,
        "provider": client.provider,
    }


@app.post("/ai/analyze")
def analyze_finding(req: AnalyzeRequest):
    """Analyze a single finding and return structured remediation."""
    if not client.available:
        return get_fallback(req.finding)

    try:
        rec = client.analyze_finding(req.finding, language=req.language)
        if rec and rec.get("explanation"):
            return rec
    except Exception:
        pass
    return get_fallback(req.finding)


@app.post("/ai/analyze-many")
def analyze_many(req: AnalyzeManyRequest):
    """Analyze multiple findings. Returns per-finding results + overall summary."""
    findings = req.findings[:50]
    results = []

    if client.available:
        for f in findings:
            try:
                rec = client.analyze_finding(f)
                if rec and rec.get("explanation") and rec.get("model") != "offline fallback":
                    results.append({"finding_id": f.get("id"), "analysis": rec})
                    continue
            except Exception:
                pass
            results.append({"finding_id": f.get("id"), "analysis": get_fallback(f)})
            time.sleep(0.5)
    else:
        results = [
            {"finding_id": f.get("id"), "analysis": get_fallback(f)}
            for f in findings
        ]

    # Build overall summary
    summary_parts = []
    if req.scan_summary:
        summary_parts.append(req.scan_summary)

    if results:
        by_sev = {}
        for r in results:
            sev = r["analysis"].get("severity", "Unknown")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_sev.items()))
        summary_parts.append(f"Findings breakdown — {sev_str}.")

        # Top 3 most severe
        top = sorted(results, key=lambda r: r["analysis"].get("severity_score", 0), reverse=True)[:3]
        for t in top:
            a = t["analysis"]
            summary_parts.append(
                f"[{a.get('severity', '?')}] {a.get('title', '?')} — {a.get('impact', '')}"
            )

    overall = " ".join(summary_parts) if summary_parts else "No findings to summarize."

    return {
        "analyzed": len(results),
        "overall_summary": overall,
        "results": results,
    }


@app.post("/ai/summarize")
def summarize_report(req: SummarizeRequest):
    """Generate an executive summary of a full scan report.

    Returns a structured summary suitable for PDF reports or dashboard display.
    """
    if client.available and req.findings:
        prompt = _build_summary_prompt(req)
        try:
            raw = client.generate_text(prompt)
            return {"summary": raw.strip(), "source": "ai"}
        except Exception:
            pass

    # Fallback: rule-based summary
    sev_counts = {}
    for f in req.findings:
        sev = f.get("severity", "Low")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    cwe_map = {}
    for f in req.findings:
        cwe = f.get("cwe", "CWE-20")
        cwe_map[cwe] = cwe_map.get(cwe, 0) + 1

    top_cwes = sorted(cwe_map.items(), key=lambda x: x[1], reverse=True)[:5]

    lines = [
        f"Security Score: {req.score}/100 (Grade: {req.grade}).",
        f"Total findings: {len(req.findings)} — "
        f"Critical: {sev_counts.get('Critical', 0)}, "
        f"High: {sev_counts.get('High', 0)}, "
        f"Medium: {sev_counts.get('Medium', 0)}, "
        f"Low: {sev_counts.get('Low', 0)}.",
    ]
    if top_cwes:
        lines.append("Top vulnerability categories: " + ", ".join(f"{c} ({n})" for c, n in top_cwes) + ".")

    lines.append(
        "Recommendation: Prioritize fixing Critical and High findings first. "
        "Focus on input validation, output encoding, and secure authentication."
    )

    return {"summary": "\n".join(lines), "source": "fallback"}


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _build_summary_prompt(req: SummarizeRequest) -> str:
    findings_text = "\n".join(
        f"- [{f.get('severity', '?')}] {f.get('title', '?')} ({f.get('cwe', 'CWE-20')}) — {f.get('file', '?')}:{f.get('line', '?')}"
        for f in req.findings[:20]
    )
    return f"""You are a senior application security engineer. Write a concise executive summary of this scan report.

Security Score: {req.score}/100 (Grade: {req.grade})
Scan Summary: {req.scan_summary}

Findings:
{findings_text}

Write 3-5 sentences covering:
1. Overall security posture
2. Most critical risk categories
3. Top remediation priorities

Use plain language for a technical manager. No markdown, no bullet lists."""
