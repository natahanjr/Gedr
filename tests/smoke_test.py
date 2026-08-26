"""Smoke test: run the full scan pipeline over sample_code."""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.scanner_manager import ScannerManager
from ai.ai_agent import GedrAgent
from reports.pdf_generator import SecurityReportGenerator
from database.sqlite_manager import SQLiteManager

SAMPLE = Path(__file__).resolve().parent.parent / "sample_code"


def main():
    db = SQLiteManager()
    m = ScannerManager(db)

    result = m.scan_path(SAMPLE, use_ai=False)
    print(f"score: {result['score']} | grade: {result['grade']}")
    print(f"files: {result['files_scanned']} | findings: {len(result['findings'])}")
    print(f"summary: {result['summary']}")

    sev = Counter(f["severity"] for f in result["findings"])
    print("severity:", dict(sev))

    for f in result["findings"][:8]:
        print(f'  [{f["severity"]}] {f["scanner"]} {f["file"]}:{f["line"]} '
              f'{f["title"]} ({f["cwe"]})')

    # AI offline fallback
    agent = GedrAgent()
    sample = result["findings"][0]
    rec = agent.analyze_finding(sample)
    assert rec["explanation"], "fallback must produce an explanation"
    print(f"\nAI fallback ({'online' if agent.available else 'offline'}): {rec['explanation'][:90]}...")
    print(f"OWASP: {rec['owasp']} | CWE: {rec['cwe']}")

    # PDF generation
    scan = db.get_scan(result["scan_id"])
    project = db.get_project(result["project_id"])
    findings = db.get_findings(result["scan_id"])
    pdf_path = SecurityReportGenerator().generate(project, scan, findings, {})
    assert pdf_path.exists() and pdf_path.stat().st_size > 1000
    print(f"\nPDF report: {pdf_path} ({pdf_path.stat().st_size} bytes)")

    # Verify persistence
    assert len(db.list_projects()) >= 1
    assert db.get_findings(result["scan_id"])
    print("\nSMOKE TEST PASSED")


if __name__ == "__main__":
    main()
