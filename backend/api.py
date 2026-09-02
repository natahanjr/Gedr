"""
FastAPI backend for Gədr.

Endpoints:
  POST /api/scan/upload      - upload one file, scan it
  POST /api/scan/project     - scan an existing local path
  GET  /api/projects         - list projects
  GET  /api/projects/{id}    - project detail with scans
  GET  /api/scans/{scan_id}  - scan result with findings
  POST /api/scans/{scan_id}/ai - run Gədr analysis on findings
  GET  /api/scans/{scan_id}/report - download PDF report
  GET  /api/health           - health + installed tools info

Run:  uvicorn backend.api:app --host 0.0.0.0 --port 8000
"""
import os
import shutil
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from fastapi import (
    BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Request,
    UploadFile, status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from starlette.background import BackgroundTask

from ai.ai_agent import GedrAgent as _DirectAgent, get_fallback as _ai_fallback
from backend.scanner_manager import ScannerManager
from backend.path_security import validate_scan_path, PathSecurityError
from backend.upload_validator import validate_upload, UploadValidationError
from database.sqlite_manager import PostgresManager
from reports.pdf_generator import SecurityReportGenerator
from backend.auth import AuthHandler, get_current_user, get_current_user_optional
from backend.autofix_engine import AutoFixEngine
from backend.rate_limit import check as rate_check

app = FastAPI(
    title="Gədr API",
    description="AI-enhanced multi-language static security analysis platform",
    version="1.0.0",
)

# Thread pool for offloading blocking scanner + AI work so FastAPI's
# event loop is never starved by a 500-file scan or a slow LLM call.
_worker_pool = ThreadPoolExecutor(
    max_workers=int(os.getenv("CCI_WORKER_THREADS", "4")),
    thread_name_prefix="gedr-worker",
)

_cors_origins = os.getenv("CCI_CORS_ORIGINS", "")
if _cors_origins:
    _allowed_origins = [o.strip() for o in _cors_origins.replace(",", ";").split(";") if o.strip()]
else:
    _allowed_origins = ["http://127.0.0.1:8000", "http://localhost:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=True,
)

db = PostgresManager()
manager = ScannerManager(db)

# Single canonical AI agent. The optional ai_service/ microservice
# remains available as a *sidecar* via CCI_AI_MICROSERVICE_URL for
# users who want container isolation, but the backend now always
# resolves through this in-process agent — no more "two parallel
# implementations disagree about whether AI is on" state.
_AI_MICROSERVICE = os.getenv("CCI_AI_MICROSERVICE_URL", "").rstrip("/")
agent = _DirectAgent()
autofix = AutoFixEngine(agent)
if _AI_MICROSERVICE:
    print(f"[AI] Sidecar microservice configured at {_AI_MICROSERVICE} (will be used as fallback if in-process agent is offline)")
elif agent.available:
    print(f"[AI] In-process agent enabled (model: {agent.model})")
else:
    print("[AI] No API key set - AI analysis will use offline fallback")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.middleware("http")
async def no_cache_static(request: Request, call_next):
    """Always revalidate static assets so frontend edits appear on refresh."""
    response = await call_next(request)
    if request.url.path.startswith("/static") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response


def _enforce_rate(limit: int, request: Request):
    allowed, info = rate_check(limit, request)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Retry after {info['retry_after']}s.",
            headers={"Retry-After": str(info["retry_after"])},
        )


async def run_in_thread(fn, *args, **kwargs):
    """Run a blocking function on the worker pool so the event loop
    stays responsive. Returns a coroutine that yields the function's
    return value."""
    import asyncio
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_worker_pool, lambda: fn(*args, **kwargs))


# ----------------------------------------------------------------------
# Authentication Endpoints
# ----------------------------------------------------------------------
@app.post("/api/auth/login")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    _enforce_rate(5, request)  # 5 login attempts per minute
    user = db.get_user(form_data.username)
    if not user or not AuthHandler.verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    access_token = AuthHandler.create_access_token(data={"sub": user["username"], "role": user["role"]})
    return {"access_token": access_token, "token_type": "bearer", "role": user["role"]}

@app.post("/api/auth/register")
async def register(request: Request, username: str = Form(...), password: str = Form(...)):
    _enforce_rate(3, request)  # 3 registrations per minute
    # Allow disabling public registration (e.g. once the first admin exists).
    if os.getenv("REGISTER_ENABLED", "true").lower() not in ("1", "true", "yes", "on"):
        raise HTTPException(status_code=403, detail="Public registration is disabled")
    if db.get_user(username):
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_pw = AuthHandler.get_password_hash(password)
    user_id = db.create_user(username, hashed_pw, "user")  # Always assign "user" role
    return {"msg": f"User {username} created successfully", "user_id": user_id}


@app.get("/")
def index():
    """Serve the SPA dashboard."""
    return FileResponse(str(FRONTEND_DIR / "index.html"))


# ----------------------------------------------------------------------
@app.get("/api/health")
def health():
    # Probe the DB so the health endpoint fails loud if the store is
    # unreachable (instead of returning "ok" while scans silently crash).
    try:
        db_ok = bool(db.list_projects()) or True  # list_projects exercises the connection
        db_err = None
    except Exception as e:
        db_ok = False
        db_err = str(e)
    return {
        "status": "ok" if db_ok else "degraded",
        "ai_enabled": agent.available,
        "ai_model": agent.model,
        "db_ok": db_ok,
        "db_error": db_err,
        "tools": {
            "bandit": bool(shutil.which("bandit")),
            "semgrep": bool(shutil.which("semgrep")),
            "spotbugs": bool(shutil.which("spotbugs")),
            "pmd": bool(shutil.which("pmd")),
            "clang": bool(shutil.which("clang")),
        },
    }


@app.get("/api/connectors")
def list_connectors():
    """List all external scanner connectors with availability status."""
    return manager.list_connectors()


@app.post("/api/scan/external")
async def scan_external(
    connector: str = Form(...),
    target: str = Form(...),
    user: dict | None = Depends(get_current_user_optional),
):
    """Run an external scanner (openvas/nmap/nessus/custom) against a target.

    Returns normalized findings in the standard CCI format.
    """
    if not target or not target.strip():
        raise HTTPException(400, "Target is required")

    def _do():
        result = manager.run_connector(connector, target.strip())
        if not result.success:
            raise RuntimeError(f"{connector} scan failed: {result.error}")
        project_id = db.create_project(f"External: {connector}", connector, target)
        scan_id = db.create_scan(project_id)
        findings = result.findings
        finding_ids = db.insert_findings(scan_id, findings)
        score = manager.risk.compute_security_score(findings, 1)
        summary = f"External scan via {connector}. {len(findings)} findings."
        db.finish_scan(scan_id, 1, score, False, summary)
        return {
            "scan_id": scan_id,
            "project_id": project_id,
            "score": score,
            "grade": manager.risk.grade(score),
            "files_scanned": 1,
            "findings": findings,
            "summary": summary,
            "ai_enabled": False,
        }

    try:
        return await run_in_thread(_do)
    except RuntimeError as e:
        raise HTTPException(502, str(e))


@app.post("/api/scan/upload")
async def scan_upload(
    request: Request,
    background: BackgroundTasks,
    file: UploadFile = File(...),
    use_ai: bool = Form(False),
    user: dict | None = Depends(get_current_user_optional),
):
    """Scan a single uploaded source file.

    Security: Validates filename, file size, MIME type, and magic bytes
    to prevent DoS, zip bombs, and binary execution attacks.
    Rate-limited to 10 scans per minute per client.

    The synchronous scan runs on a worker thread so the event loop
    stays responsive. AI enrichment (slow, per-finding LLM calls) is
    queued as a background task after the scan completes.
    """
    _enforce_rate(10, request)
    try:
        file_data = await file.read()
        validate_upload(file.filename, file_data)

        safe_name = Path(file.filename).name
        tmp = Path(tempfile.mkdtemp(prefix="cci_upload_"))
        dest = tmp / safe_name
        dest.write_bytes(file_data)

        def _do_scan():
            try:
                return manager.scan_path(dest, use_ai=False)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

        result = await run_in_thread(_do_scan)

        if use_ai and result.get("scan_id"):
            background.add_task(_run_ai_enrichment, result["scan_id"])
            background.add_task(_run_ai_summary, result["scan_id"])

        return _scan_response(result)
    
    except UploadValidationError as e:
        raise HTTPException(400, f"Upload validation failed: {str(e)}")
    except Exception as e:
        raise HTTPException(500, f"Upload processing failed: {str(e)}")


@app.post("/api/scan/project")
async def scan_project(
    request: Request,
    background: BackgroundTasks,
    path: str = Form(...),
    use_ai: bool = Form(False),
    user: dict | None = Depends(get_current_user_optional),
):
    """Scan a directory on the local filesystem.

    Security: Validates path to prevent traversal attacks, symlink
    following, and scanning system-critical directories. Absolute
    paths are only allowed when they fall under CCI_ALLOWED_SCAN_ROOTS.
    """
    try:
        allowed_roots = os.getenv("CCI_ALLOWED_SCAN_ROOTS", "")
        p = validate_scan_path(path, allow_absolute=True, allowed_roots=allowed_roots)
    except PathSecurityError as e:
        raise HTTPException(400, f"Invalid scan path: {str(e)}")

    # Heavy filesystem walk + tool execution happens off the event loop.
    result = await run_in_thread(manager.scan_path, p, use_ai=False)

    if use_ai and result.get("scan_id"):
        background.add_task(_run_ai_enrichment, result["scan_id"])
        background.add_task(_run_ai_summary, result["scan_id"])

    return _scan_response(result)


def _scan_response(result: dict) -> dict:
    return {
        "scan_id": result["scan_id"],
        "project_id": result["project_id"],
        "security_score": result["score"],
        "grade": result["grade"],
        "files_scanned": result["files_scanned"],
        "findings_count": len(result["findings"]),
        "summary": result["summary"],
        "ai_enabled": result["ai_enabled"],
        "findings": result["findings"],
    }


def _run_ai_enrichment(scan_id: str) -> None:
    """Best-effort post-scan AI enrichment.

    Runs in a worker thread so the HTTP request that triggered the
    scan does not block on slow LLM calls (each finding has a
    deliberate 0.5s sleep between calls; 50 findings = 25s).
    Failures are swallowed - the scan itself is already complete.
    """
    try:
        findings = db.get_findings(scan_id)
        if findings and agent and agent.available:
            agent.analyze_many(findings, db, max_items=50)
    except Exception:
        pass


def _run_ai_summary(scan_id: str) -> None:
    """Best-effort AI executive summary, persisted in scan summary."""
    try:
        scan = db.get_scan(scan_id)
        if not scan or not agent or not agent.available:
            return
        findings = db.get_findings(scan_id)
        if not findings:
            return
        bd = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            bd[f.get("severity", "Low")] += 1
        top = sorted(findings, key=lambda x: x.get("severity_score", 0), reverse=True)[:8]
        finding_lines = "\n".join(
            f"- [{f.get('severity')}] {f.get('title')} ({f.get('cwe', '-')}) "
            f"in {f.get('file')}:{f.get('line')}"
            for f in top
        ) or "- No findings"
        score = scan.get("security_score", 0)
        grade = manager.risk.grade(score)
        prompt = (
            "You are a senior application security engineer. Write a concise "
            "executive summary (3-5 sentences) for this security assessment.\n\n"
            f"Score: {score}/100 (Grade {grade})\n"
            f"Findings: {len(findings)} "
            f"(C:{bd['Critical']} H:{bd['High']} M:{bd['Medium']} L:{bd['Low']})\n\n"
            f"Top findings:\n{finding_lines}"
        )
        summary = agent.generate(prompt).strip()
        with db._lock if hasattr(db, "_lock") else threading.Lock():
            conn = db._connect()
            try:
                conn.execute(
                    "UPDATE scans SET ai_summary=? WHERE id=?",
                    (summary, scan_id),
                )
                conn.commit()
            finally:
                conn.close()
    except Exception:
        pass


# ----------------------------------------------------------------------
@app.get("/api/projects")
def list_projects(user: dict | None = Depends(get_current_user_optional)):
    projects = db.list_projects()
    out = []
    for pr in projects:
        scans = db.list_scans(pr["id"])
        latest = scans[0] if scans else None
        out.append({**pr, "last_score": latest.get("security_score") if latest else None,
                    "last_scan": latest.get("started_at") if latest else None})
    return out


@app.get("/api/projects/{project_id}")
def get_project(project_id: str, user: dict | None = Depends(get_current_user_optional)):
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    return {**project, "scans": db.list_scans(project_id)}


# ----------------------------------------------------------------------
@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, user: dict | None = Depends(get_current_user_optional)):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = db.get_findings(scan_id)
    enriched = []
    for f in findings:
        rec = db.get_recommendation(f["id"])
        enriched.append({**f, "ai_recommendation": rec})
    return {
        "scan": scan,
        "severity_breakdown": db.severity_breakdown(scan_id),
        "findings": enriched,
    }


@app.post("/api/scans/{scan_id}/ai")
async def run_ai_analysis(scan_id: str, user: dict | None = Depends(get_current_user_optional)):
    """Run AI analysis over all findings of a scan via microservice.

    The HTTP call to the AI microservice and the synchronous fallback
    to the local agent run on a worker thread so the event loop is
    not blocked for the duration of the LLM calls.
    """
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    findings = db.get_findings(scan_id)
    if not findings:
        return {"analyzed": 0, "total": 0, "overall_summary": "No findings to analyze."}

    def _do_ai():
        # Optional sidecar: try the AI microservice first if configured.
        # If it fails, fall back to the in-process agent. Single source
        # of truth for "AI is enabled" is agent.available.
        if _AI_MICROSERVICE:
            try:
                payload = {
                    "findings": findings,
                    "scan_summary": scan.get("summary", ""),
                }
                resp = requests.post(
                    f"{_AI_MICROSERVICE}/ai/analyze-many",
                    json=payload,
                    timeout=120,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("results", []):
                        fid = item.get("finding_id")
                        rec = item.get("analysis", {})
                        if fid and rec and rec.get("explanation") and rec.get("model") != "offline fallback":
                            try:
                                db.save_ai_recommendation(
                                    fid, {**rec, "model": rec.get("model", "ai-service")}
                                )
                            except Exception:
                                pass
                    return {
                        "analyzed": data.get("analyzed", 0),
                        "total": len(findings),
                        "overall_summary": data.get("overall_summary", ""),
                    }
            except Exception as e:
                print(f"[AI] Microservice call failed: {e}; falling back to in-process agent")

        if agent and agent.available:
            processed = agent.analyze_many(findings, db, max_items=50)
            return {"analyzed": processed, "total": len(findings)}
        raise RuntimeError("AI service not available")

    try:
        return await run_in_thread(_do_ai)
    except RuntimeError:
        raise HTTPException(503, "AI service not available. Set CCI_AI_API_KEY in .env.")


@app.post("/api/scans/{scan_id}/summary")
async def scan_summary(scan_id: str, user: dict | None = Depends(get_current_user_optional)):
    """Generate an AI executive summary for a scan.

    Runs on a worker thread so the event loop is not blocked while the
    LLM completes a potentially long summary generation.
    """
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = db.get_findings(scan_id)
    score = scan.get("security_score", 0)
    grade = manager.risk.grade(score)

    def _do_summary():
        # Optional sidecar microservice first, then in-process agent.
        if _AI_MICROSERVICE:
            try:
                payload = {
                    "scan_summary": scan.get("summary", ""),
                    "findings": findings,
                    "grade": grade,
                    "score": score,
                }
                resp = requests.post(
                    f"{_AI_MICROSERVICE}/ai/summarize",
                    json=payload,
                    timeout=60,
                )
                if resp.status_code == 200:
                    return resp.json()
            except Exception as e:
                print(f"[AI] Microservice summarize failed: {e}; falling back to in-process agent")

        # 2) Fallback: direct agent (works offline or with configured API key)
        if agent and agent.available:
            bd = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for f in findings:
                bd[f.get("severity", "Low")] += 1
            top = sorted(findings, key=lambda x: x.get("severity_score", 0), reverse=True)[:8]
            finding_lines = "\n".join(
                f"- [{f.get('severity')}] {f.get('title')} ({f.get('cwe', '-')}) in {f.get('file')}:{f.get('line')}"
                for f in top
            ) or "- No findings"
            prompt = (
                "You are a senior application security engineer. Write a concise executive summary "
                "(3-5 sentences) for this security assessment. Cover the overall risk posture, the most "
                "critical issues, and the top recommended next steps.\n\n"
                f"Security Score: {score}/100 (Grade {grade})\n"
                f"Total Findings: {len(findings)} "
                f"(Critical: {bd['Critical']}, High: {bd['High']}, Medium: {bd['Medium']}, Low: {bd['Low']})\n\n"
                f"Top findings:\n{finding_lines}\n\n"
                "Respond with plain text only - no markdown."
            )
            try:
                text = agent.generate(prompt)
                return {"summary": text.strip(), "model": agent.model}
            except Exception as e:
                raise RuntimeError(f"AI summary failed: {e}")
        raise RuntimeError("AI service not available")

    try:
        return await run_in_thread(_do_summary)
    except RuntimeError as e:
        msg = str(e)
        status_code = 503 if "not available" in msg else 502
        raise HTTPException(status_code, msg)


@app.post("/api/scans/{scan_id}/autofix")
async def run_autofix(
    scan_id: str,
    dry_run: bool = Form(False),
    current_user: dict = Depends(get_current_user),
):
    """Preview or apply AI fixes and create a security branch."""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can apply auto-fixes")

    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    findings = db.get_findings(scan_id)
    fixes = []
    for f in findings:
        rec = db.get_recommendation(f["id"])
        if rec and rec.get("secure_code"):
            fixes.append({
                "file": f["file"],
                "old_code": f["code"],
                "new_code": rec["secure_code"],
                "line": f.get("line", 0),
            })

    if not fixes:
        return {"msg": "No auto-fixable vulnerabilities found.", "dry_run": dry_run}

    project = db.get_project(scan["project_id"])
    if not project:
        raise HTTPException(500, "Project data missing for this scan")

    source = Path(project.get("source_path", ""))

    def _do_autofix():
        return autofix.create_security_pr(source, scan_id, fixes, dry_run=dry_run)

    success, result = await run_in_thread(_do_autofix)
    if success:
        return {"msg": result, "dry_run": dry_run}
    raise HTTPException(500, f"Auto-fix failed: {result}")

@app.get("/api/scans/{scan_id}/report")
async def download_report(scan_id: str, user: dict | None = Depends(get_current_user_optional)):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    project = db.get_project(scan["project_id"])
    findings = db.get_findings(scan_id)
    recs = {}
    for f in findings:
        rec = db.get_recommendation(f["id"])
        if rec:
            recs[f["id"]] = rec

    def _render():
        # Write to a unique temp file per request so concurrent downloads
        # never collide on the same output path.
        fd, tmp_path = tempfile.mkstemp(prefix="cci_report_", suffix=".pdf")
        os.close(fd)
        out = SecurityReportGenerator().generate(
            project, scan, findings, recs, output_path=Path(tmp_path)
        )
        return out

    # Heavy CPU work (PDF rendering) runs off the event loop.
    out = await run_in_thread(_render)
    return FileResponse(
        out,
        media_type="application/pdf",
        filename=out.name,
        background=BackgroundTask(os.unlink, str(out)),
    )


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str, current_user: dict = Depends(get_current_user)):
    if not db.get_project(project_id):
        raise HTTPException(404, "Project not found")
    db.delete_project(project_id)
    return {"deleted": project_id}


@app.delete("/api/history")
async def clear_history(current_user: dict = Depends(get_current_user)):
    """Delete all projects, scans, findings and AI recommendations."""
    db.clear_history()
    return {"deleted": True}
