"""SWIFT FastAPI web application."""
from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from agent.models import Patch, ScanResult, Vulnerability
from agent.orchestrator import scan_codebase
from output.formatters import JSONFormatter, MarkdownFormatter
from web.oauth import exchange_code, get_github_auth_url, list_repos
from web.storage import (
    create_engine_and_session,
    get_metrics,
    get_scan,
    get_scans,
    init_db,
    save_scan,
    _DB_PATH,
)

# ── DB setup ──────────────────────────────────────────────────────────────────
_engine, SessionLocal = create_engine_and_session()

# ── In-memory OAuth token store (MVP) ────────────────────────────────────────
_tokens: dict[str, str] = {}  # session_id → access_token

# ── In-memory scan status store ───────────────────────────────────────────────
# job_id → {"status": "running"|"done"|"error", ...result fields when done}
_scan_status: dict[str, dict] = {}

# ── Templates ─────────────────────────────────────────────────────────────────
_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


# ── Lifespan ──────────────────────────────────────────────────────────────────
_startup_log = logging.getLogger("swift.startup")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # NOTE: ANTHROPIC_API_KEY must be set as an environment variable in the
    # AppRunner service configuration. Storing in Secrets Manager is not enough —
    # the key must be linked to the service via AWS Console or CLI:
    #   aws apprunner update-service --service-arn <ARN> \
    #     --source-configuration '{"imageRepository": {...}}' ...
    # Or: AppRunner Console → Service → Configuration → Environment variables
    try:
        _startup_log.info("SWIFT starting — SWIFT_ENV=%s", os.environ.get("SWIFT_ENV", "unset"))
        _startup_log.info("ANTHROPIC_API_KEY present=%s", bool(os.environ.get("ANTHROPIC_API_KEY")))
        init_db(_engine)
        _startup_log.info("DB initialized at path: %s", _DB_PATH)
    except Exception as exc:
        _startup_log.error("Startup error: %s", exc, exc_info=True)
        sys.exit(1)
    yield
    _startup_log.info("SWIFT shutdown complete.")


app = FastAPI(title="SWIFT Scanner", version="0.1.0", lifespan=lifespan)

_NETLIFY_ORIGIN = os.environ.get("NETLIFY_ORIGIN", "https://swift-app.netlify.app")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[_NETLIFY_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Dependency ────────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Request models ────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    repo: str
    patches: bool = False


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
def health_check():
    return {"status": "ok", "service": "SWIFT Scanner"}


@app.get("/metrics")
def metrics(db: Session = Depends(get_db)):
    return get_metrics(db)


@app.get("/scans")
def list_scans(limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    records = get_scans(db, limit=limit, offset=offset)
    return [
        {
            "scan_id": r.scan_id,
            "repo_path": r.repo_path,
            "files_scanned": r.files_scanned,
            "vuln_count": r.vuln_count,
            "patch_count": r.patch_count,
            "duration_seconds": r.duration_seconds,
            "cost_usd": r.cost_usd,
            "timestamp": r.timestamp,
        }
        for r in records
    ]


@app.get("/scan/{scan_id}")
def get_single_scan(scan_id: str, db: Session = Depends(get_db)):
    record = get_scan(db, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return {
        "scan_id": record.scan_id,
        "repo_path": record.repo_path,
        "files_scanned": record.files_scanned,
        "vuln_count": record.vuln_count,
        "patch_count": record.patch_count,
        "duration_seconds": record.duration_seconds,
        "cost_usd": record.cost_usd,
        "timestamp": record.timestamp,
        "raw_json": record.raw_json,
    }


def _reconstruct_scan_result(raw_dict: dict) -> ScanResult:
    vulns: List[Vulnerability] = [
        Vulnerability(
            id=v["id"],
            file_path=v["file_path"],
            line_number=v["line_number"],
            vuln_type=v["vuln_type"],
            description=v["description"],
            confidence=v["confidence"],
            severity=v["severity"],
            code_snippet=v["code_snippet"],
        )
        for v in raw_dict.get("vulnerabilities", [])
    ]
    patches: List[Patch] = [
        Patch(
            id=p["id"],
            vuln_id=p["vuln_id"],
            file_path=p["file_path"],
            original_code=p["original_code"],
            patched_code=p["patched_code"],
            diff=p["diff"],
            confidence=p["confidence"],
        )
        for p in raw_dict.get("patches", [])
    ]
    return ScanResult(
        scan_id=raw_dict["scan_id"],
        repo_path=raw_dict["repo_path"],
        files_scanned=raw_dict["files_scanned"],
        vulnerabilities=vulns,
        patches=patches,
        duration_seconds=raw_dict["duration_seconds"],
        total_cost_usd=raw_dict["total_cost_usd"],
        timestamp=raw_dict["timestamp"],
    )


@app.get("/scan/{scan_id}/report/json")
def download_json_report(scan_id: str, db: Session = Depends(get_db)):
    record = get_scan(db, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    raw_dict = json.loads(record.raw_json)
    result = _reconstruct_scan_result(raw_dict)
    content = JSONFormatter().format(result)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="swift-report-{scan_id}.json"'},
    )


@app.get("/scan/{scan_id}/report/markdown")
def download_markdown_report(scan_id: str, db: Session = Depends(get_db)):
    record = get_scan(db, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    raw_dict = json.loads(record.raw_json)
    result = _reconstruct_scan_result(raw_dict)
    content = MarkdownFormatter().format(result)
    return Response(
        content=content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="swift-report-{scan_id}.md"'},
    )


def _run_scan(job_id: str, repo: str, patches: bool) -> None:
    """Background task: run scan, save to DB, update status store."""
    from agent.github_cloner import clone_repo, is_github_url

    cleanup = None
    db = SessionLocal()
    try:
        if is_github_url(repo):
            repo_path, cleanup = clone_repo(repo)
        else:
            repo_path = repo

        result = scan_codebase(repo_path, generate_patches_flag=patches)
        save_scan(db, result)
        _scan_status[job_id] = {
            "status": "done",
            "scan_id": result.scan_id,
            "repo_path": result.repo_path,
            "files_scanned": result.files_scanned,
            "vuln_count": len(result.vulnerabilities),
            "patch_count": len(result.patches),
            "duration_seconds": result.duration_seconds,
            "cost_usd": result.total_cost_usd,
            "timestamp": result.timestamp,
        }
    except Exception as exc:
        _scan_status[job_id] = {"status": "error", "detail": str(exc)}
    finally:
        if cleanup is not None:
            cleanup()
        db.close()


@app.post("/scan")
def trigger_scan(body: ScanRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    _scan_status[job_id] = {"status": "running"}
    background_tasks.add_task(_run_scan, job_id, body.repo, body.patches)
    return {"scan_id": job_id, "status": "running"}


@app.get("/scan/{scan_id}/status")
def get_scan_status(scan_id: str):
    status = _scan_status.get(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Job {scan_id} not found.")
    return status


@app.get("/auth/github")
def github_auth(redirect_uri: str):
    return {"auth_url": get_github_auth_url(redirect_uri)}


@app.get("/auth/callback")
def github_callback(code: str, redirect_uri: str):
    try:
        token = exchange_code(code, redirect_uri)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    session_id = str(uuid.uuid4())
    _tokens[session_id] = token
    netlify_url = os.environ.get("NETLIFY_ORIGIN", "https://swift-app.netlify.app")
    response = RedirectResponse(url=netlify_url)
    response.set_cookie(
        "session_id", session_id,
        httponly=True,
        samesite="none",  # cross-origin cookie (Netlify → tunnel)
        secure=True,      # required when samesite="none"
    )
    return response


@app.get("/repos")
def repos(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        # Also check session cookie
        session_id = request.cookies.get("session_id", "")
        token = _tokens.get(session_id)
        if not token:
            raise HTTPException(status_code=401, detail="Missing Authorization header or session.")
    else:
        token = auth[len("Bearer "):]
    try:
        return list_repos(token)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    m = get_metrics(db)
    scans = get_scans(db, limit=20)
    scan_list = [
        {
            "scan_id": r.scan_id,
            "repo_path": r.repo_path,
            "vuln_count": r.vuln_count,
            "cost_usd": r.cost_usd,
            "timestamp": r.timestamp,
        }
        for r in scans
    ]
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "metrics": m,
            "scans": scan_list,
        },
    )
