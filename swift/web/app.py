"""SWIFT FastAPI web application."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import uuid
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
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
    create_scan_job,
    get_metrics,
    get_scan,
    get_scan_job,
    get_scans,
    init_db,
    save_scan,
    update_scan_job,
    _DB_PATH,
)

# ── DB setup ──────────────────────────────────────────────────────────────────
_engine, SessionLocal = create_engine_and_session()

# ── In-memory OAuth token store (MVP) ────────────────────────────────────────
_tokens: dict[str, str] = {}  # session_id → access_token

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

_NETLIFY_ORIGIN = os.environ.get("NETLIFY_ORIGIN", "https://swiftscanner.netlify.app")
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


def _run_scan_sync(job_id: str, repo: str, patches: bool) -> None:
    """Synchronous scan execution — runs in a thread-pool executor."""
    from agent.github_cloner import clone_repo, is_github_url

    cleanup = None
    db = SessionLocal()
    try:
        if is_github_url(repo):
            repo_path, cleanup = clone_repo(repo)
        else:
            repo_path = repo

        def progress_callback(payload: dict) -> None:
            """Persist all progress fields to DB on each emit."""
            kwargs: dict = {
                "stage": payload.get("stage", 0),
                "stage_name": payload.get("stage_name", ""),
                "files_total": payload.get("files_total", 0),
                "files_scanned": payload.get("files_scanned", 0),
                "current_file": payload.get("current_file", ""),
                "progress": payload.get("progress", 0),
                "signals_detected": payload.get("signals_detected", 0),
                "batch_current": payload.get("batch_current", 0),
                "batch_total": payload.get("batch_total", 0),
            }
            if payload.get("findings_json") is not None:
                kwargs["findings_json"] = payload["findings_json"]
            # Chain-stage fields (Task 10) — only update when present in payload
            for chain_field in (
                "chain_stage", "chain_nodes", "chain_edges",
                "chain_candidates", "ranked_chains",
                "resource_limited", "resource_limit_reason",
            ):
                if chain_field in payload:
                    val = payload[chain_field]
                    # resource_limited is a bool in the payload; store as int
                    if chain_field == "resource_limited":
                        val = 1 if val else 0
                    kwargs[chain_field] = val
            update_scan_job(db, job_id, **kwargs)

        result = scan_codebase(
            repo_path,
            generate_patches_flag=patches,
            progress_callback=progress_callback,
        )
        save_scan(db, result)
        update_scan_job(
            db,
            job_id,
            status="done",
            progress=100,
            detail=result.scan_id,
        )
    except Exception as exc:
        update_scan_job(db, job_id, status="error", detail=str(exc))
    finally:
        if cleanup is not None:
            cleanup()
        db.close()


async def _run_scan_async(job_id: str, repo: str, patches: bool) -> None:
    """Async wrapper: marks job running then delegates to thread executor."""
    db = SessionLocal()
    try:
        update_scan_job(db, job_id, status="running")
    finally:
        db.close()
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _run_scan_sync, job_id, repo, patches)


@app.post("/scan")
async def trigger_scan(body: ScanRequest, db: Session = Depends(get_db)):
    job_id = str(uuid.uuid4())
    create_scan_job(db, job_id)  # status="queued", started_at=now
    asyncio.create_task(_run_scan_async(job_id, body.repo, body.patches))
    return {"job_id": job_id, "scan_id": job_id, "status": "queued"}


@app.get("/scan/{scan_id}/status")
def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    job = get_scan_job(db, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {scan_id} not found.")
    return {
        "status": job.status,
        "progress": job.progress or 0,
        "stage": job.stage,
        "stage_name": job.stage_name,
        "files_total": job.files_total,
        "files_scanned": job.files_scanned,
        "batch_current": job.batch_current or 0,
        "batch_total": job.batch_total or 0,
        "signals_detected": job.signals_detected or 0,
        "current_file": job.current_file,
        "findings": json.loads(job.findings_json) if job.findings_json else [],
        "started_at": job.started_at,
        "detail": job.detail,
        "scan_id": job.detail if job.status == "done" else None,
        # Chain-stage progress fields (Task 10)
        "chain_stage": job.chain_stage or "",
        "chain_nodes": job.chain_nodes or 0,
        "chain_edges": job.chain_edges or 0,
        "chain_candidates": job.chain_candidates or 0,
        "ranked_chains": job.ranked_chains or 0,
        "resource_limited": bool(job.resource_limited),
        "resource_limit_reason": job.resource_limit_reason or "",
    }


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
    netlify_url = os.environ.get("NETLIFY_ORIGIN", "https://swiftscanner.netlify.app")
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
