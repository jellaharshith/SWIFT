"""SWIFT FastAPI web application."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from agent.orchestrator import scan_codebase
from web.oauth import exchange_code, get_github_auth_url, list_repos
from web.storage import (
    create_engine_and_session,
    get_metrics,
    get_scan,
    get_scans,
    init_db,
    save_scan,
)

# ── DB setup ──────────────────────────────────────────────────────────────────
_engine, SessionLocal = create_engine_and_session()

# ── In-memory OAuth token store (MVP) ────────────────────────────────────────
_tokens: dict[str, str] = {}  # session_id → access_token

# ── Templates ─────────────────────────────────────────────────────────────────
_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(_engine)
    yield


app = FastAPI(title="SWIFT Scanner", version="0.1.0", lifespan=lifespan)


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


@app.post("/scan")
def trigger_scan(body: ScanRequest, db: Session = Depends(get_db)):
    try:
        result = scan_codebase(body.repo, generate_patches_flag=body.patches)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    save_scan(db, result)
    return {
        "scan_id": result.scan_id,
        "repo_path": result.repo_path,
        "files_scanned": result.files_scanned,
        "vuln_count": len(result.vulnerabilities),
        "patch_count": len(result.patches),
        "duration_seconds": result.duration_seconds,
        "cost_usd": result.total_cost_usd,
        "timestamp": result.timestamp,
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
    import uuid
    session_id = str(uuid.uuid4())
    _tokens[session_id] = token
    response = RedirectResponse(url="/dashboard")
    response.set_cookie("session_id", session_id, httponly=True, samesite="lax")
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
        "dashboard.html",
        {
            "request": request,
            "metrics": m,
            "scans": scan_list,
        },
    )
