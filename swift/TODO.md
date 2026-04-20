# SWIFT MVP — TO-DO

## Status Legend
- ✅ DONE
- 🔄 IN PROGRESS
- ⬜ PENDING

---

## MVP Tasks (Priority 2: Weeks 2-5)

| # | MVP Item | Files | Status |
|---|----------|-------|--------|
| — | Set up basic architecture | All modules + `main.py` | ✅ DONE |
| — | Get Claude API integration working | `config/settings.py`, `scanners/`, `patches/` | ✅ DONE |
| — | Build vulnerability scanner (Haiku triage) | `triage/patterns.py`, `scanners/haiku_scanner.py`, `scanners/sonnet_scanner.py` | ✅ DONE |
| — | Build patch generator (basic) | `patches/generator.py` | ✅ DONE |
| — | Build sandbox tester | `sandbox/docker_runner.py` | ✅ DONE |
| — | **Deploy publicly (AWS App Runner)** | `Dockerfile`, `apprunner.yaml`, `aws-deploy.sh` | ✅ DONE (smoke test pending) |

---

## Implementation Tasks

| # | Task | File | Status |
|---|------|------|--------|
| 1 | Project Foundation | `requirement.txt`, `config/settings.py` | ✅ DONE |
| 2 | Data Models | `agent/models.py` | ✅ DONE |
| 3 | Logging Infrastructure | `log/logger.py` | ✅ DONE |
| 4 | Regex Triage Pre-filter | `triage/patterns.py` | ✅ DONE |
| 5 | Haiku Scanner (Stage 1 API) | `scanners/haiku_scanner.py` | ✅ DONE |
| 6 | Sonnet Scanner — 95% Gate | `scanners/sonnet_scanner.py` | ✅ DONE |
| 7 | Output Formatters | `output/formatters.py` | ✅ DONE |
| 8 | Patch Generator | `patches/generator.py` | ✅ DONE |
| 9 | Docker Sandbox | `sandbox/docker_runner.py` | ✅ DONE |
| 10 | Agent Orchestrator | `agent/orchestrator.py` | ✅ DONE |
| 11 | CLI Commands | `cli/commands.py`, `main.py` | ✅ DONE |
| 12 | Shared Fixtures + Integration Tests | `test/conftest.py`, `test/integration/` | ✅ DONE |
| 13 | Install and Smoke Test | 97/97 tests pass | ✅ DONE |
| 14 | TypeScript/JS scanning support | `triage/patterns.py`, `scanners/haiku_scanner.py` | ✅ DONE |

---

## Deploy Publicly (AWS App Runner)

| Sub-task | File | Status |
|----------|------|--------|
| Fix `pyproject.toml` CLI entry point | `pyproject.toml` | ✅ DONE |
| Write `Dockerfile` (multi-stage, python:3.10-slim) + EXPOSE 8000 | `Dockerfile` | ✅ DONE |
| Write AWS App Runner config | `apprunner.yaml` | ✅ DONE |
| Write deployment helper script | `aws-deploy.sh` | ✅ DONE |
| Write env vars template | `.env.example` | ✅ DONE |
| Add `ANTHROPIC_API_KEY` to AWS Secrets Manager | ✅ LIVE: `arn:aws:secretsmanager:us-east-1:104363824413:secret:swift/anthropic-api-key-kB5L6R` | ✅ DONE |
| Push Docker image to ECR | `104363824413.dkr.ecr.us-east-1.amazonaws.com/swift-scanner:latest` | ✅ DONE |
| Create `AppRunnerECRAccessRole` IAM role | AWS IAM | ✅ DONE |
| **Create App Runner service (manual — console only)** | AWS Console → App Runner (us-east-1) | ⬜ PENDING |
| Smoke test deployed endpoint | — | ⬜ PENDING |

### ⬜ App Runner Manual Activation (one-time)

App Runner requires first-time activation via AWS Console. All infra is ready:

1. Go to **AWS Console → App Runner (us-east-1)**
2. Click **"Create service"**
3. Source: **Container registry → Amazon ECR**
4. Image URI: `104363824413.dkr.ecr.us-east-1.amazonaws.com/swift-scanner:latest`
5. ECR access role: `AppRunnerECRAccessRole` (already created)
6. Port: `8000`
7. Environment variables:
   - `SWIFT_LOG_LEVEL` = `INFO`
   - `SWIFT_CONFIDENCE_THRESHOLD` = `0.95`
   - `PYTHONPATH` = `/app`
8. Secrets (from Secrets Manager):
   - `ANTHROPIC_API_KEY` = `arn:aws:secretsmanager:us-east-1:104363824413:secret:swift/anthropic-api-key-kB5L6R`
9. Instance: **1 vCPU, 2 GB**
10. Service name: `swift-scanner` → **Create**

After creation: share service URL → smoke test `GET /` and `GET /dashboard`.

---

## Phase 2: Web Layer + Docs

| # | Task | File | Status |
|---|------|------|--------|
| 15 | FastAPI app + routes | `web/app.py` | ✅ DONE |
| 16 | GitHub OAuth | `web/oauth.py` | ✅ DONE |
| 17 | Email notifications | `web/notifications.py` | ✅ DONE |
| 18 | SQLite scan storage | `web/storage.py` | ✅ DONE |
| 19 | Dashboard HTML | `web/templates/dashboard.html` | ✅ DONE |
| 20 | ~~Heroku Procfile~~ → AWS App Runner | `apprunner.yaml` | ✅ DONE |
| 21 | README.md (updated with Phase 2 features, deploy, API) | `README.md` | ✅ DONE |
| 22 | CONTRIBUTING.md | `CONTRIBUTING.md` | ✅ DONE |
| 23 | PRODUCTION_CHECKLIST.md | `PRODUCTION_CHECKLIST.md` | ✅ DONE |
| 24 | Update requirements + env example | `requirement.txt`, `.env.example` | ✅ DONE |

---

## ⬜ NEXT: Smoke Test Deployment

1. Configure AWS credentials locally
2. Run `bash aws-deploy.sh`
3. Create App Runner service from printed command
4. Verify `GET /` returns `{"status": "ok"}`
5. Run `GET /dashboard` → confirm HTML renders

---

## ✅ DONE: Modern Frontend SPA

Full rewrite of `web/templates/dashboard.html` + async scan queue + download endpoints.

### Backend (`web/app.py`)

| Sub-task | Status |
|----------|--------|
| All imports, `_reconstruct_scan_result` helper | ✅ DONE |
| `GET /scan/{scan_id}/report/json` download endpoint | ✅ DONE |
| `GET /scan/{scan_id}/report/markdown` download endpoint | ✅ DONE |
| Async `POST /scan` via `BackgroundTasks` (returns instantly) | ✅ DONE |
| `GET /scan/{scan_id}/status` polling endpoint | ✅ DONE |

### Frontend (`web/templates/dashboard.html`)

| Sub-task | Status |
|----------|--------|
| Phase 1: GitHub URL input + patches toggle + scan button + repo suggestions | ✅ DONE |
| Phase 2: Animated loading (stage rows: Triage→Haiku→Sonnet→Patching, terminal log, elapsed timer) | ✅ DONE |
| Phase 3: Metric cards + severity bar + vuln list (confidence bar, code snippet, hljs) + diff viewer | ✅ DONE |
| Download JSON / Download Markdown buttons | ✅ DONE |
| Scan history table with "View" buttons (JS-driven, no reload) | ✅ DONE |
| Async polling (2s interval, 5min timeout, no browser hang) | ✅ DONE |
| Stage timer fix (chained setTimeout, not fixed setInterval) | ✅ DONE |
| Scan button disabled during scan, re-enabled on complete/error | ✅ DONE |

---

## ⬜ NEXT: Production Hardening

| Task | Notes |
|------|-------|
| Replace in-memory OAuth token store | Use Redis or DB-backed sessions |
| Add rate limiting to POST /scan | Scans are expensive — protect endpoint |
| Add async scan queue | Long-running scans should be async (background task + poll) |
| HTTPS + domain | App Runner provides HTTPS automatically |

---

## Run Locally
```bash
source .venv/bin/activate
python main.py scan --repo . --output json
python main.py scan --repo https://github.com/OWNER/REPO --output markdown --patches
python main.py patch --repo .
```

## Run Web Layer
```bash
source .venv/bin/activate
pip install fastapi uvicorn sqlalchemy httpx python-multipart jinja2
uvicorn web.app:app --reload --port 8000
# Open http://localhost:8000/dashboard
```

## Run Tests
```bash
source .venv/bin/activate
pytest test/unit/ -v
pytest test/integration/ -v
SWIFT_RUN_E2E=1 pytest test/e2e/ -v  # needs real API key
```

## GitHub Issues
- jellaharshith/SWIFT#1 — Data Models
- jellaharshith/SWIFT#2 — Logging
- jellaharshith/SWIFT#3 — Regex Triage
- jellaharshith/SWIFT#4 — Haiku Scanner
- jellaharshith/SWIFT#5 — Sonnet Scanner 95% Gate
- jellaharshith/SWIFT#8 — TypeScript/JS multi-language scanning support
- jellaharshith/SWIFT#9 — Feature: deploy SWIFT publicly via Fly.io + Docker (superseded)
- jellaharshith/SWIFT#10 — Feature: deploy SWIFT publicly via AWS App Runner
- jellaharshith/SWIFT#11 — Feature: FastAPI web layer with dashboard, OAuth, notifications
- jellaharshith/SWIFT#12 — Docs: add README, CONTRIBUTING, and PRODUCTION_CHECKLIST
