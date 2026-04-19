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
| Add `ANTHROPIC_API_KEY` to AWS Secrets Manager | Platform secrets | ⬜ PENDING |
| Run `aws-deploy.sh`, create App Runner service | AWS Console/CLI | ⬜ PENDING |
| Smoke test deployed endpoint | — | ⬜ PENDING |

**Deploy steps:**
```bash
export ANTHROPIC_API_KEY=sk-ant-...
export AWS_REGION=us-east-1
bash aws-deploy.sh
# Then follow printed aws apprunner create-service command
```

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
| 21 | README.md | `README.md` | ✅ DONE |
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
