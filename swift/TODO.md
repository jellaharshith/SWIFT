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
| — | **Deploy publicly** | `Dockerfile`, `fly.toml` or `render.yaml`, `pyproject.toml` | ⬜ PENDING |

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

## ⬜ NEXT: Deploy Publicly

**What's needed:**

| Sub-task | File | Status |
|----------|------|--------|
| Fix `pyproject.toml` CLI entry point (`main:cli` → `cli.commands:cli`) | `pyproject.toml` | ✅ DONE |
| Write `Dockerfile` (multi-stage, python:3.10-slim) | `Dockerfile` | ⬜ PENDING |
| Write deployment config (fly.toml or render.yaml) | `fly.toml` / `render.yaml` | ⬜ PENDING |
| Add `ANTHROPIC_API_KEY` as secret in deployment platform | Platform secrets | ⬜ PENDING |
| Smoke test deployed endpoint | — | ⬜ PENDING |

**Deployment options (pick one):**
- **Fly.io** — `flyctl launch` + `flyctl deploy` (recommended, free tier)
- **Render** — `render.yaml` + push to GitHub auto-deploys
- **PyPI package** — `pip install swift-scanner` via `pyproject.toml`

---

## Run Locally
```bash
source .venv/bin/activate
python main.py scan --repo . --output json
python main.py scan --repo https://github.com/OWNER/REPO --output markdown --patches
python main.py patch --repo .
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
