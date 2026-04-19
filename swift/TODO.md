# SWIFT MVP — TO-DO

## Status Legend
- ✅ DONE
- 🔄 IN PROGRESS
- ⬜ PENDING

---

## Tasks

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

---

## MVP Complete ✅

All tasks done. Run with:
```bash
source .venv/bin/activate
python main.py scan --repo . --output json
python main.py scan --repo . --output markdown
python main.py patch --repo .  # scan + generate patches
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
