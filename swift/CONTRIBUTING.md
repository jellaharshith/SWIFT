# Contributing to SWIFT

## Setup

```bash
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift
python -m venv .venv && source .venv/bin/activate
pip install -r requirement.txt
cp .env.example .env  # Add your ANTHROPIC_API_KEY
```

## Development Workflow

1. Create an issue for your change (see `github.md` for conventions)
2. Branch off `main` using the naming convention:
   - `feature/123-short-description` for new features
   - `bugfix/456-short-description` for bug fixes
3. Write code + tests
4. Run quality checks (see below)
5. Open a PR referencing the issue number

## Code Standards

- Python 3.10+, strict PEP 8
- Type hints on every function: `def scan(repo: str) -> List[Vulnerability]:`
- Google-style docstrings with `Args`, `Returns`, and `Raises` sections
- Comments explain *why*, not *what*
- No secrets in code — use `.env` and `config/settings.py`

```bash
black swift/       # Format
flake8 swift/      # Lint
isort swift/       # Sort imports
```

## Testing

```bash
pytest test/unit/ -v                    # Unit tests (mock Claude API, no key needed)
pytest test/integration/ -v             # Integration tests
SWIFT_RUN_E2E=1 pytest test/e2e/ -v    # E2E tests (real API key required)
pytest test/ --cov=. --cov-report=term  # Coverage report (target >80%)
```

## Key Rules

### 95% Confidence Rule

Never output findings below 95% confidence. This is non-negotiable — it is the core trust guarantee of SWIFT:

```python
if vulnerability.confidence >= 0.95:
    output_finding(vulnerability)
else:
    log_low_confidence(vulnerability)  # Suppressed — not reported to the user
```

If you are changing scanner logic, confirm this gate remains intact.

### Cost Discipline

- Use Haiku for triage (cheap and fast — ~$0.05/file, ~50ms)
- Run Sonnet only on locations already flagged by Haiku
- Target: <$2 per full scan
- Do not add Sonnet calls to the triage layer

### Sandbox Safety

All patches must be tested in Docker with these constraints enforced:

- No network access (`--network=none`)
- Read-only filesystem (except `/tmp`)
- CPU/memory limits: 2 cores, 2GB RAM
- 30-second timeout (process killed if exceeded)

Do not weaken these constraints — they are the safety guarantee for patch testing.

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `agent/` | Pipeline orchestration — ties all stages together |
| `scanners/` | Haiku triage scanner + Sonnet deep analysis |
| `patches/` | Patch generation, candidate scoring, unified diffs |
| `sandbox/` | Docker isolation for safe patch testing |
| `cli/` | Click commands: `scan`, `patch`, `validate` |
| `triage/` | Regex pre-filtering to skip obviously safe files |
| `web/` | FastAPI app, GitHub OAuth, SQLite storage, dashboard |
| `output/` | JSON and Markdown output formatters |
| `log/` | Structured logging, cost and performance metrics |

## PR Checklist

- [ ] Tests pass: `pytest test/unit/ -v`
- [ ] No new secrets committed to source
- [ ] Type hints added to all new functions
- [ ] GitHub issue number referenced in PR description
