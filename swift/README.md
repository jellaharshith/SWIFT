# SWIFT — AI-Powered Vulnerability Scanner

> Continuous security scanning powered by Claude AI. Find, verify, and fix vulnerabilities automatically.

## What SWIFT Does

- **Finds** security flaws in code (SQL injection, command injection, XSS, path traversal, and more) across Python, TypeScript, and JavaScript codebases
- **Verifies** every finding is real using a 95% confidence threshold — false positives are suppressed, not reported
- **Fixes** vulnerabilities automatically by generating Docker-sandbox-tested patches and unified diffs

## Architecture

```
Input (local path or GitHub URL)
        │
        ▼
┌───────────────────┐
│   Regex Triage    │  Free — fast pattern matching, flags suspicious code
└───────────────────┘
        │ flagged files only
        ▼
┌───────────────────┐
│  Haiku Scanner    │  $0.05/file — broad AI filter, ~50ms per file
└───────────────────┘
        │ flagged locations only
        ▼
┌───────────────────┐
│ Sonnet Analysis   │  $0.50/location — deep reasoning, ≥95% confidence gate
│  (95% gate)       │  Findings below threshold → log only, never reported
└───────────────────┘
        │ confirmed vulnerabilities
        ▼
┌────────────────────────────┐
│ Patch Generator            │  3 candidate patches, scored and ranked
│ + Docker Sandbox Testing   │  No network, read-only FS, 2 cores/2GB, 30s timeout
└────────────────────────────┘
        │
        ▼
Output (JSON for APIs / Markdown for humans)
```

## Installation

### Prerequisites

- Python 3.10+
- Docker (for sandbox patch testing)
- Anthropic API key

### Steps

```bash
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift
python -m venv .venv
source .venv/bin/activate
pip install -r requirement.txt
cp .env.example .env
# Edit .env and add ANTHROPIC_API_KEY
```

## Quick Start

```bash
# Scan current directory
python main.py scan --repo . --output json

# Scan a GitHub repository
python main.py scan --repo https://github.com/owner/repo --output markdown

# Scan and automatically generate patches
python main.py patch --repo . --output json

# Validate a specific patch
python main.py validate --patch-id PATCH-001
```

## Web Dashboard

SWIFT includes a FastAPI web layer with a browser dashboard for reviewing scan results and managing OAuth-authenticated GitHub scans.

```bash
uvicorn web.app:app --reload --port 8000
# Open http://localhost:8000/dashboard
```

The dashboard shows:
- Active and past scan results
- Vulnerability details with confidence scores
- Generated patches and their test status
- Scan cost and performance metrics

## Configuration

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Your Anthropic API key (never commit this) |
| `SWIFT_LOG_LEVEL` | No | Log verbosity: `DEBUG`, `INFO`, `WARNING` (default: `INFO`) |
| `SWIFT_CONFIDENCE_THRESHOLD` | No | Minimum confidence to report (default: `0.95` — never lower) |
| `SWIFT_DB_PATH` | No | Path for SQLite scan history (default: `./swift.db`) |
| `GITHUB_CLIENT_ID` | No | GitHub OAuth app client ID (for web dashboard) |
| `GITHUB_CLIENT_SECRET` | No | GitHub OAuth app client secret (for web dashboard) |

## Deploy to AWS

SWIFT is designed to run on AWS App Runner via Docker + ECR.

**Prerequisites:** AWS CLI configured, Docker installed

```bash
# Build and push image, create App Runner service
./aws-deploy.sh
```

After deployment, open the AWS App Runner console to find your service URL. The `ANTHROPIC_API_KEY` is stored in AWS Secrets Manager under `swift/anthropic-api-key` and wired in automatically by the deploy script.

## Cost

| Step | Model | Cost | Speed |
|---|---|---|---|
| Regex Triage | None | Free | <1ms/file |
| Haiku Scanner | Claude Haiku | ~$0.05/file | ~50ms/file |
| Sonnet Analysis | Claude Sonnet | ~$0.50/location | ~3s/location |
| **Full scan target** | — | **<$2 total** | — |

Cost is kept low by only running Sonnet on locations already flagged by Haiku. Most files never reach the expensive step.

## Testing

```bash
# Unit tests (mock Claude API, no API key needed)
pytest test/unit/ -v

# Integration tests
pytest test/integration/ -v

# Full coverage report
pytest test/ --cov=. --cov-report=term
```

## Project Structure

```
swift/
├── agent/          # Pipeline orchestration (scan_codebase, generate_patches)
├── cli/            # Click CLI commands (scan, patch, validate)
├── config/         # .env loading, API key validation, settings
├── scanners/       # Haiku triage scanner + Sonnet analysis scanner
├── patches/        # Patch generation, scoring, and unified diffs
├── sandbox/        # Docker isolation for safe patch testing
├── triage/         # Regex pre-filtering (cost optimization layer)
├── output/         # JSON and Markdown formatters
├── web/            # FastAPI app, OAuth, storage, dashboard templates
├── log/            # Structured logging, cost and performance metrics
├── test/           # Unit and integration tests
└── main.py         # CLI entry point
```

## License

MIT
