# SWIFT — AI-Powered Vulnerability Scanner

> Continuous security scanning powered by Claude AI. Find, verify, and fix vulnerabilities automatically.

## What SWIFT Does

- **Finds** security flaws in code (SQL injection, command injection, XSS, path traversal, and more) across Python, TypeScript, and JavaScript codebases
- **Verifies** every finding is real using a 95% confidence threshold — false positives are suppressed, not reported
- **Fixes** vulnerabilities automatically by generating Docker-sandbox-tested patches and unified diffs
- **Scans GitHub repos directly** — provide a repo URL or local path
- **Reports via API** — JSON endpoints for CI/CD integration, or Markdown for human review

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

## New Features (Phase 2)

### 🔗 GitHub Integration
Scan public and private GitHub repositories directly — no cloning required.

```bash
# Scan a GitHub repo
python main.py scan --repo https://github.com/owner/repo --output markdown

# Generate patches for GitHub repo
python main.py patch --repo https://github.com/owner/repo --output json
```

### 🌐 Web Dashboard & API
FastAPI-powered dashboard and REST API for scan management, results viewing, and metrics.

```bash
# Run web layer
uvicorn web.app:app --reload --port 8000
# Open http://localhost:8000/dashboard
```

Features:
- **Dashboard:** Real-time scan progress, vulnerability list, patch viewer
- **OAuth:** GitHub authentication for authenticated scans
- **REST API:** Programmatic access to scan results and history
- **Scan History:** View past scans, download JSON/Markdown reports

### 📊 Multi-Language Support
Scanner now handles Python, TypeScript, and JavaScript vulnerabilities.

### ☁️ AWS Deployment Ready
One-command deployment to AWS App Runner with auto-scaling.

```bash
./aws-deploy.sh
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

### CLI Commands

**Scan a repository:**
```bash
# Local scan (JSON output)
python main.py scan --repo . --output json

# GitHub repo scan (Markdown report)
python main.py scan --repo https://github.com/owner/repo --output markdown

# Scan with patches
python main.py scan --repo . --patches --output json --out-file results.json
```

**Generate patches:**
```bash
# Full scan + auto-patch (generates 3 candidates, picks best)
python main.py patch --repo . --output json

# GitHub repo with patches
python main.py patch --repo https://github.com/owner/repo --output markdown
```

## Web Dashboard & REST API

### Dashboard UI

Start the web server:
```bash
uvicorn web.app:app --reload --port 8000
# Open http://localhost:8000/dashboard
```

Dashboard features:
- **Scan Input:** Paste GitHub repo URL or select from saved repos
- **Live Progress:** Real-time pipeline visualization (Triage → Haiku → Sonnet → Patching)
- **Results View:** Vulnerabilities with confidence scores, code snippets, and patches
- **Report Download:** Export as JSON or Markdown
- **Scan History:** Browse past scans with filters and metrics
- **GitHub OAuth:** Authenticate to scan private repos

### REST API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check (`{"status": "ok"}`) |
| `/scans` | GET | List past scans (paginated) |
| `/scan/{scan_id}` | GET | Get scan details |
| `/scan/{scan_id}/report/json` | GET | Download JSON report |
| `/scan/{scan_id}/report/markdown` | GET | Download Markdown report |
| `/scan` | POST | Submit new scan (async) |
| `/scan/{scan_id}/status` | GET | Poll scan status |
| `/metrics` | GET | Aggregate metrics (cost, speed, vuln count) |
| `/auth/github` | GET | GitHub OAuth redirect |
| `/auth/callback` | GET | GitHub OAuth callback |

**Example: Submit scan via API**
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/owner/repo", "patches": true}'
```

**Example: Poll scan status**
```bash
curl http://localhost:8000/scan/{scan_id}/status
```

**Example: Download JSON report**
```bash
curl http://localhost:8000/scan/{scan_id}/report/json > report.json
```

## Configuration

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Your Anthropic API key (never commit this) |
| `SWIFT_LOG_LEVEL` | No | Log verbosity: `DEBUG`, `INFO`, `WARNING` (default: `INFO`) |
| `SWIFT_CONFIDENCE_THRESHOLD` | No | Minimum confidence to report (default: `0.95` — never lower) |
| `SWIFT_DB_PATH` | No | Path for SQLite scan history (default: `./swift.db`) |
| `GITHUB_CLIENT_ID` | No | GitHub OAuth app client ID (for web dashboard) |
| `GITHUB_CLIENT_SECRET` | No | GitHub OAuth app client secret (for web dashboard) |

## CI/CD Integration

### GitHub Actions

Add to `.github/workflows/security-scan.yml`:

```yaml
name: SWIFT Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run SWIFT scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          pip install -r requirement.txt
          python main.py scan --repo . --output markdown --out-file report.md
      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.md
```

### API Integration (for hosted SWIFT)

```bash
# Submit scan via REST API
SCAN_ID=$(curl -s -X POST https://your-swift-instance/scan \
  -H "Content-Type: application/json" \
  -d '{"repo": "'$GITHUB_SERVER_URL'/'$GITHUB_REPOSITORY'", "patches": false}' \
  | jq -r '.scan_id')

# Poll until done
while true; do
  STATUS=$(curl -s https://your-swift-instance/scan/$SCAN_ID/status)
  if [ "$(echo $STATUS | jq -r '.status')" = "done" ]; then
    break
  fi
  sleep 5
done

# Download report
curl https://your-swift-instance/scan/$SCAN_ID/report/markdown > report.md
```

## Deploy to AWS App Runner

SWIFT is production-ready for AWS deployment with auto-scaling, HTTPS, and Secrets Manager integration.

### Prerequisites
- AWS Account with credentials configured (`aws configure`)
- Docker installed locally
- `ANTHROPIC_API_KEY` (Anthropic API key)

### One-Command Deployment

```bash
./aws-deploy.sh
```

Script handles:
1. ECR repository setup
2. Docker image build + push
3. AWS Secrets Manager for API key
4. IAM role creation
5. Prints deployment command

### Manual App Runner Setup (if needed)

After running `aws-deploy.sh`, create the service in AWS Console:

1. Go to **AWS App Runner** (us-east-1)
2. Click **Create Service**
3. **Source:** Container registry → Amazon ECR
4. **Image URI:** `<account-id>.dkr.ecr.us-east-1.amazonaws.com/swift-scanner:latest`
5. **ECR Access Role:** `AppRunnerECRAccessRole` (created by script)
6. **Port:** `8000`
7. **Environment Variables:**
   - `SWIFT_LOG_LEVEL=INFO`
   - `SWIFT_CONFIDENCE_THRESHOLD=0.95`
   - `PYTHONPATH=/app`
8. **Secrets (from Secrets Manager):**
   - `ANTHROPIC_API_KEY` → select the secret created by deploy script
9. **Instance:** 1 vCPU, 2 GB RAM
10. Click **Create**

### After Deployment

App Runner provides:
- **Auto-scaling** — scales based on traffic
- **HTTPS** — automatic certificate
- **Health checks** — automatic restarts
- **Logs** — CloudWatch integration
- **Monitoring** — CloudWatch metrics

Test the deployment:
```bash
curl https://your-service-url/
# {"status": "ok", "service": "SWIFT Scanner"}

curl https://your-service-url/dashboard
# Opens web UI
```

### Cost Breakdown
- **App Runner Infrastructure:** ~$1/day for 1 vCPU, 2 GB (idle billing minimal)
- **AWS Secrets Manager:** $0.40/secret/month
- **API calls:** ~<$2 per full scan

## Scan Cost Model

| Step | Model | Cost per File | Speed |
|---|---|---|---|
| Regex Triage | None | Free | <1ms |
| Haiku Scanner | Claude Haiku | ~$0.05 | ~50ms |
| Sonnet Analysis | Claude Sonnet | ~$0.50/location | ~3s |
| **Target per scan** | — | **<$2 total** | — |

Cost optimization: Only runs Sonnet on locations flagged by Haiku. Most files skip expensive steps.

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
