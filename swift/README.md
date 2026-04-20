# SWIFT — AI-Powered Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Claude AI](https://img.shields.io/badge/Claude-Haiku%20%2B%20Sonnet-blueviolet?logo=anthropic)
![License](https://img.shields.io/badge/License-MIT-green)
![Confidence](https://img.shields.io/badge/Confidence%20Gate-95%25-critical)

> Continuous, AI-powered security scanning. Finds, verifies, and fixes vulnerabilities automatically — with a 95% confidence gate that eliminates false positives.

---

## What SWIFT Does

| Stage | Model | What Happens |
|-------|-------|--------------|
| Regex Triage | None (free) | Fast pattern matching flags suspicious files |
| Haiku Filter | Claude Haiku | Broad AI filter at ~50ms/file, $0.05/file |
| Sonnet Analysis | Claude Sonnet | Deep reasoning — only reports findings ≥ 95% confidence |
| Patch + Sandbox | Claude Sonnet + Docker | 3 patch candidates generated, tested in isolation, best returned |

Supports **Python, TypeScript, and JavaScript** codebases. Scans local paths or GitHub URLs directly.

---

## Features

- **Zero false positives** — 95% confidence threshold is non-negotiable; low-confidence findings go to logs, never output
- **GitHub integration** — scan public or private repos by URL, no manual cloning
- **Docker sandbox** — patches tested in complete isolation (no network, read-only FS, 30s timeout)
- **Web dashboard** — real-time scan progress, vulnerability viewer, report download
- **REST API** — JSON endpoints for CI/CD and programmatic access
- **GitHub OAuth** — authenticate to scan private repositories
- **Scan history** — browse past scans, filter by severity, export reports
- **Cost-efficient** — target <$2 per full scan via progressive filtering

---

## Installation

**Prerequisites:** Python 3.10+, Docker, Anthropic API key

```bash
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift
python -m venv .venv && source .venv/bin/activate
pip install -r requirement.txt
cp .env.example .env   # Add ANTHROPIC_API_KEY
```

---

## Quick Start

```bash
# Scan local repo
python main.py scan --repo . --output markdown

# Scan GitHub repo + generate patches
python main.py patch --repo https://github.com/owner/repo --output json

# Launch web dashboard
uvicorn web.app:app --reload --port 8000
# → http://localhost:8000/dashboard
```

---

## REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check |
| `/scans` | GET | List past scans (paginated) |
| `/scan` | POST | Submit new scan (async) |
| `/scan/{id}/status` | GET | Poll scan status |
| `/scan/{id}/report/json` | GET | Download JSON report |
| `/scan/{id}/report/markdown` | GET | Download Markdown report |
| `/metrics` | GET | Aggregate cost, speed, and vuln metrics |
| `/auth/github` | GET | GitHub OAuth redirect |
| `/auth/callback` | GET | GitHub OAuth callback |

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | **Yes** | — | Anthropic API key |
| `SWIFT_CONFIDENCE_THRESHOLD` | No | `0.95` | Minimum confidence to report — never lower |
| `SWIFT_LOG_LEVEL` | No | `INFO` | `DEBUG` / `INFO` / `WARNING` |
| `SWIFT_DB_PATH` | No | `./swift.db` | SQLite scan history path |
| `GITHUB_CLIENT_ID` | No | — | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | No | — | GitHub OAuth app client secret |

---

## CI/CD Integration

Add SWIFT to any GitHub Actions workflow via the REST API or CLI. See [CI/CD Integration Guide](docs/cicd.md) for a ready-to-use workflow template.

---

## Testing

```bash
pytest test/unit/ -v                      # Unit tests (no API key needed)
pytest test/integration/ -v              # Integration tests
pytest test/ --cov=. --cov-report=term   # Full coverage report
```

---

## License

MIT
