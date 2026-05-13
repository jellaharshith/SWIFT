# SWIFT — AI-Powered Security Scanner

**SWIFT** is a continuous, AI-powered vulnerability scanner that finds, verifies, and auto-fixes security flaws in Python code.

## Why SWIFT?

| Problem | SWIFT Solution |
|---------|---------------|
| Traditional scans take weeks | Continuous, runs in minutes |
| High false-positive rate | 95% confidence gate — only real vulns |
| Manual remediation ($50K+) | Auto-generates and tests patches |
| One-time scan | Integrates into CI/CD pipeline |

---

## Quick Start

```bash
# Install
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift
python -m venv .venv && source .venv/bin/activate
pip install -r requirement.txt

# Add API key
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# Scan a repo
python main.py scan --repo /path/to/your/repo --output json
python main.py scan --repo /path/to/your/repo --output markdown

# Scan + auto-generate patches
python main.py patch --repo /path/to/your/repo
```

---

## How It Works — 3-Layer Pipeline

```
Your Code
    │
    ▼
┌──────────────────────────────────────────────────────────┐
│  Layer 1: Regex Triage  (FREE — zero API calls)          │
│  Fast pattern matching for 8 vulnerability categories    │
│  Returns: flagged file:line pairs                        │
└─────────────────────────┬────────────────────────────────┘
                          │ Only flagged files
                          ▼
┌──────────────────────────────────────────────────────────┐
│  Layer 2: Haiku Triage  (~$0.05/file, ~50ms)            │
│  Fast AI confirmation of suspicious lines               │
│  Model: claude-haiku-4-5-20251001                       │
└─────────────────────────┬────────────────────────────────┘
                          │ Only confirmed-suspicious lines
                          ▼
┌──────────────────────────────────────────────────────────┐
│  Layer 3: Sonnet Analysis  (~$0.50/location, ~3s)        │
│  Deep reasoning + 95% CONFIDENCE GATE                   │
│  Model: claude-sonnet-4-6                               │
│  confidence < 0.95 → suppressed (never reported)        │
└─────────────────────────┬────────────────────────────────┘
                          │ Confirmed vulnerabilities
                          ▼
┌──────────────────────────────────────────────────────────┐
│  Layer 4: Patch Generator (optional)                    │
│  3 patch candidates → scored → best selected            │
│  Tested in Docker sandbox (--network=none, read-only)   │
└──────────────────────────────────────────────────────────┘
```

---

## The 95% Confidence Rule

**Only findings with confidence ≥ 0.95 are reported.** This is non-negotiable.

```python
if vulnerability.confidence >= 0.95:
    output_finding(vulnerability)   # Reported
else:
    log_low_confidence(vulnerability)  # Suppressed — never shown
```

Prevents false positives. Builds user trust. Every line of code follows this rule.

---

## CLI Reference

### `swift scan` — Find vulnerabilities

```bash
python main.py scan --repo <path> [options]

Options:
  --repo PATH          Repository to scan (required)
  --output [json|markdown]  Output format (default: json)
  --patches            Generate patches after scanning
  --out-file PATH      Write output to file instead of stdout
```

### `swift patch` — Scan + auto-fix

```bash
python main.py patch --repo <path> [options]

Options:
  --repo PATH          Repository to scan and patch (required)
  --output [json|markdown]  Output format (default: json)
  --out-file PATH      Write to file
```

### `swift validate` — Validate a patch

```bash
python main.py validate --patch-id PATCH-001
```

---

## Vulnerability Categories Detected

| Category | Example Pattern |
|----------|----------------|
| SQL Injection | `f"SELECT * FROM users WHERE id={user_id}"` |
| Command Injection | `os.system(user_input)`, `subprocess.run(..., shell=True)` |
| Hardcoded Secrets | `password = "my_secret"`, `api_key = "sk-..."` |
| Weak Cryptography | `hashlib.md5()`, `hashlib.sha1()` |
| Unsafe Deserialization | `pickle.loads(data)` |

---

## Output Formats

### JSON (for APIs / dashboards)

```json
{
  "scan": {
    "id": "SCAN-a1b2c3d4",
    "repo_path": "/path/to/repo",
    "duration_seconds": 12.3,
    "total_cost_usd": 0.42,
    "timestamp": "2026-04-19T10:00:00+00:00"
  },
  "summary": {
    "files_scanned": 45,
    "vulnerabilities_found": 3,
    "by_severity": { "critical": 1, "high": 2, "medium": 0, "low": 0 },
    "patches_generated": 3
  },
  "vulnerabilities": [...],
  "patches": [...]
}
```

### Markdown (for reports / PRs)

```markdown
# SWIFT Vulnerability Report

- **Repository:** /path/to/repo
- **Duration:** 12.3s
- **Cost:** $0.4200

## Summary
- **Files scanned:** 45
- **Vulnerabilities found:** 3

## Vulnerabilities
### sql_injection — SWIFT-001 [CRITICAL]
- **File:** `app.py:42`
- **Confidence:** 97%
...
```

---

## Docker Sandbox Safety

Every patch is tested in a fully isolated container:

| Property | Value |
|----------|-------|
| Network | `--network=none` (no outbound) |
| Filesystem | Read-only (except `/tmp`) |
| CPU | 2 cores max |
| RAM | 2 GB max |
| Timeout | 30 seconds (hard kill) |

---

## Cost Model

```
100 files scanned:

Without SWIFT triage:   Sonnet on all → ~$50
With SWIFT pipeline:    Haiku $5 + Sonnet on 10 flagged locs $5 → $10

Savings: 80%
Typical scan cost: <$2
```

---

## Testing

```bash
# Unit + integration (no API key needed — all mocked)
pytest test/unit/ test/integration/ -v

# Coverage report
pytest test/unit/ test/integration/ --cov=. --cov-report=term-missing

# E2E (requires real API key)
SWIFT_RUN_E2E=1 pytest test/e2e/ -v
```

### Test Matrix

| Suite | Files | Tests | API? |
|-------|-------|-------|------|
| Unit | `test/unit/` | 97 | No (mocked) |
| Integration | `test/integration/` | 42 | No (mocked) |
| E2E | `test/e2e/` | 7 | Yes |

---

## Project Structure

```
swift/
├── agent/              # Orchestrator + data models
│   ├── models.py       # Vulnerability, Patch, ScanResult, TestResult
│   └── orchestrator.py # scan_codebase(), generate_patches()
├── scanners/           # Two-stage AI scanning
│   ├── haiku_scanner.py    # Stage 1: fast triage (~50ms/file)
│   └── sonnet_scanner.py   # Stage 2: 95% confidence gate (~3s/loc)
├── triage/             # Regex pre-filter (zero cost)
│   └── patterns.py
├── patches/            # Patch generation
│   └── generator.py    # 3 candidates → score → best
├── sandbox/            # Docker isolated testing
│   └── docker_runner.py
├── cli/                # Click CLI commands
│   └── commands.py
├── output/             # Formatters
│   └── formatters.py   # JSONFormatter, MarkdownFormatter
├── config/             # Config management
│   └── settings.py
├── log/                # Structured logging + metrics
│   └── logger.py
├── test/               # Full test suite
│   ├── unit/           # 97 tests, no API
│   ├── integration/    # 42 tests, no API
│   └── e2e/            # 7 tests, real API
└── main.py             # Entry point
```

---

## GitHub Issues

Track all work at [jellaharshith/SWIFT/issues](https://github.com/jellaharshith/SWIFT/issues).

| Issue | Description |
|-------|-------------|
| #1 | Data Models |
| #2 | Logging Infrastructure |
| #3 | Regex Triage |
| #4 | Haiku Scanner |
| #5 | Sonnet Scanner 95% Gate |
| #6 | MVP Complete — Tasks 7-13 |
