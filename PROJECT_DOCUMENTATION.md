# SWIFT — Project Documentation

**Version:** 0.1.0  
**Last Updated:** 2026-04-21  
**Status:** Phase 2 Complete · Phase 3 Ready  
**Tests:** 234/234 passing  
**Repository:** https://github.com/jellaharshith/SWIFT

---

## Table of Contents

1. [What is SWIFT?](#1-what-is-swift)
2. [How It Works — Pipeline Overview](#2-how-it-works--pipeline-overview)
3. [Architecture](#3-architecture)
4. [Module Reference](#4-module-reference)
5. [API Reference (Web)](#5-api-reference-web)
6. [CLI Reference](#6-cli-reference)
7. [Data Models](#7-data-models)
8. [Configuration & Environment Variables](#8-configuration--environment-variables)
9. [Security Controls](#9-security-controls)
10. [Installation & Setup](#10-installation--setup)
11. [Testing](#11-testing)
12. [Deployment](#12-deployment)
13. [Phase Roadmap](#13-phase-roadmap)
14. [Known Security Findings](#14-known-security-findings)
15. [Performance Baselines](#15-performance-baselines)
16. [Contributing](#16-contributing)

---

## 1. What is SWIFT?

SWIFT (**Secure Workflow Intelligence for Threat-Finding**) is an AI-powered security scanner that automatically audits codebases for vulnerabilities, constructs multi-step exploit chains, generates minimal patches, and validates them in an isolated Docker sandbox — all through a CLI or a FastAPI web service.

### Core Differentiators

| Feature | What it does |
|---------|-------------|
| **Two-stage AI analysis** | Cheap Haiku model for fast triage, Sonnet for deep reasoning |
| **Exploit chain detection** | Identifies multi-step attack paths, not just isolated findings |
| **Patch generation** | Produces 3 candidate patches per vulnerability and scores them |
| **Sandbox validation** | Tests patches in a Docker container with no network and read-only FS |
| **Forensic audit log** | Append-only, SHA-256 hash-chained log of every action |
| **SARIF output** | Integrates directly with GitHub Advanced Security |
| **Cost discipline** | Full scan of a medium codebase costs $0.50–$2.00 in API calls |

---

## 2. How It Works — Pipeline Overview

```
User Input (repo path or GitHub URL)
        │
        ▼
┌─────────────────────────────────────────┐
│  Phase 1 — Regex Triage  (~$0, <1s)     │
│  Walk all .py/.ts/.js/.tsx/.jsx files   │
│  Match 20+ security patterns per lang   │
│  Output: { file → [flagged line nos] }  │
└─────────────────┬───────────────────────┘
                  │ (only flagged files)
                  ▼
┌─────────────────────────────────────────┐
│  Phase 2 — Haiku Scan  (~$0.05/file)    │
│  Fast LLM confirmation of flagged lines │
│  Batched in groups of 50 files          │
│  Output: { file → (source, [lines]) }   │
└─────────────────┬───────────────────────┘
                  │ (confirmed signals)
                  ▼
┌─────────────────────────────────────────┐
│  Phase 3 — REVIEW_REQUIRED Findings     │
│  Convert each Haiku signal to a         │
│  Vulnerability(confidence=0.70,         │
│    status="REVIEW_REQUIRED")            │
│  Apply RiskScorer + SeverityRanker      │
└─────────────────┬───────────────────────┘
                  │ (top findings)
                  ▼
┌─────────────────────────────────────────┐
│  Phase 4 — Exploit Chain Analysis       │
│  VulnerabilityChainAuditor builds       │
│  a bounded capability graph with DFS    │
│  ExploitChainDetector (Sonnet) enhances │
│  chain narratives                       │
└─────────────────┬───────────────────────┘
                  │ (optional)
                  ▼
┌─────────────────────────────────────────┐
│  Phase 5 — Patch Generation             │
│  PatchGenerator (Sonnet) → 3 candidates │
│  Scored by minimal diff + reasoning     │
│  Best patch → DockerSandbox test        │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Output — JSON / Markdown / SARIF       │
│  Saved to file or returned via API      │
└─────────────────────────────────────────┘
```

### Confidence Gating

| Stage | Confidence Threshold | Label |
|-------|---------------------|-------|
| Haiku signal | 0.70 | `REVIEW_REQUIRED` |
| Sonnet finding | ≥ 0.95 | `HIGH_CONFIDENCE_VULNERABILITY` |
| Exploit chain | ≥ 0.85 | Included in report |
| Patch generation | ≥ 0.90 | Patch generated |

---

## 3. Architecture

```
swift/
├── main.py                  ← Entry point (delegates to CLI)
│
├── cli/
│   └── commands.py          ← Click CLI: scan, patch, validate commands
│
├── agent/
│   ├── orchestrator.py      ← Main pipeline coordinator (scan_codebase)
│   ├── models.py            ← Data classes: Vulnerability, Patch, ScanResult, ExploitChain
│   ├── github_cloner.py     ← Validates + shallow-clones GitHub repos
│   └── vuln_chain_auditor.py← Deterministic bounded exploit graph (no LLM)
│
├── triage/
│   ├── patterns.py          ← Regex patterns for Python, JS/TS (20+ patterns each)
│   ├── ranking.py           ← RiskScorer + MAX_TRIAGE_FINDINGS cap
│   ├── severity_ranker.py   ← SeverityRanker for chain scoring
│   └── exploit_graph.py     ← Capability graph, bounded DFS, memory guards
│
├── scanners/
│   ├── haiku_scanner.py     ← HaikuTriageScanner (Anthropic claude-haiku)
│   └── sonnet_scanner.py    ← SonnetAnalysisScanner (Anthropic claude-sonnet)
│
├── chains/
│   └── detector.py          ← ExploitChainDetector: LLM-enhanced chain analysis
│
├── patches/
│   └── generator.py         ← PatchGenerator: 3 candidates → scored → best patch
│
├── sandbox/
│   └── docker_runner.py     ← DockerSandbox: isolated patch testing
│
├── security/
│   ├── permissions.py       ← PermissionLayer + Permission enum
│   ├── logging.py           ← ForensicLogger (append-only, SHA-256 hash chain)
│   └── safety_monitor.py    ← AISafetyMonitor (keyword/regex heuristics)
│
├── server/
│   └── mcp_server.py        ← MCPServer wiring all tools with permissions + logging
│
├── tools/
│   ├── semgrep_tool.py      ← subprocess semgrep with ruleset allowlist
│   ├── nmap_tool.py         ← subprocess nmap with strict flag allowlist
│   ├── sandbox_tool.py      ← subprocess Docker with constraints
│   ├── cuckoo_tool.py       ← requests to Cuckoo sandbox API
│   └── git_integrity_tool.py← subprocess git (no shell=True)
│
├── web/
│   ├── app.py               ← FastAPI application (routes, OAuth, scan jobs)
│   ├── storage.py           ← SQLAlchemy models (ScanJob, ScanRecord) + auto-migration
│   ├── oauth.py             ← GitHub OAuth (httpx, no external OAuth libs)
│   └── notifications.py     ← smtplib email on scan completion
│
├── output/
│   ├── formatters.py        ← JSONFormatter, MarkdownFormatter
│   ├── sarif.py             ← SARIF 2.1.0 export
│   └── chains.py            ← ChainsFormatter for exploit chain JSON
│
├── config/
│   └── settings.py          ← Config dataclass + get_config() / reset_config()
│
├── log/
│   └── logger.py            ← get_logger(), MetricsCollector, JSON file log
│
├── utils/
│   └── json_safe.py         ← safe_parse_json helpers (non-throwing)
│
└── test/
    ├── unit/                ← 188 unit tests (mocked Anthropic API)
    ├── integration/         ← 46 integration tests (full pipeline, mocked)
    └── e2e/                 ← Optional full scans on real vulnerable app
```

---

## 4. Module Reference

### `agent/orchestrator.py` — `scan_codebase()`

The central entry point for all scans.

```python
def scan_codebase(
    repo_path: str,
    generate_patches_flag: bool = False,
    progress_callback: Optional[Callable[[dict], None]] = None,
) -> ScanResult
```

**Parameters:**
- `repo_path` — absolute path to the local repository root
- `generate_patches_flag` — if `True`, invokes PatchGenerator + DockerSandbox after analysis
- `progress_callback` — optional callback receiving progress dicts (used by the web API for live status)

**Progress payload keys:** `stage`, `stage_name`, `files_total`, `files_scanned`, `current_file`, `progress` (0–100), `signals_detected`, `batch_current`, `batch_total`, `chain_stage`, `chain_nodes`, `chain_edges`, `chain_candidates`, `ranked_chains`, `resource_limited`, `resource_limit_reason`

---

### `triage/patterns.py` — `triage_codebase()`

Zero-cost local regex scan over all supported source files.

**Supported extensions:** `.py`, `.ts`, `.tsx`, `.js`, `.jsx`, `.c`, `.cpp`, `.cc`, `.h`

**Skipped directories:** `node_modules`, `__pycache__`, `.git`, `dist`, `build`, `.next`, `coverage`

**Python patterns detected:**
- `sql_injection_fstring` — f-string SQL queries
- `sql_injection_concat` — string concatenation in SQL
- `command_injection_os_system` — `os.system()` calls
- `command_injection_subprocess_shell` — `subprocess.run(..., shell=True)`
- `hardcoded_password` — `password = "..."` literals
- `hardcoded_api_key` — `api_key = "..."` literals
- `weak_crypto_md5` — `hashlib.md5()`
- `unsafe_pickle` — `pickle.loads()`

**JS/TS patterns detected:**
- `xss_dangerous_html` — `dangerouslySetInnerHTML`
- `xss_inner_html` — `.innerHTML =`
- `xss_document_write` — `document.write()`
- `prompt_injection_template` — user data in AI system prompts
- `cors_wildcard` — `Access-Control-Allow-Origin: *`
- `hardcoded_api_key_js` — inline token/secret literals
- `eval_usage` — `eval()`
- `function_constructor` — `new Function()`
- `node_exec` — template-literal shell commands
- `prototype_pollution` — `__proto__` / `constructor.prototype`
- `open_redirect` — user-controlled `window.location`
- `math_random_security` — `Math.random()` for tokens/sessions
- `error_leak` — `err.message` / `err.stack` sent to client
- `vite_secret_exposure` — `VITE_SECRET`, `VITE_TOKEN`, etc. in frontend bundle

---

### `agent/github_cloner.py` — `clone_repo()`

Validates a GitHub URL against a strict regex and performs a `git clone --depth 1`.

```python
def clone_repo(url: str) -> Tuple[str, Callable[[], None]]
# Returns: (local_path, cleanup_callable)
```

**Accepted formats:**
- `https://github.com/owner/repo` (optional `.git`, optional trailing `/`)
- `git@github.com:owner/repo` (optional `.git`)

**Timeout:** 120 seconds. The returned cleanup callable removes the temp directory.

---

### `security/logging.py` — `ForensicLogger`

Append-only, tamper-evident audit log. Every tool invocation is recorded as a `LogEntry` with a SHA-256 hash of itself chained to the previous entry's hash.

```python
logger = ForensicLogger("log/audit_mcp_tools.json")
logger.log_action(tool_name, action, inputs, outputs, status)
logger.verify_integrity()  # → bool
logger.get_integrity_report()  # → {"total_entries", "verified", "tampered_entries"}
```

---

### `security/permissions.py` — `PermissionLayer`

Centralized gate for all tool operations.

```python
class Permission(Enum):
    SCAN_REPO = "scan_repo"
    GENERATE_PATCH = "generate_patch"
    RUN_SANDBOX = "run_sandbox"
    NETWORK_SCAN = "network_scan"
    CUCKOO_ANALYSIS = "cuckoo_analysis"
    GIT_INTEGRITY = "git_integrity"
```

---

### `sandbox/docker_runner.py` — `DockerSandbox`

Runs a patched file inside a Docker container with:
- No network (`network_disabled=True`)
- Read-only filesystem (except a `/tmp` tmpfs)
- Memory limit from `SWIFT_SANDBOX_MEMORY`
- Timeout from `SWIFT_SANDBOX_TIMEOUT`

---

### `tools/nmap_tool.py` — `NmapTool`

Safe nmap wrapper with strict input validation:
- `target` — validated against `^[\w.\-/:]+$`, max 255 chars
- `ports` — validated against `^[\d,\-]+$`
- `host_timeout` — validated against `^\d+[smh]?$`
- Command is built internally; no freeform flag injection possible
- `BLOCKED_PATTERNS`: `--script`, `-sC`, `exploit`, `vuln`, `--script-args`, `-NSE`

---

## 5. API Reference (Web)

Base URL (production): `https://swift-scanner.fly.dev`

### Authentication

Most endpoints are currently **unauthenticated** (see [Known Security Findings](#14-known-security-findings)). The `/repos` endpoint accepts either:
- `Authorization: Bearer <github_access_token>` header
- `session_id` cookie set after GitHub OAuth

---

### `GET /`

Health check.

**Response:**
```json
{ "status": "ok", "service": "SWIFT Scanner" }
```

---

### `GET /metrics`

Aggregate scan metrics.

**Response:**
```json
{
  "total_scans": 42,
  "total_vulns": 187,
  "total_cost_usd": 12.34,
  "avg_duration_seconds": 43.5
}
```

---

### `GET /scans?limit=50&offset=0`

Paginated list of completed scans, ordered by timestamp descending.

---

### `GET /scan/{scan_id}`

Single scan record with full `raw_json` blob.

---

### `GET /scan/{scan_id}/report/json`

Download the scan as a formatted JSON report (`Content-Disposition: attachment`).

---

### `GET /scan/{scan_id}/report/markdown`

Download the scan as a Markdown report.

---

### `POST /scan`

Trigger an async scan job.

**Request body:**
```json
{
  "repo": "https://github.com/owner/repo",
  "patches": false
}
```

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
}
```

---

### `GET /scan/{scan_id}/status`

Live progress for an in-flight job.

**Response:**
```json
{
  "status": "running",
  "progress": 45,
  "stage": 2,
  "stage_name": "haiku",
  "files_total": 120,
  "files_scanned": 54,
  "batch_current": 2,
  "batch_total": 3,
  "signals_detected": 12,
  "current_file": "app.py",
  "findings": [...],
  "chain_stage": "graph_build",
  "chain_nodes": 8,
  "chain_edges": 5,
  "chain_candidates": 3,
  "ranked_chains": 0,
  "resource_limited": false,
  "resource_limit_reason": "",
  "started_at": "2026-04-21T10:00:00+00:00",
  "detail": null,
  "scan_id": null
}
```

---

### `GET /auth/github?redirect_uri=<uri>`

Returns the GitHub OAuth authorization URL.

**Response:**
```json
{ "auth_url": "https://github.com/login/oauth/authorize?..." }
```

---

### `GET /auth/callback?code=<code>&redirect_uri=<uri>`

Exchanges GitHub OAuth code for token, sets `session_id` cookie, redirects to Netlify frontend.

---

### `GET /repos`

Lists the authenticated user's GitHub repositories (requires auth).

---

### `GET /dashboard`

HTML dashboard showing aggregate metrics and recent scans (server-rendered via Jinja2).

---

## 6. CLI Reference

```bash
# Install
cd SWIFT/swift
pip install -e .

# Basic scan
swift scan --repo /path/to/code

# Scan GitHub repo
swift scan --repo https://github.com/owner/repo

# With output format
swift scan --repo /path/to/code --output json > report.json
swift scan --repo /path/to/code --output markdown > report.md
swift scan --repo /path/to/code --output sarif > report.sarif

# Generate patches
swift scan --repo /path/to/code --patches

# Custom confidence threshold
swift scan --repo /path/to/code --confidence 0.85

# Custom timeout
swift scan --repo /path/to/code --timeout 600
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--repo` | required | Local path or GitHub URL |
| `--output` | `json` | `json`, `markdown`, or `sarif` |
| `--patches` | `false` | Generate and sandbox-test patches |
| `--confidence` | `0.95` | Minimum confidence to report a finding |
| `--timeout` | `300` | Max seconds for full scan |

---

## 7. Data Models

### `Vulnerability`

```python
@dataclass
class Vulnerability:
    id: str                  # e.g. "SIGNAL-a1b2c3d4"
    file_path: str
    line_number: int
    vuln_type: str           # e.g. "sql_injection_fstring"
    description: str
    confidence: float        # 0.0 – 1.0
    severity: str            # "low" | "medium" | "high" | "critical"
    code_snippet: str
    status: str              # "REVIEW_REQUIRED" | "HIGH_CONFIDENCE_VULNERABILITY"
    cwe_id: Optional[str]    # e.g. "CWE-89"
    exploit_description: Optional[str]
    remediation: Optional[str]
```

### `Patch`

```python
@dataclass
class Patch:
    id: str                  # e.g. "PATCH-001"
    vuln_id: str
    file_path: str
    original_code: str
    patched_code: str
    diff: str                # unified diff
    confidence: float
    reasoning: Optional[str]
    sandbox_tested: bool
    test_passed: Optional[bool]
    test_logs: Optional[str]
```

### `ExploitChain`

```python
@dataclass
class ExploitChain:
    id: str
    title: str
    steps: List[AttackStep]  # ordered attack steps
    severity: str
    confidence: float
    vuln_ids: List[str]      # participating vulnerability IDs
    narrative: Optional[str] # LLM-generated prose description
```

### `AttackStep`

```python
@dataclass
class AttackStep:
    step_number: int
    description: str
    vuln_id: str
    capability: str          # e.g. "read_file", "exec_command"
```

### `ScanResult`

```python
@dataclass
class ScanResult:
    scan_id: str             # e.g. "SCAN-a1b2c3d4"
    repo_path: str
    files_scanned: int
    vulnerabilities: List[Vulnerability]
    patches: List[Patch]
    exploit_chains: List[ExploitChain]
    duration_seconds: float
    total_cost_usd: float
    timestamp: str           # ISO 8601
```

---

## 8. Configuration & Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic API key (`sk-ant-...`) |

### Optional — Scanner

| Variable | Default | Description |
|----------|---------|-------------|
| `SWIFT_CONFIDENCE_THRESHOLD` | `0.95` | Minimum confidence for Sonnet findings |
| `SWIFT_CHAIN_CONFIDENCE_THRESHOLD` | `0.85` | Minimum confidence for exploit chains |
| `SWIFT_MAX_FILE_SIZE` | `104857600` | Max file size in bytes (100 MB) |
| `SWIFT_LOG_LEVEL` | `INFO` | Logging level |
| `SWIFT_ENABLE_PATCHES` | `true` | Toggle patch generation |

### Optional — Sandbox

| Variable | Default | Description |
|----------|---------|-------------|
| `SWIFT_SANDBOX_TIMEOUT` | `30` | Docker container timeout (seconds) |
| `SWIFT_SANDBOX_MEMORY` | `2000000000` | Container memory limit (bytes, 2 GB) |

### Optional — Web / API

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | _(SQLite fallback)_ | PostgreSQL connection string (Railway) |
| `SWIFT_DB_PATH` | `./swift_scans.db` | SQLite path when `DATABASE_URL` not set |
| `NETLIFY_ORIGIN` | `https://swiftscanner.netlify.app` | Allowed CORS origin |
| `GITHUB_CLIENT_ID` | _(empty)_ | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | _(empty)_ | GitHub OAuth app client secret |
| `SWIFT_LOCAL_SCAN_BASE` | _(empty)_ | Base directory for local path scanning (security control) |

### Optional — Notifications

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | `smtp.gmail.com` | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | _(empty)_ | SMTP username |
| `SMTP_PASS` | _(empty)_ | SMTP password |
| `FROM_EMAIL` | _(SMTP_USER)_ | From address for notifications |

### Optional — MCP Tools

| Variable | Description |
|----------|-------------|
| `CUCKOO_API_KEY` | Bearer token for Cuckoo sandbox API |
| `CUCKOO_BASE_URL` | Cuckoo API base URL |

---

## 9. Security Controls

### Permission Layer

All tool invocations pass through `PermissionLayer.check_permission(Permission.X)`. Unauthorized calls raise `PermissionDenied` and are recorded in the forensic log.

### Forensic Audit Log

Every tool action is persisted to `log/audit_mcp_tools.json` as a tamper-evident chain:

```
Entry N → SHA256(entry_N_data + previous_hash) → stored as current_hash
Entry N+1 → SHA256(entry_N+1_data + entry_N.current_hash) → ...
```

Call `ForensicLogger.verify_integrity()` to detect any tampering.

### AI Safety Monitor

`AISafetyMonitor` applies regex/keyword heuristics to detect:
- Privilege escalation attempts in LLM output
- Hidden reasoning or chain-of-thought leakage
- Unauthorized tool invocation language

### Docker Sandbox

Patch testing is fully isolated:
- No network access
- Read-only base filesystem
- `tmpfs` at `/tmp` only
- Resource-limited (memory + CPU)
- Killed after `SWIFT_SANDBOX_TIMEOUT` seconds

### Nmap Tool Hardening

The `NmapTool` builds the command internally from a fixed set of safe flags. Users cannot inject arbitrary nmap flags. NSE scripts, exploit modules, and vulnerability detection plugins are permanently blocked.

---

## 10. Installation & Setup

### Prerequisites

- Python ≥ 3.10
- Git
- Docker (only required for `--patches` flag)
- Anthropic API key

### Steps

```bash
# 1. Clone
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirement.txt

# 4. Install CLI
pip install -e .

# 5. Configure
cp .env.example .env
# Edit .env and set: ANTHROPIC_API_KEY=sk-ant-...

# 6. Verify
pytest test/unit/ -q
# Expected: 188 passed
```

### Running the Web API locally

```bash
cd SWIFT/swift
source .venv/bin/activate
uvicorn web.app:app --host 0.0.0.0 --port 8000 --reload
```

Open `http://localhost:8000` for the health check, `http://localhost:8000/dashboard` for the UI.

---

## 11. Testing

### Test Structure

```
test/
├── conftest.py              ← Shared fixtures (Anthropic mock, sample vulns)
├── unit/                    ← 188 tests — isolated module logic
│   ├── test_triage.py
│   ├── test_haiku_scanner.py
│   ├── test_sonnet_scanner.py
│   ├── test_chain_detector.py
│   ├── test_permissions.py
│   ├── test_forensic_logging.py
│   ├── test_safety_monitor.py
│   ├── test_patch_generator.py
│   ├── test_docker_runner.py
│   ├── test_output_formatters.py
│   ├── test_cli.py
│   └── test_orchestrator.py
├── integration/             ← 46 tests — full pipeline, mocked API
│   ├── test_full_pipeline.py
│   ├── test_github_integration.py
│   └── test_patch_with_sandbox.py
└── e2e/
    ├── test_real_scan.py    ← Optional: real Anthropic API call
    └── test_repo/
        └── app.py           ← Deliberately vulnerable app (SQL injection, pickle, shell=True, etc.)
```

### Running Tests

```bash
# All tests
pytest test/ -v

# Unit only
pytest test/unit/ -v

# Integration only
pytest test/integration/ -v

# With coverage
pytest test/ --cov=swift --cov-report=html

# Single test
pytest test/unit/test_sonnet_scanner.py::test_confidence_gate -v

# With debug logging
PYTHONPATH=. pytest test/ -v -s --log-cli-level=DEBUG
```

### Test Results (as of 2026-04-20)

| Suite | Tests | Status |
|-------|-------|--------|
| Unit | 188 | ✅ All passing |
| Integration | 46 | ✅ All passing |
| **Total** | **234** | **✅ All passing** |

---

## 12. Deployment

### Production (Fly.io)

```bash
# Deploy
fly deploy

# View logs
fly logs -a swift-scanner

# Check status
fly status -a swift-scanner
```

**Config:** `min_machines_running=1`, `auto_start=true`, `auto_stop=true`

**Note:** Free-trial machines are killed after 5 minutes. Add a credit card at `fly.io/dashboard/.../billing` to remove the kill timer (Hobby tier is free for low traffic).

### Railway (alternative)

```bash
railway init
railway up
```

Set `DATABASE_URL` to Railway's PostgreSQL URL in the Railway dashboard.

### Environment Variables (production)

Set the following in the Fly.io / Railway dashboard (never commit to git):

```
ANTHROPIC_API_KEY=sk-ant-...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
NETLIFY_ORIGIN=https://swiftscanner.netlify.app
DATABASE_URL=postgresql://...   # (Railway provides this automatically)
```

---

## 13. Phase Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ Complete | Exploit chain detection, language-aware prompts, chain data model |
| **Phase 2** | ✅ Complete | Permission layer, forensic audit log, AI safety monitor |
| **Phase 3** | 🚀 In Progress | Evidence bundle (SARIF, CWE, remediation), `/evidence` API endpoint |
| **Phase 4** | 📋 Planned | Performance optimization, GitHub App integration, PR comments |

### Phase 3 — Evidence Bundle (Planned)

- `findings.json` with CWE IDs, exploit descriptions, remediation steps
- `exploit_chains.json` as a standalone export
- SARIF 2.1.0 format for GitHub Advanced Security
- Enhanced triage ranking (severity × exploitability × confidence × business impact)
- Patch diffs with sandbox test results embedded
- `GET /scan/{id}/evidence` API endpoint

---

## 14. Known Security Findings

The following vulnerabilities were identified during an internal security audit (2026-04-21). They are tracked for remediation.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | **CRITICAL** | Path traversal — `POST /scan` accepts arbitrary local paths | Open |
| 2 | **CRITICAL** | No authentication on `POST /scan` | Open |
| 3 | **HIGH** | OAuth CSRF — no `state` parameter generated or verified | Open |
| 4 | **HIGH** | User-controlled `redirect_uri` forwarded to GitHub OAuth | Open |
| 5 | **HIGH** | Prompt injection via adversarial repository source code | Open |
| 6 | **MEDIUM** | No rate limiting on any public endpoint | Open |

### Finding 1 — Path Traversal (CRITICAL)

**Location:** `web/app.py:221–224`

**Issue:** When `repo` doesn't start with `https://github.com/` or `git@github.com:`, it is used directly as a local filesystem path with no validation. An attacker can send `{"repo": "/etc"}` and the scanner will walk and read files from that path.

**Recommended fix:** Add a Pydantic validator on `ScanRequest.repo` that either rejects non-GitHub URLs outright, or enforces that local paths fall under `SWIFT_LOCAL_SCAN_BASE`.

### Finding 2 — Unauthenticated Scan Trigger (CRITICAL)

**Location:** `web/app.py:287–292`

**Issue:** `POST /scan` has no authentication check. Any actor can trigger unlimited scans, burning Anthropic API credits and exhausting compute.

**Recommended fix:** Add a `Depends(_require_auth)` dependency to the route.

### Finding 3 — OAuth CSRF (HIGH)

**Location:** `web/oauth.py:37–42`, `web/app.py:331–347`

**Issue:** No `state` parameter is generated when building the auth URL, and the callback never validates one. This enables CSRF attacks that can steal GitHub OAuth tokens.

**Recommended fix:** Generate `secrets.token_urlsafe(32)` as `state`, store server-side, verify in callback.

### Finding 4 — Unvalidated redirect_uri (HIGH)

**Location:** `web/app.py:327–328`

**Issue:** `redirect_uri` query parameter is user-supplied and forwarded verbatim to GitHub's OAuth endpoint with no server-side allowlist check.

**Recommended fix:** Validate `redirect_uri` against a hardcoded allowlist before forwarding.

### Finding 5 — Prompt Injection (HIGH)

**Location:** `patches/generator.py:131–137`, `agent/orchestrator.py:131–148`

**Issue:** Raw source code from the scanned repository is embedded directly into LLM prompts. A malicious file containing `IGNORE ALL PREVIOUS INSTRUCTIONS` can manipulate scan output.

**Recommended fix:** Wrap code snippets in a clearly delimited block (e.g., XML tags) and add a system-level instruction to treat the block as untrusted data.

### Finding 6 — No Rate Limiting (MEDIUM)

**Location:** `web/app.py` (all routes)

**Issue:** No rate limiting middleware. All endpoints are freely callable at any rate.

**Recommended fix:** Add `slowapi` or a similar FastAPI rate-limiting middleware; apply stricter limits to `POST /scan`.

---

## 15. Performance Baselines

| Operation | Time | Cost | Notes |
|-----------|------|------|-------|
| Triage 1 file (100 lines) | ~1 ms | $0.00 | Pure local regex |
| Haiku scan 1 file | ~50 ms | $0.05 | Single API call |
| Sonnet analysis 1 finding | ~3 s | $0.50 | Deep reasoning |
| Chain detection (5 vulns) | ~2 s | $0.10 | Graph + LLM enhancement |
| Patch generation (1 vuln) | ~20 s | $0.20 | 3 candidates + scoring |
| Full scan (10K lines) | ~5 min | $0.50–$2.00 | Depends on vuln density |

### Cost Breakdown (typical medium codebase)

```
Regex triage:    $0.00  (free)
Haiku scan:      $0.25  (5 batches × ~10 files × $0.05)
Sonnet analysis: $0.50  (1 finding deep analysis)
Chain detection: $0.10
Patch gen:       $0.20  (1 patch)
─────────────────────
Total:           ~$1.05
```

---

## 16. Contributing

### Git Workflow

```bash
# 1. Create feature branch
git checkout -b feature/issue-123-description

# 2. Make changes, run tests
pytest test/ -v

# 3. Commit with issue reference
git commit -m "feat: add feature X

Fixes #123"

# 4. Push + open PR
git push origin feature/issue-123-description
```

### Issue Tracking

Use GitHub Issues as the single source of truth. Every meaningful piece of work — features, bugs, security findings, technical debt — should have an issue.

**Issue prefixes:**
- `Feature:` — new capability
- `Bug:` — something broken
- `Security:` — vulnerability or security improvement
- `Docs:` — documentation gap
- `Refactor:` — internal improvement without behavior change

### Code Standards

- Python ≥ 3.10 syntax
- Type hints on all public functions
- Google-style docstrings with Args / Returns / Raises
- PEP 8 formatting
- Relative imports within the `swift` package
- No `datetime.utcnow()` — use `datetime.now(timezone.utc)`

### Adding a New Vulnerability Pattern

```python
# 1. Add regex to triage/patterns.py
_PYTHON_PATTERNS["my_new_pattern"] = re.compile(r'your_regex', re.IGNORECASE)

# 2. Add a unit test in test/unit/test_triage.py
def test_my_new_pattern():
    assert triage_file("fixtures/file_with_pattern.py") == {line_number}
```

### Adding a New API Endpoint

```python
# web/app.py
@app.get("/my-endpoint")
def my_endpoint(db: Session = Depends(get_db)):
    # implement
    return {...}
```

---

*Generated by SWIFT Secure-by-Design Remediation Agent · 2026-04-21*
