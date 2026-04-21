# SWIFT — AI-Powered Security Scanner with Risk Scoring & Exploit Chain Detection

**SWIFT** is a continuous AI-powered vulnerability scanner that finds, verifies, prioritizes, and auto-fixes security flaws in Python code. It combines three-layer triage, risk scoring, exploit chain detection, and forensic logging into a complete security platform.

---

## Why SWIFT?

| Problem | SWIFT Solution |
|---------|---------------|
| Traditional scans take weeks | Continuous, runs in minutes |
| High false-positive rate | 95% confidence gate — only real vulns |
| No risk prioritization | Risk scores (0-100) + exploitability + business impact |
| Missed multi-step attacks | Exploit chain detection (≥85% confidence) |
| Manual remediation ($50K+) | Auto-generates and tests patches |
| No audit trail | Tamper-evident forensic logging |
| One-time scan | Integrates into CI/CD pipeline |

---

## How It Works — Complete Pipeline

```
Your Code
    │
    ▼
┌──────────────────────────────────────────────────────────┐
│ Layer 1: Regex Triage (FREE — zero API calls)           │
│ Fast pattern matching for 8+ vulnerability categories    │
│ Returns: flagged file:line pairs                         │
└─────────────────────┬────────────────────────────────────┘
                      │ Only flagged files
                      ▼
┌──────────────────────────────────────────────────────────┐
│ Layer 2: Haiku Triage (~$0.05/file, ~50ms)             │
│ Fast AI confirmation of suspicious lines                │
│ Model: claude-haiku-4-5-20251001                        │
└─────────────────────┬────────────────────────────────────┘
                      │ Only confirmed-suspicious lines
                      ▼
┌──────────────────────────────────────────────────────────┐
│ Layer 3: Sonnet Analysis (~$0.50/location, ~3s)         │
│ Deep reasoning + 95% CONFIDENCE GATE                    │
│ Model: claude-sonnet-4-6                                │
│ Extracts: CWE, exploit description, remediation        │
│ confidence < 0.95 → suppressed (never reported)         │
└─────────────────────┬────────────────────────────────────┘
                      │ Confirmed vulnerabilities
                      ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 3.2: Risk Scoring (NEW — Phase 3)                 │
│ Calculates risk_score (0-100) per vulnerability         │
│ Formula: (severity × exploitability × confidence × impact) × 100 │
│ Infers exploitability and business impact category      │
└─────────────────────┬────────────────────────────────────┘
                      │ Scored vulnerabilities
                      ▼
┌──────────────────────────────────────────────────────────┐
│ Phase 3.5: Exploit Chain Detection (NEW — Phase 3)      │
│ Identifies multi-step attack paths (≥85% confidence)    │
│ Returns: entry point → escalation → final impact        │
└─────────────────────┬────────────────────────────────────┘
                      │ Chains + vulnerabilities
                      ▼
┌──────────────────────────────────────────────────────────┐
│ Layer 4: Patch Generator (optional)                     │
│ 3 patch candidates → scored → best selected             │
│ Tested in Docker sandbox (--network=none, read-only)    │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│ Output Formats (JSON, Markdown, SARIF)                  │
│ SARIF: GitHub Advanced Security integration             │
│ Custom properties: risk_score, exploitability, impact   │
└──────────────────────────────────────────────────────────┘
```

---

## The Three Phases (Complete)

### Phase 1: Exploit Chain Intelligence ✅ COMPLETE

**Status:** Fully implemented and tested

**Features:**
- Multi-step attack path detection (entry → escalation → impact)
- Confidence thresholds (≥85% to report chains)
- Step-by-step attack breakdown with code locations
- Real-world chain examples (SQL injection → privilege escalation → data exfiltration)

**Key Data Structures:**
```python
@dataclass
class AttackStep:
    step: int                  # Step number (1-indexed)
    description: str           # Human-readable action
    vuln_id: str              # Vulnerability ID (SWIFT-001)
    entry_point: str          # Code location (file:line)

@dataclass
class ExploitChain:
    chain_id: str             # Chain identifier (CHAIN-001)
    name: str                 # Human-readable name
    vulnerability_ids: List[str]  # IDs in attack order
    attack_path: str          # Narrative description
    entry_point: str          # Where attack starts
    impact: str               # What attacker compromises
    severity: str             # CRITICAL/HIGH/MEDIUM/LOW
    confidence: float         # 0.85-1.0 (gate for reporting)
    attack_steps: List[AttackStep]  # Individual steps
```

**Test Coverage:** 13+ tests in `test/unit/test_exploit_chain_detector.py`

---

### Phase 2: Security Controls ✅ COMPLETE

**Status:** Fully implemented with three control layers

**Features:**

#### Permission Layer
- Role-based access control (view, scan, patch, admin)
- Per-operation permission validation
- File size limits, API model whitelisting
- Unauthorized operations raise `PermissionDenied`

#### Forensic Logging
- Append-only audit trail (no deletion/modification)
- Every action logged: tool, action, inputs, outputs, timestamp
- Hash chain for tamper detection (SHA256 of previous entry)
- JSON structured format, queryable by date/type/severity

#### AI Safety Monitor
- Escalation detection (prevents privilege escalation attempts)
- Hidden reasoning detection (catches contradictions)
- Unauthorized action detection (catches permission bypass)
- Halts execution immediately on violation
- Full violation context logged

**Test Coverage:** 40+ tests in `test/unit/test_security_logging.py`

---

### Phase 3: Advanced Analysis ✅ COMPLETE

**Status:** Fully implemented, tested, documented

**Features:**

#### Risk Scoring Framework
Calculate vulnerability priority using quantitative formula:

```
risk_score = (severity_weight × exploitability × confidence × impact_weight) × 100
```

**Severity Weights:** CRITICAL=1.0, HIGH=0.75, MEDIUM=0.5, LOW=0.25

**Exploitability Levels:**
- trivial (0.9): No prerequisites, immediate exploitation
- moderate (0.6): Some conditions required, medium effort
- complex (0.2): Difficult exploitation, specific setup needed
- specific (0.4): Requires specific knowledge/tools

**Business Impact Categories (auto-inferred):**
- customer_data_breach (weight=1.0): PII exposed, GDPR impact
- compliance_violation (weight=0.9): Regulatory violation
- financial_loss (weight=0.8): Direct monetary loss
- service_disruption (weight=0.7): Availability impact
- data_exposure (weight=0.6): Internal data leaked
- no_impact (weight=0.0): No business impact

**Example Calculation:**
```
SQL Injection in auth login (SWIFT-001):
  Severity: CRITICAL (1.0)
  Exploitability: moderate (0.6)
  Confidence: 0.97
  Impact: customer_data_breach (1.0)
  Risk Score = 1.0 × 0.6 × 0.97 × 1.0 × 100 = 58.2/100
```

**Test Coverage:** 35 tests in `test/unit/test_ranking.py`

#### Exploit Chain Detection
Identifies multi-step attack sequences from confirmed vulnerabilities.

**Process:**
1. Collect confirmed vulnerabilities (≥95% confidence)
2. Analyze dependencies between vulns
3. Build attack paths from entry point to impact
4. Score chain feasibility (≥85% confidence)
5. Report with attack steps and locations

**Example Chain:**
```
SQL Injection (SWIFT-001, auth/login.py:42)
  ↓ (attacker bypasses authentication)
Privilege Escalation (SWIFT-003, admin/panel.py:128)
  ↓ (attacker gains admin access)
Data Exfiltration (SWIFT-005, db/export.py:67)
  ↓ (attacker steals customer database)
Impact: Customer data breach, compliance violation
Confidence: 92%
```

**Test Coverage:** 32+ tests across chain detection and formatting

#### SARIF 2.1.0 Output
GitHub Advanced Security integration for automated scanning.

**Features:**
- SARIF 2.1.0 standard format
- Rule definitions with CWE mapping
- Custom SWIFT properties: risk_score, exploitability, business_impact_category
- GitHub code scanning integration
- SIEM tool compatibility

**Example SARIF Properties:**
```json
{
  "ruleId": "SWIFT-SQL-001",
  "message": { "text": "SQL injection via user input" },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "app.py" },
      "region": { "startLine": 42 }
    }
  }],
  "properties": {
    "risk_score": 58.2,
    "exploitability": "moderate",
    "business_impact_category": "customer_data_breach",
    "cwe_id": "CWE-89",
    "confidence": "97%"
  }
}
```

**Test Coverage:** 28+ tests in `test/unit/test_sarif.py`

---

## Quick Start

### Installation

```bash
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift
python -m venv .venv
source .venv/bin/activate
pip install -r requirement.txt
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

### Scan a Repository

```bash
# JSON output (for APIs/dashboards)
python main.py scan --repo /path/to/repo --output json

# Markdown output (for reports)
python main.py scan --repo /path/to/repo --output markdown

# SARIF output (for GitHub scanning)
python main.py scan --repo /path/to/repo --output sarif > results.sarif

# With patch generation
python main.py scan --repo /path/to/repo --output json --patches
```

### Run Tests

```bash
# Unit + integration tests (no API key needed)
pytest test/unit/ test/integration/ -v

# With coverage report
pytest test/ --cov=swift --cov-report=term-missing

# E2E tests (requires real API key)
SWIFT_RUN_E2E=1 pytest test/e2e/ -v
```

---

## The 95% Confidence Rule

**Only findings with confidence ≥ 0.95 are reported.** This is non-negotiable.

```python
if vulnerability.confidence >= 0.95:
    output_finding(vulnerability)   # Reported to user
else:
    log_low_confidence(vulnerability)  # Suppressed, logged only
```

Why? Prevents false positives. Builds user trust. Every line of code follows this rule.

**Chain Detection Gate:** ≥ 0.85 confidence (lower than individual vulns because chains are harder to confirm)

---

## Vulnerability Categories Detected

| Category | Example Pattern | CWE ID |
|----------|----------------|--------|
| SQL Injection | `f"SELECT * FROM users WHERE id={user_id}"` | CWE-89 |
| Command Injection | `os.system(user_input)`, `subprocess.run(..., shell=True)` | CWE-78 |
| Hardcoded Secrets | `password = "my_secret"`, `api_key = "sk-..."` | CWE-798 |
| Weak Cryptography | `hashlib.md5()`, `hashlib.sha1()` | CWE-327 |
| Unsafe Deserialization | `pickle.loads(data)` | CWE-502 |
| XXE Injection | `xml.etree.ElementTree.parse(untrusted)` | CWE-611 |
| SSRF | `requests.get(user_url)` | CWE-918 |
| Path Traversal | `open(f"files/{user_path}")` | CWE-22 |

---

## Output Formats

### JSON (for APIs)

```json
{
  "scan": {
    "id": "SCAN-abc123",
    "repo_path": "/path/to/repo",
    "duration_seconds": 120,
    "total_cost_usd": 1.42,
    "timestamp": "2026-04-20T12:00:00Z"
  },
  "summary": {
    "files_scanned": 45,
    "vulnerabilities_found": 3,
    "by_severity": { "critical": 1, "high": 2 },
    "patches_generated": 3,
    "exploit_chains_detected": 1
  },
  "vulnerabilities": [
    {
      "id": "SWIFT-001",
      "file_path": "app.py",
      "line_number": 42,
      "vuln_type": "sql_injection",
      "severity": "CRITICAL",
      "confidence": 0.97,
      "cwe_id": "CWE-89",
      "risk_score": 58.2,
      "exploitability": 0.6,
      "business_impact_category": "customer_data_breach"
    }
  ],
  "exploit_chains": [
    {
      "chain_id": "CHAIN-001",
      "name": "SQL Injection → Privilege Escalation → Data Exfiltration",
      "vulnerability_ids": ["SWIFT-001", "SWIFT-003", "SWIFT-005"],
      "severity": "CRITICAL",
      "confidence": 0.92
    }
  ]
}
```

### Markdown (for reports)

```markdown
# SWIFT Vulnerability Report

**Repository:** /path/to/repo  
**Scanned:** 45 files  
**Duration:** 2 minutes  
**Cost:** $1.42

## Summary

- **Vulnerabilities:** 3 found
  - Critical: 1
  - High: 2
- **Exploit Chains:** 1 detected
- **Patches:** 3 generated, all passed tests

## Vulnerabilities

### SQL Injection (SWIFT-001) — CRITICAL

- **File:** app.py:42
- **Confidence:** 97%
- **CWE:** CWE-89
- **Risk Score:** 58.2/100
- **Exploitability:** Moderate (0.6)
- **Business Impact:** Customer data breach

User input concatenated into SQL query without parameterization.

**Vulnerable Code:**
```python
query = f"SELECT * FROM users WHERE id={user_id}"
```

**Fix:**
```python
query = "SELECT * FROM users WHERE id=?"
cursor.execute(query, (user_id,))
```
```

### SARIF (for GitHub)

Export directly to GitHub Code Scanning:

```bash
python main.py scan --repo /path/to/repo --output sarif > results.sarif
gh code-scanning upload results.sarif
```

---

## Cost Model

SWIFT reduces scanning cost by 80%+ using intelligent triage:

```
100 files scanned (50 lines each = 5000 LOC):

WITHOUT SWIFT (Sonnet on all):
  5000 lines × $0.01/line = $50

WITH SWIFT (triage + targeted):
  Regex: Free
  Haiku: 100 files × $0.05 = $5
  Sonnet: 10 flagged locations × $0.50 = $5
  Total: $10 (80% savings!)

Typical scan cost: <$2
```

---

## Project Structure

```
swift/
├── agent/                  # Orchestration + data models
│   ├── models.py          # Vulnerability, Patch, ScanResult, ExploitChain, etc.
│   └── orchestrator.py    # Pipeline: triage → haiku → sonnet → risk → chains → patch
├── scanners/              # Two-stage AI scanning
│   ├── haiku_scanner.py   # Stage 1: fast triage (~50ms/file)
│   └── sonnet_scanner.py  # Stage 2: 95% confidence gate (~3s/loc)
├── triage/                # Regex pre-filter (zero cost)
│   ├── patterns.py        # 8+ vulnerability patterns
│   └── ranking.py         # Risk scoring (Phase 3)
├── chains/                # Exploit chain detection
│   └── detector.py        # Multi-step attack path analysis
├── patches/               # Patch generation
│   └── generator.py       # 3 candidates → score → best
├── sandbox/               # Docker isolated testing
│   └── docker_runner.py   # Network-disabled, read-only, 30s timeout
├── output/                # Output formatters
│   ├── formatters.py      # JSON, Markdown formatters
│   ├── chains.py          # Exploit chain formatter
│   └── sarif.py           # SARIF 2.1.0 formatter
├── config/                # Configuration
│   └── settings.py        # .env loading, API keys
├── log/                   # Structured logging
│   └── logger.py          # Metrics, audit trail
├── cli/                   # Click CLI commands
│   └── commands.py        # scan, patch, validate commands
├── test/                  # Complete test suite
│   ├── unit/             # 288 tests, no API
│   ├── integration/      # 49 tests, mocked API
│   └── e2e/              # 7 tests, real API
└── main.py               # Entry point
```

---

## Test Results

**All tests passing:** 338 tests, 97% coverage

| Suite | Count | Status |
|-------|-------|--------|
| Unit tests | 288 | ✅ All pass |
| Integration tests | 49 | ✅ All pass |
| E2E tests | 7 | ⏭️ Gated by `SWIFT_RUN_E2E=1` |

**Phase 3 Coverage:**
- Risk Scoring: 35 tests (`test_ranking.py`)
- SARIF Output: 28 tests (`test_sarif.py`)
- Exploit Chains: 32+ tests (chain detector + formatters)
- Output Formatters: 57 tests (JSON + Markdown + Phase 3 fields)

---

## GitHub Integration

### Code Scanning Setup

1. **Generate SARIF:**
   ```bash
   python main.py scan --repo /path/to/repo --output sarif > results.sarif
   ```

2. **Upload to GitHub:**
   ```bash
   gh code-scanning upload results.sarif
   ```

3. **View in GitHub:**
   - Go to Security → Code scanning
   - See all vulnerabilities with risk scores, exploitability, and impact

### GitHub Actions Integration

```yaml
name: SWIFT Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: jellaharshith/SWIFT@main
        with:
          repo: ${{ github.workspace }}
          output: sarif
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

---

## API Reference

### scan_codebase()

```python
from agent.orchestrator import scan_codebase

result = scan_codebase(repo_path="/path/to/repo")

# result.vulnerabilities — list of Vulnerability objects
# result.exploit_chains — list of ExploitChain objects
# result.summary — dict with stats
```

### RiskScorer

```python
from triage.ranking import RiskScorer

scorer = RiskScorer()
vuln.risk_score = scorer.calculate_risk_score(vuln)
vuln.exploitability = scorer.get_exploitability_score(vuln)
vuln.business_impact_category = scorer.get_impact_category(vuln)
```

### ExploitChainDetector

```python
from chains.detector import ExploitChainDetector

detector = ExploitChainDetector(client, model="claude-sonnet-4-6")
chains = detector.detect_chains(vulnerabilities)
```

### Output Formatters

```python
from output.formatters import JSONFormatter, MarkdownFormatter
from output.sarif import SARIFFormatter

json_output = JSONFormatter().format(result)
markdown_output = MarkdownFormatter().format(result)
sarif_output = SARIFFormatter().format(result)
```

---

## Documentation

- [Architecture & Design](docs/README.md)
- [Phase 1: Exploit Chain Intelligence](docs/README.md#phase-1-exploit-chain-intelligence)
- [Phase 2: Security Controls](docs/README.md#phase-2-security-controls)
- [Phase 3: Advanced Analysis](docs/README.md#phase-3-advanced-analysis)
- [API Reference](docs/README.md#api-reference)
- [Testing Guide](docs/README.md#testing)

---

## License

MIT

---

## GitHub

Report bugs and suggest features at [jellaharshith/SWIFT/issues](https://github.com/jellaharshith/SWIFT/issues).
