# SWIFT — Secure-by-Design AI Security Engineering Platform

**SWIFT** is an AI-powered vulnerability scanner that finds security flaws, identifies multi-step attack chains, and generates safe patches — all with forensic auditability and built-in AI safety guardrails.

## What SWIFT Does

1. **Finds** vulnerabilities in code (SQL injection, command injection, hardcoded secrets, weak crypto, unsafe deserialization)
2. **Detects** multi-step exploit chains (sequences of vulns that lead to complete compromise)
3. **Verifies** findings are real (95%+ confidence only — no false positives)
4. **Fixes** vulns automatically (generates patches, tests in isolated sandbox)
5. **Logs** every action with tamper-evident forensic audit trail
6. **Reports** everything (JSON, Markdown, SARIF formats)

## Architecture

### Three-Layer Pipeline

**Phase 1: Regex Triage** (zero API cost)
- Pattern matching on all files (SQL injection, command injection, hardcoded secrets, etc.)
- Fast, cheap, broad filter

**Phase 2: Haiku Fast Scan** (~$0.05/file)
- Confirms suspicious lines using Claude Haiku
- 50ms per file, language-aware analysis

**Phase 3: Sonnet Deep Analysis** (~$0.50/location)
- Deep reasoning with 95% confidence gate
- Extracts: CWE ID, exploit description, remediation advice
- Only high-confidence findings pass through

**Phase 3.5: Exploit Chain Detection** (Phase 1 feature)
- Sonnet analyzes confirmed vulns to find multi-step attack paths
- Confidence gate: ≥0.85 (chains are harder to confirm than individual vulns)
- Returns: attack entry point → escalation steps → final impact

**Phase 4: Patch Generation + Sandbox Testing** (optional)
- Sonnet generates 3 patch candidates per vuln
- Docker isolation: network-disabled, read-only filesystem, memory/CPU limits
- Returns: patched code, unified diff, test results

### Security Controls (Phase 2 — NEW)

**Permission Enforcement Layer**
- Central gate for all tool operations
- Per-operation permission rules (scan, patch, sandbox, API call)
- File size limits, API model whitelisting
- Unauthorized operations raise `PermissionDenied`

**Forensic Logging Layer**
- Append-only audit trail (no deletion, no modification)
- Every action logged: tool, action, inputs, outputs, timestamp
- Hash chain for tamper detection (each entry includes hash of previous)
- Structured JSON format, queryable

**AI Safety Monitor**
- Detects privilege escalation attempts
- Detects hidden reasoning (contradictions between stated/actual intent)
- Detects unauthorized tool calls or permission bypass attempts
- Halts execution immediately if violation detected
- Logs full violation context

## Quick Start

### Installation

```bash
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift
python -m venv .venv
source .venv/bin/activate
pip install -r requirement.txt
```

### Usage

Scan a repository:
```bash
swift scan --repo /path/to/code --output json
```

Generate patches:
```bash
swift scan --repo /path/to/code --output json --patches
```

Export as Markdown:
```bash
swift scan --repo /path/to/code --output markdown > report.md
```

### Test

```bash
cd swift
pytest test/unit/ -v --cov=swift
```

## Key Features

### 95% Confidence Rule
Only findings with ≥95% confidence are output. Low-confidence findings are logged, not reported.

### Exploit Chain Detection
Beyond individual vulnerabilities, SWIFT identifies multi-step attack paths:
- Entry point (where attacker starts)
- Escalation steps (how they move deeper)
- Final impact (what they compromise)
- Confidence ≥0.85 (lower gate than vulns — chains are harder to confirm)

### Language-Aware Analysis
- Detects language from file extension (.py, .js, .ts, etc.)
- Language-specific code blocks in prompts
- Exact syntax analysis per language

### Tamper-Evident Audit Trail
- Every tool call logged with inputs, outputs, timestamp
- Hash chain: each log entry includes SHA256 hash of previous entry
- Integrity verification: detect any modification to audit log
- JSON format, structured and queryable

### AI Safety
- Permission enforcement: all tool calls validated before execution
- Escalation detection: identifies privilege escalation attempts
- Hidden reasoning detection: catches contradictions in agent behavior
- Unauthorized action detection: catches attempts to skip permission checks

## Output Formats

### JSON
```json
{
  "scan": {
    "id": "SCAN-001",
    "repo_path": "/path/to/repo",
    "duration_seconds": 120,
    "total_cost_usd": 1.23,
    "timestamp": "2026-04-20T12:00:00Z"
  },
  "summary": {
    "files_scanned": 42,
    "vulnerabilities_found": 5,
    "by_severity": { "critical": 2, "high": 2, "medium": 1, "low": 0 },
    "patches_generated": 5
  },
  "vulnerabilities": [
    {
      "id": "SWIFT-001",
      "file_path": "app.py",
      "line_number": 42,
      "vuln_type": "sql_injection",
      "description": "User input concatenated into SQL query",
      "severity": "CRITICAL",
      "confidence": 0.97,
      "cwe_id": "CWE-89",
      "exploit_description": "Attacker can bypass authentication or extract data",
      "remediation": "Use parameterized queries",
      "code_snippet": "query = f'SELECT * FROM users WHERE id={uid}'"
    }
  ],
  "exploit_chains": [
    {
      "chain_id": "CHAIN-001",
      "name": "SQL Injection → Auth Bypass → Admin Access",
      "vulnerability_ids": ["SWIFT-001", "SWIFT-003"],
      "attack_path": "1. Exploit SQL injection in login query\n2. Bypass authentication\n3. Access admin panel",
      "entry_point": "auth/views.py:42",
      "impact": "Full admin access without credentials",
      "severity": "CRITICAL",
      "confidence": 0.91
    }
  ],
  "patches": [
    {
      "id": "PATCH-001",
      "vuln_id": "SWIFT-001",
      "file_path": "app.py",
      "original_code": "query = f'SELECT * FROM users WHERE id={uid}'",
      "patched_code": "query = 'SELECT * FROM users WHERE id=?'; cursor.execute(query, (uid,))",
      "diff": "--- app.py\n+++ app.py\n@@ -42,1 +42,1 @@\n-query = f'SELECT...'",
      "confidence": 0.97
    }
  ]
}
```

### Markdown
Human-readable report with sections for metadata, summary, vulnerabilities (with code snippets), exploit chains, and patches (with diffs).

## Phase Progress

### ✅ Phase 1 — Exploit Chain Intelligence (COMPLETE)

- ExploitChain data model
- Language-aware Haiku + Sonnet prompts (extend with CWE, exploit_description, remediation)
- ExploitChainDetector (multi-step attack path reasoning using Sonnet)
- Orchestrator Phase 3.5 (chain detection between Sonnet confirm and patch)
- Output formatters (chains in JSON + Markdown)
- **Tests:** 153/153 pass (10 new chain detector tests, 6 new output tests)
- **Commit:** 743f6a6

### ✅ Phase 2 — Security Controls (COMPLETE)

- **Permission Enforcement Layer** (`swift/security/permissions.py`)
  - All tool calls validated before execution
  - Per-operation permission rules
  - File size limits, API model whitelisting
  - Tests: 14 tests, all passing

- **Forensic Logging Layer** (`swift/security/logging.py`)
  - Append-only audit trail with hash chain
  - Tamper detection via SHA256 verification
  - Structured JSON format
  - Tests: 13 tests, all passing

- **AI Safety Monitor** (`swift/security/safety_monitor.py`)
  - Privilege escalation detection
  - Hidden reasoning detection
  - Unauthorized action detection
  - Tests: 8 tests, all passing

- **Tests:** 35 new security tests, all passing
- **Total Tests:** 188 passing (Phase 1: 153 + Phase 2: 35)
- **Status:** Ready for integration

### ⬜ Phase 3 — Evidence Bundle + Compliance (PENDING)

- Enhanced findings.json (CWE, exploit_description, remediation in output)
- exploit_chains.json (standalone export)
- SARIF output format (GitHub Advanced Security integration)
- Enhanced triage ranking (severity × exploitability × confidence × business impact)
- Patch diffs with sandbox test results embedded
- `/scan/{id}/evidence` API endpoint for compliance bundles

## Code Quality

- **Type hints:** Every function has type hints
- **Docstrings:** Google-style, describe Args/Returns/Raises
- **PEP 8:** Run `black swift/` before commit
- **Test coverage:** >80%
- **No secrets:** Use .env files, never commit API keys

## Critical Constraints

- **95% Confidence Rule:** Only findings ≥95% confidence are output
- **Chain Gate:** Chain confidence ≥0.85 (chains are harder to confirm)
- **Sandbox Safety:** Network-disabled, read-only filesystem, isolated
- **Append-Only Logs:** No modification after write
- **Best-Effort Security:** Chain detection failures don't block patches

## Cost Discipline

Target: <$2 cost per full scan
- Haiku: $0.05/file (broad filter)
- Sonnet: $0.50/flagged location (deep reasoning)
- Savings: 60% cheaper than Sonnet on all code

## GitHub Issues

- #21 — Phase 1 Complete (exploit chains + language-aware prompts)
- #22 — Phase 2 Complete (permission layer + forensic logging + AI safety)
- #23 — Phase 3 Pending (evidence bundle + compliance)

## Contributing

1. Fork the repo
2. Create feature branch (`git checkout -b feature/your-feature`)
3. Write tests first (TDD)
4. Run `pytest test/ -v --cov=swift`
5. Commit with descriptive message
6. Push and open a pull request

## Security

SWIFT is designed with security-first principles:
- All tool calls go through permission enforcement
- Every action logged in tamper-evident audit trail
- AI safety monitor detects unsafe agent behavior
- Sandbox isolation for patch testing

For security issues, please email security@SWIFT.dev (or open a private security advisory on GitHub).

## License

MIT License — see LICENSE file for details

## Architecture Decision Log

See `docs/decisions/` for detailed ADRs on:
- Why Sonnet for analysis vs. other models
- Why hash chains for tamper detection
- Why 95% confidence threshold
- Why append-only logs

## Roadmap

**Q2 2026:** Phase 3 (Evidence Bundle) — SARIF output, enhanced triage
**Q3 2026:** Performance optimizations, batch scanning
**Q4 2026:** GitHub Actions integration, CI/CD plugins
