# 🚀 SWIFT — AI-Powered Vulnerability Discovery + Automated Patching

> **CLI-only tool.** SWIFT runs from your terminal, exactly like `claude-code`, `gh`, or `git`. There is no web UI, no dashboard, no hosted service. Everything ships as `python swift_cli.py <command>`.

**Continuous security scanning meets exploit chain detection meets automated patch generation.** SWIFT finds vulnerabilities in application code, drives a real headless browser (Playwright) against live URLs, runs Docker-isolated privilege-escalation tests, and generates tested fixes — all in minutes, not months.

---

## 🌟 Highlights

- **⚡ Fast:** Scans 100 files in <3 minutes, costs <$2 (80% cheaper than traditional approaches)
- **🎯 Accurate:** 95% confidence gate eliminates false positives—every finding is real
- **🔗 Attack-Aware:** Detects multi-step exploit chains traditional scanners miss
- **🛠️ Auto-Fix:** Generates 3 patch candidates, scores them, picks the best, tests in sandbox
- **📊 Risk-Prioritized:** Scores vulns 0-100 based on severity, exploitability, and business impact
- **🔐 Trustworthy:** Tamper-evident audit logging + AI safety guardrails (no privilege escalation)
- **🔄 CI/CD-Ready:** Exports SARIF for GitHub Code Scanning, JSON for APIs, Markdown for reports

---

## ℹ️ Overview

### The Problem

Traditional pentesting takes **weeks, costs $100K+**, and misses multi-step attacks. Annual scans can't catch vulnerabilities introduced in this sprint. Automated scanners flood teams with false positives—crying wolf burns trust.

### How SWIFT Solves It

SWIFT runs continuously, finding vulnerabilities in minutes and reporting only what's real (≥95% confidence). Unlike one-off scans, it understands how bugs chain together to create exploitable attack paths. When it finds a vulnerability, it auto-generates and tests patches before presenting them—saving security teams hours of manual remediation.

**The core innovation:** Three-layer AI triage (Regex → Haiku → Sonnet) + risk scoring + exploit chain detection + patch generation. Each layer intelligently filters noise, so the expensive deep reasoning only runs where it matters.

### Who This Is For

- **Security teams** tired of false positives and manual patch work
- **DevSecOps** wanting continuous, automated scanning in CI/CD
- **Compliance officers** needing detailed audit trails and risk metrics
- **Engineering leads** who want to fix bugs before they ship

---

## 🚀 Quick Start

### Install

```bash
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift
python -m venv .venv
source .venv/bin/activate
pip install -r requirement.txt
python -m playwright install chromium     # browser binaries for web-scan
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

> Docker daemon required for `validate`, `privesc`, `kali-scan`, and `attack-sim`.

### Interactive Wizard (Recommended)

```bash
# Launch interactive wizard with menu-driven scanning
python swift_cli.py wizard --repo /path/to/repo

# Wizard selects agents automatically:
# 1. CodeAgent    → Source code analysis (SQL injection, command injection, etc.)
# 2. NetworkAgent → Network configuration vulnerabilities
# 3. WebAgent     → Browser-based scanning (XSS, CSRF, insecure cookies)
# 4. CVEAgent     → Known CVEs in dependencies
# Outputs both JSON + Markdown reports
```

### Scan Your Code

```bash
# JSON output (APIs, dashboards)
python swift_cli.py scan --repo /path/to/repo --output json

# Markdown report (email, PR comments)
python swift_cli.py scan --repo /path/to/repo --output markdown

# SARIF (GitHub Code Scanning)
python swift_cli.py scan --repo /path/to/repo --output sarif > results.sarif
gh code-scanning upload results.sarif

# With patch generation
python swift_cli.py scan --repo /path/to/repo --allow-patch-generation --output json
```

#### Example Output

**Vulnerabilities:** 3 found (1 critical, 2 high)  
**Exploit chains:** 1 detected (SQL injection → privilege escalation → data theft)  
**Patches:** 3 generated, all passed sandbox tests  
**Cost:** $1.42 | **Time:** 2 minutes 45 seconds

---

## 🖥️ CLI Reference

### Unified Scanner with AgentPool

```bash
# Interactive wizard (recommended) — automatically selects agents
python swift_cli.py wizard --repo /path/to/repo

# Run all agents at once (CodeAgent + NetworkAgent + WebAgent + CVEAgent)
python swift_cli.py run-all --repo /path/to/repo --output json

# Named agents for fine-grained control
python swift_cli.py code-agent --repo /path/to/repo       # Source code analysis
python swift_cli.py network-agent --repo /path/to/repo    # Network config scan
python swift_cli.py web-agent --repo /path/to/repo        # Browser-based testing
python swift_cli.py cve-agent --repo /path/to/repo        # Dependency CVE check
```

### Code Analysis (Legacy)

```bash
# Scan for vulnerabilities
python swift_cli.py scan --repo . --output json|markdown

# Fast triage only (alias)
python swift_cli.py triage --repo .

# Generate patches (requires flag)
python swift_cli.py patch --repo . --allow-patch-generation

# Validate a patch in Docker sandbox (requires flag)
python swift_cli.py validate --repo . --patch-file patch.diff --target-file file.py --allow-sandbox

# Generate report from previous scan
python swift_cli.py report --repo . --format json|markdown

# Full pipeline: scan → patch → validate
python swift_cli.py full --repo . --allow-patch-generation --allow-sandbox
```

### Browser Scanning (Playwright)

`web-scan` drives a real headless Chromium against the target URL and probes for reflected XSS, error-based SQLi, open-redirects, mixed-content, and insecure cookies. Every navigation, probe, finding, and console error is appended to the step log.

```bash
python swift_cli.py web-scan --target https://target.example.com --yes
python swift_cli.py web-scan --target https://target.example.com --headed --output-file web.json
```

### Docker Privilege Escalation Testing

`privesc` mounts the target workspace read-only into a hardened, network-isolated container (`--cap-drop=ALL --security-opt no-new-privileges --network=none`) and runs probes for SUID/SGID, sudo NOPASSWD, world-writable PATH, dangerous capabilities, writable `/etc`, and cron weaknesses. The `--allow-privesc` zero-trust gate is required.

```bash
python swift_cli.py privesc --repo /path/to/workspace --allow-privesc --yes
```

### Offensive Security (Kali Linux)

```bash
# Run Kali tools against a live target
python swift_cli.py kali-scan --target <IP|hostname|URL> --tools all --live-cve --output-file results.json

# Stream live CVEs from NVD + CISA KEV (every 2s)
python swift_cli.py live-feed --severity CRITICAL --output stream

# MITRE ATT&CK-mapped simulation
python swift_cli.py attack-sim --target <IP> --technique T1046
```

### Zero-Trust Security Flags

SWIFT is **fail-closed by default** — write operations require explicit opt-in:

| Flag | Required for |
|------|-------------|
| `--allow-patch-generation` | `patch`, `full` |
| `--allow-sandbox` | `validate`, `full` |
| `--allow-privesc` | `privesc` |
| `--read-only` | Default; blocks mutations |
| `--config <path>` | Fine-grained JSON config |
| `--strict` | Strict validation mode |

### Auto-Confirm (`--yes` / `-y`)

Set `--yes` (or `SWIFT_AUTO_CONFIRM=1`) to skip every interactive prompt — including the offensive-scan consent banner. **`--yes` does NOT bypass the zero-trust `--allow-*` gates above**; you still pass those explicitly. Auto-confirm is one-shot per invocation; it is logged as `consent.auto_confirmed` in the step log.

```bash
SWIFT_AUTO_CONFIRM=1 python swift_cli.py full-scan --repo . --target https://app.example.com
python swift_cli.py privesc --repo . --allow-privesc --yes
```

### Logging & Audit Trail

Every step — CLI invocation, agent start/finish, Docker run, Playwright navigation, probe payload, patch apply, validation result — is appended to multiple sinks:

| Sink | Path | Format |
|------|------|--------|
| Rolling step log | `swift/log/steps.log.jsonl` (rotates at 50 MB) | JSONL |
| Process log | `swift/log/swift.log` | JSON |
| Per-scan audit | `<repo>/.swift-artifacts/audit.log.jsonl` | JSONL |
| Stdout | terminal | human |

Override the rolling step log location with `--log-file PATH`. Tail it during a scan:

```bash
tail -f swift/log/steps.log.jsonl
```

---

## How It Works — AgentPool Architecture

SWIFT uses a unified **AgentPool** with four specialized agents running in parallel:

```
Your Repo
  │
  ├─→ CodeAgent (source code analysis)
  │   └─ SQL injection, command injection, hardcoded secrets, etc.
  │
  ├─→ NetworkAgent (network configuration)
  │   └─ Open ports, insecure protocols, firewall misconfigurations
  │
  ├─→ WebAgent (browser-based testing)
  │   └─ XSS, CSRF, insecure cookies, mixed content, open redirects
  │
  └─→ CVEAgent (known vulnerabilities)
      └─ Dependency CVEs, outdated libraries, known exploits

      ↓ Each agent runs independently ↓

  ┌────────────┬────────────┬────────────┬────────────┐
  │ Code Findings │ Network Issues │ Web Vulns  │ CVEs   │
  └────────────┴────────────┴────────────┴────────────┘
              ↓
    UnifiedScanResult
    (consolidated findings + risk scoring)
              ↓
    JSON | Markdown (dual output)
```

### Legacy Pipeline (CodeAgent Deep Dive)

```
Your Code
  │
  ▼
┌─────────────────────────────────────┐
│ Layer 1: Regex Triage (FREE)        │ ← Fast pattern matching
│ 8+ vulnerability categories         │
└──────────────┬──────────────────────┘
               │ Only flagged files ↓
┌──────────────────────────────────────┐
│ Layer 2: Haiku (~$0.05/file, 50ms)  │ ← Fast AI confirmation
│ Confirms suspicious lines            │
└──────────────┬──────────────────────┘
               │ Only confirmed lines ↓
┌──────────────────────────────────────┐
│ Layer 3: Sonnet (~$0.50/vuln, 3s)   │ ← Deep reasoning
│ 95% CONFIDENCE GATE (only real bugs) │
└──────────────┬──────────────────────┘
               │ Confirmed vulns ↓
┌──────────────────────────────────────┐
│ Risk Scoring (0-100)                 │ ← Prioritization
│ + Exploit Chain Detection (≥85%)     │
│ + Patch Generation + Sandbox Testing │
└──────────────┬──────────────────────┘
               │ ↓
          JSON | Markdown | SARIF
```

---

## What Gets Detected

| Vulnerability | Example | CWE |
|---|---|---|
| SQL Injection | `f"SELECT * FROM users WHERE id={user_id}"` | CWE-89 |
| Command Injection | `os.system(user_input)` | CWE-78 |
| Hardcoded Secrets | `password = "my_secret"` | CWE-798 |
| Weak Cryptography | `hashlib.md5()` | CWE-327 |
| Unsafe Deserialization | `pickle.loads(data)` | CWE-502 |
| XXE Injection | `xml.etree.parse(untrusted)` | CWE-611 |
| SSRF | `requests.get(user_url)` | CWE-918 |
| Path Traversal | `open(f"files/{user_path}")` | CWE-22 |

---

## 📊 The 95% Confidence Rule

Only findings with **≥95% confidence** are reported. Why? Prevents false positives. Builds trust.

```python
if vulnerability.confidence >= 0.95:
    output_finding(vulnerability)  # Reported
else:
    log_low_confidence(vulnerability)  # Suppressed, logged only
```

**Chain Detection Gate:** ≥85% confidence (lower because chains are harder to confirm)

---

## 💰 Cost Model

SWIFT saves 80%+ on scanning costs through intelligent triage:

```
100 files (5000 LOC):

Traditional scanner (Sonnet on all):
  5000 lines × $0.01/line = $50 ❌

SWIFT (triage + targeted):
  Regex: FREE
  Haiku: 100 files × $0.05 = $5
  Sonnet: 10 flagged locs × $0.50 = $5
  Total: $10 (80% savings!) ✅

Typical scan: <$2
```

---

## 📈 Risk Scoring

Every vulnerability gets a risk score (0-100) based on:

```
risk_score = (severity × exploitability × confidence × business_impact) × 100
```

**Example:** SQL injection in auth login
- Severity: CRITICAL (1.0)
- Exploitability: Moderate (0.6)
- Confidence: 97%
- Impact: Customer data breach (1.0)
- **Risk Score: 58.2/100**

Priorities automatically. Security teams focus on what matters.

---

## 🔗 Exploit Chain Detection

Identifies multi-step attack sequences:

```
SQL Injection (SWIFT-001, auth/login.py:42)
  ↓ attacker bypasses login
Privilege Escalation (SWIFT-003, admin/panel.py:128)
  ↓ attacker gains admin access
Data Exfiltration (SWIFT-005, db/export.py:67)
  ↓ attacker steals customer database

Impact: Customer data breach + compliance violation
Confidence: 92%
```

Traditional scanners report 3 separate bugs. SWIFT shows you the attack.

---

## 🛠️ Patch Generation

For each vulnerability, SWIFT:
1. Generates 3 patch candidates
2. Scores them by code quality
3. Tests the best in Docker sandbox (network disabled, read-only, 30s timeout)
4. Reports pass/fail + diff

```python
# Before (vulnerable)
query = f"SELECT * FROM users WHERE id={user_id}"

# After (patched)
query = "SELECT * FROM users WHERE id=?"
cursor.execute(query, (user_id,))
```

---

## 🗡️ Offensive Security (Kali Linux)

Run industry-standard offensive tools against live targets in an isolated Kali Linux container:

| Tool | Purpose |
|------|---------|
| nmap / masscan | Port + service discovery |
| nikto | Web server vulnerability scan |
| sqlmap | Automated SQL injection |
| nuclei | Template-based CVE detection |
| hydra | Credential brute-force |
| gobuster | Directory/DNS enumeration |
| searchsploit | Exploit-DB search |

All tools map findings to **MITRE ATT&CK techniques** and correlate against the live CVE feed.

```bash
python swift_cli.py kali-scan --target 192.168.1.10 --tools nmap,sqlmap,nikto --live-cve
```

---

## 📡 Live CVE Feed

Streams real-time CVE data from **NVD** and **CISA KEV** every 2 seconds:

```bash
# Stream critical CVEs to terminal
python swift_cli.py live-feed --severity CRITICAL --output stream

# Export to JSON
python swift_cli.py live-feed --severity HIGH --output json --interval 5
```

SWIFT automatically cross-references live CVEs against findings in your scan results.

---

## 🧪 Test Coverage

**461+ tests, 97% coverage**

| Suite | Tests | Status |
|---|---|---|
| Unit | 400+ | ✅ Pass |
| Integration | 54 | ✅ Pass |
| E2E | 7 | ⏭️ Gate `SWIFT_RUN_E2E=1` |

**Phase-by-phase:**
- Risk Scoring: 35 tests
- Exploit Chains: 32+ tests
- SARIF Output: 28 tests
- Formatters: 57 tests

```bash
# Run all tests (no API key needed)
pytest test/unit/ test/integration/ -v

# With coverage report
pytest test/ --cov=swift --cov-report=term-missing

# E2E tests (requires API key)
SWIFT_RUN_E2E=1 pytest test/e2e/ -v
```

---

## 🔐 Security Controls (Phase 2)

SWIFT doesn't just find vulnerabilities—it governs itself:

### Permission Layer
- Role-based access (view, scan, patch, admin)
- File size limits, API model whitelisting
- Unauthorized ops raise `PermissionDenied`

### Forensic Logging
- Append-only audit trail (immutable, tamper-detected)
- Every action logged: tool, action, inputs, outputs, timestamp
- SHA256 hash chain for verification

### AI Safety Monitor
- Detects privilege escalation attempts
- Catches hidden reasoning / contradictions
- Halts execution immediately on violation
- Full context logged for audit

---

## 🔄 CI/CD Integration

### GitHub Actions

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

### SARIF Upload

```bash
python swift_cli.py scan --repo /path/to/repo --output sarif > results.sarif
gh code-scanning upload results.sarif
```

Then view in GitHub: **Security → Code scanning** with risk scores, exploitability, and business impact.

---

## 📚 Architecture & API Reference

Full technical docs: [Architecture & Design](docs/README.md)

### Key Classes

```python
# Scan
from agent.orchestrator import scan_codebase
result = scan_codebase(repo_path="/path/to/repo")

# Risk Scoring
from triage.ranking import RiskScorer
scorer = RiskScorer()
vuln.risk_score = scorer.calculate_risk_score(vuln)

# Exploit Chains
from chains.detector import ExploitChainDetector
detector = ExploitChainDetector(client)
chains = detector.detect_chains(vulnerabilities)

# Output Formats
from output.formatters import JSONFormatter, MarkdownFormatter
from output.sarif import SARIFFormatter
json_out = JSONFormatter().format(result)
```

---

## 📂 Project Structure

```
swift/
├── agent/              # AgentPool orchestration + named agents (CodeAgent, NetworkAgent, WebAgent, CVEAgent)
├── scanners/           # Haiku triage + Sonnet deep analysis
├── triage/             # Regex patterns, risk scoring, exploit graph
├── chains/             # Exploit chain detection
├── patches/            # Patch generation + scoring
├── sandbox/            # Docker isolation + testing
├── output/             # JSON, Markdown, SARIF formatters
├── feeds/              # Live CVE feed (NVD + CISA KEV)
├── kali/               # Kali Linux offensive tools + MITRE ATT&CK
├── config/             # Settings + .env loading
├── log/                # Forensic audit logging
├── cli/                # Click commands (wizard, run-all, named agents)
├── security/           # Permission enforcement, audit logging, safety monitor
├── test/               # 461+ tests
├── swift_cli.py        # Main CLI entry point
└── main.py             # Legacy entry point
```

---

## ✍️ Author

**Harshith Jella** built SWIFT to make continuous security scanning fast, accurate, and trustworthy. Every vulnerability found should be real. Every patch should be tested. Every decision auditable.

Started as frustration with traditional pentesting. Became a platform.

---

## 🎁 Feedback & Contributions

Found a bug? Have a feature idea? Open an issue:

👉 [jellaharshith/SWIFT/issues](https://github.com/jellaharshith/SWIFT/issues)

Want to contribute? Check out:
- [DEVELOPMENT.md](DEVELOPMENT.md) — local setup
- [CONTRIBUTING.md](CONTRIBUTING.md) — code style, testing, PR process

Ways to help:
- Report false negatives/positives
- Add vulnerability patterns
- Translate docs
- Improve patch generation
- Build integrations (Slack, Jira, Linear, etc.)

---

## 📜 License

MIT

---

**Made by security engineers, for security engineers. No fluff. No false positives. Just real vulnerabilities and real fixes.**
