# SWIFT Documentation

This directory contains comprehensive documentation for SWIFT's architecture, features, and Phase-based development roadmap.

## Documentation Overview

| Document | Purpose |
|----------|---------|
| [Main README](../README.md) | Project overview, installation, quick start |
| [Phase 1: Exploit Chain Intelligence](#phase-1-exploit-chain-intelligence) | Multi-step attack path detection |
| [Phase 2: Security Controls](#phase-2-security-controls) | Permission layer, forensic logging, AI safety |
| [Phase 3: Advanced Analysis](#phase-3-advanced-analysis) | Risk scoring, exploit chains, SARIF output |

---

## Phase 1: Exploit Chain Intelligence

**Status:** Completed  
**Purpose:** Identify multi-step attack paths that combine multiple vulnerabilities

### Key Features

- **Chain Detection:** Analyzes confirmed vulnerabilities for chaining opportunities
- **Attack Path Mapping:** Traces entry points through privilege escalation to data exfiltration
- **Confidence Threshold:** Requires ≥85% confidence to report a chain
- **Step-by-Step Analysis:** Each chain broken into discrete attack steps with locations

### Data Model

```python
@dataclass
class AttackStep:
    step: int                    # Step number in chain (1-indexed)
    description: str             # Human-readable action
    vuln_id: str                 # Vulnerability ID (e.g., "SWIFT-001")
    entry_point: str             # Code location (e.g., "auth/views.py:42")

@dataclass
class ExploitChain:
    chain_id: str                # Unique chain identifier
    name: str                    # Human-readable name
    vulnerability_ids: List[str] # IDs in attack order
    attack_path: str             # Narrative description
    entry_point: str             # Where attack starts
    impact: str                  # What attacker compromises
    severity: str                # CRITICAL/HIGH/MEDIUM/LOW
    confidence: float            # 0.0-1.0 (≥0.85 to report)
    attack_steps: List[AttackStep]  # Individual steps with locations
```

### Example Chain

**Chain:** SQL Injection → Privilege Escalation → Data Exfiltration

```
Step 1: SQL Injection (SWIFT-001)
  Location: auth/views.py:42
  Action: Attacker bypasses authentication via SQL injection
  
Step 2: Privilege Escalation (SWIFT-003)
  Location: admin/panel.py:128
  Action: Attacker gains admin access to modify user roles
  
Step 3: Data Exfiltration (SWIFT-005)
  Location: db/export.py:67
  Action: Attacker exports entire customer database undetected
  
Impact: Customer data breach (PII compromise)
Confidence: 92%
Severity: CRITICAL
```

### Detection Process

1. **Vulnerability Collection:** Gather all confirmed findings (≥95% confidence)
2. **Dependency Analysis:** Identify which vulns enable access to other vulns
3. **Path Construction:** Build ordered chains from entry point to impact
4. **Confidence Scoring:** Estimate feasibility of executing the chain
5. **Reporting:** Output chains with ≥85% confidence

---

## Phase 2: Security Controls

**Status:** Completed  
**Purpose:** Secure the AI-powered scanning pipeline with permission layers, logging, and safety guardrails

### Key Features

#### 1. Permission Layer
- Role-based access control for scan management
- Fine-grained permissions: view, scan, patch, admin
- OAuth integration for GitHub private repositories
- Team-level scan isolation

#### 2. Forensic Logging
- Immutable audit trail of all scanning activity
- Logs include: user, action, timestamp, findings, cost
- Searchable by date, vulnerability type, severity
- JSON structured logs for SIEM integration

#### 3. AI Safety
- Hardcoded 95% confidence threshold (non-negotiable)
- Low-confidence findings suppressed from output (logged only)
- Reasoning documentation for every finding
- Automatic vulnerability verification before patching

### Confidence Gate

The 95% confidence rule is the foundation of SWIFT's reliability:

```python
# Only output findings with confidence >= 0.95
if vulnerability.confidence >= 0.95:
    output_finding(vulnerability)
else:
    log_low_confidence(vulnerability)  # Suppressed, never output
```

This prevents false positives and builds user trust in reported findings.

---

## Phase 3: Advanced Analysis

**Status:** Completed  
**Purpose:** Quantify vulnerability risk, detect exploit chains, and integrate with GitHub Advanced Security

---

### 1. Risk Scoring Framework

#### Purpose
Quantify vulnerability risk using a quantitative formula that combines severity, exploitability, confidence, and business impact. This enables prioritization of remediation efforts based on real-world risk.

#### Risk Score Formula

```
risk_score = (severity_weight × exploitability × confidence × impact_weight) × 100
```

**Output Range:** 0-100 (higher = riskier)

#### Severity Weights

| Severity | Weight | Description |
|----------|--------|-------------|
| CRITICAL | 1.0 | System compromise, data loss, RCE |
| HIGH | 0.75 | Significant impact, elevated privileges |
| MEDIUM | 0.5 | Moderate impact, limited scope |
| LOW | 0.25 | Minor impact, workarounds exist |

#### Exploitability Levels

Measures how easily an attacker can exploit the vulnerability:

| Level | Score | Description |
|-------|-------|-------------|
| Trivial | 0.9 | Requires no skill, basic HTTP tools |
| Moderate | 0.6 | Requires some knowledge, common techniques |
| Specific | 0.4 | Requires specific conditions or tools |
| Complex | 0.2 | Requires advanced techniques, multiple steps |

#### Business Impact Categories

Impact weights reflect real-world business consequences:

| Category | Weight | Description |
|----------|--------|-------------|
| customer_data_breach | 1.0 | Personal data, GDPR, PCI-DSS, legal liability |
| compliance_violation | 0.9 | SOC2, HIPAA, ISO 27001, audit failures |
| financial_loss | 0.8 | Direct monetary damage |
| service_disruption | 0.7 | Availability impact, downtime |
| data_exposure | 0.6 | Information disclosure, confidentiality breach |
| no_impact | 0.0 | Theoretical finding with no real risk |

#### Implementation

```python
from triage.ranking import RiskScorer

# Calculate risk score for a vulnerability
risk_score = RiskScorer.calculate_risk_score(vuln)
print(f"Risk Score: {risk_score}/100")

# Rank all vulnerabilities by risk
vulnerabilities = [...]
ranked = RiskScorer.rank_vulnerabilities(vulnerabilities)
for vuln, score in ranked:
    print(f"{vuln.id}: {score:.1f}/100")

# Auto-infer impact category
impact = RiskScorer.get_impact_category(vuln)
print(f"Impact: {impact}")

# Auto-infer exploitability
exploitability = RiskScorer.get_exploitability_score(vuln)
print(f"Exploitability: {exploitability:.1f}")
```

#### Example: SQL Injection in Authentication

```
Vulnerability: SQL Injection in login form
Severity: CRITICAL (1.0)
Exploitability: Moderate (0.6) - parameterized query bypass
Confidence: 97% (0.97)
Impact Category: customer_data_breach (1.0)

Risk Score = (1.0 × 0.6 × 0.97 × 1.0) × 100 = 58.2/100
```

#### Example: Hardcoded API Key in Source

```
Vulnerability: Hardcoded API key
Severity: HIGH (0.75)
Exploitability: Trivial (0.9) - visible in code
Confidence: 99% (0.99)
Impact Category: customer_data_breach (1.0)

Risk Score = (0.75 × 0.9 × 0.99 × 1.0) × 100 = 66.8/100
```

---

### 2. Exploit Chain Detection

#### Purpose
Identify multi-step attack paths where multiple vulnerabilities can be chained together to achieve critical impact. Goes beyond individual findings to show attack sequences.

#### Chain Detection Process

1. **Vulnerability Collection:** Gather all confirmed findings (≥95% confidence)
2. **Dependency Mapping:** Identify which vulns enable access to others
   - SQL injection → access to user table → privilege escalation
   - XSS → session hijacking → admin panel access
   - Hardcoded credentials → database compromise → data exfiltration
3. **Path Construction:** Build ordered attack sequences
4. **Confidence Scoring:** Estimate feasibility of executing chain (≥85%)
5. **Impact Assessment:** Determine worst-case outcome

#### Chain Components

| Component | Type | Example |
|-----------|------|---------|
| vulnerability_ids | List[str] | ["SWIFT-001", "SWIFT-003", "SWIFT-005"] |
| attack_path | str | "SQL Injection → Privilege Escalation → Data Breach" |
| attack_steps | List[AttackStep] | Step-by-step breakdown with code locations |
| severity | str | CRITICAL/HIGH/MEDIUM/LOW |
| confidence | float | 0.0-1.0 (only report if ≥0.85) |
| entry_point | str | auth/login.py:42 |
| impact | str | Customer data exfiltration, regulatory violation |

#### Example Attack Chain

**Chain Name:** Authentication Bypass Leading to Database Compromise

```
Vulnerability Sequence:
1. SQL Injection (SWIFT-001) at auth/views.py:42
   → Allows bypassing login check
   
2. Privilege Escalation (SWIFT-003) at admin/panel.py:128
   → Grants admin role after successful injection
   
3. Data Exfiltration (SWIFT-005) at db/export.py:67
   → Admin can export entire customer database
   
Attack Narrative:
  1. Attacker injects SQL payload in login form
  2. Query evaluates to TRUE, bypassing password check
  3. User gains admin privileges due to missing role validation
  4. Admin panel reveals database export endpoint
  5. Attacker downloads full customer database (PII, payment info)

Impact: Complete data breach, GDPR violation, regulatory fines
Confidence: 92% (high probability of successful exploitation)
Severity: CRITICAL
```

#### Detection Code

```python
from chains.detector import ChainDetector

detector = ChainDetector()
chains = detector.detect_chains(vulnerabilities)

for chain in chains:
    print(f"\nChain: {chain.name}")
    print(f"Entry Point: {chain.entry_point}")
    print(f"Confidence: {chain.confidence:.0%}")
    print(f"Severity: {chain.severity}")
    
    for step in chain.attack_steps:
        print(f"  Step {step.step}: {step.description} ({step.vuln_id})")
        print(f"    Location: {step.entry_point}")
```

#### Confidence Threshold

Only chains with **≥85% confidence** are reported. This threshold reflects:
- Probability that vulnerabilities can actually be exploited in sequence
- Likelihood of attack succeeding given real-world conditions
- Assessment by the AI model of feasibility

---

### 3. SARIF Output Format

#### Purpose
Export scan results in SARIF 2.1.0 format for seamless integration with GitHub Advanced Security, GitHub Code Scanning, and other SIEM/security tools.

#### What is SARIF?

**SARIF** (Static Analysis Results Interchange Format) is an OASIS standard that allows security scanning tools to communicate findings in a standardized, machine-readable format. Benefits:

- **GitHub Integration:** Automatic upload to GitHub code scanning
- **CI/CD:** Native support in GitHub Actions, GitLab CI, Azure Pipelines
- **SIEM Systems:** Compatibility with Splunk, ELK, Datadog, etc.
- **Interoperability:** One format works across all platforms

#### SARIF 2.1.0 Structure

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SWIFT",
          "version": "0.1.0",
          "informationUri": "https://github.com/jellaharshith/SWIFT",
          "rules": [
            {
              "id": "CWE-89",
              "name": "SQL Injection",
              "shortDescription": { "text": "User input used in SQL query" },
              "defaultConfiguration": { "level": "error" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CWE-89",
          "message": { "text": "SQL injection vulnerability" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "auth/views.py" },
                "region": { "startLine": 42 }
              }
            }
          ],
          "properties": {
            "risk_score": 58.2,
            "exploitability": 0.6,
            "business_impact_category": "customer_data_breach",
            "cwe_id": "CWE-89"
          }
        }
      ],
      "properties": {
        "scan_id": "scan-20260420-001",
        "repo_path": "https://github.com/owner/repo",
        "files_scanned": 45,
        "duration_seconds": 120,
        "total_cost_usd": 1.85,
        "timestamp": "2026-04-20T15:30:00Z"
      }
    }
  ]
}
```

#### Custom SWIFT Properties

SWIFT extends SARIF with Phase 3 fields in the `properties` section:

| Property | Type | Description |
|----------|------|-------------|
| risk_score | float | Calculated 0-100 risk score |
| exploitability | float | 0.0-1.0 how easy to exploit |
| business_impact_category | string | Customer data breach, compliance violation, etc. |
| cwe_id | string | Common Weakness Enumeration ID |
| confidence | float | Model confidence (0.0-1.0, always ≥0.95 for output) |

#### GitHub Integration Usage

```bash
# Generate SARIF output
python main.py scan --repo . --output sarif > results.sarif

# Upload to GitHub code scanning
# (automatically detected by GitHub Actions)
# Or manually:
gh code-scanning upload results.sarif --repository owner/repo
```

Once uploaded, findings appear in:
- GitHub **Security** tab → **Code scanning alerts**
- Pull request **Checks** section
- **SARIF viewer** for detailed analysis
- **Trends** dashboard for tracking fixes

#### SARIF Integration Example

```python
from output.sarif import SARIFFormatter
from agent.models import ScanResult

# Run scan
result: ScanResult = scan_codebase(".")

# Format as SARIF
formatter = SARIFFormatter()
sarif_json = formatter.format(result)

# Save and upload
with open("results.sarif", "w") as f:
    f.write(sarif_json)

# GitHub Actions automatically picks this up if in the repo
# Alternatively, upload manually via CLI:
# gh code-scanning upload results.sarif
```

---

### 4. Evidence Bundle Fields

#### Purpose
Extend the Vulnerability model with rich metadata for detailed security analysis, remediation guidance, and reporting.

#### Evidence Bundle Fields

The `Vulnerability` dataclass includes optional fields for comprehensive evidence:

| Field | Type | Description |
|-------|------|-------------|
| cwe_id | str | CWE identifier (e.g., "CWE-89") |
| cwe_url | str | URL to CWE definition on MITRE |
| owasp_category | str | OWASP category (e.g., "A03:2021 – Injection") |
| exploit_description | str | How attacker exploits this vuln |
| exploit_impact | str | What attacker can compromise |
| remediation | str | Recommended fix steps |
| remediation_code | str | Fixed code example |
| remediation_effort | str | LOW/MEDIUM/HIGH effort to fix |
| remediation_time_minutes | int | Estimated time to implement fix |
| affected_code | dict | "before" and "after" code snippets |
| references | list | URLs to security documentation |
| exploitability | float | How easy to exploit (0.0-1.0) |
| business_impact_category | str | Real-world impact category |
| risk_score | float | Calculated risk score (0-100) |

#### Example Evidence Bundle

```python
vulnerability = Vulnerability(
    id="SWIFT-001",
    file_path="auth/views.py",
    line_number=42,
    vuln_type="sql_injection",
    description="User input concatenated into SQL query",
    confidence=0.97,
    severity="CRITICAL",
    code_snippet='query = f"SELECT * FROM users WHERE id={user_id}"',
    
    # Evidence fields
    cwe_id="CWE-89",
    cwe_url="https://cwe.mitre.org/data/definitions/89.html",
    owasp_category="A03:2021 – Injection",
    exploit_description="Attacker injects SQL code via user input to bypass authentication",
    exploit_impact="Complete authentication bypass, account takeover, data access",
    remediation="Use parameterized queries instead of string concatenation",
    remediation_code="""
        prepared = db.prepare("SELECT * FROM users WHERE id=?")
        cursor.execute(prepared, (user_id,))
    """,
    remediation_effort="LOW",
    remediation_time_minutes=5,
    affected_code={
        "before": 'query = f"SELECT * FROM users WHERE id={user_id}"',
        "after": "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
    },
    references=[
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
    ],
    
    # Phase 3 risk fields
    exploitability=0.6,
    business_impact_category="customer_data_breach",
    risk_score=58.2
)
```

#### Auto-Inference

If evidence fields are not provided, SWIFT automatically infers them:

```python
from triage.ranking import RiskScorer

# Auto-infer exploitability from vulnerability type
exploitability = RiskScorer.get_exploitability_score(vuln)
# SQL injection → 0.6 (moderate)
# XSS → 0.9 (trivial)
# Complex auth bypass → 0.4 (specific)

# Auto-infer business impact from context
impact = RiskScorer.get_impact_category(vuln)
# SQL injection in auth → customer_data_breach
# XSS in admin panel → compliance_violation
# DoS → service_disruption
```

---

## Feature Comparison: Phase 1 vs Phase 2 vs Phase 3

| Capability | Phase 1 | Phase 2 | Phase 3 |
|-----------|---------|---------|---------|
| **Individual Vulnerability Detection** | ✓ | ✓ | ✓ |
| **Multi-Step Attack Paths** | ✓ | ✓ | ✓ |
| **Confidence Gate (95%)** | ✓ | ✓ | ✓ |
| **Permission Layer** | | ✓ | ✓ |
| **Forensic Logging** | | ✓ | ✓ |
| **AI Safety Guardrails** | | ✓ | ✓ |
| **Risk Scoring (0-100)** | | | ✓ |
| **Exploitability Assessment** | | | ✓ |
| **Business Impact Quantification** | | | ✓ |
| **GitHub Code Scanning (SARIF)** | | | ✓ |
| **Evidence Bundle** | | | ✓ |
| **Ranked Remediation** | | | ✓ |

---

## Quick Reference: Phase 3 APIs

### Risk Scoring

```python
from triage.ranking import RiskScorer
from agent.models import Vulnerability

# Calculate risk for single vulnerability
vuln: Vulnerability = ...
risk = RiskScorer.calculate_risk_score(vuln)  # 0.0-100.0

# Rank all vulnerabilities by risk
vulns = [...]
ranked = RiskScorer.rank_vulnerabilities(vulns)
# Returns: [(vuln, score), (vuln, score), ...]

# Get impact category
impact = RiskScorer.get_impact_category(vuln)
# "customer_data_breach" | "compliance_violation" | ...

# Get exploitability
exploit = RiskScorer.get_exploitability_score(vuln)
# 0.0-1.0 (0.9=trivial, 0.6=moderate, 0.4=specific, 0.2=complex)
```

### Exploit Chain Detection

```python
from chains.detector import ChainDetector
from agent.models import Vulnerability, ExploitChain

detector = ChainDetector()
chains: List[ExploitChain] = detector.detect_chains(vulnerabilities)

for chain in chains:
    print(f"{chain.name}: {chain.confidence:.0%}")
    for step in chain.attack_steps:
        print(f"  {step.step}. {step.description}")
```

### SARIF Output

```python
from output.sarif import SARIFFormatter
from agent.models import ScanResult

result: ScanResult = scan_codebase(".")
formatter = SARIFFormatter()
sarif_json = formatter.format(result)

# Save or upload to GitHub
with open("results.sarif", "w") as f:
    f.write(sarif_json)
```

---

## Running Scans with Phase 3 Features

```bash
# Basic scan with risk scoring
python main.py scan --repo . --output json

# Output includes:
# - risk_score (0-100)
# - exploitability (0.0-1.0)
# - business_impact_category
# - exploit_chains (if detected)

# Generate SARIF for GitHub
python main.py scan --repo . --output sarif > results.sarif
# Upload to GitHub code scanning (automatic in GitHub Actions)

# View ranked vulnerabilities
python main.py scan --repo . --output json | jq '.vulnerabilities | sort_by(.risk_score) | reverse'
```

---

## Testing Phase 3

```bash
# Unit tests
pytest test/unit/test_ranking.py -v      # Risk scoring
pytest test/unit/test_exploit_chain_detector.py -v       # Chain detection
pytest test/unit/test_sarif.py -v        # SARIF format

# Integration tests
pytest test/integration/ -v

# Full test suite
pytest test/ --cov=swift
```

---

## Architecture Diagram

```
Input (Code Repository)
        ↓
    Triage (Pattern Matching)
        ↓
    Analysis (Sonnet AI Model)
        ↓
    ┌─────────────────────────────────┐
    │  Confirmed Vulnerabilities      │
    │  (≥95% confidence)              │
    └──────────┬────────────────────┬─┘
               ↓                    ↓
        Risk Scoring           Chain Detection
        (Phase 3)              (Phase 1/3)
               ↓                    ↓
        Risk Score             Exploit Chains
        (0-100)                (≥85% conf)
               ↓                    ↓
               └────────┬──────────┘
                        ↓
            Output Formatters
            ├─ JSON (API)
            ├─ Markdown (Reports)
            └─ SARIF (GitHub Scanning)
                        ↓
        GitHub Code Scanning / SIEM Integration
```

---

## Support & Resources

- **Main README:** [../README.md](../README.md)
- **API Reference:** See docstrings in `agent/models.py`, `triage/ranking.py`, `output/sarif.py`
- **Module Documentation:** Each module has a `CLAUDE.md` file
  - `agent/CLAUDE.md` - Pipeline orchestration
  - `scanners/CLAUDE.md` - Vulnerability detection
  - `triage/CLAUDE.md` - Risk scoring framework
  - `output/CLAUDE.md` - Output formatters
- **Testing:** `pytest test/ -v`
- **CI/CD Integration:** See main README

---

**Last Updated:** 2026-04-20  
**SWIFT Version:** 0.1.0  
**Documentation Status:** Complete through Phase 3
