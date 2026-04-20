# SWIFT: Secure-by-Design AI Security Engineering Platform
## Comprehensive Project Documentation

**Version:** 0.1.0  
**Last Updated:** 2026-04-20  
**Status:** Phase 2 Complete, Phase 3 Ready  

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Core Concepts](#core-concepts)
4. [System Components](#system-components)
5. [Data Flow](#data-flow)
6. [API Reference](#api-reference)
7. [Security Model](#security-model)
8. [Usage Guide](#usage-guide)
9. [Configuration](#configuration)
10. [Testing](#testing)
11. [Deployment](#deployment)
12. [Troubleshooting](#troubleshooting)

---

## Project Overview

### What is SWIFT?

SWIFT is an AI-powered vulnerability scanner that:
- **Finds** security flaws in code (SQL injection, command injection, hardcoded secrets, weak crypto, unsafe deserialization)
- **Detects** multi-step exploit chains (sequences of vulnerabilities leading to complete compromise)
- **Verifies** findings with 95%+ confidence (no false positives)
- **Fixes** vulnerabilities automatically (generates patches, tests in isolated sandbox)
- **Logs** every action with tamper-evident forensic audit trail
- **Reports** in multiple formats (JSON, Markdown, SARIF)

### Problem Statement

Traditional vulnerability scanning is:
- **Slow:** Weeks to months per scan
- **Expensive:** $50K+ per full assessment
- **Reactive:** Discovered after deployment
- **Noisy:** High false positive rate
- **Manual:** Requires expert analysis

SWIFT solves this by making vulnerability scanning:
- **Continuous:** Scan on every commit
- **Affordable:** <$2 per full scan
- **Proactive:** Caught before deployment
- **Accurate:** 95% confidence threshold
- **Automated:** AI-driven analysis & patching

### Key Features

1. **Three-Layer Analysis Pipeline** (Triage → Analysis → Patching)
2. **95% Confidence Rule** (No false positives)
3. **Exploit Chain Detection** (Multi-step attacks)
4. **Automatic Patch Generation** (3 candidates per vuln)
5. **Sandbox Testing** (Docker isolation)
6. **Forensic Logging** (Tamper-evident audit trail)
7. **Permission Enforcement** (Central security gate)
8. **AI Safety Monitoring** (Privilege escalation detection)

---

## Architecture

### System Design

```
┌─────────────────────────────────────────────────────────────┐
│                        USER INPUT                           │
│              (CLI, API, GitHub Actions)                     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │   CLI / API Gateway            │
        │   (Click / FastAPI)            │
        └────────────┬───────────────────┘
                     │
        ┌────────────▼───────────────────┐
        │  Permission Layer              │
        │  (Per-op security gate)        │
        └────────────┬───────────────────┘
                     │
        ┌────────────▼───────────────────┐
        │  Forensic Logging              │
        │  (Append-only audit trail)     │
        └────────────┬───────────────────┘
                     │
      ┌──────────────▼──────────────────┐
      │                                 │
      ▼                                 ▼
┌────────────────┐            ┌─────────────────┐
│  TRIAGE        │            │  FILE LOADER    │
│  (Patterns)    │            │  (Git/local)    │
│  [$0.05]       │            └────────┬────────┘
└────────┬───────┘                     │
         │         ┌───────────────────┘
         │         │
         ▼         ▼
   ┌─────────────────────┐
   │  HAIKU SCANNER      │
   │  (Fast flagging)    │
   │  50ms/file [$0.05]  │
   └──────────┬──────────┘
              │
              ▼ (flagged lines only)
   ┌─────────────────────┐
   │  SONNET SCANNER     │
   │  (Deep analysis)    │
   │  3s/location [$0.50]│
   │  (≥95% confidence)  │
   └──────────┬──────────┘
              │
              ▼ (confirmed vulns)
   ┌─────────────────────┐
   │  CHAIN DETECTOR     │
   │  (Multi-step paths) │
   │  (≥85% confidence)  │
   └──────────┬──────────┘
              │
              ├──────────────────┬──────────────┐
              ▼                  ▼              ▼
        ┌─────────────┐  ┌──────────┐  ┌──────────┐
        │ JSON Output │  │  Markdown│  │  SARIF   │
        └─────────────┘  └──────────┘  └──────────┘
              │
              ├─ (Optional: Patch Gen)
              │
              ▼
        ┌────────────────┐
        │ PATCH GENERATOR│
        │ (3 candidates) │
        └────────┬───────┘
                 │
                 ▼
        ┌────────────────┐
        │  SANDBOX TEST  │
        │  (Docker)      │
        └────────┬───────┘
                 │
                 ▼
        ┌────────────────┐
        │  Patched Output│
        └────────────────┘
```

### Component Layers

#### Layer 1: Input & Validation
- **CLI** (Click): Command-line interface
- **API** (FastAPI): REST API for integrations
- **File Loader** (Git/local): Code source handling
- **Permission Gate** (Central): All operations validated

#### Layer 2: Security & Logging
- **Permission Enforcement** (PermissionLayer): Per-operation rules
- **Forensic Logging** (ForensicLogger): Append-only audit trail
- **AI Safety Monitor** (SafetyMonitor): Behavior validation

#### Layer 3: Analysis Pipeline
- **Triage** (Regex patterns): Fast, cheap, broad filter (~1ms/file)
- **Haiku Scanner** (Claude Haiku): Fast flagging (50ms/file)
- **Sonnet Scanner** (Claude Sonnet): Deep reasoning (3s/location)
- **Chain Detector** (Multi-step analysis): Attack path reasoning

#### Layer 4: Output & Integration
- **JSON Formatter**: Structured output for APIs
- **Markdown Formatter**: Human-readable reports
- **SARIF Formatter**: GitHub Advanced Security format
- **Storage** (File/DB): Results persistence

#### Layer 5: Remediation (Optional)
- **Patch Generator**: 3 candidate patches per vuln
- **Sandbox** (Docker): Isolated testing environment
- **Diff Generator**: Unified diffs for review

---

## Core Concepts

### The 95% Confidence Rule

**Golden Rule:** Only output findings with confidence ≥ 95%.

```python
if vulnerability.confidence >= 0.95:
    output_finding(vulnerability)  # Include in report
else:
    log_low_confidence(vulnerability)  # Log but suppress
```

**Why?**
- Prevents false positives
- Builds user trust
- Guides all code decisions
- Low-confidence findings logged, not reported

**Examples:**
- SQL injection with obvious unsanitized input → 98% confidence → **Output**
- SQL injection with complex validation logic → 67% confidence → **Log only**
- Command injection in shell script → 91% confidence → **Log only** (below gate)

### Exploit Chain Detection

**Definition:** Multi-step attack path connecting multiple vulnerabilities.

**Example:**
```
Entry Point: SQL Injection in login form (SWIFT-001)
    ↓ Escalation: Bypass authentication check
    ↓ Escalation: Access admin panel (SWIFT-003)
    ↓ Final Impact: Full admin access without credentials
Severity: CRITICAL
Confidence: 0.91 (≥0.85 threshold)
```

**How It Works:**
1. Sonnet analyzes confirmed vulnerabilities
2. Builds attack graph (connections between vulns)
3. Finds paths from entry → final impact
4. Ranks by severity + exploitability
5. Outputs chains ≥0.85 confidence

### Cost Discipline

**Target:** <$2 per full scan

**Breakdown:**
- **Regex Triage:** ~$0 (pattern matching)
- **Haiku Scanner:** ~$0.05/file (50ms, fast flagging)
- **Sonnet Scanner:** ~$0.50/flagged location (deep analysis)
- **Chain Detection:** ~$0.10/confirmed vuln (attack path reasoning)
- **Total:** Variable, typically $0.50-$2.00 per scan

**Optimization:**
- Regex filters 60% of code as safe (no API cost)
- Haiku flags suspicious lines (~40% of code)
- Sonnet analyzes flagged only (~5% of code)
- Cost scales with code complexity, not linearly with size

### Permission Model

**Concept:** Central gate validates all operations.

```python
# Before any tool call:
if not permissions.can(operation, parameters):
    raise PermissionDenied(operation, reason)

# Examples:
permissions.can("scan", {"repo": "/path/to/code", "size": 50_000_000})
# → False if repo >100MB

permissions.can("patch", {"model": "opus"})
# → False if model not in whitelist

permissions.can("sandbox", {"timeout": 120})
# → False if timeout > 60 seconds
```

**Rules Enforced:**
- File size limits (no scanning 1GB+ repos)
- API model whitelist (Haiku, Sonnet only)
- Timeout limits (30s max per operation)
- Rate limits (API quota protection)

### Forensic Logging

**Concept:** Tamper-evident audit trail using hash chains.

**Structure:**
```json
{
  "entry_id": "LOG-001",
  "timestamp": "2026-04-20T12:00:00Z",
  "tool": "HaikuScanner",
  "action": "scan_file",
  "inputs": {"file": "app.py", "size": 1024},
  "outputs": {"flags": 3, "cost": 0.05},
  "previous_hash": "sha256(LOG-000)",
  "hash": "sha256(this entry)"
}
```

**Properties:**
- Append-only (no deletion, modification)
- Hash chain links all entries
- Tamper detection: verify hash(current) matches stored hash
- Queryable: find entries by tool, action, timestamp

**Use Cases:**
- Compliance audits
- Incident investigation
- Cost tracking
- Security monitoring

---

## System Components

### 1. Triage Module (`triage/`)

**Purpose:** Fast, cheap pattern matching to filter obvious code.

**Implementation:** Regex patterns for common vulnerability patterns.

**Patterns:**
- SQL injection: Unquoted concatenation, f-strings in queries
- Command injection: Unquoted shell arguments, os.popen
- Hardcoded secrets: API keys, passwords in strings
- Weak crypto: MD5, DES, unsalted hashing
- Unsafe deserialization: pickle.loads, yaml.load(unsafe=True)

**Cost:** ~$0 (local processing)  
**Speed:** ~1ms/file  
**Output:** List of (file, line, pattern_type)

**Files:**
- `triage/detector.py` → Main pattern matcher
- `triage/patterns.py` → Pattern definitions
- `test/unit/test_triage.py` → 12 tests

### 2. Haiku Scanner (`scanners/haiku.py`)

**Purpose:** Fast confirmation of suspicious lines using Claude Haiku.

**Process:**
1. Receives flagged lines from triage
2. Sends each line to Haiku with context
3. Haiku returns: is_vulnerable (yes/no/maybe)
4. ~40% of flags filtered out (false positives)
5. Remaining sent to Sonnet

**Cost:** ~$0.05/file  
**Speed:** 50ms/file  
**Confidence:** ~70% (filters false positives)

**Prompt Style:**
```
You are a security expert. Is this line vulnerable?
[code snippet]
Return: VULNERABLE, SAFE, or UNCLEAR
```

**Files:**
- `scanners/haiku_scanner.py` → Main scanner
- `scanners/prompts.py` → Haiku prompts
- `test/unit/test_haiku_scanner.py` → 18 tests

### 3. Sonnet Scanner (`scanners/sonnet.py`)

**Purpose:** Deep reasoning to confirm vulnerabilities with 95%+ confidence.

**Process:**
1. Receives flagged lines from Haiku
2. Sends full function context to Sonnet
3. Sonnet analyzes: vulnerability type, CWE, exploit path, remediation
4. Returns: confidence score, severity, exploitation details
5. Only outputs findings ≥95% confidence

**Cost:** ~$0.50/location  
**Speed:** ~3s/location  
**Confidence:** ≥95% (gate enforced)

**Prompt Style:**
```
You are a security expert. Analyze this code for vulnerabilities.
[function context]
Return JSON with:
- vulnerability_type: (type)
- confidence: (0.0-1.0)
- cwe_id: (CWE-XXX)
- exploit_description: (how attacker exploits)
- remediation: (fix)
```

**Files:**
- `scanners/sonnet_scanner.py` → Main scanner
- `scanners/prompts.py` → Sonnet prompts
- `agent/models.py` → Vulnerability dataclass
- `test/unit/test_sonnet_scanner.py` → 22 tests

### 4. Chain Detector (`chains/detector.py`)

**Purpose:** Find multi-step exploit paths connecting vulnerabilities.

**Process:**
1. Receives confirmed vulnerabilities
2. Analyzes relationships between vulns
3. Builds attack graph
4. Finds paths: entry_point → escalations → impact
5. Ranks by exploitability + severity
6. Returns chains ≥85% confidence

**Cost:** ~$0.10/confirmed vuln  
**Speed:** ~2s/chain  
**Confidence:** ≥0.85 (lower than vulns, chains harder to confirm)

**Example Chain:**
```
Entry: SQL Injection (SWIFT-001)
  ├─ Escalation: Bypass authentication
  ├─ Escalation: Access admin panel
  └─ Impact: Full admin access without credentials
Confidence: 0.91
```

**Files:**
- `chains/detector.py` → Main detector
- `agent/models.py` → ExploitChain dataclass
- `test/unit/test_exploit_chain_detector.py` → 10 tests

### 5. Patch Generator (`patches/generator.py`)

**Purpose:** Generate, score, and select best patch for each vulnerability.

**Process:**
1. Receives confirmed vulnerability + code context
2. Generates 3 patch candidates using Sonnet
3. Evaluates: correctness, security, maintainability
4. Returns ranked patches with diffs
5. Sandbox-tests top candidate

**Cost:** ~$0.20/vuln (3 candidates × $0.05 + scoring)  
**Speed:** ~10s/vuln  
**Confidence:** Variable (depends on vuln complexity)

**Patch Ranking:**
- **Security:** Does fix address root cause? (40%)
- **Correctness:** Will it break existing code? (30%)
- **Maintainability:** Is it readable? (20%)
- **Performance:** Does it impact speed? (10%)

**Files:**
- `patches/generator.py` → Patch generation
- `patches/scorer.py` → Patch evaluation
- `test/unit/test_patch_generator.py` → 15 tests

### 6. Sandbox (`sandbox/docker.py`)

**Purpose:** Isolated testing of patches.

**Environment:**
- Docker container
- Network disabled (--network=none)
- Read-only filesystem (except /tmp)
- Resource limits: 2 CPU, 2GB RAM
- 30-second timeout

**Process:**
1. Copy patched code to container
2. Run original + patch through test suite
3. Compare results
4. Return: test_passed, execution_time, output_diff

**Safety Guarantees:**
- No network access (prevents data exfiltration)
- Read-only root (prevents persistence)
- Timeout (prevents infinite loops)
- Resource limits (prevents resource exhaustion)

**Files:**
- `sandbox/docker.py` → Docker orchestration
- `sandbox/runner.py` → Test execution
- `test/unit/test_sandbox.py` → 8 tests

### 7. CLI (`cli/commands.py`)

**Purpose:** Command-line interface for SWIFT.

**Commands:**
```bash
# Scan a repository
swift scan --repo /path/to/code --output json

# Generate patches
swift scan --repo /path/to/code --patches --output json

# Export as Markdown
swift scan --repo /path/to/code --output markdown > report.md

# Run tests
swift test --unit --integration
```

**Arguments:**
- `--repo` → Path to code repository
- `--output` → Format (json, markdown, sarif)
- `--patches` → Generate patches (optional)
- `--timeout` → Scan timeout in seconds (default: 300)
- `--confidence` → Minimum confidence (default: 0.95)

**Files:**
- `cli/commands.py` → Main CLI
- `cli/validators.py` → Argument validation
- `test/unit/test_cli.py` → 16 tests

### 8. Output Formatters (`output/`)

#### JSON Formatter (`output/json.py`)
Structure: Scan metadata + vulnerabilities + chains + patches
```json
{
  "scan": {"id": "SCAN-001", "repo": "...", "duration": 120, "cost": 1.23},
  "summary": {"files_scanned": 42, "vulnerabilities_found": 5},
  "vulnerabilities": [{...}],
  "exploit_chains": [{...}],
  "patches": [{...}]
}
```

#### Markdown Formatter (`output/markdown.py`)
Structure: Metadata + summary + detailed sections
```markdown
# SWIFT Vulnerability Report
## Scan Metadata
- Repository: ...
- Files Scanned: 42
- Vulnerabilities Found: 5

## Vulnerabilities
[Detailed list with code snippets]

## Exploit Chains
[Attack paths with severity]

## Patches
[Patched code with diffs]
```

#### SARIF Formatter (`output/sarif.py`)
Structure: GitHub Advanced Security format
```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "SWIFT"}},
      "results": [
        {"ruleId": "CWE-89", "level": "error", "locations": [...]}
      ]
    }
  ]
}
```

### 9. Security Controls

#### Permission Enforcement (`security/permissions.py`)
**Purpose:** Central gate for all operations.

**Rules:**
```python
PERMISSIONS = {
    "scan": {
        "max_file_size": 100_000_000,  # 100MB
        "allowed_models": ["haiku", "sonnet"],
        "rate_limit": "100 scans/hour"
    },
    "patch": {
        "allowed_models": ["sonnet"],
        "requires_sandbox_test": True,
        "max_timeout": 60
    },
    "sandbox": {
        "max_concurrent": 5,
        "max_timeout": 30,
        "max_memory": 2_000_000_000  # 2GB
    }
}
```

**Files:**
- `security/permissions.py` → Permission layer
- `test/unit/test_security_permissions.py` → 14 tests

#### Forensic Logging (`security/logging.py`)
**Purpose:** Tamper-evident audit trail.

**Features:**
- Append-only (immutable after write)
- Hash chain (each entry signs previous)
- Queryable (JSON format)
- Structured (tool, action, inputs, outputs)

**Files:**
- `security/logging.py` → Logger implementation
- `test/unit/test_security_logging.py` → 13 tests

#### AI Safety Monitor (`security/safety_monitor.py`)
**Purpose:** Detect unsafe agent behavior.

**Monitors:**
1. Privilege escalation (attempting elevated permissions)
2. Hidden reasoning (contradictions between stated/actual intent)
3. Unauthorized actions (bypassing permission checks)

**Response:** Halt execution immediately, log violation.

**Files:**
- `security/safety_monitor.py` → Safety monitor
- `test/unit/test_security_safety_monitor.py` → 8 tests

### 10. Orchestrator (`agent/orchestrator.py`)

**Purpose:** Coordinate entire analysis pipeline.

**Workflow:**
```python
def scan_codebase(repo: str) -> ScanResult:
    # 1. Load and validate repository
    files = load_code_files(repo)
    
    # 2. Triage: Fast filtering
    flagged = triage_patterns(files)  # Cost: ~$0
    
    # 3. Haiku: Fast confirmation
    confirmed_haiku = haiku_scan(flagged)  # Cost: ~$0.05/file
    
    # 4. Sonnet: Deep reasoning
    vulnerabilities = sonnet_scan(confirmed_haiku)  # Cost: ~$0.50/vuln
    
    # 5. Chain Detection: Multi-step analysis
    chains = detect_chains(vulnerabilities)  # Cost: ~$0.10/chain
    
    # 6. Optional: Patch Generation
    if generate_patches:
        patches = generate_patches(vulnerabilities)  # Cost: ~$0.20/vuln
        patches = sandbox_test(patches)  # Cost: ~$0.05/patch
    
    # 7. Format outputs
    return ScanResult(
        vulnerabilities=vulnerabilities,
        chains=chains,
        patches=patches,
        cost=total_cost,
        duration=elapsed
    )
```

**Files:**
- `agent/orchestrator.py` → Main orchestrator
- `agent/models.py` → Data models (Vulnerability, Chain, Patch, etc.)
- `test/integration/test_scan_pipeline.py` → 12 integration tests

---

## Data Flow

### Full Scan Workflow

```
1. USER INPUT
   └─ CLI: swift scan --repo /path/to/code --output json

2. VALIDATION & PERMISSION CHECK
   ├─ Validate repo exists and readable
   ├─ Check file size limits
   └─ Log request in forensic trail

3. FILE LOADING
   ├─ Discover code files (.py, .js, .ts, .java, etc.)
   ├─ Filter non-code files
   └─ Load into memory

4. TRIAGE (Phase 1)
   ├─ Apply regex patterns to all files
   ├─ Mark suspicious lines
   └─ Cost: ~$0

5. HAIKU SCANNING (Phase 2a)
   ├─ Send flagged lines to Claude Haiku
   ├─ Filter ~40% as false positives
   ├─ Log results in forensic trail
   └─ Cost: ~$0.05/file

6. SONNET SCANNING (Phase 2b)
   ├─ Send Haiku-confirmed lines to Claude Sonnet
   ├─ Deep reasoning + CWE analysis
   ├─ Apply 95% confidence gate
   ├─ Log results in forensic trail
   └─ Cost: ~$0.50/vuln

7. CHAIN DETECTION (Phase 3.5)
   ├─ Analyze relationships between vulns
   ├─ Find multi-step attack paths
   ├─ Apply 85% confidence gate
   ├─ Log results in forensic trail
   └─ Cost: ~$0.10/chain

8. OPTIONAL: PATCH GENERATION (Phase 4)
   ├─ Generate 3 candidates per vuln (Sonnet)
   ├─ Score and rank patches
   ├─ Test in Docker sandbox
   ├─ Log results in forensic trail
   └─ Cost: ~$0.20/vuln

9. OUTPUT FORMATTING
   ├─ JSON (for APIs)
   ├─ Markdown (for humans)
   └─ SARIF (for GitHub)

10. RESULTS RETURNED
    ├─ Vulnerabilities with CWE/severity/remediation
    ├─ Exploit chains
    ├─ Patches (if enabled)
    ├─ Cost summary
    └─ Duration summary
```

### State Transitions

```
File
  ├─ UNTRIAGED → TRIAGE FLAGGED (regex match)
  ├─ TRIAGE FLAGGED → HAIKU CONFIRMED (Haiku analysis)
  ├─ HAIKU CONFIRMED → SONNET ANALYZED (Sonnet deep reasoning)
  ├─ SONNET ANALYZED → CONFIDENCE GATE (≥95% check)
  │  ├─ PASS → VULNERABILITY (output)
  │  └─ FAIL → LOW CONFIDENCE (logged, suppressed)
  ├─ VULNERABILITY → CHAIN ANALYZED (relationship analysis)
  ├─ VULNERABILITY → PATCH GENERATED (optional, 3 candidates)
  └─ PATCH GENERATED → SANDBOX TESTED (Docker isolation)
```

---

## API Reference

### Orchestrator API

#### `scan_codebase(repo_path: str, generate_patches: bool = False) -> ScanResult`

Scans repository for vulnerabilities, chains, and optionally patches.

**Parameters:**
- `repo_path` (str): Path to repository
- `generate_patches` (bool): Generate patches? Default: False

**Returns:** ScanResult object containing:
- `vulnerabilities` (List[Vulnerability])
- `exploit_chains` (List[ExploitChain])
- `patches` (List[Patch]) if patches enabled
- `total_cost_usd` (float)
- `duration_seconds` (float)

**Example:**
```python
from agent.orchestrator import scan_codebase

result = scan_codebase("/path/to/repo", generate_patches=True)
print(f"Found {len(result.vulnerabilities)} vulns")
print(f"Cost: ${result.total_cost_usd:.2f}")
```

### Scanner APIs

#### Haiku Scanner

```python
from scanners.haiku_scanner import HaikuTriageScanner

scanner = HaikuTriageScanner()
flagged_lines = [(file, line_no, code)]
confirmed = scanner.scan(flagged_lines)  # Returns: List[Tuple[str, int, bool]]
```

#### Sonnet Scanner

```python
from scanners.sonnet_scanner import SonnetAnalysisScanner

scanner = SonnetAnalysisScanner()
confirmed = [(file, line_no, code)]
vulns = scanner.scan(confirmed)  # Returns: List[Vulnerability]
```

### Permission API

```python
from security.permissions import PermissionLayer, Permission

perms = PermissionLayer()

# Check permission
can_scan = perms.can(Permission.SCAN, {"repo": repo, "size": file_size})
if not can_scan:
    raise PermissionDenied("Repo too large")

# Enforce permission
perms.enforce(Permission.PATCH, {"model": "sonnet"})  # Raises if denied
```

### Logging API

```python
from security.logging import ForensicLogger

logger = ForensicLogger(log_file="log/swift.log")

# Log action
logger.log(
    tool="HaikuScanner",
    action="scan_file",
    inputs={"file": "app.py"},
    outputs={"flags": 3}
)

# Verify log integrity
is_valid = logger.verify_chain()
print(f"Log integrity: {is_valid}")
```

---

## Security Model

### Threat Model

**Threats Addressed:**
1. **Code Injection:** Attackers control inputs
2. **Privilege Escalation:** Unauthorized permission grants
3. **Audit Tampering:** Modification/deletion of logs
4. **Unsafe Agent Behavior:** AI making unauthorized decisions
5. **Resource Exhaustion:** DoS via infinite loops/memory

### Defense Mechanisms

#### 1. Permission Enforcement (Threat #2, #5)
- Central gate validates all operations
- Per-operation rules (file size, model whitelist, timeout)
- Unauthorized operations raise PermissionDenied
- Protects against privilege escalation + resource exhaustion

#### 2. Forensic Logging (Threat #3)
- Append-only audit trail (no deletion)
- Hash chain links all entries
- Tamper detection via SHA256 verification
- Protects against audit tampering

#### 3. AI Safety Monitor (Threat #2, #4)
- Detects privilege escalation attempts
- Detects hidden reasoning (contradictions)
- Detects unauthorized tool calls
- Halts execution immediately on violation

#### 4. Sandbox Isolation (Threat #1, #5)
- Docker container with restrictions
- Network disabled (no data exfiltration)
- Read-only root (no persistence)
- Resource limits (no exhaustion)
- 30-second timeout (no infinite loops)

#### 5. Confidence Gates (Threat #1)
- 95% confidence threshold for vulns (no false positives)
- 85% confidence threshold for chains
- Suppresses low-confidence findings
- Prevents reporting unverified claims

### Compliance Features

- **Audit Trail:** Append-only, tamper-evident logs
- **Access Control:** Permission enforcement per operation
- **Isolation:** Sandbox testing prevents contamination
- **Traceability:** Every action logged with timestamp + actor
- **Integrity:** Hash chain prevents tampering

---

## Usage Guide

### Installation

```bash
# Clone repository
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirement.txt
```

### Configuration

Create `.env` file:
```bash
# Anthropic API configuration
ANTHROPIC_API_KEY=sk-ant-...

# Optional settings
SWIFT_CONFIDENCE_THRESHOLD=0.95
SWIFT_CHAIN_CONFIDENCE_THRESHOLD=0.85
SWIFT_MAX_FILE_SIZE=100000000  # 100MB
SWIFT_SANDBOX_TIMEOUT=30
SWIFT_SANDBOX_MEMORY=2000000000  # 2GB
```

### Basic Usage

#### Scan a Repository

```bash
# Scan with JSON output
swift scan --repo /path/to/code --output json > report.json

# Scan with Markdown output
swift scan --repo /path/to/code --output markdown > report.md

# Generate patches (optional)
swift scan --repo /path/to/code --patches --output json
```

#### Programmatic Usage

```python
from agent.orchestrator import scan_codebase

# Scan repository
result = scan_codebase("/path/to/repo", generate_patches=True)

# Access findings
for vuln in result.vulnerabilities:
    print(f"{vuln.vuln_type} in {vuln.file_path}:{vuln.line_number}")
    print(f"  Severity: {vuln.severity}")
    print(f"  Confidence: {vuln.confidence:.2%}")
    print(f"  Remediation: {vuln.remediation}")
    print()

# Access chains
for chain in result.exploit_chains:
    print(f"Chain: {chain.name}")
    print(f"  Entry: {chain.entry_point}")
    print(f"  Impact: {chain.impact}")
    print(f"  Confidence: {chain.confidence:.2%}")
    print()

# Access patches
if result.patches:
    for patch in result.patches:
        print(f"Patch for {patch.vuln_id}")
        print(f"  Score: {patch.score:.2%}")
        print(patch.diff)
        print()
```

### Advanced: Custom Scanners

Extend SWIFT with custom vulnerability types:

```python
from scanners.sonnet_scanner import SonnetAnalysisScanner
from agent.models import Vulnerability

class CustomScanner(SonnetAnalysisScanner):
    def scan(self, flagged_lines):
        # Custom analysis logic
        vulns = super().scan(flagged_lines)
        
        # Add custom checks
        for vuln in vulns:
            if "custom_pattern" in vuln.code_snippet:
                vuln.custom_field = "custom_value"
        
        return vulns
```

### Running Tests

```bash
# Unit tests
pytest test/unit/ -v --cov=swift

# Integration tests
pytest test/integration/ -v

# All tests
pytest test/ -v --cov=swift

# Specific test
pytest test/unit/test_sonnet_scanner.py -v
```

---

## Configuration

### Environment Variables

```bash
# API Configuration
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_TIMEOUT=300

# Security Settings
SWIFT_CONFIDENCE_THRESHOLD=0.95              # Min confidence for vulns
SWIFT_CHAIN_CONFIDENCE_THRESHOLD=0.85        # Min confidence for chains
SWIFT_ENABLE_PATCHES=true                    # Enable patch generation

# Resource Limits
SWIFT_MAX_FILE_SIZE=100000000                # Max file size (bytes)
SWIFT_MAX_SCAN_DURATION=300                  # Max scan time (seconds)
SWIFT_MAX_CONCURRENT_SCANS=5                 # Concurrent scans

# Sandbox Settings
SWIFT_SANDBOX_TIMEOUT=30                     # Max sandbox time (seconds)
SWIFT_SANDBOX_MEMORY=2000000000              # Sandbox memory limit (bytes)
SWIFT_SANDBOX_CPU=2                          # CPU limit (cores)

# Logging
SWIFT_LOG_LEVEL=INFO                         # Logging level
SWIFT_LOG_FILE=log/swift.log                 # Log file path
```

### pyproject.toml

```toml
[build-system]
requires = ["setuptools>=68"]

[project]
name = "swift"
version = "0.1.0"
requires-python = ">=3.10"

[project.scripts]
swift = "cli.commands:cli"
```

---

## Testing

### Test Strategy

**Unit Tests (188):** Mock Claude API, test logic in isolation  
**Integration Tests (46):** Test components together, validate workflows  
**E2E Tests (Optional):** Full scan on real vulnerable repo

### Running Tests

```bash
# All tests with coverage
pytest test/ -v --cov=swift

# Unit only
pytest test/unit/ -v

# Integration only
pytest test/integration/ -v

# Single test file
pytest test/unit/test_sonnet_scanner.py -v

# Single test
pytest test/unit/test_sonnet_scanner.py::test_confidence_gate -v
```

### Test Coverage

```
swift/
├── agent/          95%  (models + orchestrator)
├── scanners/       92%  (haiku + sonnet)
├── chains/         90%  (detector)
├── patches/        88%  (generator + scorer)
├── sandbox/        85%  (docker testing)
├── security/       91%  (permissions + logging + safety)
├── cli/            87%  (commands)
├── output/         89%  (formatters)
└── triage/         94%  (patterns)

Total Coverage: 90%+
```

### Mocking Strategy

**Claude API Mocking:**
```python
from unittest.mock import patch, MagicMock

@patch("anthropic.Anthropic.messages.create")
def test_haiku_scan(mock_create):
    mock_create.return_value = MagicMock(
        content=[MagicMock(text="VULNERABLE")]
    )
    # Test logic
```

**Docker Mocking:**
```python
@patch("docker.from_env")
def test_sandbox(mock_docker):
    mock_container = MagicMock()
    mock_docker.return_value.containers.run.return_value = mock_container
    mock_container.logs.return_value = b"test output"
    # Test logic
```

---

## Deployment

### Prerequisites

- Python 3.10+
- Docker (for sandbox testing)
- Anthropic API key
- 2GB+ RAM
- 10GB+ disk space

### Local Deployment

```bash
# Setup
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirement.txt

# Configure
cp .env.example .env
# Edit .env with API key

# Test
pytest test/ -v

# Run
swift scan --repo /path/to/code --output json
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install -r requirement.txt
ENV ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}

ENTRYPOINT ["swift"]
CMD ["scan", "--repo", "/scan-target", "--output", "json"]
```

### CI/CD Integration

**GitHub Actions:**
```yaml
name: SWIFT Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r swift/requirement.txt
      - run: swift scan --repo . --output json > report.json
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: report.json
```

---

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'swift'"

**Cause:** Package not installed, import paths incorrect  
**Solution:**
```bash
# Install package (not in editable mode)
pip install -e .

# Or use relative imports from within swift/ directory
cd swift
python -m pytest test/
```

### Issue: "PermissionDenied: Repo too large"

**Cause:** Repository exceeds 100MB limit  
**Solution:**
```bash
# Increase limit in .env
SWIFT_MAX_FILE_SIZE=500000000  # 500MB

# Or scan specific directories
swift scan --repo /path/to/code/src --output json
```

### Issue: "Timeout waiting for Sonnet response"

**Cause:** API timeout or network latency  
**Solution:**
```bash
# Increase timeout in .env
ANTHROPIC_TIMEOUT=600  # 10 minutes

# Or reduce repo size
swift scan --repo /path/to/subset --output json
```

### Issue: "Docker daemon not running"

**Cause:** Sandbox testing requires Docker  
**Solution:**
```bash
# Start Docker
docker daemon

# Or disable patching (skip sandbox)
swift scan --repo /path/to/code --output json  # (no --patches flag)
```

### Issue: "Test failure: AssertionError in test_confidence_gate"

**Cause:** Model response changed, confidence calculation off  
**Solution:**
```bash
# Review mock response in test
vim test/unit/test_sonnet_scanner.py

# Update mock to match current behavior
# Rerun test
pytest test/unit/test_sonnet_scanner.py::test_confidence_gate -v
```

---

## Monitoring & Observability

### Metrics to Track

- **Scans:** Count, avg duration, cost distribution
- **Vulnerabilities:** By type, severity, confidence
- **Patches:** Generated, tested, accepted
- **Costs:** Total, per file, per scan
- **Performance:** Triage time, Haiku latency, Sonnet latency

### Logging

Structured JSON logs in `log/swift.log`:
```json
{
  "timestamp": "2026-04-20T12:00:00Z",
  "level": "INFO",
  "tool": "HaikuScanner",
  "action": "scan_file",
  "inputs": {"file": "app.py"},
  "outputs": {"flags": 3},
  "duration_ms": 45,
  "cost_usd": 0.05
}
```

### Health Checks

```bash
# Check API connectivity
curl -X GET https://api.anthropic.com/health

# Verify Docker
docker ps

# Test scan (small repo)
swift scan --repo /tmp/test-code --output json
```

---

## Roadmap

### Phase 1 ✅ Complete
- [x] Exploit chain detection
- [x] Language-aware prompts
- [x] CWE identification
- [x] Exploit description generation

### Phase 2 ✅ Complete
- [x] Permission enforcement
- [x] Forensic logging
- [x] AI safety monitoring
- [x] Hash chain tamper detection

### Phase 3 🚀 Ready
- [ ] Evidence bundle (CWE + exploit + remediation)
- [ ] SARIF output (GitHub Advanced Security)
- [ ] Enhanced triage ranking (severity × exploitability × confidence × impact)
- [ ] API endpoint (`/scan/{id}/evidence`)

### Phase 4 (Future)
- [ ] Performance optimization
- [ ] Batch scanning
- [ ] GitHub Actions integration
- [ ] CI/CD plugins (Jenkins, GitLab)
- [ ] Web UI for reporting

---

## Contributing

### Development Workflow

```bash
# Create feature branch
git checkout -b feature/your-feature

# Write tests first (TDD)
pytest test/unit/test_your_feature.py

# Implement feature
vim swift/your_module.py

# Run all tests
pytest test/ -v --cov=swift

# Format code
black swift/

# Commit
git commit -m "feat: add your feature"

# Push and open PR
git push origin feature/your-feature
```

### Code Standards

- ✅ Type hints on every function
- ✅ Google-style docstrings
- ✅ PEP 8 compliant
- ✅ 90%+ test coverage
- ✅ No secrets in code

---

## License

MIT License — see LICENSE file

---

## Contact & Support

**GitHub:** https://github.com/jellaharshith/SWIFT  
**Issues:** https://github.com/jellaharshith/SWIFT/issues  
**Security:** security@SWIFT.dev

---

## Appendix: Data Models

### Vulnerability

```python
@dataclass
class Vulnerability:
    id: str  # SWIFT-001
    file_path: str
    line_number: int
    vuln_type: str  # sql_injection, command_injection, etc.
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float  # 0.0-1.0, gated at ≥0.95
    cwe_id: str  # CWE-89
    exploit_description: str  # How attacker exploits
    remediation: str  # How to fix
    code_snippet: str  # Vulnerable code
```

### ExploitChain

```python
@dataclass
class ExploitChain:
    id: str  # CHAIN-001
    name: str  # "SQL Injection → Auth Bypass → Admin Access"
    vulnerability_ids: List[str]  # [SWIFT-001, SWIFT-003]
    entry_point: str  # auth/views.py:42
    attack_path: str  # Step-by-step description
    impact: str  # "Full admin access without credentials"
    severity: str  # CRITICAL, HIGH, etc.
    confidence: float  # 0.0-1.0, gated at ≥0.85
```

### Patch

```python
@dataclass
class Patch:
    id: str  # PATCH-001
    vuln_id: str  # SWIFT-001
    file_path: str
    original_code: str
    patched_code: str
    diff: str  # Unified diff
    score: float  # Patch quality score (0.0-1.0)
    sandbox_tested: bool  # Did it pass tests?
    test_results: Optional[str]  # Test output
```

---

**End of Documentation**
