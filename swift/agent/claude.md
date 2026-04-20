# SWIFT: agent/claude.md

## Purpose

Orchestrate the complete scanning pipeline: triage → analysis → patching → validation.

## Core Function: scan_codebase()

```python
def scan_codebase(repo_path: str, config: Config) -> ScanResult
```

**Input:** Repository path (local or GitHub URL)  
**Process:**

1. Load code, detect languages
2. Haiku triage: flag suspicious patterns (~50ms/file, $0.05)
3. Sonnet analysis: deep reasoning on flagged (~3s/location, confidence ≥95%)
4. Detect exploit chains: can vulns be combined into attacks?
5. Generate patches: 3 candidates per vulnerability
6. Test patches: sandbox validation

**Output:** `ScanResult` with vulnerabilities, patches, chains

**Critical:** Only output findings with confidence ≥ 95%

## Core Function: generate_patches()

```python
def generate_patches(vulnerabilities: List[Vulnerability]) -> List[Patch]
```

**Input:** Confirmed vulnerabilities (≥95% confidence)  
**Output:** List of `Patch` objects with unified diffs, reasoning, test results

**Skip if:** Vulnerability confidence < 90%

## Data Structures

```python
@dataclass
class Vulnerability:
    id: str              # "SWIFT-001"
    title: str           # "SQL Injection"
    severity: str        # "critical" | "high" | "medium" | "low"
    confidence: float    # 0.0-1.0, only output if >= 0.95
    file: str
    line: int
    code_snippet: str
    cwe_id: str          # "CWE-89"
    exploit_description: str
    remediation: str

@dataclass
class Patch:
    id: str              # "PATCH-001"
    vuln_id: str
    original_code: str
    patched_code: str
    diff: str            # Unified diff format
    reasoning: str
    sandbox_tested: bool
    test_passed: bool
    test_logs: str

@dataclass
class ScanResult:
    scan_id: str
    timestamp: str
    repository: str
    duration_seconds: float
    vulnerabilities: List[Vulnerability]
    patches: List[Patch]
    summary: Dict        # {total, by_severity, patches_passed}
```

## Workflow Example

```python
from agent import scan_codebase
from config import CONFIG
from output import format_output

# Scan
result = scan_codebase("https://github.com/user/project", CONFIG)

# Verify 95% rule
for vuln in result.vulnerabilities:
    assert vuln.confidence >= 0.95  # Non-negotiable

# Output
print(format_output(result, "json"))
```

## Implementation Notes

- **API Calls:** Use Haiku for triage, Sonnet for analysis (cost optimization)
- **Retries:** Implement exponential backoff on API errors (3 attempts)
- **Logging:** Log every step (triage phase, analysis phase, patch phase)
- **Error Handling:** Catch and log all errors; never crash silently
- **Cost Tracking:** Record tokens, cost, and time per scan (log module)

## Testing

```bash
# Unit test (mock API)
pytest test/unit/test_agent.py -v

# Integration test (real API, gated)
pytest test/integration/test_scan_pipeline.py -v

# E2E test (real repo, real vulns)
SWIFT_RUN_E2E=1 pytest test/e2e/test_real_vulnerabilities.py -v
```

## Key Commands

```bash
# Test orchestration
python -c "from agent import scan_codebase; result = scan_codebase('./test-repo'); print(result)"

# Full pipeline
python main.py scan --repo . --output json
```

---

**Location:** `swift/agent/claude.md`  
**Depends on:** scanners, patches, sandbox, config, log  
**Is depended on by:** cli, main.py
