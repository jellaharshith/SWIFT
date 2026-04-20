# SWIFT: scanners/claude.md

## Purpose

Find vulnerabilities using two-stage pipeline: Haiku (fast, cheap) → Sonnet (deep, strict).

## Why Two Stages?

- **Haiku:** $0.05/file, 50ms, 80% confidence (broad filter)
- **Sonnet:** $0.50/location, 3s, 95%+ confidence (strict verification)
- **Result:** 4x cheaper than Sonnet on all code

## Stage 1: HaikuTriageScanner

```python
def scan_file(file_path: str, content: str) -> Set[int]
```

**Input:** Source code  
**Output:** Set of flagged line numbers  
**Speed:** ~50ms per file  
**Cost:** ~$0.05 per file  
**Confidence:** 80%+ (permissive, catches false positives)

**Patterns flagged:**

- SQL injection: `f"SELECT {var}"`, `query.format()`
- Command injection: `os.system()`, `subprocess.run(..., shell=True)`
- Hardcoded secrets: `password="..."`, `api_key="..."`
- Weak crypto: `hashlib.md5()`, `hashlib.sha1()`
- Unsafe deserialization: `pickle.loads()`, `yaml.load()`

```python
# Example
scanner = HaikuTriageScanner()
flagged = scanner.scan_file("app.py", code_content)
# Returns: {2, 5, 12}  (line numbers)
```

## Stage 2: SonnetAnalysisScanner

```python
def analyze_location(file_path: str, line_num: int, context: str) -> Vulnerability | None
```

**Input:** File path, line number, code context  
**Output:** `Vulnerability` object **only if confidence ≥ 95%**, else None  
**Speed:** ~3 seconds per location  
**Cost:** ~$0.50 per location  
**Confidence:** 95%+ (strict, only high-confidence outputs)

**Deep reasoning:**

1. Is the code actually vulnerable?
2. How confident are you (0-100%)?
3. What's the severity?
4. How to exploit it?
5. How to fix it?

```python
# Example
analyzer = SonnetAnalysisScanner()
vuln = analyzer.analyze_location("app.py", 2, code_context)
if vuln:
    assert vuln.confidence >= 0.95  # Guaranteed
    output_finding(vuln)
else:
    # Low confidence, suppressed
    log_for_analysis(vuln)
```

## Pipeline Coordinator

```python
def scan_codebase(repo_path: str) -> List[Vulnerability]
```

1. Haiku triage all files → flagged locations
2. Sonnet analyze flagged → confirmed vulnerabilities (≥95%)
3. Return only high-confidence findings

```python
# Phase 1: Fast triage
flagged = triage_scanner.triage_codebase(repo_path)
# Result: {"app.py": [2, 5, 12], "utils.py": [45]}

# Phase 2: Deep analysis
findings = []
for file_path, line_numbers in flagged.items():
    for line_num in line_numbers:
        vuln = sonnet_analyzer.analyze_location(file_path, line_num, context)
        if vuln:  # Only if confidence >= 95%
            findings.append(vuln)

return findings
```

## Cost Example

```
Code: 100 files, 5000 lines total

Option A: Sonnet on all code
- 5000 lines × $0.50/100 lines = $25

Option B: Haiku triage + Sonnet on flagged (10 locs)
- Haiku: 100 files × $0.05 = $5
- Sonnet: 10 locations × $0.50 = $5
- Total: $10 (60% savings!)
```

## Critical Implementation Detail

**The 95% Confidence Rule:**

```python
if vuln.confidence >= 0.95:
    output_finding(vuln)  # Good
else:
    log_low_confidence(vuln)  # Suppressed, NOT output
```

This is non-negotiable. Low confidence findings confuse users and damage trust.

## Testing

```bash
# Unit test Haiku
pytest test/unit/test_scanners.py::test_haiku_sql_injection -v

# Unit test Sonnet confidence rule
pytest test/unit/test_scanners.py::test_sonnet_confidence_threshold -v

# Integration test full pipeline
pytest test/integration/test_scan_pipeline.py -v
```

## Key Commands

```bash
# Scan repo
python main.py scan --repo . --output json

# Test scanners specifically
pytest test/unit/test_scanners.py -v --cov=scanners
```

---

**Location:** `swift/scanners/claude.md`  
**Depends on:** config, log  
**Is depended on by:** agent, main.py
