# SWIFT: Quick Reference Guide

**Last Updated:** 2026-04-20  
**Status:** Phase 2 Complete, Phase 3 Ready

---

## Get Started in 5 Minutes

```bash
# 1. Setup
cd SWIFT/swift
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirement.txt

# 2. Configure
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# 3. Scan
swift scan --repo /path/to/code --output json

# 4. View Results
cat report.json
```

---

## Key Concepts at a Glance

| Concept | What | Why | Where |
|---------|------|-----|-------|
| **95% Confidence Rule** | Only output vulns ≥95% confidence | No false positives | sonnet_scanner.py:87 |
| **Exploit Chains** | Multi-step attack paths (≥85% confidence) | Show real exploitability | chains/detector.py |
| **Cost Discipline** | <$2 per scan (Haiku $0.05, Sonnet $0.50) | Affordable at scale | agent/orchestrator.py |
| **Sandbox Testing** | Docker isolation (no network, read-only) | Safe patch validation | sandbox/docker.py |
| **Permission Layer** | Central gate for all operations | Prevent privilege escalation | security/permissions.py |
| **Forensic Logging** | Append-only hash-chained audit trail | Compliance + tamper detection | security/logging.py |
| **AI Safety Monitor** | Detects escalation/hidden reasoning | Prevent unsafe behavior | security/safety_monitor.py |

---

## CLI Cheat Sheet

```bash
# Basic scan
swift scan --repo /path/to/code --output json > report.json

# With patches
swift scan --repo /path/to/code --patches --output json

# Markdown report
swift scan --repo /path/to/code --output markdown > report.md

# SARIF for GitHub
swift scan --repo /path/to/code --output sarif > report.sarif

# Custom timeout
swift scan --repo /path/to/code --timeout 600 --output json

# Custom confidence threshold
swift scan --repo /path/to/code --confidence 0.85 --output json
```

---

## File Structure

```
swift/
├── agent/              # Orchestration
│   ├── orchestrator.py # Main pipeline coordinator
│   └── models.py       # Data classes (Vulnerability, Chain, etc.)
├── scanners/           # Analysis (Haiku + Sonnet)
│   ├── haiku_scanner.py
│   ├── sonnet_scanner.py
│   └── prompts.py
├── chains/             # Exploit chain detection
│   └── detector.py
├── patches/            # Patch generation
│   ├── generator.py
│   └── scorer.py
├── sandbox/            # Docker testing
│   └── docker.py
├── security/           # Permission, logging, safety
│   ├── permissions.py
│   ├── logging.py
│   └── safety_monitor.py
├── triage/             # Fast filtering (regex)
│   └── detector.py
├── cli/                # Command-line interface
│   └── commands.py
├── output/             # Format generators
│   ├── json.py
│   ├── markdown.py
│   └── sarif.py
├── log/                # Logging infrastructure
│   └── logger.py
└── test/               # Tests
    ├── unit/           # 188 tests
    ├── integration/    # 46 tests
    └── e2e/            # Optional full-scan tests
```

---

## Common Tasks

### Run Tests

```bash
# All tests
pytest test/ -v --cov=swift

# Unit only
pytest test/unit/ -v

# Integration only
pytest test/integration/ -v

# Single test
pytest test/unit/test_sonnet_scanner.py::test_confidence_gate -v
```

### Add Custom Vulnerability Type

```python
# In sonnet_scanner.py, extend prompt:
CUSTOM_PATTERN_PROMPT = """
Analyze for custom vulnerability pattern...
"""

# In triage/detector.py, add regex:
CUSTOM_PATTERNS = {
    "custom_vuln": r"your_regex_pattern"
}
```

### Debug a Scan

```python
# In agent/orchestrator.py, add logging:
import logging
logger = logging.getLogger(__name__)
logger.debug(f"Scanning {file_path}")
logger.debug(f"Found {len(vulns)} vulnerabilities")

# Run with debug output:
PYTHONPATH=. pytest test/ -v -s --log-cli-level=DEBUG
```

### Extend Patch Generator

```python
# In patches/generator.py:
class CustomPatchGenerator(PatchGenerator):
    def generate_candidates(self, vuln):
        # Your custom logic
        return candidates
```

---

## Architecture Overview

```
Input Code
    ↓
[TRIAGE] Regex patterns (~$0)
    ↓ (flagged lines)
[HAIKU] Fast confirmation ($0.05/file)
    ↓ (confirmed lines)
[SONNET] Deep reasoning ($0.50/vuln, ≥95% confidence)
    ↓ (confirmed vulns)
[CHAINS] Multi-step paths ($0.10/chain, ≥85% confidence)
    ↓
[PATCHES] Generation + sandbox ($0.20/vuln, optional)
    ↓
[OUTPUT] JSON/Markdown/SARIF
```

---

## Key Files to Know

| File | Purpose | Size | Complexity |
|------|---------|------|-----------|
| `agent/orchestrator.py` | Pipeline coordinator | 300 lines | Medium |
| `scanners/sonnet_scanner.py` | Deep reasoning | 250 lines | Medium |
| `chains/detector.py` | Attack path analysis | 200 lines | High |
| `security/permissions.py` | Permission enforcement | 150 lines | Low |
| `security/logging.py` | Forensic audit trail | 180 lines | Low |
| `patches/generator.py` | Patch synthesis | 280 lines | High |
| `sandbox/docker.py` | Isolation testing | 200 lines | Medium |
| `cli/commands.py` | CLI interface | 120 lines | Low |

---

## Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...

# Security Settings
SWIFT_CONFIDENCE_THRESHOLD=0.95
SWIFT_CHAIN_CONFIDENCE_THRESHOLD=0.85

# Resource Limits
SWIFT_MAX_FILE_SIZE=100000000           # 100MB
SWIFT_SANDBOX_TIMEOUT=30                # 30 seconds
SWIFT_SANDBOX_MEMORY=2000000000         # 2GB

# Optional
SWIFT_LOG_LEVEL=INFO
SWIFT_ENABLE_PATCHES=true
```

---

## Common Errors & Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: No module named 'swift'` | Import path issue | Use relative imports or `cd swift` |
| `PermissionDenied: Repo too large` | Exceeds 100MB | Increase `SWIFT_MAX_FILE_SIZE` |
| `Timeout waiting for Sonnet` | API latency | Increase `ANTHROPIC_TIMEOUT` |
| `Docker daemon not running` | Sandbox requires Docker | Start Docker or skip `--patches` |
| `AssertionError in test_confidence_gate` | Model response changed | Update test mock |

---

## Testing Strategy

- **Unit:** Mock Claude API, test logic in isolation (188 tests)
- **Integration:** Test full pipeline with mocked API (46 tests)
- **E2E:** Full scan on real vulnerable repo (optional)

```bash
# Test specific component
pytest test/unit/test_haiku_scanner.py -v

# Test with coverage
pytest test/ --cov=swift --cov-report=html

# Test specific scenario
pytest test/unit/test_sonnet_scanner.py::test_confidence_gate -v
```

---

## Performance Baselines

| Operation | Time | Cost | Notes |
|-----------|------|------|-------|
| Triage file (100 lines) | 1ms | $0 | Local regex matching |
| Haiku scan (100 lines) | 50ms | $0.05 | API call |
| Sonnet analysis (10 lines) | 3s | $0.50 | Deep reasoning |
| Chain detection (5 vulns) | 2s | $0.10 | Multi-step analysis |
| Patch generation (1 vuln) | 20s | $0.20 | 3 candidates + scoring |
| Full scan (10K lines) | ~5 min | $0.50-$2.00 | Depends on vuln density |

---

## Git Workflow

```bash
# Feature branch
git checkout -b feature/your-feature

# Commit with reference
git commit -m "feat: add feature

Fixes #23"

# Push
git push origin feature/your-feature

# Create PR
# Reference issue in PR body
```

---

## Key Metrics to Monitor

- **Cost per scan** (target: <$2)
- **Scans per day** (throughput)
- **Vuln detection rate** (accuracy)
- **False positive rate** (precision)
- **Patch acceptance rate** (quality)
- **Sandbox test pass rate** (correctness)

---

## Phase Progress

| Phase | Status | Work | Tests |
|-------|--------|------|-------|
| Phase 1 | ✅ Complete | Exploit chains + language-aware | 153 tests |
| Phase 2 | ✅ Complete | Security controls (permissions, logging, safety) | 35 tests |
| Phase 3 | 🚀 Ready | Evidence bundle + compliance (SARIF, API) | TBD |
| Phase 4 | 📋 Planned | Performance + GitHub integration | TBD |

---

## Resources

- **GitHub:** https://github.com/jellaharshith/SWIFT
- **Issues:** https://github.com/jellaharshith/SWIFT/issues
- **Documentation:** See PROJECT_DOCUMENTATION.md
- **Test & Debug Report:** See PHASE_3_COMPLETE.md

---

## Quick Copy-Paste Commands

```bash
# Setup from scratch
git clone https://github.com/jellaharshith/SWIFT.git
cd SWIFT/swift
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirement.txt
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# Verify setup
pytest test/unit/ -q

# Scan a repo
swift scan --repo /path/to/code --output json > report.json

# Generate report
cat report.json | jq '.summary'
```

---

**Last Updated:** 2026-04-20  
**Tests Passing:** 234/234 ✅  
**Ready for:** Phase 3 Implementation 🚀
