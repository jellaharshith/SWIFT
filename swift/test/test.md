# SWIFT: test/claude.md

## Purpose

Verify SWIFT works correctly: unit tests, integration tests, E2E tests.

## Test Strategy

**Test Pyramid:**

- 70% Unit tests (fast, mocked)
- 20% Integration tests (slower, real API)
- 10% E2E tests (slowest, real everything)

## Unit Tests (Fast, Mocked)

Mock Claude API, test logic in isolation:

```python
import pytest
from unittest.mock import Mock, patch

@pytest.fixture
def mock_claude():
    with patch('anthropic.Anthropic') as mock:
        mock.return_value.messages.create.return_value = Mock(
            content=[Mock(text='1, 5, 12')]
        )
        yield mock

def test_haiku_detects_sql_injection(mock_claude):
    """Haiku should flag SQL injection"""
    from scanners import HaikuTriageScanner

    scanner = HaikuTriageScanner()
    code = 'query = f"SELECT * FROM users WHERE id={var}"'
    flagged = scanner.scan_file("test.py", code)

    assert len(flagged) > 0

def test_sonnet_confidence_rule(mock_claude):
    """Only return findings with confidence >= 95%"""
    from scanners import SonnetAnalysisScanner

    # Mock low confidence
    mock_claude.return_value.messages.create.return_value = Mock(
        content=[Mock(text='{"confidence": 42}')]
    )

    analyzer = SonnetAnalysisScanner()
    finding = analyzer.analyze_location("test.py", 2, "")

    assert finding is None  # Suppressed
```

Run: `pytest test/unit/ -v`

## Integration Tests (Real API, Gated)

Test components together using real API:

```python
@pytest.mark.integration
def test_scan_pipeline():
    """Test full: triage → analysis → patching"""
    from agent import scan_codebase
    from config import CONFIG

    result = scan_codebase("./test-repo", CONFIG)

    # Verify 95% rule
    for vuln in result.vulnerabilities:
        assert vuln.confidence >= 0.95
```

Run: `pytest test/integration/ -v -m integration`

## E2E Tests (Real Everything)

Test full pipeline on real vulnerable code:

```python
@pytest.mark.e2e
@pytest.mark.skipif(
    not os.getenv("SWIFT_RUN_E2E"),
    reason="E2E requires SWIFT_RUN_E2E=1"
)
def test_scan_real_vulnerable_code():
    """Scan known vulnerable code"""
    from agent import scan_codebase

    result = scan_codebase("./vulnerable-test-repo")

    # Should find vulnerabilities
    assert len(result.vulnerabilities) > 0

    # All should be high-confidence
    for vuln in result.vulnerabilities:
        assert vuln.confidence >= 0.95
```

Run: `SWIFT_RUN_E2E=1 pytest test/e2e/ -v`

## Test Fixtures

```python
# conftest.py
@pytest.fixture
def temp_repo():
    """Create temp repo with vulnerable code"""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        (repo / "app.py").write_text('''
def vulnerable():
    query = f"SELECT * FROM users WHERE id={user_id}"
''')
        yield str(repo)

@pytest.fixture
def mock_claude():
    """Mock Claude API responses"""
    with patch('anthropic.Anthropic') as mock:
        yield mock
```

## Running Tests

```bash
# All tests
pytest test/ -v --cov=swift

# Unit only (fast)
pytest test/unit/ -v

# Integration only
pytest test/integration/ -v -m integration

# E2E only
SWIFT_RUN_E2E=1 pytest test/e2e/ -v

# With coverage report
pytest test/ --cov=swift --cov-report=html

# Watch mode (auto-run on changes)
ptw test/
```

## Makefile

```makefile
.PHONY: test test-unit test-integration test-e2e test-coverage

test:
	pytest test/ -v --cov=swift

test-unit:
	pytest test/unit/ -v

test-integration:
	pytest test/integration/ -v -m integration

test-e2e:
	SWIFT_RUN_E2E=1 pytest test/e2e/ -v

test-coverage:
	pytest test/ --cov=swift --cov-report=html
```

## Coverage Goals

- Overall: 80%+
- Scanners: 95%+
- Patches: 90%+
- Output: 85%+

## Key Testing Principle

**Never test the 95% confidence rule differently per module. Test it everywhere.**

Every module that outputs findings should respect the 95% rule. Make this explicit in tests.

---

**Location:** `swift/test/claude.md`  
**Is depended on by:** Development workflow  
**Depends on:** All modules
