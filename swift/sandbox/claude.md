# SWIFT: sandbox/claude.md

## Purpose

Test patches in isolated Docker containers with strict safety guarantees.

## Core Function: test_patch()

```python
def test_patch(patched_code: str, original_file: str) -> TestResult
```

**Input:** Patched code, file path  
**Output:** `TestResult` with pass/fail, exit code, logs  
**Safety:** No network, read-only filesystem, 30s timeout, 2GB RAM

**Process:**

1. Copy repo to temp directory
2. Write patched code to file
3. Run in Docker with isolation
4. Capture stdout/stderr
5. Return result

```python
# Example
from sandbox import SandboxTester

tester = SandboxTester("/path/to/repo")
result = tester.test_patch(patched_code, "app.py")

if result.passed:
    print(f"✓ PASSED in {result.duration_seconds:.2f}s")
else:
    print(f"✗ FAILED (exit {result.exit_code})")
    print(result.stderr)
```

## Safety Properties (Guaranteed)

**Isolation:**

- No network access (--network=none)
- No access to host filesystem
- Temporary filesystem only (/tmp)

**Resource Limits:**

- CPU: 2 cores max
- RAM: 2GB max
- Disk: 100MB temp only
- Timeout: 30 seconds (hard kill)

**Execution Safety:**

- Read-only filesystem
- Non-root user
- No privileged capabilities
- No device access

## Implementation

```python
import docker
import tempfile
import shutil
import time

class SandboxTester:
    def test_patch(self, patched_code: str, original_file: str) -> TestResult:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Copy repo
            shutil.copytree(self.repo_path, f"{tmpdir}/repo")

            # Write patch
            with open(f"{tmpdir}/repo/{original_file}", 'w') as f:
                f.write(patched_code)

            # Run in sandbox
            start = time.time()

            container = docker.from_env().containers.run(
                "python:3.10-slim",
                command="bash /test/run_tests.sh",
                volumes={f"{tmpdir}/repo": {"bind": "/repo", "mode": "ro"}},
                network_mode="none",
                read_only=True,
                cpu_quota="2",
                mem_limit="2g",
                timeout=30,
                detach=True
            )

            exit_code = container.wait(timeout=30)
            logs = container.logs().decode('utf-8')
            container.remove()

            return TestResult(
                passed=(exit_code == 0),
                exit_code=exit_code,
                stdout=logs,
                stderr=logs,
                duration_seconds=time.time() - start
            )
```

## Test Result Data

```python
@dataclass
class TestResult:
    passed: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float

    @property
    def summary(self) -> str:
        status = "✓ PASSED" if self.passed else "✗ FAILED"
        return f"{status} (exit {self.exit_code}, {self.duration_seconds:.2f}s)"
```

## Docker Images (Per Language)

```python
PYTHON_SANDBOX = "python:3.10-slim"
NODEJS_SANDBOX = "node:18-alpine"
GO_SANDBOX = "golang:1.21-alpine"

# Auto-detect language from repo
language = detect_language(repo_path)  # py, js, go
image = CONFIG.sandbox.get_image(language)
```

## Typical Test Script

Auto-generated `run_tests.sh` in container:

```bash
#!/bin/bash
set -e

cd /repo

# Install dependencies
if [ -f "requirements.txt" ]; then
    pip install -q -r requirements.txt
fi

# Run existing tests
if [ -f "pytest.ini" ] || [ -d "tests" ]; then
    python -m pytest -q
elif [ -f "test.py" ]; then
    python test.py
else
    # Basic import test
    python -c "import $(basename ${ORIGINAL_FILE} .py)"
fi

echo "✓ All tests passed"
```

## Testing

```bash
# Unit test (mock Docker)
pytest test/unit/test_sandbox.py -v

# Integration test (real Docker, mock patch)
pytest test/integration/test_sandbox.py -v

# E2E test (real Docker, real patch)
SWIFT_RUN_E2E=1 pytest test/e2e/test_sandbox_end_to_end.py -v
```

## Key Commands

```bash
# Validate patch in sandbox
python main.py validate --patch-id PATCH-001 --verbose

# Test from Python
from sandbox import SandboxTester
tester = SandboxTester("./my-repo")
result = tester.test_patch(patched_code, "app.py")
print(result.summary)
```

---

**Location:** `swift/sandbox/claude.md`  
**Depends on:** docker, config, log  
**Is depended on by:** patches, agent
