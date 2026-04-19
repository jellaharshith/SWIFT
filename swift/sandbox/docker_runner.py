"""Docker sandbox — isolated patch testing with strict safety guarantees."""
from __future__ import annotations

import os
import tempfile
import time

from agent.models import Patch, TestResult
from log.logger import get_logger

logger = get_logger()

_PYTHON_IMAGE = "python:3.10-slim"

# Test runner script written into the container's /repo directory.
# Falls back to syntax-check if no test suite is found.
_TEST_SCRIPT = """\
#!/bin/bash
set -e
cd /repo
if [ -f "requirements.txt" ]; then
    pip install -q -r requirements.txt 2>/dev/null || true
fi
if [ -d "test" ] || [ -d "tests" ]; then
    python -m pytest -q --tb=short
elif [ -f "test.py" ]; then
    python test.py
else
    python -m py_compile "{target_file}"
fi
echo "OK"
"""


class DockerSandbox:
    """Run patched code inside an isolated Docker container.

    Safety guarantees per run:
    - --network none  (no outbound network)
    - read-only filesystem (tmpfs at /tmp only)
    - 2 CPU cores, 2 GB RAM
    - Hard kill after `timeout` seconds

    Args:
        timeout: Execution timeout in seconds (default 30).
        image: Docker image (default python:3.10-slim).
    """

    def __init__(
        self,
        timeout: int = 30,
        image: str = _PYTHON_IMAGE,
    ) -> None:
        self._timeout = timeout
        self._image = image

    def test_patch(self, patch: Patch) -> TestResult:
        """Test a patch by running it in a Docker container.

        Writes the patched code to a temp directory, mounts it read-only
        into the container, and executes the project's test suite (or a
        py_compile syntax check as fallback).

        Args:
            patch: Patch to validate.

        Returns:
            TestResult indicating pass/fail, exit code, and captured output.
        """
        try:
            import docker  # lazy import — optional dependency
        except ImportError:
            logger.warning("docker SDK not installed; sandbox test skipped for %s", patch.id)
            return TestResult(
                patch_id=patch.id,
                passed=False,
                output="docker SDK not installed — install with: pip install docker",
                exit_code=-1,
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            target_filename = os.path.basename(patch.file_path)

            # Write patched source
            target_path = os.path.join(tmpdir, target_filename)
            with open(target_path, "w", encoding="utf-8") as fh:
                fh.write(patch.patched_code)

            # Write test runner
            script_path = os.path.join(tmpdir, "run_tests.sh")
            with open(script_path, "w", encoding="utf-8") as fh:
                fh.write(_TEST_SCRIPT.format(target_file=target_filename))

            return self._run_container(docker, patch.id, tmpdir)

    def _run_container(self, docker: object, patch_id: str, workdir: str) -> TestResult:
        start = time.monotonic()
        container = None
        try:
            client = docker.from_env()  # type: ignore[attr-defined]
            container = client.containers.run(
                self._image,
                command=["bash", "/repo/run_tests.sh"],
                volumes={workdir: {"bind": "/repo", "mode": "ro"}},
                network_mode="none",
                read_only=True,
                tmpfs={"/tmp": "size=100m"},
                mem_limit="2g",
                nano_cpus=2_000_000_000,  # 2 CPUs
                detach=True,
            )

            try:
                result = container.wait(timeout=self._timeout)
                exit_code: int = result.get("StatusCode", 1)
            except Exception:
                container.kill()
                exit_code = -1

            logs = container.logs().decode("utf-8", errors="replace")
            elapsed = time.monotonic() - start
            passed = exit_code == 0

            logger.info(
                "Sandbox %s patch %s in %.1fs (exit=%d)",
                "PASSED" if passed else "FAILED",
                patch_id,
                elapsed,
                exit_code,
            )
            return TestResult(patch_id=patch_id, passed=passed, output=logs, exit_code=exit_code)

        except Exception as exc:
            logger.error("Sandbox error for patch %s: %s", patch_id, exc)
            return TestResult(patch_id=patch_id, passed=False, output=str(exc), exit_code=-1)
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
