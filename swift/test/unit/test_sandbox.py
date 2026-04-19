"""Unit tests for DockerSandbox (SandboxTester) — Docker SDK fully mocked."""
from __future__ import annotations

import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from agent.models import Patch, TestResult
from sandbox.docker_runner import DockerSandbox


def _make_patch() -> Patch:
    return Patch(
        id="PATCH-001",
        vuln_id="SWIFT-001",
        file_path="app.py",
        original_code='query = f"SELECT * FROM users WHERE id={uid}"',
        patched_code='query = "SELECT * FROM users WHERE id=?"\ncursor.execute(query, (uid,))',
        diff="--- a/app.py\n+++ b/app.py\n",
        confidence=0.97,
    )


def _make_docker_mock(exit_code: int = 0, logs: bytes = b"OK\n"):
    """Return (docker_module_mock, client_mock, container_mock)."""
    container = MagicMock()
    container.wait.return_value = {"StatusCode": exit_code}
    container.logs.return_value = logs

    client = MagicMock()
    client.containers.run.return_value = container

    docker_mod = MagicMock()
    docker_mod.from_env.return_value = client

    return docker_mod, client, container


class TestDockerSandbox:
    def test_sandbox_calls_docker_run(self):
        """_run_container must call client.containers.run exactly once."""
        docker_mod, client, container = _make_docker_mock()
        sandbox = DockerSandbox()
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "run_tests.sh"), "w") as f:
                f.write("echo OK")
            sandbox._run_container(docker_mod, "PATCH-001", tmpdir)
        client.containers.run.assert_called_once()

    def test_sandbox_network_none(self):
        """containers.run must be called with network_mode='none'."""
        docker_mod, client, container = _make_docker_mock()
        sandbox = DockerSandbox()
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "run_tests.sh"), "w") as f:
                f.write("echo OK")
            sandbox._run_container(docker_mod, "PATCH-001", tmpdir)
        call_kwargs = client.containers.run.call_args[1]
        assert call_kwargs.get("network_mode") == "none"

    def test_sandbox_mem_limit(self):
        """containers.run must be called with mem_limit='2g'."""
        docker_mod, client, container = _make_docker_mock()
        sandbox = DockerSandbox()
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "run_tests.sh"), "w") as f:
                f.write("echo OK")
            sandbox._run_container(docker_mod, "PATCH-001", tmpdir)
        call_kwargs = client.containers.run.call_args[1]
        assert call_kwargs.get("mem_limit") == "2g"

    def test_sandbox_passed_on_exit_0(self):
        """TestResult.passed must be True when container StatusCode == 0."""
        docker_mod, _, _ = _make_docker_mock(exit_code=0)
        sandbox = DockerSandbox()
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "run_tests.sh"), "w") as f:
                f.write("echo OK")
            result = sandbox._run_container(docker_mod, "PATCH-001", tmpdir)
        assert result.passed is True
        assert result.exit_code == 0

    def test_sandbox_failed_on_exit_1(self):
        """TestResult.passed must be False when container StatusCode != 0."""
        docker_mod, _, _ = _make_docker_mock(exit_code=1, logs=b"FAIL\n")
        sandbox = DockerSandbox()
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "run_tests.sh"), "w") as f:
                f.write("exit 1")
            result = sandbox._run_container(docker_mod, "PATCH-001", tmpdir)
        assert result.passed is False
        assert result.exit_code == 1

    def test_sandbox_container_removed_after_success(self):
        """container.remove(force=True) must be called after exit code 0."""
        docker_mod, _, container = _make_docker_mock(exit_code=0)
        sandbox = DockerSandbox()
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "run_tests.sh"), "w") as f:
                f.write("echo OK")
            sandbox._run_container(docker_mod, "PATCH-001", tmpdir)
        container.remove.assert_called_once_with(force=True)

    def test_sandbox_container_removed_after_failure(self):
        """container.remove(force=True) must be called even after non-zero exit."""
        docker_mod, _, container = _make_docker_mock(exit_code=1)
        sandbox = DockerSandbox()
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "run_tests.sh"), "w") as f:
                f.write("exit 1")
            sandbox._run_container(docker_mod, "PATCH-001", tmpdir)
        container.remove.assert_called_once_with(force=True)

    def test_sandbox_docker_unavailable_returns_failed_result(self):
        """If docker SDK is not importable, return TestResult(passed=False) gracefully."""
        saved = sys.modules.get("docker")
        sys.modules["docker"] = None  # type: ignore[assignment]
        try:
            sandbox = DockerSandbox()
            result = sandbox.test_patch(_make_patch())
            assert result.passed is False
            assert result.exit_code == -1
            assert "docker" in result.output.lower()
        finally:
            if saved is None:
                sys.modules.pop("docker", None)
            else:
                sys.modules["docker"] = saved

    def test_sandbox_writes_patched_file(self):
        """test_patch must write patch.patched_code to a temp file before calling _run_container."""
        written_content = {}

        real_open = open

        def spy_open(path, mode="r", encoding=None, **kw):
            if mode == "w":
                # intercept write, capture content
                import io
                buf = io.StringIO()

                class SpyFH:
                    def write(self_, data):
                        written_content[path] = data
                        return len(data)
                    def __enter__(self_): return self_
                    def __exit__(self_, *a): pass

                return SpyFH()
            return real_open(path, mode, encoding=encoding, **kw) if encoding else real_open(path, mode, **kw)

        # Inject a fake docker module so the import succeeds
        fake_docker = MagicMock()
        fake_docker.from_env.return_value.containers.run.return_value = MagicMock(
            wait=MagicMock(return_value={"StatusCode": 0}),
            logs=MagicMock(return_value=b"OK"),
        )

        with patch.dict("sys.modules", {"docker": fake_docker}):
            with patch("sandbox.docker_runner.DockerSandbox._run_container") as mock_run:
                mock_run.return_value = TestResult(
                    patch_id="PATCH-001", passed=True, output="OK", exit_code=0
                )
                with patch("builtins.open", side_effect=spy_open):
                    sandbox = DockerSandbox()
                    sandbox.test_patch(_make_patch())

        # Patched source file must have been written
        assert any("app.py" in p for p in written_content), (
            f"Expected app.py write, got: {list(written_content.keys())}"
        )

    def test_sandbox_patch_id_in_result(self):
        """TestResult.patch_id must equal the input Patch.id."""
        with patch("sandbox.docker_runner.DockerSandbox._run_container") as mock_run:
            mock_run.return_value = TestResult(
                patch_id="PATCH-001", passed=True, output="OK", exit_code=0
            )
            sandbox = DockerSandbox()
            result = sandbox.test_patch(_make_patch())
        assert result.patch_id == "PATCH-001"

    def test_test_result_summary_passed(self):
        """TestResult.summary must return 'PASSED' when passed=True."""
        result = TestResult(patch_id="PATCH-001", passed=True, output="", exit_code=0)
        assert result.summary == "PASSED"

    def test_test_result_summary_failed(self):
        """TestResult.summary must return 'FAILED' when passed=False."""
        result = TestResult(patch_id="PATCH-001", passed=False, output="", exit_code=1)
        assert result.summary == "FAILED"
