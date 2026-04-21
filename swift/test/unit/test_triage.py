import os
import tempfile
import pytest
from triage.patterns import TriageScanner, triage_file, triage_codebase


SQL_FSTRING = 'query = f"SELECT * FROM users WHERE id={user_id}"\n'
SQL_CONCAT  = 'query = "SELECT * FROM " + table_name\n'
CMD_OS      = 'os.system(user_input)\n'
CMD_SUBPROC = 'subprocess.run(cmd, shell=True)\n'
HARDCODED_PW= 'password = "hunter2"\n'
HARDCODED_KEY='api_key = "sk-abc123"\n'
WEAK_CRYPTO = 'hashlib.md5(data)\n'
UNSAFE_PICKLE='pickle.loads(data)\n'
COMMENT_ONLY= '# sql = f"SELECT {x}"\n'
CLEAN_CODE  = 'x = 1 + 2\n'


def _write_file(path: str, lines: list) -> None:
    with open(path, "w") as f:
        f.writelines(lines)


def test_sql_injection_fstring():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(SQL_FSTRING)
        name = f.name
    try:
        result = triage_file(name)
        assert 1 in result
    finally:
        os.unlink(name)


def test_sql_injection_concatenation():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(SQL_CONCAT)
        name = f.name
    try:
        assert 1 in triage_file(name)
    finally:
        os.unlink(name)


def test_command_injection_os_system():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(CMD_OS)
        name = f.name
    try:
        assert 1 in triage_file(name)
    finally:
        os.unlink(name)


def test_command_injection_subprocess_shell():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(CMD_SUBPROC)
        name = f.name
    try:
        assert 1 in triage_file(name)
    finally:
        os.unlink(name)


def test_hardcoded_password():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(HARDCODED_PW)
        name = f.name
    try:
        assert 1 in triage_file(name)
    finally:
        os.unlink(name)


def test_hardcoded_api_key():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(HARDCODED_KEY)
        name = f.name
    try:
        assert 1 in triage_file(name)
    finally:
        os.unlink(name)


def test_weak_crypto_md5():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(WEAK_CRYPTO)
        name = f.name
    try:
        assert 1 in triage_file(name)
    finally:
        os.unlink(name)


def test_unsafe_pickle():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(UNSAFE_PICKLE)
        name = f.name
    try:
        assert 1 in triage_file(name)
    finally:
        os.unlink(name)


def test_comment_lines_ignored():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(COMMENT_ONLY)
        name = f.name
    try:
        result = triage_file(name)
        assert len(result) == 0
    finally:
        os.unlink(name)


def test_returns_correct_line_numbers():
    lines = [CLEAN_CODE, SQL_FSTRING, CLEAN_CODE]
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.writelines(lines)
        name = f.name
    try:
        result = triage_file(name)
        assert 2 in result
        assert 1 not in result
    finally:
        os.unlink(name)


def test_triage_codebase_walks_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_file(os.path.join(tmpdir, "a.py"), [SQL_FSTRING])
        _write_file(os.path.join(tmpdir, "b.py"), [CMD_OS])
        result = triage_codebase(tmpdir)
        assert len(result) == 2


def test_triage_codebase_skips_unsupported_extensions():
    # .txt is not in _SUPPORTED_EXTENSIONS — only the .py file should be flagged.
    # Note: .js is now a supported extension (triage scans Python, JS, TS, C/C++).
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_file(os.path.join(tmpdir, "a.py"), [SQL_FSTRING])
        _write_file(os.path.join(tmpdir, "b.txt"), [SQL_FSTRING])
        result = triage_codebase(tmpdir)
        assert len(result) == 1


def test_triage_codebase_skips_git_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        git_dir = os.path.join(tmpdir, ".git")
        os.makedirs(git_dir)
        _write_file(os.path.join(git_dir, "hook.py"), [SQL_FSTRING])
        _write_file(os.path.join(tmpdir, "app.py"), [CLEAN_CODE])
        result = triage_codebase(tmpdir)
        for path in result:
            assert ".git" not in path
