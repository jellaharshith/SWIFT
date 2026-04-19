"""Regex triage pre-filter — zero API calls, runs before Haiku."""
from __future__ import annotations

import os
import re
from typing import Dict, List, Set

# Supported source file extensions.
_SUPPORTED_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".jsx"}

# Skip these heavy/generated directories to avoid false positives and wasted cycles.
_SKIP_DIRS = {"node_modules", "__pycache__", ".git", "dist", "build", ".next", "coverage"}

# Python-specific patterns.
_PYTHON_PATTERNS: Dict[str, re.Pattern] = {
    "sql_injection_fstring": re.compile(
        r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{', re.IGNORECASE
    ),
    "sql_injection_concat": re.compile(
        r'(?:SELECT|INSERT|UPDATE|DELETE).*["\'\s]\s*\+', re.IGNORECASE
    ),
    "command_injection_os_system": re.compile(r'\bos\.system\s*\('),
    "command_injection_subprocess_shell": re.compile(
        r'\bsubprocess\.(?:run|call|Popen)\s*\(.*shell\s*=\s*True'
    ),
    "hardcoded_password": re.compile(
        r'\bpassword\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE
    ),
    "hardcoded_api_key": re.compile(
        r'\bapi[_-]?key\s*=\s*["\'][^"\']{6,}["\']', re.IGNORECASE
    ),
    "weak_crypto_md5": re.compile(r'\bhashlib\.md5\s*\('),
    "unsafe_pickle": re.compile(r'\bpickle\.loads\s*\('),
}

# JavaScript/TypeScript-specific patterns.
_JS_PATTERNS: Dict[str, re.Pattern] = {
    # XSS
    "xss_dangerous_html": re.compile(r'dangerouslySetInnerHTML', re.IGNORECASE),
    "xss_inner_html": re.compile(r'\.innerHTML\s*='),
    "xss_document_write": re.compile(r'\bdocument\.write\s*\('),
    # Prompt injection — user data injected into AI system prompts without sanitization
    "prompt_injection_template": re.compile(
        r'SYSTEM_PROMPT\s*\+\s*context|contextBlock\s*\+=.*\$\{|content.*SYSTEM_PROMPT.*context',
        re.IGNORECASE,
    ),
    # CORS wildcard on API endpoints
    "cors_wildcard": re.compile(
        r'["\']Access-Control-Allow-Origin["\']\s*[,:].*["\']\*["\']'
    ),
    # Hardcoded secrets — real values (not env var references)
    "hardcoded_api_key_js": re.compile(
        r'(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["\'][A-Za-z0-9+/=_\-]{8,}["\']',
        re.IGNORECASE,
    ),
    # eval / Function constructor — code injection vectors
    "eval_usage": re.compile(r'\beval\s*\('),
    "function_constructor": re.compile(r'\bnew\s+Function\s*\('),
    # Command injection in Node.js
    "node_exec": re.compile(
        r'\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*[`"\'].*\$\{', re.IGNORECASE
    ),
    # Prototype pollution
    "prototype_pollution": re.compile(r'__proto__\s*[=\[]|constructor\.prototype'),
    # Open redirect
    "open_redirect": re.compile(
        r'(?:window\.location|location\.href|router\.push)\s*=.*(?:req\.|params\.|query\.)',
        re.IGNORECASE,
    ),
    # Insecure random for security-sensitive use
    "math_random_security": re.compile(
        r'Math\.random\s*\(\s*\).*(?:token|secret|password|key|session|csrf)',
        re.IGNORECASE,
    ),
    # Error details leaked to client
    "error_leak": re.compile(
        r'(?:res\.send|res\.json|Response\s*\()\s*.*(?:err\.message|error\.message|err\.stack)',
        re.IGNORECASE,
    ),
    # Sensitive env vars exposed via VITE_ (bundled into frontend)
    "vite_secret_exposure": re.compile(
        r'VITE_(?:SECRET|TOKEN|API_KEY|PASSWORD|PRIVATE)',
        re.IGNORECASE,
    ),
}

# All patterns combined for quick lookup by extension group.
_PATTERNS_BY_LANG: Dict[str, Dict[str, re.Pattern]] = {
    ".py": _PYTHON_PATTERNS,
    ".ts": _JS_PATTERNS,
    ".tsx": _JS_PATTERNS,
    ".js": _JS_PATTERNS,
    ".jsx": _JS_PATTERNS,
}

# Comment prefixes per language group (used to skip pure-comment lines).
_COMMENT_RE_PYTHON = re.compile(r'^\s*#')
_COMMENT_RE_JS = re.compile(r'^\s*//')


def _get_comment_re(ext: str) -> re.Pattern:
    if ext == ".py":
        return _COMMENT_RE_PYTHON
    return _COMMENT_RE_JS


def triage_file(file_path: str) -> Set[int]:
    """Return 1-indexed line numbers matching any pattern for the file's language.

    Skips pure single-line comment lines.

    Args:
        file_path: Absolute or relative path to a supported source file.

    Returns:
        Set of 1-indexed line numbers with suspicious patterns.
        Returns empty set for unsupported extensions.
    """
    ext = os.path.splitext(file_path)[1].lower()
    patterns = _PATTERNS_BY_LANG.get(ext)
    if patterns is None:
        return set()

    comment_re = _get_comment_re(ext)
    flagged: Set[int] = set()
    with open(file_path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            if comment_re.match(line):
                continue
            for pattern in patterns.values():
                if pattern.search(line):
                    flagged.add(lineno)
                    break
    return flagged


def triage_codebase(repo_path: str) -> Dict[str, List[int]]:
    """Walk repo_path, triage every supported source file (skip hidden/generated dirs).

    Supported extensions: .py, .ts, .tsx, .js, .jsx

    Args:
        repo_path: Root directory to scan.

    Returns:
        Dict mapping file_path → sorted list of flagged line numbers.
        Files with zero flags are omitted.
    """
    results: Dict[str, List[int]] = {}
    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Prune irrelevant/generated directories in-place.
        dirnames[:] = [
            d for d in dirnames
            if not d.startswith(".") and d not in _SKIP_DIRS
        ]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _SUPPORTED_EXTENSIONS:
                continue
            full_path = os.path.join(dirpath, fname)
            flagged = triage_file(full_path)
            if flagged:
                results[full_path] = sorted(flagged)
    return results


class TriageScanner:
    """Thin wrapper around triage_codebase for dependency injection."""

    def scan(self, repo_path: str) -> Dict[str, List[int]]:
        return triage_codebase(repo_path)
