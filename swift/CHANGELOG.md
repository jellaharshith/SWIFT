# Changelog

All notable changes to SWIFT are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- CLI startup banner (ANSI Shadow ASCII art, Rich-rendered, pipe-safe to stderr)
- SWIFT logo (SVG vector + PNG raster set 16/32/64/256/1024 + favicon.ico)
- `assets/logo/` brand assets directory with build script
- CI/CD: GitHub Actions matrix test (Python 3.10 / 3.11 / 3.12)
- Release workflow: PyPI OIDC trusted publish + ghcr.io Docker push (multi-arch)
- Multi-stage Dockerfile: builder (python:3.12-slim) + runtime (kali-rolling), non-root user uid 10001, HEALTHCHECK
- Secret redaction filter on all log handlers (scrubs API keys, Bearer tokens, env secrets)
- Top-level exception handler: `KeyboardInterrupt` → 130, IO errors → 2, unexpected → 1
- `--version`, `--no-banner`, `--quiet` global CLI flags
- `swift/__init__.py` as single `__version__` source of truth
- Pre-commit hooks (ruff, black, detect-private-key)
- `[tool.ruff]`, `[tool.mypy]`, `[tool.pytest.ini_options]`, `[tool.coverage.*]` in `pyproject.toml`
- `README.md`, `LICENSE` (MIT), `SECURITY.md`, `CHANGELOG.md` at repo root
- `.dockerignore` and GitHub PR/issue templates

## [2.0.0] - 2026-04-19

### Added
- Unified scanner pipeline (code + Kali + CVE simultaneously via `full-scan`)
- Offensive web scanner layers 1-7: SSRF, XSS, SQLi, IDOR, auth bypass, business logic, chained exploits
- Pentester persona module with AgentPool orchestration
- Playwright-driven web scan (`web-scan` command)
- Docker-based privilege escalation tester (`privesc` command)
- Live CVE feed from NVD + CISA KEV (`live-feed` command)
- MITRE ATT&CK-mapped attack simulation (`attack-sim` command)
- Interactive wizard (`wizard` command)
- Bug bounty and pentest report formatters
- SARIF output support
- Structured JSONL audit logging

### Changed
- Three-layer pipeline: Haiku triage + Sonnet analysis + Sonnet patching
- Confidence threshold enforcement at ≥95% (non-negotiable, gates all output)

## [1.0.0] - 2026-01-01

### Added
- Initial release: static code analysis, patch generation, Docker sandbox validation
- JSON and Markdown output formats
