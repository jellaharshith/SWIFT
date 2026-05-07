# Changelog

## [6.0.0.0] — 2026-05-07

### Added
- **OOB SSRF Probe** — async `OOBCallbackServer` + Interactsh integration; cloud metadata bypass (AWS/GCP/Azure); confirms SSRF via real out-of-band TCP callbacks
- **OAuth/OIDC Attack Probe** — 5 attacks: PKCE downgrade, redirect_uri manipulation, token leakage recon, credential stuffing, implicit flow abuse
- **WebSocket Attack Probe** — 5 attacks: CSWSH, unauthenticated upgrade, IDOR, injection, namespace abuse
- **Business Logic Probe** — Sonnet-powered flow analysis + 5 Playwright executors: price manipulation, coupon stacking race condition, workflow step skipping, negative quantity, privilege escalation
- **Agentic Red-Team Loop** — `RedTeamAgent` Sonnet tool-use autonomous loop with plateau detection, budget gates, context compression, and full audit trail; CLI: `swiftsec redteam --agentic`
- **Immutable Audit Log** — SHA-256 / HMAC-SHA256 keyed hash chain per engagement, tamper detection, 10 MB rotation, automatic credential redaction; CLI: `swiftsec audit verify|export`
- **Plugin SDK** — `BaseModule` ABC, `Finding` dataclass, `@roe_gated` / `@cached_result` / `@retry` decorators, `PluginRegistry` auto-discovery, migration adapters for all existing browser probes; CLI: `swiftsec plugin list|install|remove|validate`
- New ROE techniques: `oob_ssrf`, `oauth_attack`, `websocket_attack`, `bizlogic`, `agentic_loop`
- `chain_primitive` + `oob_confirmed` fields on `Vulnerability` dataclass
- `SWIFT_AUDIT_HMAC_KEY` env var — opt-in forge-resistant hash chain
- `INTERACTSH_URL` validation at startup (must be `https://`, non-localhost)
- Scope enforcement in agentic tool dispatch — off-scope probe targets blocked

### Security
- All 13 GitHub Actions pinned to commit SHAs (supply chain hardening)
- Nuclei pinned to v3.3.9 with SHA-256 checksum verification in Dockerfile
- `OOBCallbackServer` memory cap (1 000 tokens), token + request size bounds
- `INTERACTSH_URL` validated at startup against attacker-controlled server injection

## v3.0.0 — Red-Team Automation Pentester (2026-05-04)
### Breaking Changes
- Removed `patch`, `validate`, `--allow-patch-generation` commands and flags
- Removed `patches/` module, `patch_apply.py`, `patch_validator.py`
### Added
- `redteam` command: full red-team pipeline with ROE gate
- `osint` command: DNS recon, GitHub dorks, Shodan, WHOIS
- `Credential` model: captured credential from a probe chain
- `OsintFinding` model: finding from the OSINT recon phase
- `PostExploitFinding` model: simulated post-exploitation capability assessment
- SessionManager: credential/JWT reuse across probe chains
- LLM payload generator: context-aware payload mutation via Claude Haiku
- Post-exploit simulators: data-exfil, persistence, C2 feasibility (simulate-only)
- Advanced Kali: WAF evasion flags, 7 additional tools

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
