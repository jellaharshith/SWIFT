# SWIFT TODO

## Status: Production hardening + CLI banner COMPLETE (2026-05-03)

---

## Completed This Session

- [x] **Brand assets** — `assets/logo/`: SVG shield+arrow logo, ANSI Shadow ASCII art, PNG rasters (16/32/64/256/1024), favicon.ico, build script
- [x] **CLI startup banner** — `cli/banner.py`: Rich-rendered, ANSI Shadow "SWIFT", pipe-safe (stderr only), suppressed via `--no-banner`, `--quiet`, `SWIFT_NO_BANNER=1`, non-TTY, `--version`, `--help`, JSON output mode
- [x] **`swift/__init__.py`** — `__version__` single source of truth via `importlib.metadata`
- [x] **`swift_cli.py` wiring** — `--version`, `--no-banner`, `--quiet` flags; banner injection in `main()`; top-level exception handler (exit codes 1/2/130); removed old `_WIZARD_BANNER`
- [x] **`pyproject.toml`** — `[tool.ruff]`, `[tool.black]`, `[tool.mypy]`, `[tool.pytest.ini_options]`, `[tool.coverage.*]`; added `swift`, `assets`, `assets.logo` packages; dev deps: ruff/mypy/pre-commit/build/cairosvg/pyfiglet
- [x] **CI/CD** — `.github/workflows/ci.yml` (matrix py3.10/3.11/3.12), `release.yml` (PyPI OIDC + ghcr Docker), `dependabot.yml`, issue templates, PR template
- [x] **Dockerfile** — Multi-stage (python:3.12-slim builder + kali-rolling runtime), non-root user uid 10001, HEALTHCHECK, OCI labels; `.dockerignore` hardened
- [x] **Logger secret redaction** — `_SecretRedactingFilter` + `_redact()` in `log/logger.py`; scrubs `sk-ant-*`, Bearer tokens, env secrets; applied to both handlers
- [x] **Tests** — `test/unit/test_banner.py` (9 tests), `test/unit/test_redaction.py` (5 tests) — all 14 pass
- [x] **Docs** — `README.md` (root), `LICENSE` (MIT), `CHANGELOG.md`, `SECURITY.md`, `.gitignore`, `.pre-commit-config.yaml`

---

## Upcoming Tasks

### High Priority
- [ ] **PyPI trusted publisher setup** — Configure OIDC trusted publisher on PyPI for jellaharshith/SWIFT (`release.yml` ready, needs PyPI side config)
- [ ] **ghcr.io Docker push** — First manual push to test `ghcr.io/jellaharshith/swift:2.0.0`
- [ ] **Codecov integration** — Add `CODECOV_TOKEN` secret to repo settings
- [ ] **Pre-commit install** — Run `pre-commit install` in repo, fix any initial ruff/black violations
- [ ] **Type coverage expansion** — Gradually expand mypy scope beyond `swift_cli.py cli config log` to full codebase
- [ ] **Dependency pinning** — Consider `pip-compile` or `uv lock` for reproducible builds in CI

### Medium Priority
- [ ] **Banner terminal demo** — Record asciinema of `swiftsec wizard` showing banner + scan flow for README GIF
- [ ] **SARIF output test** — Add unit test for `output/sarif.py`
- [ ] **`log/audit.py` redaction** — Apply `_redact()` to JSONL writer output (currently only logging handlers are covered)
- [ ] **Exit code 3** — Implement "vulnerabilities found but scan succeeded" exit code for CI use (`swiftsec scan . && echo clean`)
- [ ] **`swiftsec version` test** — Add to CI: `SWIFT_NO_BANNER=1 swiftsec --version | grep 2.0.0`

### Nice to Have
- [ ] **Obsidian context update** — Save production hardening context to `/Users/harshithjella/SWIFT/Obsidian - SWIFT/SWIFT/context/`
- [ ] **AppRunner deployment** — Investigate why service not responding (see memory: apprunner-deployment-status.md)
- [ ] **Coverage gate raise** — Increase `fail_under` from 50 → 70 once more tests added
- [ ] **Docker multi-arch test** — Verify `linux/arm64` build works on Apple Silicon via `docker buildx`

---

## Smoke Tests (run to verify everything works)

```bash
source .venv/bin/activate
SWIFT_NO_BANNER=1 swiftsec --version          # → swiftsec 2.0.0
SWIFT_NO_BANNER=1 swiftsec --help             # → argparse help, no banner
swiftsec --no-banner scan ./test/e2e/test_repo # → no banner
swiftsec scan ./test/e2e/test_repo | cat      # → no banner (non-TTY stderr)
pytest test/unit/test_banner.py test/unit/test_redaction.py -v  # → 14 passed
```
