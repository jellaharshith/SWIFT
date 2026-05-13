# SWIFT Full Stack DX Overhaul — Next Up

## Phase 1A: CTF Golden Path (Days 1-2) — DONE ✅
- [x] Add `[ctf]` extras alias in `pyproject.toml` = `web + oob` — prerequisite for golden path
- [x] Add `swiftsec init --ctf <target>` subcommand in `swift/swift_cli.py` — generates pre-filled `roe.yaml` for Juice Shop/DVWA/Metasploitable from `swift/config/ctf_targets.py`
- [x] Add pre-flight reachability check + Playwright install check in `run_redteam()` / `run_web_scan()` — fast-fail with hint (`docker run -p 3000:3000 bkimminich/juice-shop`)
- [x] Create `docs/QUICKSTART.md` — 5-command Juice Shop tutorial using `pip install "swiftsec[ctf]"` + `web-scan --live`
- [x] Add `[ctf] = web + oob` to `pyproject.toml` optional-dependencies

## Phase 1B: Scan Quality + Feedback (Days 3-5) — DONE ✅
- [ ] Measure Juice Shop baseline TTHW before plateau fix (run `scripts/benchmark_tthw.sh`)
- [x] Fix plateau detection in `swift/agent/redteam_agent.py:131` — expand window 5→8, add fallback to unexplored vector
- [x] Add ScanEventBus (event callback system) — `swift/events/bus.py`, module-level singleton, Phase 2 TUI subscribes to same events
- [x] Fix top 5 first-run error messages — add problem + cause + exact fix command: ROE not found, API key missing, target unreachable, Playwright not installed, scan.json not found (in `_fail_closed()`)
- [x] Add Rich terminal summary by default in `run_redteam()` / `run_web_scan()` — `--json` flag for raw JSON stdout
- [x] Add `scripts/benchmark_tthw.sh` — times full Juice Shop clean-room run (fresh venv, pinned env, time-to-first-finding)

## Phase 2: Rich TUI + CLI Polish (Week 2) — DONE ✅
- [x] Build Rich TUI dashboard — `swift/cli/tui.py`, ScanEventBus subscriber, `--live` flag
- [ ] Group `swiftsec --help` by category (Getting Started / Red Team / Intel / Plugins / Utilities) using argparse groups
- [x] Deprecate `triage` (alias for `scan`) and `full` (alias for `full-scan`) with deprecation warnings — hard remove in v8
- [x] Add `swiftsec web-scan --live` as the CTF golden path command (update quickstart + README)

## Phase 3: Wizard + Bug Bounty (Week 3) — DONE ✅
- [x] `swiftsec init` interactive Rich wizard — prompts target URL, techniques, window dates, generates roe.yaml
- [x] HackerOne scope JSON validation — `swiftsec init --bugbounty <program.json>`, fnmatch wildcard, fail-closed (`swift/config/hackerone_validator.py`)
- [ ] Run on one real HackerOne public program target

## Post-Phase 2: Marketing
- [ ] Record demo GIF of SWIFT TUI finding a CRITICAL vuln on Juice Shop (use asciinema or ttygif)
- [ ] Add GIF to README below badges with caption "New here? → [QUICKSTART.md]"
- [ ] Reconcile docs drift: swift/README.md says v3.0, top README says v7.0

---

# SWIFT v7.0 Release — SHIPPED ✅ (2026-05-12)

## Session Summary
- [x] Feature: v7 intelligence engine (10-source RAG, ChromaDB, RAG injection)
- [x] Feature: Extended probes (cloud SSRF, supply chain, credential breach, mobile, AD, network service)
- [x] Feature: Kali runners (impacket, metasploit, crackmapexec, openvas, semgrep)
- [x] Feature: AI enhancement layer (multi-model fallback, payload mutator, attack graph, confidence calibrator)
- [x] Docs: README.md updated to v7.0
- [x] CI/CD: Intel sync workflow + test matrix updated

**Commits to main:**
- f3f44a8: feat: v7 intelligence engine + extended probes + kali tools
- 37c09be: docs: update README to v7.0
- 499431c: ci: add nightly intel sync workflow
- f492056: ci: include intel + kali extras in test matrix

---

# SWIFT v5.0 — Full Red-Team Hacker Upgrade

## Status: SHIPPED ✓ (488/490 tests pass, 2 pre-existing failures unrelated to v5)

## WS1 — Payload Customization ✓
- [x] `browser/payload_library.py` — load `~/.swift/payloads/{vuln_type}/*.txt` + `./payloads/`
- [x] `browser/payload_uploader.py` — validate, dedupe, register
- [x] modify `browser/payload_generator.py` — merge precedence: user > LLM > builtin
- [x] modify `browser/probes.py` — read from PayloadLibrary
- [x] CLI: `swift payload add|list|remove`
- [x] schema: `{vuln_type, payload, tags[], waf_bypass, framework_hint, source}`

## WS2 — OSINT 5→10 ✓
- [x] `osint/crtsh.py` — cert transparency subdomain enum
- [x] `osint/subdomain_takeover.py` — CNAME fingerprint check
- [x] `osint/wayback.py` — Wayback CDX URL discovery
- [x] `osint/tech_fingerprint.py` — Wappalyzer-style header/body detect (30+ signatures)
- [x] `osint/email_enum.py` — hunter.io / pattern guesser
- [x] modify `osint/runner.py` — all 10 sources concurrent
- [x] modify `agent/attack_surface.py` + `agent/bounty_models.py` — new fields

## WS3 — Niche Classifier ✓
- [x] `agent/niche_classifier.py` — Sonnet ranks OWASP/CWE niches per target
- [x] output `NicheProfile{primary_niches[], focus_payloads[], bounty_tier}`
- [x] modify `agent/bounty_orchestrator.py` — call post-OSINT, gate active phase

## WS4 — CISSP Persona ✓
- [x] `agent/pentester_persona.py` — system prompt: CISSP/OSCP 10yr, MITRE ATT&CK, STRIDE
- [x] inject into `agent/novel_method.py`, `agent/fix_suggester.py`, niche_classifier
- [x] modify `output/bug_bounty_report.py` — exec summary CISSP voice

## WS5 — Advanced Web Modules ✓
- [x] `browser/graphql_probe.py` — introspection, batching, alias overload, BOLA
- [x] `browser/race_condition.py` — asyncio burst N=20-50 on state-change endpoints
- [x] `browser/api_key_bruteforce.py` — bounded wordlist, ROE-gated, rate-limited
- [x] `browser/dom_idor.py` — Playwright crawl + numeric/UUID mutate w/ second session
- [x] modify `browser/playwright_runner.py` — register cohort

## WS6 — Live Chain Execution (Sandbox) ✓
- [x] `agent/chain_executor.py` — replay chain steps w/ real session tokens
- [x] sandbox allowlist (Juice Shop / DVWA)
- [x] modify `chains/detector.py` — attach executor results
- [x] modify `security/roe.py` — `allow_chain_execution` flag

## CLI Additions ✓
- [x] `swift payload add|list|remove`
- [x] `swift niche <target>`
- [x] `swift chain --execute <chain_id>`
- [ ] `swift osint --full <target>` — defer v5.1 (osint command not yet in cli/commands.py)
- [ ] `swift bounty <target> --niche-auto --custom-payloads ./payloads/` — defer v5.1

## Verification
- [x] unit: `test/unit/test_payload_library.py` — 13 pass
- [x] unit: `test/unit/test_niche_classifier.py` — 11 pass
- [x] unit: `test/unit/test_osint_new_sources.py` — 16 pass
- [x] unit: `test/unit/test_chain_executor.py` — 13 pass
- [ ] e2e: `SWIFT_RUN_E2E=1 pytest test/e2e/test_juice_shop.py` — requires live Juice Shop
- [ ] manual: `swift bounty juice-shop.local --niche-auto --custom-payloads ./payloads/`
- [ ] ROE deny test → exit 2

## v5.1 Backlog
- `swift osint --full <target>` CLI command
- `swift bounty --niche-auto --custom-payloads` flag
- e2e test_juice_shop.py with live target
- Real `cli/commands.py` subcommands (currently in swift_cli.py handlers)
- Cloud recon (AWS/GCP/Azure)
- Mobile (Frida/objection)
- Dark-web/pastebin scraping

## Out of Scope (permanent)
- Real C2/persistence execution (stays simulate-only)

---

# SWIFT v6.0 — 7-Module Red-Team Platform

## Status: SHIPPED ✓ (597/597 tests pass, ruff clean — commit ce70b82)

**Goal:** OOB SSRF + OAuth + WebSocket + BizLogic probes + Agentic loop + Immutable audit log + Plugin SDK

**Branch:** feature/unified-scanner

### Phase 0 — Pre-work ✓
- [x] Task 0.1: pyproject.toml v6.0 deps (websockets, cryptography, jsonschema, diskcache, dnslib + entry-points group)
- [x] Task 0.2: ROEViolation + new techniques (oob_ssrf, oauth_attack, websocket_attack, bizlogic, agentic_loop)
- [x] Task 0.3: .env.example (INTERACTSH_URL, SWIFT_GPG_KEY_ID, SWIFT_AGENT_BUDGET_*)

### Phase 1 — Foundations [Modules 6+7] ✓
- [x] Task 1.1: swift/audit/immutable_log.py — HashChainLogger, LogEntry, tamper detection, 10MB rotation
- [x] Task 1.2: swift/audit/decorators.py + manifest.py — @audit_logged, EngagementManifest (GPG/HMAC)
- [x] Task 1.3: swift/audit/reporter.py + cli.py — audit verify/export argparse subcommands
- [x] Task 1.4: swift/sdk/base.py — Finding, Phase, VulnType, Severity, BaseModule ABC
- [x] Task 1.5: swift/sdk/decorators.py — @roe_gated, @cached_result, @retry
- [x] Task 1.6: swift/sdk/registry.py + migration.py — PluginRegistry + 6 adapter wrappers
- [x] Task 1.7: swift/sdk/testing.py — SwiftTestHarness, MockSessionManager, DEFAULT_TEST_ROE
- [x] Task 1.8: swift/sdk/cli.py — plugin install/list/remove/validate argparse commands
- [x] Task 1.9: docs/sdk/WRITING_A_MODULE.md — complete CSRF example + tutorial

### Phase 2 — Probes [Modules 1-4] ✓
- [x] Task 2.1: swift/probes/oob_ssrf.py — OOBCallbackServer + Interactsh + cloud metadata bypass
- [x] Task 2.2: swift/probes/oauth.py — 5 attacks: redirect_uri, PKCE, token_leak, cred_stuff, logout
- [x] Task 2.3: swift/probes/websocket.py — 5 attacks: CSWSH, unauth, IDOR, injection, namespace
- [x] Task 2.4: swift/probes/bizlogic.py — Sonnet flow analysis + 5 Playwright attack executors
- [x] Task 2.5: swift/probes/__init__.py — registry wiring (all 10 modules discoverable)

### Phase 3 — Agentic Loop [Module 5] ✓
- [x] Task 3.1: swift/agent/agent_tools.py — 5 tool schemas + async dispatch_tool()
- [x] Task 3.2: swift/agent/agent_prompts.py — AGENT_SYSTEM_PROMPT (verbatim) + dataclasses
- [x] Task 3.3: swift/agent/redteam_agent.py — RedTeamAgent (plateau, compression, budget, audit)
- [x] Task 3.4: CLI --agentic flag + agent-status subcommand

### Phase 4 — Integration ✓
- [x] Task 4.1: Wire HashChainLogger into engagement init
- [x] Task 4.2: Add chain_primitive + oob_confirmed to Vulnerability dataclass
- [x] Task 4.4: test/integration/test_v6_e2e.py — mock-based pipeline test

### Phase 5 — Reviews (manual, run after merge)
- [ ] /codex consult — agentic loop safety + OOBCallbackServer reflector risk + hash chain gotchas
- [ ] /plan-eng-review — architecture review
- [ ] /cso daily — security audit (audit/, oauth.py, oob_ssrf.py)
- [ ] /codex challenge — adversarial review of RedTeamAgent + OOBCallbackServer

### New Files
```
swift/probes/__init__.py, base.py, oob_ssrf.py, oauth.py, websocket.py, bizlogic.py
swift/probes/_oob/server.py, interactsh.py
swift/audit/__init__.py, immutable_log.py, decorators.py, manifest.py, cli.py, reporter.py
swift/sdk/__init__.py, base.py, decorators.py, registry.py, testing.py, cli.py, migration.py
swift/agent/redteam_agent.py, agent_tools.py, agent_prompts.py
docs/sdk/WRITING_A_MODULE.md
test/unit/test_oob_ssrf.py, test_oauth.py, test_websocket.py, test_bizlogic.py
test/unit/test_audit.py, test_audit_chain.py
test/unit/test_sdk_base.py, test_sdk_decorators.py, test_sdk_registry.py, test_sdk_testharness.py
test/unit/test_redteam_agent.py
test/integration/test_agent_loop.py, test_audit_e2e.py, test_v6_e2e.py
```

### Modified Files
```
swift/security/roe.py          +ROEViolation, +new techniques
swift/browser/session_manager.py  +set_oauth_token(), +set_ws_token()
swift/agent/models.py          +chain_primitive, +oob_confirmed
swift/agent/redteam_orchestrator.py  +--agentic dispatch
swift_cli.py                   +audit/plugin/agent-status subparsers
pyproject.toml                 +deps, +entry-points
.env.example                   +v6.0 vars
```

### Verification Commands
```bash
pytest test/unit/ -v --cov=swift -k "oob_ssrf or oauth or websocket or bizlogic or redteam_agent or audit or sdk"
python -c "from swift.sdk.registry import PluginRegistry; r=PluginRegistry(); r.discover(); print(sorted(r._modules))"
swiftsec audit verify --log ~/.swift/engagements/<id>/audit.jsonl
swiftsec plugin list
ruff check swift/ && black --check swift/ && mypy swift/ --strict
```
