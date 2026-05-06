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
