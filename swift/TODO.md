# SWIFT v3.0 — Red-Team Automation Pentester

## Status: IN PROGRESS (sub-agents dispatched 2026-05-04)

## Objective
Transform SWIFT from a defensive scanner into a full red-team automation tool.
Remove patching feature. Add: ROE gate, OSINT, SessionManager, LLM payloads, post-exploit sim, advanced Kali.
All offensive ops sandboxed. Simulate-only post-exploit.

---

## Part A — Patch Feature Excision [ ]
- [ ] Delete patches/, patch_apply.py, patch_validator.py
- [ ] Delete test/integration/test_patch_generator.py
- [ ] Edit agent/orchestrator.py — remove generate_patches_flag, Phase-4 block, generate_patches(), PatchGenerator import
- [ ] Edit agent/unified_orchestrator.py — remove generate_patches param
- [ ] Edit agent/models.py — drop Patch + ScanResult.patches; add OsintFinding, PostExploitFinding, Credential, RedTeamResult
- [ ] Edit swift_cli.py — remove patch/validate cmds + --allow-patch-generation; add redteam/osint stubs
- [ ] Edit cli/commands.py — remove patch Click command
- [ ] Edit output/formatters.py, report_normalizer.py, unified_report.py — remove patches sections
- [ ] Edit CLAUDE.md, README.md, CHANGELOG.md — update docs

## Part B — Security Infra: ROE Gate + RedTeam Sandbox [ ]
- [ ] Create security/roe.py — ROE dataclass, load_roe(), assert_target_in_scope(), assert_technique_allowed(), assert_window_active()
- [ ] Create sandbox/redteam_workbench.py — RedTeamSandbox using kalilinux/kali-rolling, network-scoped to target, ephemeral
- [ ] Create roe.example.yaml — starter template
- [ ] Update requirement.txt — add python-whois, dnspython, shodan, PyGithub, cryptography, httpx[http2]

## Part C — OSINT Phase [ ]
- [ ] Create osint/dns_recon.py — AXFR, subdomain enum via amass+subfinder, crt.sh, dnsx
- [ ] Create osint/whois_asn.py — whois + team-cymru ASN
- [ ] Create osint/github_dorks.py — GitHub code search for leaked secrets/endpoints
- [ ] Create osint/shodan_query.py — Shodan host lookup (optional, key-gated)
- [ ] Create osint/runner.py — async run_osint(roe) → OsintResult; feeds exploit_graph

## Part D — Browser: SessionManager + LLM Payloads [ ]
- [ ] Create browser/session_manager.py — shared cookie/JWT/header state across probes
- [ ] Create browser/payload_generator.py — Haiku-backed mutated payload gen with prompt cache
- [ ] Edit browser/probes.py — async wrapper calls generator; hardcoded as fallback
- [ ] Edit browser/playwright_runner.py — thread SessionManager, capture after each probe

## Part E — Post-Exploit Simulators [ ]
- [ ] Create post_exploit/data_exfil_sim.py — count rows/IDs, PII heuristic, no real pull
- [ ] Create post_exploit/persistence_sim.py — detect writable cron/.ssh/systemd, score feasibility
- [ ] Create post_exploit/c2_sim.py — DNS canary egress test, no real C2

## Part F — Kali + Persona + Graph Upgrades [ ]
- [ ] Edit kali/runner.py — add wfuzz, ffuf, httpx, subfinder, amass, feroxbuster; WAF evasion flags
- [ ] Edit triage/exploit_graph.py — new node classes (exposed_credential, data_exposure, c2_feasibility); MAX_CHAIN_DEPTH 3→5
- [ ] Edit agent/pentester_persona.py — extend preamble with OSINT + post-exploit node reasoning

## Part G — Integration & Verification [ ]
- [ ] Wire swift redteam command: ROE → sandbox → OSINT → codescan → web probes → Kali → chains → post-exploit → report
- [ ] Create output/redteam_report.py
- [ ] Run pytest swift/test/ — coverage ≥ 80%
- [ ] E2E on Juice-Shop: ≥3 confirmed vulns, ≥1 chain crossing ≥3 nodes

---

## Done
- [x] Unified scanner pipeline (Layers 1-7)
- [x] Playwright probes (12 types)
- [x] Haiku triage → Sonnet analysis → 95% confidence gate
- [x] Exploit chain graph (DFS, bounded)
- [x] Pentester persona prompting
- [x] Kali Docker runner (nmap, nikto, sqlmap, nuclei, gobuster)
- [x] PrivEsc runner (Docker sandbox)
- [x] Bug bounty + pentest report formatters
