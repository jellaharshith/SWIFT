# SWIFT — AI-Powered Red-Team Automation Pentester

> OSINT → active probes → credential-chained attacks → post-exploit assessment. All sandboxed. All AI-driven.

[![CI](https://github.com/jellaharshith/SWIFT/actions/workflows/ci.yml/badge.svg)](https://github.com/jellaharshith/SWIFT/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/swiftsec.svg)](https://pypi.org/project/swiftsec/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

```
███████╗██╗    ██╗██╗███████╗████████╗
██╔════╝██║    ██║██║██╔════╝╚══██╔══╝
███████╗██║ █╗ ██║██║█████╗     ██║
╚════██║██║███╗██║██║██╔══╝     ██║
███████║╚███╔███╔╝██║██║        ██║
╚══════╝ ╚══╝╚══╝ ╚═╝╚═╝        ╚═╝

  AI-Powered Red-Team Automation Pentester
  v8.0.0 · CISSP/OSCP-grade · Multi-Agent Kill Chain + Bug-Bounty Automation
```

## v8.0 -- merged platform

SWIFT v8 absorbs two upstream projects (see `/NOTICE` for attribution):

* [Decepticon](https://github.com/PurpleAILAB/Decepticon) (Apache-2.0)
  -- 16 specialist agents + 10 LangGraph sub-graphs + Kali sandbox stack.
* [claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) (MIT)
  -- 8 agent skills + 23 slash commands + hunt memory + 7-question
  validator + multi-platform report formatters + web3 auditor.

Eleven new `swiftsec` subcommands:

```
swiftsec engage           swiftsec hunt           swiftsec web3-audit
swiftsec redteam-full     swiftsec validate       swiftsec lab
swiftsec vuln-pipeline    swiftsec autopilot      swiftsec skills
swiftsec bb-report        swiftsec kg
```

Run `swiftsec <cmd> --help` for each. Full architecture: `swift/CLAUDE.md`.

## What SWIFT does (v7 surface preserved)

| Phase | Tools | Result |
|-------|-------|--------|
| **OSINT** | DNS recon, crt.sh, Wayback, tech fingerprint, subdomain takeover, GitHub dorks, Shodan, WHOIS | Target intel before first packet |
| **Triage** | Claude Haiku | Flags suspicious code patterns (~50ms/file) |
| **Active probes** | Playwright + Claude Sonnet | 12 vuln types confirmed at ≥95% confidence |
| **Credential chains** | SessionManager | JWT/cookie reuse across SQLi → auth → IDOR → privesc |
| **LLM payloads** | LLMPayloadMutator + Haiku | Context-aware WAF-bypass variants per tech stack |
| **Intel Engine** | 10-source RAG (MITRE, ExploitDB, Nuclei, HackerOne…) | ChromaDB + MiniLM embeddings injected into every Sonnet prompt |
| **Extended probes** | Cloud SSRF, supply chain, credential breach, mobile static, AD, network service | ROE-gated per technique |
| **Kali Suite** | impacket, metasploit, crackmapexec, openvas, semgrep + 13 WAF-evading tools | Kali container, --network=none sandbox |
| **Post-exploit sim** | Docker sandbox | Data-exfil, persistence, C2 feasibility — simulate only |
| **Reporting** | Markdown / JSON / SARIF | Bug bounty + pentest report formats |

## Quick start

```bash
pip install swiftsec
export ANTHROPIC_API_KEY=sk-ant-...

# Copy and fill in the ROE template (required for offensive commands)
cp roe.example.yaml roe.yaml
# Edit roe.yaml: set authorized_targets, window dates, contact

# Full red-team pipeline
swiftsec redteam --roe roe.yaml --target https://your-authorized-target.com

# OSINT only
swiftsec osint --roe roe.yaml --out osint.json

# Static code scan
swiftsec scan ./my-project

# Kali offensive scan
swiftsec kali-scan --target 10.0.0.1 --roe roe.yaml --tools nmap,nikto,nuclei,ffuf

# Playwright web probe
swiftsec web-scan --target https://your-authorized-target.com --roe roe.yaml

# Interactive wizard
swiftsec wizard
```

## ROE gate

Every offensive command requires a signed Rules-of-Engagement file:

```yaml
# roe.yaml
engagement_id: "ENG-001"
authorized_targets:
  - "https://target.example.com"
allowed_techniques:
  - osint
  - active_scan
  - exploit
  - post_exploit
window_start: "2026-01-01T00:00:00"
window_end:   "2026-12-31T23:59:59"
contact:      "you@yourorg.com"
simulate_only: true
```

SWIFT **hard fails** (`[DENY]` + exit 2) if:
- No ROE file provided
- Target not in `authorized_targets`
- Technique not in `allowed_techniques`
- Current time outside `window_start`/`window_end`

## Commands

| Command | Description |
|---------|-------------|
| `redteam` | Full pipeline: ROE → OSINT → scan → probes → Kali → chains → post-exploit |
| `osint` | Recon only: DNS, subdomain enum, GitHub dorks, Shodan, WHOIS |
| `scan` | Static code vulnerability scan (local path or GitHub URL) |
| `triage` | Fast pattern-matching triage only |
| `full-scan` | Code + Kali + CVE scan simultaneously |
| `kali-scan` | 13 Kali tools against live target with WAF evasion |
| `web-scan` | Playwright-driven active web vulnerability scan (12 types) |
| `attack-sim` | MITRE ATT&CK-mapped exploit simulation |
| `live-feed` | Stream live CVEs from NVD + CISA KEV |
| `privesc` | Docker-based privilege escalation tester |
| `wizard` | Interactive scanner wizard |
| `ai info\|sync\|ask\|repl` | LLM ethical-hacker assistant: live-CVE RAG (NVD→SQLite/FTS5) + tool-calling over recon/scan/scope/report. Backends: Ollama or Anthropic (no SDK). Active tools ROE-gated; reports drafted only. See root README → "AI Assistant". |

## Active probe types

XSS · SQLi · SSRF · SSTI · IDOR · JWT alg:none · XXE · CRLF · NoSQL · Prototype Pollution · Auth Bypass · HTTP Smuggling

## Credential chaining

`SessionManager` shares cookies and JWTs across probe steps:

```
SQLi → leaked password → form login → JWT captured → IDOR as victim → privilege escalation
```

Payloads are LLM-generated per detected stack (Haiku, prompt-cached). Hardcoded library used as fallback.

## Post-exploit (simulate only)

| Module | What it measures |
|--------|-----------------|
| `data_exfil_sim` | Record count, PII type exposure, no real pull |
| `persistence_sim` | Writable cron/ssh/systemd — read-only check |
| `c2_sim` | DNS + HTTP egress to canary host — no real C2 |

All run inside the Docker workbench. `simulate_only: true` is the default and enforced by the ROE.

## Exploit chain graph

DFS over a directed vuln graph with `MAX_CHAIN_DEPTH = 5`. New node types:

```
exposed_credential → auth_bypass → privilege_escalation
github_leak        → credential_stuffing
shodan_service     → exposed_service → network_access
data_exposure      → sensitive_data_exposure
c2_feasibility     → command_and_control
```

## Kali tools

| Tool | MITRE | WAF evasion |
|------|-------|-------------|
| nmap | T1046 | `-T2 --max-rate 100 --scan-delay 200ms` |
| nikto | T1190 | `-evasion 1` |
| sqlmap | T1190 | `--random-agent --tamper=between,space2comment --delay=1` |
| nuclei | T1190 | `-rate-limit-minute 30 -timeout 10` |
| gobuster | T1595.002 | — |
| masscan | T1595 | — |
| ffuf | T1595.002 | `-p 0.1-0.3` |
| wfuzz | T1595.002 | — |
| feroxbuster | T1595.002 | `--rate-limit 50` |
| httpx | T1595.001 | — |
| subfinder | T1590.001 | — |
| amass | T1590.001 | — |
| searchsploit | T1588.005 | — |

## Configuration

```bash
cp swift/.env.example .env
```

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | ✅ | Claude API key |
| `GITHUB_TOKEN` | Optional | GitHub dork search |
| `SHODAN_API_KEY` | Optional | Shodan intel |
| `NVD_API_KEY` | Optional | NVD CVE feed (higher rate limit) |
| `SWIFT_ROE` | Optional | Default ROE file path |

## Safety guarantees

- ROE gate: hard fail-closed on scope/technique/window violations
- All offensive ops inside ephemeral Docker container (auto-removed)
- No host filesystem mounts during offensive runs
- Post-exploit: simulate-only by default, enforced by ROE
- Code scan sandbox: `--network=none`, read-only FS, 2-core / 2 GB / 30 s
- **Only reports findings with confidence ≥ 95%**

## CI/CD integration

```yaml
- name: SWIFT code scan
  run: swiftsec scan . --output json > swift-report.json
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    SWIFT_NO_BANNER: "1"
```

## Output is pipe-safe

Banner always goes to stderr. JSON to stdout:

```bash
swiftsec scan ./repo | jq '.findings[] | select(.severity == "CRITICAL")'
```

## Docs

Full architecture: [`docs/README.md`](docs/README.md)

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) · Run tests: `pytest test/ -v --cov`

## Security

[`SECURITY.md`](SECURITY.md)

## License

MIT — [`LICENSE`](LICENSE)
