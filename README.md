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
  v5.0.0 · CISSP/OSCP-grade · mode: red-team
```

## What SWIFT does

| Phase | Tools | Result |
|-------|-------|--------|
| **OSINT (10 sources)** | DNS, crt.sh cert transparency, CNAME takeover, Wayback CDX, tech fingerprint, email enum, GitHub dorks, Shodan, WHOIS | Full target intel before first packet |
| **Niche Classification** | Claude Sonnet + CISSP persona | Ranks OWASP/CWE attack niches, gates active probe phase |
| **Triage** | Claude Haiku | Flags suspicious code patterns (~50ms/file) |
| **Active probes** | Playwright + Claude Sonnet | 16 vuln types confirmed at ≥95% confidence |
| **GraphQL attacks** | httpx | Introspection, batching, alias overload, BOLA |
| **Race conditions** | asyncio burst | N=20–50 concurrent requests, 2σ anomaly detection |
| **API key discovery** | Bounded wordlist | ROE-gated, rate-limited, 50-key max |
| **DOM IDOR** | Playwright | Numeric/UUID mutation with second-session PII diff |
| **Custom payloads** | PayloadLibrary | User payloads from `~/.swift/payloads/` take precedence over LLM > builtin |
| **Credential chains** | SessionManager | JWT/cookie reuse across SQLi → auth → IDOR → privesc |
| **LLM payloads** | Claude Haiku | Context-aware mutation, WAF-bypassing variants |
| **Kali automation** | 13 tools + WAF evasion | nmap, nikto, sqlmap, nuclei, ffuf, amass, feroxbuster + more |
| **Chain execution** | ROE-gated sandbox | Replay attack chains with real session tokens (Juice Shop / DVWA) |
| **Post-exploit sim** | Docker sandbox | Data-exfil, persistence, C2 feasibility — simulate only |
| **Reporting** | CISSP-voice Markdown / JSON / SARIF | Bug bounty + pentest report formats |

## Quick start

```bash
pip install swiftsec
export ANTHROPIC_API_KEY=sk-ant-...

# Copy and fill in the ROE template (required for offensive commands)
cp roe.example.yaml roe.yaml
# Edit roe.yaml: set authorized_targets, window dates, contact

# Full red-team pipeline (default phases: osint → niche → active → chain → postex)
swiftsec redteam --roe roe.yaml --target https://your-authorized-target.com

# With local repo (static scan + exploit chains)
swiftsec redteam --roe roe.yaml --target https://your-authorized-target.com --repo ./my-app

# Optional privesc phase
swiftsec --yes redteam --roe roe.yaml --target https://your-authorized-target.com --repo ./my-app \
  --phases osint,code,active,chain,privesc,postex --allow-privesc

# OSINT only (10 sources)
swiftsec osint --roe roe.yaml --out osint.json

# Classify attack niches for a target
swiftsec niche example.com

# Static code scan
swiftsec scan ./my-project

# Kali offensive scan
swiftsec kali-scan --target 10.0.0.1 --tools nmap,nikto,nuclei,ffuf

# Playwright web probe
swiftsec web-scan --target https://your-authorized-target.com --yes

# Manage custom payloads
swiftsec payload add ./my-payloads.txt --vuln-type xss
swiftsec payload list
swiftsec payload remove --vuln-type xss --payload "<script>alert(1)</script>"

# Execute a validated attack chain (sandbox only)
swiftsec chain --execute CHAIN-001 --roe roe.yaml

# Interactive wizard
swiftsec wizard
```

## ROE gate

Subcommands **`redteam`** and **`osint`** require a Rules-of-Engagement YAML (`--roe`). Scope, allowed techniques, and time window are validated before work starts.

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
allow_chain_execution: false   # set true only for Juice Shop / DVWA targets
```

SWIFT **hard fails** (`[DENY]` + exit 2) when ROE is missing or when:
- Target not in `authorized_targets`
- Requested technique not in `allowed_techniques`
- Current time outside `window_start` / `window_end`

`allow_chain_execution: true` enables live chain replay — only effective against Juice Shop / DVWA.

## v5.0 highlights

### 10-source OSINT (up from 5)

| New source | What it finds |
|-----------|---------------|
| `crtsh` | Subdomains via certificate transparency logs |
| `subdomain_takeover` | CNAME fingerprints for dangling DNS |
| `wayback` | Historical endpoints via Wayback CDX API |
| `tech_fingerprint` | 30+ tech signatures from headers + body |
| `email_enum` | Pattern-guessed mailboxes + optional hunter.io |

### Niche Classifier

Sonnet analyzes the full attack surface (tech stack, open ports, GitHub leaks) and ranks the top OWASP/CWE niches before active probing. Active phase only fires payloads relevant to the target's profile.

```
Target Attack Profile: api_security, auth_bypass, idor
Bounty Tier: high
```

### Custom Payload Library

Drop `.txt` files into `~/.swift/payloads/{vuln_type}/` — SWIFT loads them at runtime. Precedence: **user > LLM-generated > builtin**.

```bash
swift payload add custom-xss.txt --vuln-type xss
swift payload list --vuln-type sqli
```

### Advanced Web Modules

- **GraphQL probe** — introspection enabled, batching abuse, alias overload, BOLA detection
- **Race condition** — asyncio burst (N=20–50), detects duplicate-success and timing anomalies
- **API key bruteforce** — ROE-gated, rate-limited, bounded 50-key wordlist
- **DOM IDOR** — Playwright crawl with numeric/UUID ID mutation and cross-session PII diff

### Sandboxed Chain Execution

Replay validated attack chains with real session tokens against allowed targets. Each step captures response evidence. `validated: true` only when the full chain succeeds.

### CISSP/OSCP Persona

All LLM prompts now use offensive attacker framing:
- MITRE ATT&CK + STRIDE reasoning
- Chains primitives: auth bypass → IDOR → privesc
- Executive reports written in CISSP voice

## Global CLI flags

| Flag | Env | Effect |
|------|-----|--------|
| `--version` | — | Print version and exit |
| `--yes` / `-y` | `SWIFT_AUTO_CONFIRM=1` | Skip interactive consent |
| `--no-banner` | `SWIFT_NO_BANNER=1` | Suppress ASCII banner |
| `--quiet` / `-q` | — | Minimal output |
| `--log-file PATH` | — | Override step log |

## Commands (quick index)

| Command | ROE YAML | Notes |
|---------|:--------:|-------|
| `redteam` | Required | Full pipeline, all 6 phases |
| `osint` | Required | 10-source recon only |
| `niche <target>` | — | OSINT → niche classification |
| `scan` | — | Static codebase scan |
| `triage` | — | Alias of `scan` |
| `report` | — | Needs prior scan artifacts |
| `full-scan` | — | Code + Kali + CVE correlation |
| `kali-scan` | — | Kali tools only |
| `web-scan` | — | Playwright active probe |
| `payload add\|list\|remove` | — | Manage custom payload library |
| `chain --execute` | Required | Replay chain (sandbox only) |
| `attack-sim` | — | MITRE-mapped Kali run |
| `live-feed` | — | NVD + CISA KEV stream |
| `privesc` | — | Docker privesc (--allow-privesc) |
| `wizard` | — | Interactive menu |

## Active probe types

XSS · SQLi · SSRF · SSTI · IDOR · JWT alg:none · XXE · CRLF · NoSQL · Prototype Pollution · Auth Bypass · HTTP Smuggling · GraphQL · Race Condition · API Key Discovery · DOM IDOR

## Credential chaining

`SessionManager` shares cookies and JWTs across probe steps:

```
SQLi → leaked password → form login → JWT captured → IDOR as victim → privilege escalation
```

Payloads: user library → LLM-generated (Haiku, prompt-cached) → hardcoded fallback.

## Post-exploit (simulate only)

| Module | What it measures |
|--------|-----------------|
| `data_exfil_sim` | Record count, PII type exposure, no real pull |
| `persistence_sim` | Writable cron/ssh/systemd — read-only check |
| `c2_sim` | DNS + HTTP egress to canary host — no real C2 |

## Exploit chain graph

DFS over directed vuln graph with `MAX_CHAIN_DEPTH = 5`. Node types:

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
| `HUNTER_API_KEY` | Optional | hunter.io email enumeration |
| `SWIFT_ROE` | Optional | Default ROE file path |

## Safety guarantees

- ROE gate: hard fail-closed on scope/technique/window violations
- `allow_chain_execution` flag required + target allowlist for live chain replay
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
