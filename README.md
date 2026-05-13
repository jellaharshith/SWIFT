# SWIFT — AI-Powered Red-Team Automation Pentester

> OSINT → active probes → credential-chained attacks → post-exploit assessment. All sandboxed. All AI-driven.

[![CI](https://github.com/jellaharshith/SWIFT/actions/workflows/ci.yml/badge.svg)](https://github.com/jellaharshith/SWIFT/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/swiftsec.svg)](https://pypi.org/project/swiftsec/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![SWIFT TUI finding CRITICAL vuln on Juice Shop](docs/demo.gif)

> New here? → [QUICKSTART.md](docs/QUICKSTART.md)

```
███████╗██╗    ██╗██╗███████╗████████╗
██╔════╝██║    ██║██║██╔════╝╚══██╔══╝
███████╗██║ █╗ ██║██║█████╗     ██║
╚════██║██║███╗██║██║██╔══╝     ██║
███████║╚███╔███╔╝██║██║        ██║
╚══════╝ ╚══╝╚══╝ ╚═╝╚═╝        ╚═╝

  AI-Powered Red-Team Automation Pentester
  v7.0.0 · CISSP/OSCP-grade · Continuous Intelligence + Extended Attack Coverage
```

## What SWIFT does (v7.0)

### Intelligence Engine — Continuous Learning

| Component | Sources | Function |
|-----------|---------|----------|
| **Intel Sync** | MITRE ATT&CK, ExploitDB, GitHub Advisories, Nuclei templates, PayloadsAllTheThings, SecLists, HackerOne disclosures, OWASP WSTG, Security blogs RSS, Snyk VulnDB | 10-source RAG knowledge base at `~/.swift/intel/chromadb` |
| **RAG Retrieval** | ChromaDB + all-MiniLM-L6-v2 embeddings | Inject fresh payloads + techniques into every Sonnet prompt |
| **Payload Injection** | LLMPayloadMutator + Haiku | Context-aware WAF-bypass variants per tech stack |
| **Confidence Calibration** | ConfidenceCalibrator + sklearn | OOB confirmed=keep, keyword-only=×0.7, tool+AI agree=×1.1 |

### Extended Attack Coverage

| Probe | Targets | ROE |
|-------|---------|-----|
| **Cloud SSRF** | AWS IMDS (IPv4/IPv6), GCP metadata, Azure IMDS | `active_scan` |
| **Supply Chain** | Dependency confusion, typosquatting (PyPI/NPM) | `osint` |
| **Credential Breach** | HIBP k-anonymity breach check | `osint` |
| **Mobile Static** | APK decompile, API key/endpoint grep | `active_scan` |
| **Active Directory** | LDAP enum, Kerberoasting (Impacket) | `exploit` |
| **Network Service** | nmap service version → NVD CVE → exploitdb PoC | `active_scan` |

### Kali Tool Suite (v7.0)

| Tool | MITRE | Purpose | ROE |
|------|-------|---------|-----|
| **impacket-scripts** | T1550.001 | Kerberoasting, LDAP enum | `exploit` |
| **metasploit-framework** | T1587.004 | Module exploitation (msfrpc, simulate_only default) | `exploit` |
| **crackmapexec** | T1021.002 | SMB/WinRM/LDAP/MSSQL enum | `active_scan` |
| **openvas** | T1046 | GMP XML API, CVSSv3 scoring | `active_scan` |
| **semgrep-rules** | T1526 | SAST: py/js/java/go/ruby/php | `osint` |

### AI Enhancement Layer (v7.0)

| Component | Model | Function |
|-----------|-------|----------|
| **MultiModelClient** | Claude → GPT-4o → Gemini | Fallback on RateLimitError |
| **Attack Graph Reasoner** | Sonnet (tool-use) | MITRE ATT&CK-mapped exploit chains |
| **Confidence Calibrator** | sklearn LogisticRegression | Downscale keyword-only, boost OOB/multi-signal |

### v6.0 Features (Still Active)

| Phase | Tools | Result |
|-------|-------|--------|
| **OSINT (10 sources)** | DNS, crt.sh, CNAME takeover, Wayback CDX, tech fingerprint, email enum, GitHub dorks, Shodan, WHOIS | Full target intel before first packet |
| **Niche Classification** | Claude Sonnet + CISSP persona | Ranks OWASP/CWE attack niches, gates active probe phase |
| **Triage** | Claude Haiku | Flags suspicious code patterns (~50ms/file) |
| **Active probes** | Playwright + Claude Sonnet | 26 vuln types (v6+v7) confirmed at ≥95% confidence |
| **OOB SSRF** | Async callback server + Interactsh | Confirmed out-of-band SSRF via real DNS/HTTP callbacks |
| **OAuth/OIDC attacks** | httpx | PKCE downgrade, redirect_uri manipulation, token leakage, cred stuffing |
| **WebSocket attacks** | websockets + Playwright | CSWSH, unauth upgrade, IDOR, injection, namespace abuse |
| **Business logic** | Sonnet + Playwright | Price manipulation, coupon stacking, workflow skip, negative qty |
| **Agentic loop** | RedTeamAgent (Sonnet tool-use) | Autonomous pentesting with plateau detection + budget gates |
| **GraphQL attacks** | httpx | Introspection, batching, alias overload, BOLA |
| **Race conditions** | asyncio burst | N=20–50 concurrent requests, 2σ anomaly detection |
| **API key discovery** | Bounded wordlist | ROE-gated, rate-limited, 50-key max |
| **DOM IDOR** | Playwright | Numeric/UUID mutation with second-session PII diff |
| **Custom payloads** | PayloadLibrary | User payloads from `~/.swift/payloads/` take precedence over LLM > builtin |
| **Credential chains** | SessionManager | JWT/cookie reuse across SQLi → auth → IDOR → privesc |
| **Chain execution** | ROE-gated sandbox | Replay attack chains with real session tokens (Juice Shop / DVWA) |
| **Post-exploit sim** | Docker sandbox | Data-exfil, persistence, C2 feasibility — simulate only |
| **Immutable audit log** | SHA-256 hash chain | Tamper-evident engagement log, GPG/HMAC manifest signing |
| **Plugin SDK** | BaseModule ABC + PluginRegistry | Write custom probes, auto-discovered at runtime |
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

# Agentic mode — Sonnet drives the engagement autonomously
swiftsec redteam --roe roe.yaml --target https://your-authorized-target.com --agentic

# Watch live agent progress
swiftsec agent-status

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

# Audit log — verify hash chain integrity
swiftsec audit verify --log ~/.swift/engagements/<id>/audit.jsonl

# Audit log — export engagement report
swiftsec audit export --log ~/.swift/engagements/<id>/audit.jsonl --out report.md

# Plugin SDK — manage custom probe modules
swiftsec plugin list
swiftsec plugin install ./my_probe/
swiftsec plugin validate ./my_probe/

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
  - oob_ssrf        # v6.0 — OOB SSRF with callback server
  - oauth_attack    # v6.0 — OAuth/OIDC attack probes
  - websocket_attack # v6.0 — WebSocket attack probes
  - bizlogic        # v6.0 — Business logic probes
  - agentic_loop    # v6.0 — Autonomous agentic pentesting
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

## v7.0 highlights

### RAG-Powered Intelligence Engine

SWIFT learns from the internet continuously — syncs MITRE ATT&CK, ExploitDB, GitHub Advisories, Nuclei templates, PayloadsAllTheThings, SecLists, HackerOne disclosed reports, OWASP WSTG, security blogs (PortSwigger, NCC, Project Zero, Assetnote, Snyk), and Snyk VulnDB into a ChromaDB knowledge base. Every Sonnet prompt is RAG-enriched with fresh payloads and techniques before firing any probe.

```bash
# Auto-sync all sources nightly (or on-demand)
swiftsec intel sync [--sources mitre_attack,exploitdb,nuclei_templates] [--force]

# Search the knowledge base
swiftsec intel search "SQL injection WAF bypass" --n 10

# Check sync status
swiftsec intel status

# Version tracking + rollback
swiftsec intel version --list | --rollback {id}
```

### Extended Attack Coverage — 6 New Probes

1. **Cloud SSRF** — AWS/GCP/Azure IMDS metadata extraction (active_scan ROE)
2. **Supply Chain** — Dependency confusion + typosquatting via PyPI/NPM (osint ROE)
3. **Credential Breach** — HIBP k-anonymity check for discovered emails (osint ROE)
4. **Mobile Static** — APK decompile + secret grep (active_scan ROE)
5. **Active Directory** — LDAP enum + Kerberoasting via Impacket (exploit ROE)
6. **Network Service** — nmap service version → NVD CVE lookup → exploitdb PoC (active_scan ROE)

### Kali Tool Runners

Docker-isolated runners for Kali automation:
- **impacket-scripts** — Kerberoasting, LDAP enumeration
- **metasploit-framework** — msfrpc API with simulate_only default
- **crackmapexec** — SMB/WinRM/LDAP/MSSQL enum
- **openvas** — GMP XML API with CVSSv3 parsing
- **semgrep-rules** — SAST across py/js/java/go/ruby/php

All respect WAF-evasion flags, ROE gates, and `--network=none` sandbox.

### AI Enhancement Layer

- **MultiModelClient** — Claude → GPT-4o → Gemini fallback on rate limits
- **LLMPayloadMutator** — Haiku bulk mutation + Sonnet WAF-bypass variants per tech stack
- **AttackGraphReasoner** — Sonnet maps MITRE ATT&CK exploit chains from findings + RAG context
- **ConfidenceCalibrator** — Smart downscaling (keyword-only=×0.7), boosting (tool+AI=×1.1)

### New VulnTypes (26 Total)

Added to v6's 20: `CLOUD_MISCONFIGURATION`, `SUPPLY_CHAIN`, `CREDENTIAL_BREACH`, `KERBEROAST`, `MOBILE_HARDCODED_SECRET`, `DEPENDENCY_CONFUSION`

---

## v6.0 highlights

### Agentic Red-Team Loop

`RedTeamAgent` runs Sonnet in a tool-use loop, autonomously selecting probes, forming hypotheses, and chaining findings — without operator intervention.

```
swiftsec redteam --roe roe.yaml --target https://target.com --agentic
```

Features: plateau detection (stops when last 5 calls return nothing new), budget gates (`SWIFT_AGENT_BUDGET_PROBES`, `SWIFT_AGENT_BUDGET_SONNET_CALLS`), automatic context compression at 20+ turns, full audit trail per iteration.

### OOB SSRF with Confirmed Callbacks

`OOBSSRFProbe` starts an async TCP listener, allocates per-injection tokens, injects callback URLs into target parameters, and waits for real HTTP callbacks. Cloud metadata bypass variants included (AWS IMDS, GCP metadata, Azure IMDS).

```
Confirmed: OOB SSRF at param 'url' — callback received from 10.0.0.5 (source_ip)
```

Set `INTERACTSH_URL` to route callbacks through Interactsh instead of local listener (required when target can't reach your machine directly).

### OAuth/OIDC Attack Probe

Five distinct attacks per OAuth surface discovered:
- **PKCE downgrade** — strips `code_challenge`, checks if server accepts plain auth codes
- **redirect_uri manipulation** — tests open redirectors and unvalidated redirect targets
- **Token leakage recon** — checks Referer/fragment leakage via implicit flow
- **Credential stuffing** — ROE-gated, rate-limited password spray
- **Implicit flow abuse** — forces token in fragment, checks for leakage

### WebSocket Attack Probe

Five attack categories against discovered WebSocket endpoints:
- **CSWSH** (Cross-Site WebSocket Hijacking) — forge unauthenticated upgrades from cross-origin
- **Unauthenticated upgrade** — test WS without session cookie/token
- **IDOR over WS** — mutate numeric/UUID IDs in message payloads
- **Injection** — SQLi, XSS, SSTI payloads over WS messages
- **Namespace abuse** — join unauthorized rooms/channels

### Business Logic Probe

Sonnet analyzes the target's workflow to identify multi-step logic flaws, then executes Playwright-driven attacks:
- Price manipulation (negative/zero quantities, parameter tampering)
- Coupon stacking via asyncio race condition (N=20 concurrent requests)
- Workflow step skipping (jump to checkout without cart validation)
- Privilege escalation via role parameter manipulation

### Immutable Audit Log

Every engagement writes a SHA-256 hash-chained JSONL log. Each entry links to the previous via `prev_hash` — any tampered entry is immediately detectable.

```bash
swiftsec audit verify --log ~/.swift/engagements/ENG-001/audit.jsonl
# Chain valid: 142 entries checked, no tampering detected

swiftsec audit export --log ~/.swift/engagements/ENG-001/audit.jsonl --out report.md
```

Credentials are redacted from all log entries automatically (Bearer tokens, API keys, passwords).

### Plugin SDK

Write custom probes in ~50 lines by extending `BaseModule`:

```python
from sdk.base import BaseModule, Finding, Phase, VulnType, Severity
from sdk.decorators import roe_gated

class MyProbe(BaseModule):
    name = "my_probe"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.SSRF]

    @roe_gated("active_scan")
    async def probe(self, target, session, roe) -> list[Finding]:
        ...
```

Drop into any directory, run `swiftsec plugin install ./my_probe/` — auto-discovered via `PluginRegistry`. Decorators: `@roe_gated`, `@cached_result`, `@retry`. Test harness: `SwiftTestHarness` with `MockSessionManager`. Full tutorial: [`docs/sdk/WRITING_A_MODULE.md`](swift/docs/sdk/WRITING_A_MODULE.md).

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
| `redteam` | Required | Full pipeline, all phases |
| `redteam --agentic` | Required | Autonomous Sonnet-driven loop |
| `agent-status` | — | Live agentic loop progress |
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
| `audit verify` | — | Verify hash chain integrity |
| `audit export` | — | Export engagement report |
| `plugin list\|install\|remove\|validate` | — | Manage custom probe modules |
| `attack-sim` | — | MITRE-mapped Kali run |
| `live-feed` | — | NVD + CISA KEV stream |
| `privesc` | — | Docker privesc (--allow-privesc) |
| `wizard` | — | Interactive menu |

## Active probe types (26 total)

**v6 base (20):** XSS · SQLi · SSRF · OOB SSRF · SSTI · IDOR · JWT alg:none · XXE · CRLF · NoSQL · Prototype Pollution · Auth Bypass · HTTP Smuggling · GraphQL · Race Condition · API Key Discovery · DOM IDOR · OAuth/OIDC · WebSocket · Business Logic

**v7 extended (6):** Cloud SSRF Metadata · Supply Chain (Dep Confusion) · Credential Breach (HIBP) · Kerberoasting · Mobile Hardcoded Secrets · Network Service CVE

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

### Core (Required)

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | ✅ Claude API key |

### OSINT & Recon

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub dork search + GHSA sync (v7.0) |
| `SHODAN_API_KEY` | Shodan intel |
| `NVD_API_KEY` | NVD CVE feed (higher rate limit) |
| `HUNTER_API_KEY` | hunter.io email enumeration |

### v7.0 Intelligence Engine

| Variable | Description |
|----------|-------------|
| `INTEL_DB_PATH` | ChromaDB path (default: `~/.swift/intel/chromadb`) |
| `INTEL_SYNC_INTERVAL_HOURS` | Auto-sync interval (default: 24) |
| `SWIFT_INTEL_AUTO_SYNC` | Set to `1` for background sync on every scan |
| `OPENAI_API_KEY` | GPT-4o fallback model |
| `GEMINI_API_KEY` | Gemini fallback model |
| `HIBP_API_KEY` | Have I Been Pwned v3 API (credential breach probe) |

### Offensive & Chains

| Variable | Description |
|----------|-------------|
| `SWIFT_ROE` | Default ROE file path |
| `INTERACTSH_URL` | Route OOB callbacks through Interactsh (v6.0) |
| `SWIFT_GPG_KEY_ID` | GPG key ID for engagement manifest signing (v6.0) |
| `SWIFT_AGENT_BUDGET_PROBES` | Max probe calls per agentic engagement (v6.0) |
| `SWIFT_AGENT_BUDGET_SONNET_CALLS` | Max Sonnet calls per agentic engagement (v6.0) |

## Safety guarantees

- ROE gate: hard fail-closed on scope/technique/window violations
- `allow_chain_execution` flag required + target allowlist for live chain replay
- All offensive ops inside ephemeral Docker container (auto-removed)
- No host filesystem mounts during offensive runs
- Post-exploit: simulate-only by default, enforced by ROE
- Code scan sandbox: `--network=none`, read-only FS, 2-core / 2 GB / 30 s
- Agentic loop: budget gates prevent runaway API spend; plateau detection stops stalled loops
- Audit log: SHA-256 hash chain — tampered entries detected on `audit verify`
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

Full architecture: [`docs/README.md`](docs/README.md) · Plugin SDK tutorial: [`docs/sdk/WRITING_A_MODULE.md`](swift/docs/sdk/WRITING_A_MODULE.md)

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) · Run tests: `pytest test/ -v --cov`

## Security

[`SECURITY.md`](SECURITY.md)

## License

MIT — [`LICENSE`](LICENSE)
