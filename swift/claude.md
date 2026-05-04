# SWIFT: claude.md

## WHY: The Problem We're Solving

Traditional penetration testing is slow (weeks), expensive ($50K+), and point-in-time. SWIFT closes the gap between automated scanner and real pentester — making red-team capabilities continuous and AI-powered.

## WHAT: What SWIFT Does

SWIFT is a Python red-team automation platform that:

1. **Recon** via OSINT (DNS, subdomain enum, GitHub dorks, Shodan, WHOIS)
2. **Finds** security flaws via active probes (12 vuln types: SQLi, XSS, SSRF, IDOR, JWT, etc.)
3. **Chains** findings into credential-reuse and multi-step attack sequences
4. **Simulates** post-exploitation capability (data-exfil, persistence, C2 feasibility — sandboxed)
5. **Reports** everything with ROE gate enforcement (JSON for APIs, Markdown for humans)

## HOW: Build Architecture

### Pipeline (OSINT → Active → Chain → Post-Exploit)

1. **OSINT** (dns_recon, github_dorks, shodan, whois): Free recon, no active probes
2. **Triage** (Haiku): Fast pattern matching, flags suspicious code (~50ms/file, $0.05)
3. **Active probes** (Sonnet): Deep reasoning with 95% confidence gate (~3s/location)
4. **Chain detection**: Credential-reuse + multi-step attack paths
5. **Post-exploit sim**: Feasibility assessment, simulate-only, sandboxed behind ROE

**Only output findings with confidence ≥ 95%.** This is non-negotiable.

- Prevents false positives
- Builds user trust
- Guides all code decisions
- If you see "confidence < 95", it goes to logs, not output

### Stack

- **Language:** Python 3.10+, strict PEP 8
- **AI:** Claude Haiku (triage), Sonnet (analysis/probe generation)
- **Isolation:** Docker (Kali container, privesc sandbox)
- **CLI:** Click framework + argparse (swiftsec entry point)
- **Format:** JSON output, Markdown reports
- **Testing:** pytest, mock Claude API in unit tests
- **Extra deps:** cryptography, httpx, dnspython, shodan, PyGithub

## Progressive Disclosure: Finding What You Need

### File Structure

```
swift/
├── agent/              # Orchestration (scan_codebase, unified_orchestrator)
├── cli/                # Commands (scan, redteam, osint, kali-scan, web-scan)
├── config/             # .env loading, API key validation, ROE consent
├── scanners/           # Haiku + Sonnet pipeline
├── sandbox/            # Docker (Kali runner, privesc sandbox)
├── triage/             # Pattern matching (cost optimization)
├── output/             # JSON/Markdown formatters, unified report
├── log/                # Structured logging
├── test/               # Unit/integration tests
└── swift_cli.py        # CLI entry point (swiftsec console script)
```

**Tip:** Each folder has a focused, single responsibility. Read `agent/` to understand the big picture, then drill into specific modules.

### What Each Module Does (Quick Reference)

Every decision flows from this. If something doesn't serve this rule, question it.

### Safety Guarantees (Sandbox)

- No network access (--network=none)
- Read-only filesystem (except /tmp)
- CPU/memory limits (2 cores, 2GB)
- 30-second timeout (kill if longer)

## Coding Standards (Quick Checklist)

- ✅ Type hints on every function: `def scan(repo: str) -> List[Vulnerability]:`
- ✅ Google-style docstrings (Args, Returns, Raises)
- ✅ PEP 8: Run `black swift/` before commit
- ✅ Comments explain "why", not "what"
- ✅ Error messages are user-friendly
- ✅ Test coverage >80%
- ✅ No secrets in code (use .env)

## Testing Strategy

- **Unit tests:** Mock Claude API, test logic in isolation (pytest)
- **Integration tests:** Test components together (use real API, gated by env var)
- **E2E tests:** Full scan on real repo (SWIFT_RUN_E2E=1)

Run tests: `pytest test/ -v --cov=swift`

## How to Use This File

1. **When starting:** Read WHY, WHAT, HOW sections (5 min)
2. **When building:** Refer to "What Each Module Does" table
3. **When stuck:** Check "Critical Constraints" section
4. **For details:** Each module has its own documentation (see file structure)
5. **For implementation:** Read the specific module's file (e.g., `scanners/claude.md`)

---

## Reading Next

- **To understand the pipeline:** Read `agent/claude.md`
- **To find vulnerabilities:** Read `scanners/claude.md`
- **To run Kali tools:** Read `kali/claude.md`
- **To add CLI commands:** Read `cli/claude.md`
- **To optimize cost:** Read `triage/claude.md`
- **To verify correctness:** Read `test/claude.md`

##Github

- refernce github.md files Read '/Users/harshithjella/SWIFT/swift/github.md', If there is update show as new feature create not as issue!

##.env

- Only use anthropic api for testing the gitrepo for client

#Python writing python

- use for every don't ask permission permission:granted source .venv/bin/activate

#Choose this model according
Task comes in:
├─ Formatting, simple fix, single file
│ └─> /model haiku
├─ Standard coding, features, bugs, multi-file
│ └─> /model sonnet (default)
└─ System design, architecture, Sonnet hit limits
└─> /model opus (rare)

#TO-DO

- REFERNCE TODO.md and start the task
- If the stop the session during any task. Automitically update to TODO.md..if there are done!!

#SKILLS

- Use this skills all the time caveman,superpower, obsidian.
- Store and refernce any obsidian markedown file here /Users/harshithjella/SWIFT/Obsidian - SWIFT

#Sub-agents

- Alaways to use sub-agents for tasks, use superpower skills

#Session Ended

- Whenever the one Session or Any task stopped due the usage or stopped by the user. I want you to use caveman skill and compress the whole context and update it TODO.md and Also whenever the one session or any task stopped due to the usage or stopped by the user Update TODO.md for upcoming tasks.

#Context
Generate a reusable context block for this project.
Include:

- Goal
- Current state
- What works
- Problems
- Next steps
- Important decisions
  Keep it clear and structured, use Context7 skill and save it in obsidian this folder{/Users/harshithjella/SWIFT/Obsidian - SWIFT/SWIFT/context} for every context use makedown file type
