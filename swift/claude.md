# SWIFT: claude.md

## WHY: The Problem We're Solving

Traditional vulnerability scanning is slow (weeks), expensive ($50K+), and reactive. SWIFT makes it continuous, AI-powered, and automated.

## WHAT: What SWIFT Does

SWIFT is a Python vulnerability scanner that:

1. **Finds** security flaws in code (SQL injection, command injection, etc.)
2. **Verifies** findings are real (95%+ confidence only)
3. **Fixes** them automatically (generates and tests patches)
4. **Reports** everything (JSON for APIs, Markdown for humans)

## HOW: Build Architecture

### Three-Layer Pipeline

1. **Triage** (Haiku): Fast pattern matching, flags suspicious code (~50ms/file, $0.05)
2. **Analysis** (Sonnet): Deep reasoning, confirms vulnerabilities (~3s/location, confidence ≥95%)
3. **Patching** (Sonnet + Docker): Generate fixes, test in sandbox, output diffs

### Key Design: 95% Confidence Rule

**Only output findings with confidence ≥ 95%.** This is non-negotiable.

- Prevents false positives
- Builds user trust
- Guides all code decisions
- If you see "confidence < 95", it goes to logs, not output

### Stack

- **Language:** Python 3.10+, strict PEP 8
- **AI:** Claude Haiku (triage), Sonnet (analysis/patching)
- **Isolation:** Docker (sandbox testing)
- **CLI:** Click framework
- **Format:** JSON output, unified diffs
- **Testing:** pytest, mock Claude API in unit tests

## Progressive Disclosure: Finding What You Need

### File Structure

```
swift/
├── agent/              # Orchestration (scan_codebase, generate_patches)
├── cli/                # Commands (scan, patch, validate)
├── config/             # .env loading, API key validation
├── scanners/           # Haiku + Sonnet pipeline
├── patches/            # Generation, scoring, diffs
├── sandbox/            # Docker testing
├── triage/             # Pattern matching (cost optimization)
├── output/             # JSON/Markdown formatters
├── log/                # Structured logging
├── test/               # Unit/integration tests
└── main.py             # CLI entry point
```

**Tip:** Each folder has a focused, single responsibility. Read `agent/` to understand the big picture, then drill into specific modules.

### What Each Module Does (Quick Reference)

| Module        | Responsibility       | Key Function                                  |
| ------------- | -------------------- | --------------------------------------------- |
| **agent/**    | Orchestrate pipeline | `scan_codebase(repo)` → findings + patches    |
| **scanners/** | Find vulns           | `HaikuTriageScanner`, `SonnetAnalysisScanner` |
| **patches/**  | Fix vulns            | Generate 3 candidates, score, return best     |
| **sandbox/**  | Test patches         | Docker isolation, safety guarantees           |
| **cli/**      | User interface       | `scan --repo <path> --output json`            |
| **config/**   | Load settings        | API key, confidence threshold (95%)           |
| **triage/**   | Fast filtering       | Regex patterns, 10x cheaper than Sonnet       |
| **output/**   | Format results       | JSON for APIs, Markdown for reports           |
| **log/**      | Track metrics        | Cost, speed, accuracy per scan                |
| **test/**     | Verify correctness   | Mock Claude, test 95% rule                    |

## Critical Constraints

### The 95% Confidence Rule

```python
# This is the law of the land
if vulnerability.confidence >= 0.95:
    output_finding(vulnerability)
else:
    log_low_confidence(vulnerability)  # Suppressed
```

Every decision flows from this. If something doesn't serve this rule, question it.

### Cost Discipline

- Haiku: $0.05/file (50ms, broad filter)
- Sonnet on flagged only: $0.50/scan (instead of $2 on all code)
- Target: <$2 cost per full scan

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
- **To generate patches:** Read `patches/claude.md`
- **To test code:** Read `sandbox/claude.md`
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
