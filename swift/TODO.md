# SWIFT MVP — TO-DO

## Status Legend

- ✅ DONE
- 🔄 IN PROGRESS
- ⬜ PENDING

## Security

### ✅ API Key Exposure — Fix .gitignore (2026-04-19)

- `.gitignore` had `.env/` (directory) not `.env` (file)
- Fixed: now has `.env` and `**/.env`
- Git history checked: key was NEVER committed — safe
- `swift/.env` now correctly git-ignored

## Deployment

### ✅ Deploy to Fly.io (2026-04-20)

Deployed to `swift-scanner.fly.dev`. Config: `min_machines_running=1`, `auto_start_machines=true`, `auto_stop_machines=true`.

### ⬜ Fix Fly.io trial 5-minute machine kill

**Root cause:** Fly.io free trial kills machines after 5 min → `"failed to fetch"` on frontend.
**Confirmed via logs:** `"Trial machine stopping. To run for longer than 5m0s, add a credit card"`

**Options (pick one):**
- A) Add credit card at `https://fly.io/dashboard/jellaharshith/billing` — Hobby tier free for low usage, removes kill timer
- B) Migrate backend to Railway (free $5/mo credit, no kill timer): `railway init && railway up`

Machine config already correct — will work once billing added.

## Phase 1 — Exploit Chain Intelligence 🔄 IN PROGRESS

- ✅ ExploitChain data model added to models.py
- ✅ Extended Vulnerability with cwe_id, exploit_description, remediation
- ✅ Extended Patch with reasoning, sandbox_tested, test_passed, test_logs
- ✅ Extended ScanResult with exploit_chains list
- ✅ ExploitChainDetector (chains/detector.py) using Sonnet
- ✅ Language-aware prompts in Haiku + Sonnet scanners
- ✅ Orchestrator Phase 3.5: chain detection between Sonnet and patch
- ✅ JSON output formatter: added exploit_chains section
- ✅ Markdown output formatter: added Exploit Chains section
- 🔄 Tests (unit + integration)
- 🔄 Verification (pytest, manual scan)

## Phase 2 — Security Controls ⬜ PENDING

- Permission enforcement layer (wrap all tool calls)
- Append-only tamper-evident forensic audit log
- AI safety monitor (detect escalation, hidden reasoning, unauthorized actions)
- Compliance readiness validation

## Phase 3 — Evidence Bundle + Compliance ⬜ PENDING

- findings.json (CWE, exploit_description, remediation)
- exploit_chains.json (standalone export)
- SARIF output format
- Enhanced triage ranking (severity × exploitability × confidence × business impact)
- Patch diffs with sandbox test results embedded
- /scan/{id}/evidence API endpoint
