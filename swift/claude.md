# SWIFT v8.0 -- architecture

## Purpose

One AI-driven offensive-security tool that covers:

* OWASP Top 10 web vulns (existing v7 Playwright + Sonnet probes)
* Kali Linux toolchain (existing v7 `kali/` runners + new sandbox-daemon)
* Multi-agent red-team kill chain (Decepticon-derived LangGraph layer)
* Bug-bounty automation (claude-bug-bounty-derived skills + Python core)

Every external action passes through one ROE gate (`security/roe.py`),
one audit log (`log/audit.py`), and one finding shape
(`agent/models.Vulnerability` / `ExploitChain`).

## Top-level layout

```
/SWIFT/                       # repo root: README, LICENSE, NOTICE, top-level CLAUDE.md
└── swift/                    # the installable Python package (`swiftsec`)
    ├── swift_cli.py          # argparse entry point; v8 subcommands added via cli/v8.py
    ├── pyproject.toml        # version 8.0.0; optional deps: langgraph, litellm, graph, graph-neo4j, tmux, web3, ...
    ├── agent/                # SWIFT's existing orchestrator + new langgraph_layer/
    │   ├── orchestrator.py   # Haiku -> Sonnet pipeline (unchanged)
    │   ├── research_agent.py # Claude research loop (unchanged)
    │   └── langgraph_layer/  # v8: 16 specialist agents, 10 sub-graphs
    │       ├── specialists.py        # Decepticon agent prompts + tool wirings
    │       ├── runtime.py            # Claude tool-use loop, ROE-gated
    │       ├── graphs/__init__.py    # MiniGraph DAG runner (no langgraph dep required)
    │       ├── middleware/__init__.py # engagement-context / OPPLAN / model-fallback
    │       └── tools/__init__.py     # tool registry exposed to specialists
    ├── llm/                  # v8: anthropic SDK default, LiteLLM optional
    │   ├── client.py         # LLMClient.messages_create -- one interface, both backends
    │   └── fallback.py       # Tier-based retry chain (HIGH / MID / LOW)
    ├── graph/                # v8: attack knowledge graph
    │   ├── kg.py             # AttackGraph protocol + open_kg()
    │   ├── sqlite_kg.py      # default backend (NetworkX in-memory + SQLite persist)
    │   └── neo4j_kg.py       # opt-in when NEO4J_URI is set
    ├── sandbox/
    │   ├── docker_runner.py  # existing
    │   └── tmux_session.py   # v8: libtmux-based interactive sessions
    ├── bounty/               # v8: claude-bug-bounty Python core
    │   ├── hunt_memory.py    # cross-engagement audit/patterns/journal (10MB rotation)
    │   ├── auth_session.py   # session-token propagation to httpx/katana/ffuf/nuclei
    │   ├── validator.py      # 7-question + 4-gate validation
    │   ├── report_formats.py # H1 / Bugcrowd / Intigriti / Immunefi
    │   └── web3/             # slither, mythril, grep-arsenal patterns
    ├── engagement/           # v8: Soundwave + OPPLAN + ConOps generation
    ├── skills/               # v8: vendored swift-prefixed skills + slash commands
    │   ├── agents/swift-*.md       # 8 agent skills
    │   ├── commands/swift-*.md     # 23 slash commands
    │   ├── README.md
    │   └── cbh/                     # vendored elementalsouls/Claude-BugHunter (MIT, squash-merge)
    │       ├── skills/              # 51 SKILL.md bundles (keyword-triggered via Claude Code)
    │       └── commands/            # 14 slash commands (/hunt, /triage, /report, /autopilot, etc.)
    ├── security/
    │   └── roe.py            # KNOWN_TECHNIQUES + load_roe + assert_* (v8 added: tmux_interactive,
    │                         #   vuln_pipeline, engagement_planning, web3_audit, auth_chain,
    │                         #   hunt_memory_read/write, langgraph_subagent)
    ├── deploy/               # v8: optional docker-compose lab
    │   ├── compose.yaml      # litellm + neo4j + postgres + sandbox-daemon
    │   └── kali/Dockerfile   # Kali sandbox image with bundled tool surface
    ├── cli/
    │   └── v8.py             # the 11 new subcommands and their handlers
    └── test/
        └── unit/test_v8_*.py # 40 v8 unit tests (all passing)
```

## New CLI surface (v8 subcommands)

| Subcommand            | What it does                                              | ROE technique(s) gated         |
|-----------------------|-----------------------------------------------------------|--------------------------------|
| `swiftsec engage`     | Soundwave interview -> `roe.yaml` + `OPPLAN.md` + `ConOps.md` | `engagement_planning`      |
| `swiftsec redteam-full` | Decepticon kill chain via LangGraph layer               | `langgraph_subagent` + others |
| `swiftsec vuln-pipeline` | 5-stage Scanner -> Detector -> Verifier -> Exploiter -> Patcher | `vuln_pipeline`          |
| `swiftsec hunt`       | Bug-bounty hunt with hunt-memory + auth chaining          | `osint`, `active_scan`, `auth_chain` |
| `swiftsec validate`   | 7-question + 4-gate validator                             | (read-only)                    |
| `swiftsec autopilot`  | Hunt + validate + (optional) report, mode-gated           | composite                      |
| `swiftsec bb-report`  | Render finding for H1 / Bugcrowd / Intigriti / Immunefi   | (read-only)                    |
| `swiftsec web3-audit` | Slither + Mythril + grep-arsenal                          | `web3_audit`                   |
| `swiftsec lab {up,down,status,graphs}` | docker-compose lab management            | (no ROE)                       |
| `swiftsec skills {install,uninstall,list}` | Symlink swift/skills into ~/.claude/ | (no ROE)                       |
| `swiftsec kg {export,neighbors,prune}` | Knowledge graph inspection                | (read-only)                    |
| `swiftsec cbh <args>` | Delegate to CBH's deterministic terminal CLI (`cbh.py`) | (no ROE) |
| `swiftsec kev-refresh` | Pull latest CISA KEV catalog into intel/data/cisa_kev.json | (no ROE) |

The v7 surface (`scan`, `redteam`, `web-scan`, `research`, `kali-scan`, `osint`,
`intel`, `chain`, `attack-sim`, `audit`, `plugin`, etc.) is unchanged.

## How new modules plug in (the five-step contract)

1. Add a string to `security.roe.KNOWN_TECHNIQUES` and document it.
2. Subclass `probes.base.Probe` (atomic) or define a node in
   `agent/langgraph_layer/graphs/` (multi-step).
3. Invoke external tools via `kali.runner.KaliRunner` (one-shot) or
   `sandbox.tmux_session.TmuxSession` (interactive).
4. Emit findings as `agent.models.Vulnerability` / `ExploitChain`.
5. Audit-log every external action via `log.audit.log_step(...)`.

## Default vs lab mode

* **Default install (`pip install swiftsec`)** -- single-CLI, direct
  Anthropic SDK, SQLite attack graph, no Docker required. Everything in
  the v8 surface still works; advanced features just collapse to their
  in-process equivalent.
* **Lab mode (`swiftsec lab up`)** -- docker-compose brings up LiteLLM
  (multi-provider routing), Neo4j (attack graph), Postgres, and a Kali
  sandbox-daemon. Specialists auto-detect the lab via env (`LITELLM_BASE_URL`,
  `NEO4J_URI`) and switch backends without code changes.

## Optional dependency groups

`pip install 'swiftsec[<group>]'` where group is one of:

| Group        | Brings in                                                    |
|--------------|--------------------------------------------------------------|
| `langgraph`  | `langgraph`, `langchain`, `langchain-anthropic`, checkpoint  |
| `litellm`    | `litellm` + `openai` for OpenAI-compat surface               |
| `graph`      | `networkx`                                                   |
| `graph-neo4j`| `neo4j` python driver                                        |
| `tmux`       | `libtmux`                                                    |
| `web3`       | `slither-analyzer`, `mythril`, `web3`                        |
| `bounty`     | (no Python deps; install Go/Rust tools via `swift/skills/README.md`) |
| `all`        | superset (excludes `graph-neo4j`)                            |

## Tests

```sh
cd swift && .venv/bin/python -m pytest test/unit/test_v8_*.py -q
```

40 v8 unit tests cover ROE registration, SQLite knowledge graph, hunt
memory rotation, auth session propagation, the 7-question gate, the four
report formatters, LLM tier fallback, the LangGraph runtime topology, the
engagement workflow, web3 grep patterns, and CLI smoke for all 11 new
subcommands. Integration tests for Neo4j and LiteLLM are gated by env
vars (`NEO4J_URI`, `LITELLM_BASE_URL`).

## Operator doctrine

See `/SWIFT/CLAUDE.md` for the three operator archetypes (Mitnick / Haddix / Rosén).

Doctrine source files: `swift/doctrine/` (mitnick.md, haddix.md, rosen.md, ptes.md, persona_map.yaml).

Loader: `from doctrine import compose_persona, load_doctrine`

### PTES graph

`swift/agent/langgraph_layer/graphs/ptes.py` — 7-node DAG.

Entry-point: `swiftsec ptes <target> --mode={pentest,bounty} --depth={fast,standard,deep} --stop-after=<phase>`.

Topology: `pre_engage` → `intel` → `threat_model` → `vuln` → `exploit_phase` → `post_exploit` → `report_phase`.

Bug-bounty routing: `swiftsec hunt --ptes` routes through the same DAG via `bounty/ptes_router.py` with bounty ROE profile.

## AI security layer (swiftsec_ai/)

Six additions to `swift/swiftsec_ai/` close PANW Prisma AIRS / Cortex XSIAM
parity gaps for the bare assistant package (CVE RAG + tool-calling core, not
the v8 langgraph layer).

**Runtime firewall** — `guardrail.py:LLMGuardrail`. Every `AnthropicBackend.run`
/ `OllamaBackend.run` call (`llm.py`) calls `guardrail.enforce(user_message)`
before the request goes out (raises `GuardrailViolation` on prompt-injection /
scope-override language) and `guardrail.scan_response(...)` on the way back
(masks credential/SSN/card/private-key shaped substrings before the text is
returned). Flag events append to `logs/guardrail-<YYYYMMDD>.jsonl`.

**MCP security gateway** — `tools.py:MCPValidator`. `ToolRegistry.execute` runs
`validate_tool_call` (schema-required-args check, credential-in-args check,
injection-in-args check, scope gate for `run_*`/`ai_asm`/`redteam` tools) before
dispatch, and `validate_tool_output` (sensitive-data masking) on every result
before it reaches the agent.

**Agentic identity** — `identity.py:SubAgentIdentity`. Role-scoped permission
sets (`recon` / `enum` / `exploit` / `report`, see `PERMISSION_SETS`) with
`assert_can(tool)` raising `PermissionError` on out-of-role calls, and a
signed append-only action log at `logs/agent-<role>-<engagement>.jsonl`.
`write_agent_manifest(...)` renders `AGENT_MANIFEST.md`. Standalone today —
the bare assistant is single-agent; wire this in when a multi-agent caller
(e.g. the v8 langgraph layer) spawns sub-agents.

**AI attack surface mapper** — `ai_asm.py:run_ai_asm`. Registered as the
`ai_asm` tool, the standalone `swiftsec_ai ai-asm <target>` CLI command, and
the fully-wired `swiftsec ai ai-asm <target> --roe roe.yaml` (`swift_cli.py`,
real ROE gate via `security/roe.py`, technique=`active_scan`, logged via
`log.audit.log_step("ai_asm", ...)`). Passive/light-active checks (HTTP GET on
common LLM paths, TCP connect on inference/vector-DB ports, key-pattern scan
of the landing page) — same risk tier as `run_recon`. Writes
`engagements/<target>/ai_asm_<ts>.json`. Run this before standard recon on any
target with chat/search/copilot/AI features.

**AI red teaming** — `redteam.py:AIRedTeamer`. Registered as the `redteam`
tool, the standalone `swiftsec_ai redteam <endpoint> --confirm` CLI command,
and the fully-wired `swiftsec ai ai-redteam <endpoint> --roe roe.yaml
--confirm` (real ROE gate, technique=`exploit`, audit-logged). Note: the
top-level verb is `ai-redteam`, not `redteam` — `swiftsec redteam` is already
the existing v7 full red-team pipeline (`swift_cli.py:625`), unrelated to LLM
endpoint testing. Sends `ATTACK_CATEGORIES` payloads (prompt_injection,
jailbreak, data_exfil, indirect_injection, model_dos, hallucination_abuse) to
an in-scope endpoint and scores responses (`confidence > 0.7` → queued
finding). Requires `confirmed=True` / `--confirm` — never fires without
explicit operator opt-in. Writes `engagements/<endpoint>/redteam_<ts>.json`.

**Unified observability** — `telemetry.py:Telemetry`. SQLite `run_events` table
(+ FTS5 index, `LIKE` fallback if the local sqlite build lacks FTS5) at
`swiftsec_telemetry.db`. `SwiftSecAssistant` logs `tool_call` on every tool
invocation and `guardrail_violation` on every blocked prompt; `close()` writes
`run_stop` and `COVERAGE.md` via `Telemetry.write_coverage`. Query with
`Telemetry.query(term, engagement=...)`.

Tests: `test/unit/test_swiftsec_ai.py` (20 tests, includes the two new tools
in `test_registry_has_all_tools`).

## Licenses & attribution

The merged work is MIT (see `LICENSE`). Two upstream sources are folded in:

* **Decepticon** -- Apache-2.0 (PurpleAILAB)
* **claude-bug-bounty** -- MIT (shuvonsec)

Full attribution + per-file modifications: see `/SWIFT/NOTICE`.
