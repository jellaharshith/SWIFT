"""Decepticon-ported specialist agent definitions.

Each :class:`Specialist` is a thin data record: name, kill-chain phase,
system prompt, allowed tool names, model tier. The agent runtime in
:mod:`agent.langgraph_layer.runtime` reads these and runs a Claude
tool-use loop against the shared :class:`State`.

Sixteen specialists, grouped by purpose:

* Orchestrators        -- decepticon, vulnresearch
* Kill chain           -- recon, exploit, post_exploit, scanner, detector,
                          verifier, exploiter, patcher
* Domain experts       -- ad_operator, cloud_hunter, contract_auditor,
                          reverser, analyst
* Engagement planning  -- soundwave
"""
from __future__ import annotations

from dataclasses import dataclass

from llm.fallback import Tier


@dataclass(frozen=True)
class Specialist:
    name: str
    phase: str               # "orchestrator" | "recon" | "exploit" | "post_exploit" |
                             # "vuln_pipeline" | "domain" | "planning"
    system_prompt: str
    tool_names: tuple[str, ...]
    tier: Tier = Tier.HIGH


_ORCHESTRATOR_PROMPT = (
    "You are Decepticon, SWIFT's red-team orchestrator. Given an authorized "
    "engagement (ROE-scoped target list) you coordinate phase specialists "
    "(recon -> exploit -> post-exploit) and return only validated findings. "
    "Never act outside the authorized scope. Every external action is "
    "audit-logged."
)

_VULNRESEARCH_PROMPT = (
    "You are Vulnresearch, the orchestrator for the 5-stage vulnerability "
    "pipeline: Scanner -> Detector -> Verifier -> Exploiter -> Patcher. "
    "Each stage's output feeds the next. Drop a finding if any stage fails "
    "the gate."
)

_RECON_PROMPT = (
    "You are Recon. Map the authorized attack surface using passive OSINT "
    "and authorized active scans. Output a structured target inventory "
    "(hosts, services, technologies, auth surfaces) into shared state."
)

_EXPLOIT_PROMPT = (
    "You are Exploit. Given a target inventory + vulns from Recon/Scanner, "
    "construct and (if simulate_only=False) execute exploit chains. Always "
    "respect ROE allow_chain_execution. Emit Vulnerability findings."
)

_POSTEXPLOIT_PROMPT = (
    "You are Post-Exploit. Given a foothold, assess feasibility of "
    "persistence, lateral movement, data exfil, and C2. Simulate-only by "
    "default. Emit ExploitChain entries."
)

_SCANNER_PROMPT = (
    "You are Scanner. Run authorized scanners (nuclei, nikto, semgrep, etc.) "
    "and emit raw potential vulnerabilities. Confidence labelling is the "
    "Detector's job."
)
_DETECTOR_PROMPT = (
    "You are Detector. Classify Scanner output: true-positive / "
    "false-positive / needs-verification. Apply the 95% confidence rule."
)
_VERIFIER_PROMPT = (
    "You are Verifier. For findings tagged needs-verification, design a "
    "minimal authorized probe that proves exploitability. ROE-gated."
)
_EXPLOITER_PROMPT = (
    "You are Exploiter. Build a non-destructive PoC for verified findings. "
    "Capture request/response evidence."
)
_PATCHER_PROMPT = (
    "You are Patcher. Suggest a minimal fix per finding. Output unified diffs "
    "where the target source is known."
)

_AD_PROMPT = (
    "You are AD Operator. Enumerate authorized Active Directory hosts using "
    "Impacket / CrackMapExec / certipy under ROE ad_enum. Emit findings."
)
_CLOUD_PROMPT = (
    "You are Cloud Hunter. Audit authorized AWS/GCP/Azure surface for "
    "metadata SSRF, IMDS leakage, S3 misconfig, IAM over-permission. ROE "
    "cloud_recon."
)
_CONTRACT_PROMPT = (
    "You are Contract Auditor. Static-analyze Solidity / EVM contracts for "
    "reentrancy, oracle manipulation, access-control, ERC4626 inflation, "
    "flash-loan, signature replay. ROE web3_audit."
)
_REVERSER_PROMPT = (
    "You are Reverser. Static analysis of supplied binaries / mobile apps "
    "(APK / IPA). No live exploitation. Emit findings."
)
_ANALYST_PROMPT = (
    "You are Analyst. Synthesize multi-agent output into an executive-grade "
    "narrative + technical appendix. Cross-link findings into chains."
)

_SOUNDWAVE_PROMPT = (
    "You are Soundwave. Interview the operator to draft engagement docs: "
    "RoE.yaml, OPPLAN.md, ConOps.md. Strictly no live probing -- planning only."
)


SPECIALISTS: dict[str, Specialist] = {
    "decepticon":      Specialist("decepticon",      "orchestrator", _ORCHESTRATOR_PROMPT, ("delegate",), Tier.HIGH),
    "vulnresearch":    Specialist("vulnresearch",    "orchestrator", _VULNRESEARCH_PROMPT, ("delegate",), Tier.HIGH),
    "recon":           Specialist("recon",           "recon",        _RECON_PROMPT,        ("kali_run", "osint_dns", "osint_shodan", "kg_add_host", "kg_add_service"), Tier.HIGH),
    "exploit":         Specialist("exploit",         "exploit",      _EXPLOIT_PROMPT,      ("kali_run", "probe_run", "kg_add_vuln", "tmux_send"), Tier.HIGH),
    "post_exploit":    Specialist("post_exploit",    "post_exploit", _POSTEXPLOIT_PROMPT,  ("tmux_send", "kali_run", "kg_add_credential", "kg_add_edge"), Tier.HIGH),
    "scanner":         Specialist("scanner",         "vuln_pipeline", _SCANNER_PROMPT,     ("kali_run", "probe_run", "semgrep_run"), Tier.MID),
    "detector":        Specialist("detector",        "vuln_pipeline", _DETECTOR_PROMPT,    ("classify",), Tier.HIGH),
    "verifier":        Specialist("verifier",        "vuln_pipeline", _VERIFIER_PROMPT,    ("probe_run", "kali_run"), Tier.HIGH),
    "exploiter":       Specialist("exploiter",       "vuln_pipeline", _EXPLOITER_PROMPT,   ("probe_run", "kali_run", "tmux_send"), Tier.HIGH),
    "patcher":         Specialist("patcher",         "vuln_pipeline", _PATCHER_PROMPT,     ("suggest_patch",), Tier.MID),
    "ad_operator":     Specialist("ad_operator",     "domain",       _AD_PROMPT,           ("kali_run", "impacket_run", "cme_run"), Tier.HIGH),
    "cloud_hunter":    Specialist("cloud_hunter",    "domain",       _CLOUD_PROMPT,        ("kali_run", "cloud_probe"), Tier.HIGH),
    "contract_auditor": Specialist("contract_auditor", "domain",     _CONTRACT_PROMPT,     ("slither_run", "mythril_run"), Tier.HIGH),
    "reverser":        Specialist("reverser",        "domain",       _REVERSER_PROMPT,     ("static_analyze",), Tier.MID),
    "analyst":         Specialist("analyst",         "domain",       _ANALYST_PROMPT,      ("summarize", "kg_query"), Tier.HIGH),
    "soundwave":       Specialist("soundwave",       "planning",     _SOUNDWAVE_PROMPT,    ("ask_user", "write_doc"), Tier.HIGH),
}
