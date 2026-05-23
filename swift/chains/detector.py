"""Exploit chain summarisation — LLM enhances pre-ranked chains, never generates them.

Architecture (Task 7):
- The LLM is an ENHANCER, not the chain engine.
- SWIFT deterministically builds bounded chains via VulnerabilityChainAuditor first.
- This module sends at most MAX_RANKED_CHAINS pre-built chains to the LLM.
- Input is capped at MAX_MODEL_CHAIN_INPUT_CHARS before the API call.
- Response is validated with json.loads; on any failure the original deterministic
  chains are returned unchanged — no crash, no fallback confusion.
- detect_chains(vulnerabilities) is kept for backward compatibility but is now a
  thin wrapper that builds an intermediate graph result before calling the LLM.
"""
from __future__ import annotations

import itertools
import json
import time
from dataclasses import asdict
from typing import Any, List, Optional

from agent.models import AttackStep, ExploitChain, Vulnerability
from log.logger import get_logger

# Constants formerly in triage.exploit_graph (now inlined after triage deletion)
MAX_MODEL_CHAIN_INPUT_CHARS: int = 40_000
MAX_RANKED_CHAINS: int = 10
_MEMORY_SAFE_THRESHOLD_MB: int = 500


def _is_memory_safe(label: str) -> bool:  # noqa: ARG001
    """Return True if process RSS is below the safety threshold."""
    try:
        import psutil
        rss_mb = psutil.Process().memory_info().rss / 1024 / 1024
        return rss_mb < _MEMORY_SAFE_THRESHOLD_MB
    except Exception:  # noqa: BLE001
        return True

logger = get_logger()

# Timeout protection for the entire chain-enhancement stage
MAX_CHAIN_DETECTION_TIME: int = 30

# Prompt for chain summarisation (receives pre-built compact chain JSON)
_ENHANCE_PROMPT_TEMPLATE = """\
You are a senior security architect reviewing pre-identified exploit chains.

The following chains were discovered by SWIFT's deterministic graph analysis.
Your task is to review and improve the narrative, impact description, and \
attack path clarity. You may NOT add new chains or change vulnerability IDs.

Pre-built chains (JSON):
{chains_json}

For each chain, return an improved version with:
- A clearer, more descriptive "name"
- A richer "attack_path" narrative
- A precise "impact" statement
- The same "chain_id", "vulnerability_ids", "severity", and "confidence"

Respond with ONLY valid JSON array (no markdown, no explanation):
[
  {{
    "chain_id": "CHAIN-001",
    "name": "Improved chain name",
    "vulnerability_ids": ["..."],
    "attack_path": "Improved multi-step narrative",
    "entry_point": "file.py:42",
    "impact": "Precise impact statement",
    "severity": "CRITICAL",
    "confidence": 0.92,
    "attack_steps": [...]
  }}
]

If you cannot improve a chain, return it unchanged.
If the JSON is not parseable or you cannot produce valid output, return: []
"""

# Legacy prompt retained for the detect_chains() backward-compat path
_LEGACY_PROMPT_TEMPLATE = """\
You are an expert security architect specializing in attack path analysis.

Analyze the following confirmed vulnerabilities and identify exploit chains — \
sequences of multiple vulnerabilities that can be chained together into a \
complete attack.

Vulnerabilities:
{vulns_json}

For each exploit chain you identify:
1. List the vulnerability IDs in attack order
2. Describe the complete attack path
3. Identify the entry point (file:line)
4. Describe the final impact/compromise achieved
5. Assign a severity (CRITICAL, HIGH, MEDIUM, LOW)
6. Rate your confidence in the chain (0.0-1.0)

Respond with ONLY valid JSON array (no markdown, no explanation):
[
  {{
    "chain_id": "CHAIN-001",
    "name": "SQL Injection → Auth Bypass → Admin Access",
    "vulnerability_ids": ["SWIFT-001", "SWIFT-003"],
    "attack_path": "1. Exploit SQL injection ...\\n2. Access admin panel ...",
    "attack_steps": [
      {{"step": 1, "description": "...", "vuln_id": "SWIFT-001", "entry_point": "auth/views.py:42"}}
    ],
    "entry_point": "auth/views.py:42",
    "impact": "Full admin access without credentials",
    "severity": "CRITICAL",
    "confidence": 0.92
  }}
]

If no chains exist, return: []
"""


class ExploitChainDetector:
    """Deterministic exploit chain detector.

    LLM enhancement removed — no API key required. enhance_chains() returns
    the pre-built chains from VulnerabilityChainAuditor unchanged.
    detect_chains() is kept for backward compatibility and returns an empty
    list; callers should use VulnerabilityChainAuditor directly.

    Args:
        client: Ignored (kept for import compatibility).
        model:  Ignored.
    """

    CONFIDENCE_THRESHOLD = 0.85
    _counter: itertools.count = itertools.count(1)

    def __init__(self, client: Any = None, model: str = "") -> None:
        pass  # no LLM client needed

    # ------------------------------------------------------------------
    # Primary: LLM-enhanced summarisation of pre-built chains  (Task 7)
    # ------------------------------------------------------------------

    def enhance_chains(self, chains: List[ExploitChain]) -> List[ExploitChain]:
        """Return chains unchanged — LLM enhancement disabled.

        Args:
            chains: Pre-ranked ExploitChain objects from VulnerabilityChainAuditor.

        Returns:
            The same chains list unmodified.
        """
        logger.debug("[CHAIN] LLM enhancement disabled; returning %d deterministic chains", len(chains))
        return chains

    # ------------------------------------------------------------------
    # Backward-compat: detect_chains from raw findings
    # ------------------------------------------------------------------

    def detect_chains(
        self,
        vulnerabilities: List[Vulnerability],
        chain_executor=None,
        roe=None,
    ) -> List[ExploitChain]:
        """Detect exploit chains from raw vulnerability findings.

        Kept for backward compatibility. Now hard-caps input to prevent
        oversized prompts, and validates JSON strictly.

        Prefer VulnerabilityChainAuditor for new call sites — it builds
        chains deterministically without any LLM.

        Returns:
            Empty list — LLM-based chain detection disabled.
            Use VulnerabilityChainAuditor.audit() instead.
        """
        logger.debug(
            "[CHAIN-DETECT] LLM chain detection disabled; use VulnerabilityChainAuditor"
        )
        return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _chain_to_compact_dict(chain: ExploitChain) -> dict:
        """Serialise an ExploitChain to a compact dict."""
        return {
            "chain_id": chain.chain_id,
            "name": chain.name,
            "vulnerability_ids": chain.vulnerability_ids,
            "attack_path": chain.attack_path,
            "entry_point": chain.entry_point,
            "impact": chain.impact,
            "severity": chain.severity,
            "confidence": chain.confidence,
            "attack_steps": [
                {
                    "step": s.step,
                    "description": s.description,
                    "vuln_id": s.vuln_id,
                    "entry_point": s.entry_point,
                }
                for s in (chain.attack_steps or [])
            ],
        }

    def _parse_enhanced_chains(
        self,
        data: list,
        originals: List[ExploitChain],
    ) -> List[ExploitChain]:
        """Merge LLM-enhanced chain data with the original deterministic chains.

        The model may only update narrative fields. The structural fields
        (chain_id, vulnerability_ids, severity, confidence) are taken from
        the original chains to prevent model hallucination from corrupting data.
        If the model omits a chain, the original is kept.
        """
        original_by_id = {c.chain_id: c for c in originals}
        updated_by_id: dict = {}

        for item in data:
            if not isinstance(item, dict):
                continue
            chain_id = item.get("chain_id", "")
            if not chain_id or chain_id not in original_by_id:
                continue  # never allow model to invent new chain IDs
            original = original_by_id[chain_id]
            try:
                updated_by_id[chain_id] = ExploitChain(
                    chain_id=original.chain_id,          # structural — keep original
                    vulnerability_ids=original.vulnerability_ids,  # structural
                    severity=original.severity,           # structural
                    confidence=original.confidence,       # structural
                    attack_steps=original.attack_steps,   # structural
                    # Narrative fields: accept LLM improvements
                    name=item.get("name", original.name),
                    attack_path=item.get("attack_path", original.attack_path),
                    entry_point=item.get("entry_point", original.entry_point),
                    impact=item.get("impact", original.impact),
                )
            except Exception as exc:
                logger.debug("[CHAIN-LLM] Merge failed for %s: %s; keeping original", chain_id, exc)

        # Return originals for any chain the model did not touch
        result = []
        for original in originals:
            result.append(updated_by_id.get(original.chain_id, original))
        return result

    def _maybe_execute_top_chain(
        self,
        chains: List[ExploitChain],
        chain_executor=None,
        roe=None,
    ) -> List[ExploitChain]:
        """Execute the top-ranked chain if ROE allows and executor is provided.

        Attaches execution_result to the chain object as a dynamic attribute if
        execution succeeds. Never raises — always returns the original chains list.

        Args:
            chains: Pre-built ExploitChain list.
            chain_executor: Module or callable with execute_chain coroutine.
            roe: ROE object; must have allow_chain_execution=True to proceed.

        Returns:
            Original chains list (potentially with execution_result attached to top chain).
        """
        if not chains or chain_executor is None or roe is None:
            return chains

        allow_exec = bool(getattr(roe, "allow_chain_execution", False))
        if not allow_exec:
            logger.debug("[CHAIN-EXEC] allow_chain_execution=False; skipping live replay")
            return chains

        top_chain = chains[0]
        logger.info("[CHAIN-EXEC] Attempting live replay of chain %s", top_chain.chain_id)

        try:
            import asyncio
            exec_fn = getattr(chain_executor, "execute_chain", chain_executor)
            result = asyncio.run(exec_fn(top_chain, roe))
            # Attach as dynamic attribute (ExploitChain is a dataclass — may need __dict__)
            try:
                object.__setattr__(top_chain, "execution_result", result)
            except (TypeError, AttributeError):
                top_chain.__dict__["execution_result"] = result  # type: ignore[attr-defined]
            logger.info(
                "[CHAIN-EXEC] Replay complete: validated=%s steps=%d/%d",
                result.validated,
                result.steps_succeeded,
                result.steps_attempted,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("[CHAIN-EXEC] Chain replay failed: %s", exc)

        return chains

    def _parse_legacy_response(self, raw: str) -> List[ExploitChain]:
        """Parse a raw detect_chains() LLM response.

        Uses strict json.loads (not a lenient parser) and returns an empty
        list on any parse failure rather than crashing or returning garbage.
        """
        try:
            # Strip any markdown fences if the model added them
            text = raw.strip()
            if text.startswith("```"):
                lines = text.splitlines()
                # Drop opening and closing fence lines
                inner = [l for l in lines if not l.startswith("```")]
                text = "\n".join(inner)
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "[CHAIN-DETECT] model_output_invalid: JSON parse failed (%s); "
                "returning empty list (deterministic chains preserved)",
                exc,
            )
            return []

        if not isinstance(data, list):
            logger.warning("[CHAIN-DETECT] model_output_invalid: not a JSON array; returning empty list")
            return []

        chains: List[ExploitChain] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                confidence = item.get("confidence")
                if confidence is None or float(confidence) < self.CONFIDENCE_THRESHOLD:
                    logger.debug(
                        "[CHAIN-DETECT] Chain confidence %.2f below threshold; skipping",
                        float(confidence) if confidence is not None else -1.0,
                    )
                    continue
                chain_id = item.get("chain_id") or f"CHAIN-{next(self._counter):03d}"
                attack_steps: List[AttackStep] = []
                for sd in item.get("attack_steps", []):
                    if not isinstance(sd, dict):
                        continue
                    try:
                        attack_steps.append(
                            AttackStep(
                                step=int(sd.get("step", len(attack_steps) + 1)),
                                description=str(sd.get("description", "")),
                                vuln_id=str(sd.get("vuln_id", "")),
                                entry_point=str(sd.get("entry_point", "")),
                            )
                        )
                    except Exception as exc:
                        logger.debug("[CHAIN-DETECT] Attack step parse failed: %s", exc)

                chains.append(
                    ExploitChain(
                        chain_id=chain_id,
                        name=item.get("name", "Unknown chain"),
                        vulnerability_ids=item.get("vulnerability_ids", []),
                        attack_path=item.get("attack_path", ""),
                        entry_point=item.get("entry_point", ""),
                        impact=item.get("impact", ""),
                        severity=str(item.get("severity", "MEDIUM")).upper(),
                        confidence=float(confidence),
                        attack_steps=attack_steps,
                    )
                )
            except Exception as exc:
                logger.warning("[CHAIN-DETECT] Chain item parse failed: %s", exc)

        return chains
