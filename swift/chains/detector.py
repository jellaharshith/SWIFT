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
from triage.exploit_graph import (
    MAX_MODEL_CHAIN_INPUT_CHARS,
    MAX_RANKED_CHAINS,
    _is_memory_safe,
)

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
    """LLM-based exploit chain summarisation.

    The primary method is enhance_chains(), which takes pre-built ExploitChain
    objects from VulnerabilityChainAuditor and uses the LLM to improve their
    narrative quality. On any failure it returns the originals unchanged.

    detect_chains() is preserved for backward compatibility; it now hard-caps
    its input to MAX_FINDINGS_FOR_CHAINING findings before calling the API to
    prevent the oversized-prompt / invalid-JSON / OOM class of failures.

    Args:
        client: Anthropic client instance.
        model:  Sonnet model ID.
    """

    MODEL = "claude-sonnet-4-6"
    CONFIDENCE_THRESHOLD = 0.85
    _counter: itertools.count = itertools.count(1)

    def __init__(self, client: Any, model: str = MODEL) -> None:
        self._client = client
        self._model = model

    # ------------------------------------------------------------------
    # Primary: LLM-enhanced summarisation of pre-built chains  (Task 7)
    # ------------------------------------------------------------------

    def enhance_chains(self, chains: List[ExploitChain]) -> List[ExploitChain]:
        """Use the LLM to improve narrative of pre-built chains.

        Guarantees:
        - At most MAX_RANKED_CHAINS chains are sent to the model.
        - Input JSON is truncated to MAX_MODEL_CHAIN_INPUT_CHARS.
        - Response validated with json.loads; on failure returns originals.
        - Memory guard before API call.
        - Timeout protection (MAX_CHAIN_DETECTION_TIME seconds).
        - Never crashes — always returns a valid list.

        Args:
            chains: Pre-ranked ExploitChain objects from VulnerabilityChainAuditor.

        Returns:
            Enhanced chain list if LLM response is valid, else original chains.
        """
        if not chains:
            return []

        start = time.monotonic()

        # Cap number of chains sent to model
        chains_to_send = chains[:MAX_RANKED_CHAINS]
        if len(chains) > MAX_RANKED_CHAINS:
            logger.info(
                "[CHAIN-LLM] Sending top %d of %d chains to LLM (others kept as-is)",
                MAX_RANKED_CHAINS, len(chains),
            )

        # Serialise to compact JSON and enforce character limit
        try:
            chains_json = json.dumps(
                [self._chain_to_compact_dict(c) for c in chains_to_send],
                indent=2,
            )
        except Exception as exc:
            logger.warning("[CHAIN-LLM] Serialisation failed: %s; keeping deterministic chains", exc)
            return chains

        if len(chains_json) > MAX_MODEL_CHAIN_INPUT_CHARS:
            logger.info(
                "[CHAIN-LLM] Input JSON (%d chars) exceeds MAX_MODEL_CHAIN_INPUT_CHARS=%d; "
                "keeping deterministic chains",
                len(chains_json), MAX_MODEL_CHAIN_INPUT_CHARS,
            )
            return chains

        # Memory guard before API call
        if not _is_memory_safe("pre-llm-chain-call"):
            logger.warning("[CHAIN-LLM] Memory threshold exceeded; keeping deterministic chains")
            return chains

        prompt = _ENHANCE_PROMPT_TEMPLATE.format(chains_json=chains_json)

        try:
            elapsed = time.monotonic() - start
            if elapsed > MAX_CHAIN_DETECTION_TIME:
                logger.warning("[CHAIN-LLM] Pre-call timeout (%.1fs); keeping deterministic chains", elapsed)
                return chains

            raw = self._call_api(prompt)

            elapsed = time.monotonic() - start
            if elapsed > MAX_CHAIN_DETECTION_TIME:
                logger.warning("[CHAIN-LLM] Post-call timeout (%.1fs); keeping deterministic chains", elapsed)
                return chains

        except Exception as exc:
            logger.warning("[CHAIN-LLM] API call failed (%.1fs): %s; keeping deterministic chains",
                           time.monotonic() - start, exc)
            return chains

        # Memory guard after API call
        if not _is_memory_safe("post-llm-chain-call"):
            logger.warning("[CHAIN-LLM] Memory threshold after API call; keeping deterministic chains")
            return chains

        # Strict JSON validation (Task 7)
        try:
            data = json.loads(raw.strip()) if raw and raw.strip() else None
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "[CHAIN-LLM] model_output_invalid: JSON parse failed (%s); "
                "using deterministic chains unchanged",
                exc,
            )
            return chains

        if not isinstance(data, list):
            logger.warning(
                "[CHAIN-LLM] model_output_invalid: expected JSON array, got %s; "
                "using deterministic chains unchanged",
                type(data).__name__,
            )
            return chains

        if not data:
            # Empty array is valid — model found nothing to enhance; keep originals
            logger.info("[CHAIN-LLM] Model returned empty array; keeping deterministic chains")
            return chains

        enhanced = self._parse_enhanced_chains(data, chains)
        logger.info(
            "[CHAIN-LLM] Enhancement complete: %d/%d chains updated (%.1fs)",
            len(enhanced), len(chains), time.monotonic() - start,
        )
        return enhanced

    # ------------------------------------------------------------------
    # Backward-compat: detect_chains from raw findings
    # ------------------------------------------------------------------

    def detect_chains(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[ExploitChain]:
        """Detect exploit chains from raw vulnerability findings.

        Kept for backward compatibility. Now hard-caps input to prevent
        oversized prompts, and validates JSON strictly.

        Prefer enhance_chains() for new call sites — it receives pre-built
        chains from VulnerabilityChainAuditor and only asks the LLM to
        improve narrative, not to generate chains from scratch.

        Returns:
            List of ExploitChain objects with confidence >= CONFIDENCE_THRESHOLD.
            Empty list on any error, timeout, or insufficient input.
        """
        from triage.ranking import MAX_TRIAGE_FINDINGS  # avoid circular at module level

        if len(vulnerabilities) < 2:
            logger.debug("[CHAIN-DETECT] Too few vulnerabilities (%d < 2)", len(vulnerabilities))
            return []

        # Hard cap: never send more than MAX_TRIAGE_FINDINGS findings to model
        capped = vulnerabilities[:MAX_TRIAGE_FINDINGS]
        if len(vulnerabilities) > MAX_TRIAGE_FINDINGS:
            logger.info(
                "[CHAIN-DETECT] Capped from %d to %d findings before LLM call",
                len(vulnerabilities), MAX_TRIAGE_FINDINGS,
            )

        start = time.monotonic()

        try:
            vulns_json = json.dumps(
                [
                    {
                        "id": v.id,
                        "file_path": v.file_path,
                        "line_number": v.line_number,
                        "vuln_type": v.vuln_type,
                        "description": v.description,
                        "severity": v.severity,
                    }
                    for v in capped
                ],
                indent=2,
            )
        except Exception as exc:
            logger.warning("[CHAIN-DETECT] Serialisation failed: %s", exc)
            return []

        # Enforce character limit
        if len(vulns_json) > MAX_MODEL_CHAIN_INPUT_CHARS:
            logger.warning(
                "[CHAIN-DETECT] Input JSON (%d chars) exceeds limit=%d; skipping LLM call",
                len(vulns_json), MAX_MODEL_CHAIN_INPUT_CHARS,
            )
            return []

        prompt = _LEGACY_PROMPT_TEMPLATE.format(vulns_json=vulns_json)

        try:
            if time.monotonic() - start > MAX_CHAIN_DETECTION_TIME:
                logger.warning("[CHAIN-DETECT] Pre-call timeout; skipping")
                return []

            if not _is_memory_safe("pre-detect-chains-llm"):
                logger.warning("[CHAIN-DETECT] Memory threshold; skipping LLM call")
                return []

            raw = self._call_api(prompt)
            elapsed = time.monotonic() - start

            if elapsed > MAX_CHAIN_DETECTION_TIME:
                logger.warning("[CHAIN-DETECT] Post-call timeout (%.1fs); skipping", elapsed)
                return []

            if not raw or not raw.strip():
                logger.warning("[CHAIN-DETECT] Empty LLM response")
                return []

            chains = self._parse_legacy_response(raw)
            logger.info("[CHAIN-DETECT] Detected %d chains (%.1fs)", len(chains), elapsed)
            return chains

        except Exception as exc:
            logger.warning("[CHAIN-DETECT] Failed after %.1fs: %s", time.monotonic() - start, exc)
            return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_api(self, prompt: str) -> str:
        """Call the configured Claude model and return the text response."""
        response = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    @staticmethod
    def _chain_to_compact_dict(chain: ExploitChain) -> dict:
        """Serialise an ExploitChain to a compact dict for LLM input."""
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
