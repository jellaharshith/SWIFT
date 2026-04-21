"""Chains export formatter — standalone exploit chain JSON export with attack steps."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List

from agent.models import ExploitChain, ScanResult


class ChainsFormatter:
    """Exports exploit chains to a standalone JSON file with complete attack step details.

    Structure:
    {
      "export_timestamp": "2026-04-20T...",
      "scan_id": "SCAN-001",
      "total_chains": 2,
      "chains": [
        {
          "chain_id": "CHAIN-001",
          "name": "SQL Injection → Auth Bypass → Admin Access",
          "vulnerability_ids": ["SWIFT-001", "SWIFT-003"],
          "attack_steps": [
            {
              "step": 1,
              "description": "...",
              "vuln_id": "SWIFT-001",
              "entry_point": "auth/views.py:42"
            }
          ],
          "estimated_impact": "...",
          "attack_feasibility": "HIGH",
          "time_to_exploit": "5 minutes",
          "entry_point": "auth/views.py:42",
          "confidence": 0.91,
          "severity": "CRITICAL"
        }
      ]
    }
    """

    def format(self, result: ScanResult) -> str:
        """Convert a ScanResult's exploit chains to a standalone JSON export.

        Args:
            result: Completed scan result containing exploit chains.

        Returns:
            Indented JSON string ready for file output.
        """
        chains_data = [
            self._serialize_chain(chain)
            for chain in result.exploit_chains
        ]

        payload = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": result.scan_id,
            "scan_repo_path": result.repo_path,
            "total_chains": len(result.exploit_chains),
            "chains": chains_data,
        }

        return json.dumps(payload, indent=2)

    def _serialize_chain(self, chain: ExploitChain) -> Dict:
        """Serialize a single ExploitChain to a dictionary.

        Args:
            chain: The ExploitChain to serialize.

        Returns:
            Dictionary with complete chain details including attack steps.
        """
        return {
            "chain_id": chain.chain_id,
            "name": chain.name,
            "vulnerability_ids": chain.vulnerability_ids,
            "attack_steps": [
                {
                    "step": step.step,
                    "description": step.description,
                    "vuln_id": step.vuln_id,
                    "entry_point": step.entry_point,
                }
                for step in chain.attack_steps
            ],
            "estimated_impact": chain.impact,
            "attack_feasibility": self._derive_feasibility(chain.confidence),
            "time_to_exploit": self._derive_time_estimate(chain.confidence),
            "entry_point": chain.entry_point,
            "attack_path": chain.attack_path,
            "confidence": chain.confidence,
            "severity": chain.severity,
        }

    @staticmethod
    def _derive_feasibility(confidence: float) -> str:
        """Derive attack feasibility from confidence score.

        Args:
            confidence: Confidence score (0.0–1.0).

        Returns:
            Feasibility level: CRITICAL, HIGH, MEDIUM, LOW, or MINIMAL.
        """
        if confidence >= 0.95:
            return "CRITICAL"
        elif confidence >= 0.85:
            return "HIGH"
        elif confidence >= 0.70:
            return "MEDIUM"
        elif confidence >= 0.50:
            return "LOW"
        else:
            return "MINIMAL"

    @staticmethod
    def _derive_time_estimate(confidence: float) -> str:
        """Estimate time to exploit based on confidence.

        Higher confidence chains are typically simpler/faster to exploit.

        Args:
            confidence: Confidence score (0.0–1.0).

        Returns:
            Human-readable time estimate (e.g., "5 minutes", "2 hours").
        """
        if confidence >= 0.95:
            return "< 5 minutes"
        elif confidence >= 0.85:
            return "5-15 minutes"
        elif confidence >= 0.70:
            return "15 minutes - 1 hour"
        else:
            return "1+ hours"
