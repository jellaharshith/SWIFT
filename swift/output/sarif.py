"""SARIF 2.1.0 formatter for GitHub Advanced Security integration.

SARIF (Static Analysis Results Interchange Format) is the standard format for
code scanning tools to communicate security findings to GitHub and other SIEM
systems. This formatter converts SWIFT vulnerabilities into valid SARIF 2.1.0
JSON for GitHub code scanning integration.

Reference: https://github.com/oasis-tcs/sarif-spec/blob/master/Schemata/sarif-schema-2.1.0.json
"""
from __future__ import annotations

import json
from typing import Dict, List, Set

from agent.models import ScanResult, Vulnerability


class SARIFFormatter:
    """Formats SWIFT scan results as valid SARIF 2.1.0 JSON for GitHub scanning.

    SARIF structure:
    - version: 2.1.0
    - runs: Array of analysis runs (one per invocation)
      - tool: Information about the analyzing tool (SWIFT)
        - driver: Tool metadata and rules
          - rules: Array of CWE definitions extracted from vulnerabilities
      - results: Array of findings (one per vulnerability)
        - properties: Custom SWIFT-specific metadata (risk score, etc.)
    """

    SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    SWIFT_REPO_URI = "https://github.com/jellaharshith/SWIFT"
    SWIFT_VERSION = "0.1.0"

    def format(self, result: ScanResult) -> str:
        """Convert a ScanResult to valid SARIF 2.1.0 JSON.

        Args:
            result: Completed scan result with vulnerabilities.

        Returns:
            Valid SARIF 2.1.0 JSON string suitable for GitHub code scanning.
        """
        # Extract unique CWE IDs and build rules
        rules = self._build_rules(result.vulnerabilities)

        # Convert vulnerabilities to SARIF results
        results = [
            self._vulnerability_to_result(vuln)
            for vuln in result.vulnerabilities
        ]

        # Build the complete SARIF document
        sarif_doc = {
            "version": "2.1.0",
            "$schema": self.SARIF_SCHEMA_URI,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SWIFT",
                            "version": self.SWIFT_VERSION,
                            "informationUri": self.SWIFT_REPO_URI,
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "scan_id": result.scan_id,
                        "repo_path": result.repo_path,
                        "files_scanned": result.files_scanned,
                        "duration_seconds": result.duration_seconds,
                        "total_cost_usd": result.total_cost_usd,
                        "timestamp": result.timestamp,
                    },
                }
            ],
        }

        return json.dumps(sarif_doc, indent=2)

    def _build_rules(self, vulnerabilities: List[Vulnerability]) -> List[Dict]:
        """Extract unique CWEs and build SARIF rule definitions.

        Each rule represents a CWE (Common Weakness Enumeration) with
        metadata about severity, remediation, and references.

        Args:
            vulnerabilities: List of vulnerabilities to extract CWEs from.

        Returns:
            List of SARIF rule objects (one per unique CWE).
        """
        # Track unique CWEs and the worst severity for each
        cwe_map: Dict[str, tuple[str, str, List[str]]] = {}  # cwe_id -> (worst_severity, description, urls)

        for vuln in vulnerabilities:
            if not vuln.cwe_id:
                continue

            cwe_id = vuln.cwe_id
            if cwe_id not in cwe_map:
                cwe_map[cwe_id] = (vuln.severity, vuln.description, [])

            # Update severity to worst case
            current_severity = cwe_map[cwe_id][0]
            new_severity = self._merge_severities(current_severity, vuln.severity)
            urls = list(cwe_map[cwe_id][2])
            if vuln.cwe_url and vuln.cwe_url not in urls:
                urls.append(vuln.cwe_url)
            cwe_map[cwe_id] = (new_severity, vuln.description, urls)

        # Convert to SARIF rules
        rules = []
        for cwe_id, (severity, description, urls) in sorted(cwe_map.items()):
            rule = {
                "id": cwe_id,
                "name": self._get_cwe_name(cwe_id),
                "shortDescription": {
                    "text": description,
                },
                "help": {
                    "text": self._get_cwe_help_text(cwe_id),
                },
                "defaultConfiguration": {
                    "level": self._severity_to_sarif_level(severity),
                },
            }

            # Add reference URLs if available
            if urls:
                rule["helpUri"] = urls[0]  # SARIF uses single URI; add others as references
                if len(urls) > 1:
                    rule["relatedLocations"] = [
                        {"physicalLocation": {"artifactLocation": {"uri": url}}}
                        for url in urls[1:]
                    ]

            rules.append(rule)

        return rules

    def _vulnerability_to_result(self, vuln: Vulnerability) -> Dict:
        """Convert a Vulnerability to a SARIF result object.

        Args:
            vuln: Vulnerability to convert.

        Returns:
            SARIF result object with location, message, and custom properties.
        """
        result = {
            "ruleId": vuln.cwe_id or "SWIFT-GENERIC",
            "level": self._severity_to_sarif_level(vuln.severity),
            "message": {
                "text": vuln.description,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": vuln.file_path,
                        },
                        "region": {
                            "startLine": vuln.line_number,
                        },
                    }
                }
            ],
            "properties": {
                "swift-severity": vuln.severity,
                "swift-confidence": vuln.confidence,
                "swift-vuln-type": vuln.vuln_type,
                "swift-id": vuln.id,
            },
        }

        # Add risk score if available
        if hasattr(vuln, "risk_score") and vuln.risk_score is not None:
            result["properties"]["swift-risk-score"] = round(vuln.risk_score, 1)

        # Add exploitability if available
        if hasattr(vuln, "exploitability") and vuln.exploitability is not None:
            result["properties"]["swift-exploitability"] = vuln.exploitability

        # Add business impact if available
        if (
            hasattr(vuln, "business_impact_category")
            and vuln.business_impact_category is not None
        ):
            result["properties"]["swift-business-impact"] = vuln.business_impact_category

        # Add code snippet if available
        if vuln.code_snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": vuln.code_snippet,
            }

        # Add remediation guidance if available
        if vuln.remediation:
            result["fix"] = {
                "artifactChanges": [
                    {
                        "artifactLocation": {"uri": vuln.file_path},
                        "replacements": [
                            {
                                "deletedRegion": {
                                    "startLine": vuln.line_number,
                                },
                                "insertedContent": {
                                    "text": vuln.remediation_code or vuln.remediation,
                                },
                            }
                        ],
                    }
                ]
            }

        return result

    def _severity_to_sarif_level(self, swift_severity: str) -> str:
        """Map SWIFT severity levels to SARIF levels.

        SARIF level values: error, warning, note, none

        Args:
            swift_severity: SWIFT severity (CRITICAL, HIGH, MEDIUM, LOW).

        Returns:
            SARIF level string.
        """
        severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
        }
        return severity_map.get(swift_severity.upper(), "warning")

    def _merge_severities(self, sev1: str, sev2: str) -> str:
        """Return the worse of two severity levels.

        Args:
            sev1: First severity level.
            sev2: Second severity level.

        Returns:
            The more severe of the two.
        """
        severity_order = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
        }
        sev1_val = severity_order.get(sev1.upper(), 0)
        sev2_val = severity_order.get(sev2.upper(), 0)
        return sev1 if sev1_val >= sev2_val else sev2

    @staticmethod
    def _get_cwe_name(cwe_id: str) -> str:
        """Get human-readable name for a CWE ID.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-89").

        Returns:
            Human-readable name for the CWE.
        """
        # Common CWE names (extended set for coverage)
        cwe_names = {
            "CWE-89": "SQL Injection",
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-78": "OS Command Injection",
            "CWE-94": "Code Injection",
            "CWE-611": "XML External Entity (XXE) Processing",
            "CWE-434": "Unrestricted Upload of File with Dangerous Type",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
            "CWE-863": "Incorrect Authorization",
            "CWE-287": "Improper Authentication",
            "CWE-295": "Improper Certificate Validation",
            "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
            "CWE-330": "Use of Insufficiently Random Values",
            "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
            "CWE-345": "Insufficient Verification of Data Authenticity",
            "CWE-347": "Improper Verification of Cryptographic Signature",
            "CWE-352": "Cross-Site Request Forgery (CSRF)",
            "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization",
            "CWE-400": "Uncontrolled Resource Consumption",
            "CWE-401": "Missing Release of Memory after Effective Lifetime",
            "CWE-415": "Double Free",
            "CWE-416": "Use After Free",
            "CWE-457": "Use of Uninitialized Variable",
            "CWE-476": "NULL Pointer Dereference",
            "CWE-787": "Out-of-bounds Write",
            "CWE-125": "Out-of-bounds Read",
            "CWE-190": "Integer Overflow or Wraparound",
            "CWE-191": "Integer Underflow (Wrap or Wraparound)",
            "CWE-444": "Inconsistent Interpretation of HTTP Requests",
            "CWE-693": "Protection Mechanism Failure",
            "CWE-694": "Use of Multiple Resources with Duplicate Identifier",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
            "CWE-912": "Hidden Functionality",
            "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
            "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
            "CWE-1025": "Comparison Using Wrong Factors",
            "CWE-1104": "Use of Unmaintained Third Party Components",
        }
        return cwe_names.get(cwe_id, cwe_id)

    @staticmethod
    def _get_cwe_help_text(cwe_id: str) -> str:
        """Get remediation guidance for a CWE.

        Args:
            cwe_id: CWE identifier.

        Returns:
            Remediation guidance text.
        """
        help_texts = {
            "CWE-89": "Use parameterized queries (prepared statements) to prevent SQL injection attacks. Never concatenate user input directly into SQL queries.",
            "CWE-79": "Properly escape or sanitize all user input before rendering in HTML context. Use content security policies (CSP) to limit XSS impact.",
            "CWE-78": "Avoid executing OS commands with user-supplied input. Use language-native APIs instead of shell commands when possible.",
            "CWE-94": "Never dynamically execute code from untrusted sources. Use safe templating or serialization libraries.",
            "CWE-611": "Disable XML External Entity (XXE) processing. Use safe XML parsers with DTD and entity processing disabled.",
            "CWE-434": "Validate file types and restrict uploads to safe extensions. Store uploads outside the web root and use random filenames.",
            "CWE-502": "Avoid deserializing untrusted data. Use JSON formats or safe serialization libraries with strict type controls.",
            "CWE-200": "Minimize sensitive data exposure. Use encryption for data at rest and in transit. Remove sensitive information from error messages.",
            "CWE-863": "Implement proper access controls. Validate user permissions for all operations. Use principle of least privilege.",
            "CWE-287": "Implement strong authentication mechanisms. Use multi-factor authentication when possible. Avoid storing plain-text passwords.",
            "CWE-295": "Always validate SSL/TLS certificates. Pin certificates for critical connections. Enable certificate revocation checking.",
            "CWE-327": "Use only strong, modern cryptographic algorithms. Avoid deprecated or weak algorithms like MD5, SHA1, or DES.",
            "CWE-330": "Use cryptographically secure random number generators. Avoid predictable randomness sources like time-based seeds.",
            "CWE-352": "Implement CSRF tokens (synchronizer tokens) for state-changing operations. Use SameSite cookie attributes.",
            "CWE-400": "Implement rate limiting and request throttling. Monitor and limit resource consumption per user or IP address.",
            "CWE-798": "Never hard-code credentials. Use environment variables, secure vaults, or configuration management systems.",
        }
        return help_texts.get(
            cwe_id,
            f"Review the vulnerability and apply secure coding practices. Consult {cwe_id} documentation for detailed guidance.",
        )
