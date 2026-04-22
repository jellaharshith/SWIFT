"""SWIFT Security Report Normalizer.

Transforms raw scan findings into a professional, low-noise, human-readable
report suitable for CTOs, founders, and engineering managers.

Rules enforced:
- Status labels: REVIEW_REQUIRED | LIKELY_VULNERABILITY | HIGH_CONFIDENCE_VULNERABILITY
  (never "CONFIRMED")
- Scanner noise is filtered: comments, imports, blank lines, boilerplate
- Finding caps: 3 Critical, 5 High, 5 Medium, 0 Low (by default)
- Similar findings are grouped into themes
- Plain-English explanations for every finding
- Executive summary in 5-8 lines
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from agent.models import ExploitChain, ScanResult, Vulnerability

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CAPS: Dict[str, int] = {
    "CRITICAL": 3,
    "HIGH": 5,
    "MEDIUM": 5,
    "LOW": 0,
}

# Keywords that suggest the repo is a training/challenge/demo app.
_TRAINING_REPO_SIGNALS = [
    "juice-shop",
    "juiceshop",
    "dvwa",
    "webgoat",
    "hackazon",
    "vulnerable",
    "ctf",
    "intentionally",
    "challenge",
    "training",
    "demo",
    "insecure",
    "bwapp",
    "mutillidae",
    "railsgoat",
    "gruyere",
    "security-shepherd",
    "hackthissite",
]

# Patterns that indicate the snippet is scanner noise.
_COMMENT_RE = re.compile(r"^\s*(#|//|/\*|\*|<!--)")
_IMPORT_RE = re.compile(
    r"^\s*(import\s|from\s+\S+\s+import|require\s*\(|const\s+\w+\s*=\s*require)"
)
_BLANK_RE = re.compile(r"^\s*$")
_ROUTE_ONLY_RE = re.compile(
    r"""^\s*(app|router)\.(get|post|put|patch|delete|use)\s*\(""",
    re.IGNORECASE,
)
_BRACE_ONLY_RE = re.compile(r"^\s*[\{\}\[\]\(\);\,]+\s*$")
_BOILERPLATE_MIDDLEWARE_RE = re.compile(
    r"""(helmet\s*\(|noSniff|contentSecurityPolicy|app\.use\s*\(\s*express\.|
        cors\s*\(\s*\)|morgan\s*\(|bodyParser\.|express\.json\s*\(|
        express\.urlencoded)""",
    re.IGNORECASE | re.VERBOSE,
)
_CLEAN_DESCRIPTION_RE = re.compile(
    r"\b(clean|no vulnerability|not vulnerable|no issue|safe code)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Status mapping
# ---------------------------------------------------------------------------

def _map_status(vuln: Vulnerability) -> str:
    """Map internal confidence/severity to one of the three allowed labels.

    Returns:
        One of: HIGH_CONFIDENCE_VULNERABILITY | LIKELY_VULNERABILITY | REVIEW_REQUIRED
    """
    c = vuln.confidence
    sev = vuln.severity.upper()

    if c >= 0.95 and sev in ("CRITICAL", "HIGH"):
        return "HIGH_CONFIDENCE_VULNERABILITY"
    if c >= 0.90 or (c >= 0.80 and sev in ("CRITICAL", "HIGH")):
        return "LIKELY_VULNERABILITY"
    if c >= 0.80:
        return "LIKELY_VULNERABILITY"
    return "REVIEW_REQUIRED"


# ---------------------------------------------------------------------------
# Noise detection
# ---------------------------------------------------------------------------

def _strip(text: str) -> str:
    return text.strip()


def _is_noise(vuln: Vulnerability) -> bool:
    """Return True if this finding is scanner noise and should be dropped."""
    snippet = _strip(vuln.code_snippet)

    # Empty snippet
    if not snippet or _BLANK_RE.match(snippet):
        return True

    # Pure comment line
    if _COMMENT_RE.match(snippet):
        return True

    # Pure import statement
    if _IMPORT_RE.match(snippet):
        return True

    # Pure braces / punctuation
    if _BRACE_ONLY_RE.match(snippet):
        return True

    # Route declaration with no injection signals
    if _ROUTE_ONLY_RE.match(snippet):
        has_injection = any(
            kw in snippet
            for kw in ("req.query", "req.params", "req.body", "req.headers",
                       "user_input", "getParameter", "request.GET", "request.POST")
        )
        if not has_injection:
            return True

    # Harmless security middleware (helmet, cors boilerplate)
    if _BOILERPLATE_MIDDLEWARE_RE.search(snippet):
        return True

    # Scanner said it's clean
    if _CLEAN_DESCRIPTION_RE.search(vuln.description):
        return True

    # vuln_type == none/unknown with weak confidence
    if vuln.vuln_type.lower() in ("none", "unknown", "clean") and vuln.confidence < 0.75:
        return True

    return False


# ---------------------------------------------------------------------------
# Grouping similar findings
# ---------------------------------------------------------------------------

def _group_theme_key(vuln: Vulnerability) -> Tuple[str, str]:
    """Produce a grouping key: (vuln_type, file_path)."""
    return (vuln.vuln_type.lower(), vuln.file_path)


def _group_similar(vulns: List[Vulnerability]) -> List[Vulnerability | _GroupedFinding]:
    """Collapse repeated vuln_type+file combos into a single representative finding.

    If a group has 3+ items in the same file with the same type, keep only the
    highest-confidence one and annotate it with the group count.
    """
    # Map key → list
    buckets: Dict[Tuple[str, str], List[Vulnerability]] = defaultdict(list)
    for v in vulns:
        buckets[_group_theme_key(v)].append(v)

    results: List[Vulnerability | _GroupedFinding] = []
    for (vtype, _fpath), group in buckets.items():
        if len(group) >= 3:
            best = max(group, key=lambda v: v.confidence)
            results.append(_GroupedFinding(best, len(group), vtype))
        else:
            results.extend(group)

    return results


class _GroupedFinding:
    """Wrapper that marks a finding as representing N similar items."""

    def __init__(self, vuln: Vulnerability, count: int, theme: str) -> None:
        self.vuln = vuln
        self.count = count
        self.theme = theme

    # Delegate attribute access so we can treat it as a Vulnerability
    def __getattr__(self, name: str):
        return getattr(self.vuln, name)


# ---------------------------------------------------------------------------
# Selection / capping
# ---------------------------------------------------------------------------

def _select_top_findings(
    vulns: List[Vulnerability],
    include_low: bool = False,
) -> List[Vulnerability]:
    """Filter noise, then select up to _CAPS findings per severity bucket."""
    # Step 1: drop noise
    clean = [v for v in vulns if not _is_noise(v)]

    # Step 2: sort by risk_score desc, then confidence desc within each bucket
    clean.sort(key=lambda v: (v.risk_score or 0.0, v.confidence), reverse=True)

    caps = dict(_CAPS)
    if include_low:
        caps["LOW"] = 5

    selected: List[Vulnerability] = []
    counts: Dict[str, int] = defaultdict(int)

    for v in clean:
        sev = v.severity.upper()
        limit = caps.get(sev, 0)
        if counts[sev] < limit:
            selected.append(v)
            counts[sev] += 1

    return selected


# ---------------------------------------------------------------------------
# Training / demo repo detection
# ---------------------------------------------------------------------------

def _is_training_repo(repo_path: str) -> bool:
    """Heuristic: check if repo_path contains known training app signals."""
    path_lower = repo_path.lower()
    return any(sig in path_lower for sig in _TRAINING_REPO_SIGNALS)


# ---------------------------------------------------------------------------
# Exploit-chain theme extraction
# ---------------------------------------------------------------------------

def _chain_theme(chains: List[ExploitChain]) -> Optional[str]:
    if not chains:
        return None
    names = [c.name for c in chains[:3]]
    joined = ", ".join(names)
    return f"Exploit chain(s) detected: {joined}"


# ---------------------------------------------------------------------------
# Report renderer
# ---------------------------------------------------------------------------

def _severity_emoji_free_label(sev: str) -> str:
    mapping = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
    }
    return mapping.get(sev.upper(), sev.title())


def _confidence_label(c: float) -> str:
    pct = int(round(c * 100))
    return f"{pct}%"


def _vuln_type_title(vtype: str) -> str:
    return vtype.replace("_", " ").title()


def _explain_why_it_matters(vuln: Vulnerability) -> str:
    """Return a short plain-English sentence on attacker impact."""
    if vuln.exploit_impact:
        return vuln.exploit_impact
    generic = {
        "sql_injection": (
            "An attacker can read, modify, or delete any data in the database "
            "without authentication."
        ),
        "command_injection": (
            "An attacker can execute arbitrary OS commands on the server, "
            "leading to full system compromise."
        ),
        "hardcoded_secret": (
            "The exposed credential can be used directly to authenticate "
            "as a privileged user or service."
        ),
        "hardcoded_api_key": (
            "The exposed key gives an attacker the same API access as the "
            "application, potentially at the developer's expense."
        ),
        "hardcoded_password": (
            "Hard-coded passwords are trivially extracted and reused to "
            "access any system sharing that credential."
        ),
        "weak_crypto": (
            "Weak algorithms (MD5/SHA1) are broken; an attacker can forge "
            "signatures or crack hashed passwords offline."
        ),
        "unsafe_deserialization": (
            "Deserialising untrusted data can allow an attacker to execute "
            "arbitrary code inside the application process."
        ),
        "xss": (
            "An attacker can inject scripts that run in a victim's browser, "
            "stealing session cookies or performing actions on their behalf."
        ),
        "cors_wildcard": (
            "Any website can make credentialed requests to this API, "
            "bypassing same-origin protections."
        ),
        "open_redirect": (
            "Attackers can craft phishing links that appear to originate "
            "from your trusted domain."
        ),
        "prototype_pollution": (
            "Polluting Object.prototype can override security checks and "
            "enable denial-of-service or remote code execution."
        ),
    }
    for key, text in generic.items():
        if key in vuln.vuln_type.lower():
            return text
    return (
        "This finding indicates a pattern commonly associated with exploitable "
        "security bugs. Developer review is recommended."
    )


def _what_to_check_next(vuln: Vulnerability) -> str:
    """Return a short developer-facing next-step sentence."""
    if vuln.remediation:
        short = vuln.remediation.split(".")[0].strip()
        return short + "." if short and not short.endswith(".") else short
    type_advice = {
        "sql_injection": "Replace string concatenation with parameterised queries.",
        "command_injection": "Use safe APIs (subprocess with a list, not shell=True) and validate input.",
        "hardcoded_secret": "Move the secret to an environment variable and rotate it immediately.",
        "hardcoded_api_key": "Move the key to an environment variable and rotate it immediately.",
        "hardcoded_password": "Move the credential to a secrets manager and rotate it immediately.",
        "weak_crypto": "Replace MD5/SHA1 with SHA-256 or bcrypt for passwords.",
        "unsafe_deserialization": "Avoid pickle.loads on untrusted data; use JSON or schema-validated input.",
        "xss": "Sanitise all user-supplied HTML and avoid innerHTML or dangerouslySetInnerHTML.",
        "cors_wildcard": "Restrict Access-Control-Allow-Origin to specific trusted origins.",
        "open_redirect": "Whitelist redirect destinations; never pass raw user input to location.href.",
        "prototype_pollution": "Use Object.create(null) for key-value maps and validate merge inputs.",
    }
    for key, advice in type_advice.items():
        if key in vuln.vuln_type.lower():
            return advice
    return "Review the flagged code and validate that user-supplied data is properly sanitised."


def _plain_english_description(vuln: Vulnerability) -> str:
    """Return the description if it reads like prose; otherwise synthesise one."""
    desc = (vuln.description or "").strip()
    if len(desc) > 30 and not desc.lower().startswith("the code"):
        return desc

    type_desc = {
        "sql_injection": (
            "User-controlled input is concatenated directly into a SQL query "
            "without parameterisation or sanitisation."
        ),
        "command_injection": (
            "User input flows into a shell command without sanitisation, "
            "allowing arbitrary OS command execution."
        ),
        "hardcoded_secret": (
            "A secret (password, key, or token) is embedded directly in "
            "source code where it can be extracted from version control."
        ),
        "hardcoded_api_key": (
            "An API key is hard-coded in source, making it trivially "
            "extractable from git history or build artefacts."
        ),
        "hardcoded_password": (
            "A password is hard-coded in source code rather than stored "
            "in a secrets manager or environment variable."
        ),
        "weak_crypto": (
            "A cryptographically weak algorithm (e.g. MD5 or SHA-1) is used "
            "where a stronger one is required."
        ),
        "unsafe_deserialization": (
            "Untrusted data is passed to a deserialisation function (e.g. "
            "pickle.loads) that can execute arbitrary code during loading."
        ),
        "xss": (
            "Unsanitised user data is written directly into the DOM, "
            "enabling script injection in a victim's browser."
        ),
    }
    for key, text in type_desc.items():
        if key in vuln.vuln_type.lower():
            return text
    return desc or "A potentially exploitable pattern was detected in this code."


# ---------------------------------------------------------------------------
# Main formatter class
# ---------------------------------------------------------------------------

class NormalizedReportFormatter:
    """Produces a professional, low-noise Markdown security report.

    Rules:
    - Status labels: REVIEW_REQUIRED | LIKELY_VULNERABILITY | HIGH_CONFIDENCE_VULNERABILITY
    - Scanner noise filtered out
    - Finding caps per severity (3 Critical, 5 High, 5 Medium, 0 Low)
    - Similar findings grouped
    - Plain-English explanations
    """

    def format(
        self,
        result: ScanResult,
        include_low: bool = False,
        repo_label: Optional[str] = None,
    ) -> str:
        """Render a normalised Markdown report from a ScanResult.

        Args:
            result: Completed scan result.
            include_low: If True, include Low severity findings (up to 5).
            repo_label: Optional display name for the repo in the report.

        Returns:
            Markdown string ready for display or file output.
        """
        is_training = _is_training_repo(result.repo_path)
        label = repo_label or result.repo_path.rstrip("/").split("/")[-1]

        selected = _select_top_findings(result.vulnerabilities, include_low=include_low)
        grouped = _group_similar(selected)

        patches_count = len(result.patches)
        files_scanned = result.files_scanned
        total_raw = len(result.vulnerabilities)
        shown = len(selected)
        chains = result.exploit_chains

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines: List[str] = []

        # ---- Header ----
        lines.append("# SWIFT Security Report")
        lines.append("")
        lines.append(f"**Repository:** `{label}`  ")
        lines.append(f"**Scan Date:** {now}  ")
        lines.append(f"**Scan ID:** `{result.scan_id}`")
        lines.append("")
        lines.append("---")
        lines.append("")

        # ---- 1. Executive Summary ----
        lines.append("## 1. Executive Summary")
        lines.append("")

        if is_training:
            lines.append(
                f"> **Note:** `{label}` appears to be a training or intentionally "
                "vulnerable application (e.g. Juice Shop, DVWA, WebGoat). "
                "Findings below reflect patterns in the codebase but should not be "
                "treated as production incidents."
            )
            lines.append("")

        summary_lines = self._build_summary(
            label=label,
            files_scanned=files_scanned,
            total_raw=total_raw,
            shown=shown,
            patches_count=patches_count,
            chains=chains,
            is_training=is_training,
            result=result,
        )
        for sl in summary_lines:
            lines.append(sl)
        lines.append("")
        lines.append("---")
        lines.append("")

        # ---- 2. What Matters Most ----
        lines.append("## 2. What Matters Most")
        lines.append("")
        what_matters = self._build_what_matters(selected, chains, is_training)
        for wm in what_matters:
            lines.append(wm)
        lines.append("")
        lines.append("---")
        lines.append("")

        # ---- 3. Top Findings ----
        lines.append("## 3. Top Findings")
        lines.append("")

        if not grouped:
            lines.append(
                "_No high-value findings selected after noise filtering. "
                "The scanner detected signals but none passed the quality threshold "
                "for inclusion in this report._"
            )
            lines.append("")
        else:
            for item in grouped:
                section = self._render_finding(item)
                lines.extend(section)

        # ---- 4. Exploit Chains (if any) ----
        if chains:
            lines.append("---")
            lines.append("")
            lines.append("## 4. Exploit Chain Analysis")
            lines.append("")
            lines.append(
                "The following exploit chains were detected. A chain means that two or "
                "more vulnerabilities can be chained together by an attacker to achieve "
                "a more severe impact than any single finding in isolation."
            )
            lines.append("")
            for chain in chains[:3]:
                conf_pct = int(round(chain.confidence * 100))
                lines.append(f"### {chain.name} [{chain.severity.upper()}]")
                lines.append("")
                lines.append(f"- **Entry Point:** `{chain.entry_point}`")
                lines.append(f"- **Impact:** {chain.impact}")
                lines.append(f"- **Confidence:** {conf_pct}%")
                lines.append(f"- **Vulnerabilities involved:** {', '.join(chain.vulnerability_ids)}")
                lines.append("")
                if chain.attack_path:
                    lines.append("**Attack Path:**")
                    lines.append("")
                    lines.append("```")
                    for ap_line in chain.attack_path.strip().split("\n"):
                        if ap_line.strip():
                            lines.append(ap_line)
                    lines.append("```")
                    lines.append("")

        # ---- 5. Patches ----
        if result.patches:
            lines.append("---")
            lines.append("")
            lines.append("## 5. Generated Patches")
            lines.append("")
            lines.append(
                f"SWIFT generated **{patches_count} patch(es)** "
                "automatically. Each patch was validated in a sandboxed Docker "
                "environment (no network, read-only filesystem, 30-second timeout)."
            )
            lines.append("")
            for patch in result.patches[:5]:
                lines.append(f"### Patch `{patch.id}` → fixes `{patch.vuln_id}`")
                lines.append("")
                lines.append(f"**File:** `{patch.file_path}`")
                lines.append("")
                lines.append("```diff")
                lines.append(patch.diff.strip())
                lines.append("```")
                lines.append("")

        # ---- Footer ----
        lines.append("---")
        lines.append("")
        lines.append(
            "_Report generated by [SWIFT](https://github.com/your-org/swift) — "
            "AI-powered continuous security scanner._"
        )
        lines.append("")

        return "\n".join(lines)

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _build_summary(
        self,
        *,
        label: str,
        files_scanned: int,
        total_raw: int,
        shown: int,
        patches_count: int,
        chains: List[ExploitChain],
        is_training: bool,
        result: ScanResult,
    ) -> List[str]:
        lines = []

        repo_type = "intentionally vulnerable training application" if is_training else "codebase"
        lines.append(
            f"SWIFT scanned **{files_scanned} file(s)** in the `{label}` {repo_type}. "
            f"The scanner detected **{total_raw} raw signal(s)** before noise filtering."
        )

        lines.append(
            f"After removing scanner noise (comments, imports, boilerplate, and "
            f"low-confidence signals), **{shown} high-value finding(s)** were selected "
            "for this report."
        )

        if patches_count > 0:
            lines.append(
                f"SWIFT auto-generated **{patches_count} patch(es)** that have been "
                "sandbox-tested and are ready for developer review."
            )
        else:
            lines.append("No patches were requested or generated in this scan.")

        if chains:
            lines.append(
                f"**{len(chains)} exploit chain(s)** were detected, meaning "
                "vulnerabilities can be combined for higher-impact attacks."
            )

        # Overall risk sentence
        crits = sum(1 for v in result.vulnerabilities if v.severity.upper() == "CRITICAL")
        highs = sum(1 for v in result.vulnerabilities if v.severity.upper() == "HIGH")

        if crits > 0:
            lines.append(
                f"**Overall risk is HIGH** — {crits} critical-severity finding(s) "
                "require immediate attention."
            )
        elif highs > 0:
            lines.append(
                f"**Overall risk is ELEVATED** — {highs} high-severity finding(s) "
                "should be addressed before next release."
            )
        elif shown > 0:
            lines.append(
                "**Overall risk is MODERATE** — findings are present but no critical "
                "issues were confirmed."
            )
        else:
            lines.append(
                "**Overall risk appears LOW** — no significant findings passed the "
                "quality threshold for this report."
            )

        return lines

    def _build_what_matters(
        self,
        selected: List[Vulnerability],
        chains: List[ExploitChain],
        is_training: bool,
    ) -> List[str]:
        lines = []

        # Deduplicate themes
        themes = list(dict.fromkeys(v.vuln_type.lower() for v in selected))

        if not themes and not chains:
            lines.append("- No high-priority risk themes identified after noise filtering.")
            return lines

        if themes:
            lines.append("**Top risk themes:**")
            for t in themes[:5]:
                lines.append(f"- {_vuln_type_title(t)}")
            lines.append("")

        if chains:
            lines.append(
                f"**Exploit chaining is possible** — {len(chains)} chain(s) detected. "
                "Review Section 4 for full attack paths."
            )
            lines.append("")

        # Concentration in test/demo code?
        test_paths = [v for v in selected if any(
            kw in v.file_path.lower()
            for kw in ("test", "demo", "challenge", "mock", "fixture", "spec", "example")
        )]
        if test_paths:
            pct = int(round(len(test_paths) / max(len(selected), 1) * 100))
            lines.append(
                f"**{pct}% of selected findings are in test/demo/challenge files.** "
                "These may be intentional or lower-risk in a production context."
            )
            lines.append("")

        if is_training:
            lines.append(
                "**This is a training/CTF application** — most vulnerabilities are "
                "intentional. Focus on patterns that appear in actual runtime paths "
                "rather than challenge code."
            )
            lines.append("")

        # Immediate action needed?
        crits = [v for v in selected if v.severity.upper() == "CRITICAL"]
        if crits:
            lines.append(
                f"**Immediate action required** — {len(crits)} critical finding(s) "
                "identified. Treat these as production incidents."
            )
        else:
            lines.append("No critical findings require immediate incident-level response.")

        return lines

    def _render_finding(self, item) -> List[str]:
        """Render a single finding (or grouped finding) as Markdown."""
        is_grouped = isinstance(item, _GroupedFinding)
        vuln: Vulnerability = item.vuln if is_grouped else item

        status = _map_status(vuln)
        sev_label = _severity_emoji_free_label(vuln.severity)
        conf_pct = _confidence_label(vuln.confidence)
        title = _vuln_type_title(vuln.vuln_type)

        if is_grouped:
            title = f"{title} (×{item.count} similar instances)"

        lines: List[str] = []
        lines.append(f"### [{sev_label}] {title}")
        lines.append("")
        lines.append(f"**Status:** {status}  ")
        lines.append(f"**Confidence:** {conf_pct}  ")
        lines.append(f"**Location:** `{vuln.file_path}:{vuln.line_number}`  ")

        if vuln.cwe_id:
            cwe_url = vuln.cwe_url or f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-', '')}.html"
            lines.append(f"**CWE:** [{vuln.cwe_id}]({cwe_url})  ")

        if vuln.owasp_category:
            lines.append(f"**OWASP:** {vuln.owasp_category}  ")

        lines.append("")

        # What this means
        lines.append("**What this means:**")
        lines.append("")
        desc = _plain_english_description(vuln)
        if is_grouped:
            desc += (
                f" This pattern appears **{item.count} times** across the same file "
                "— likely a systemic issue, not an isolated mistake."
            )
        lines.append(desc)
        lines.append("")

        # Why it matters
        lines.append("**Why this matters:**")
        lines.append("")
        lines.append(_explain_why_it_matters(vuln))
        lines.append("")

        # What to check next
        lines.append("**What to check next:**")
        lines.append("")
        lines.append(_what_to_check_next(vuln))
        lines.append("")

        # Evidence
        lines.append("**Evidence:**")
        lines.append("")

        lang = _detect_language(vuln.file_path)
        snippet = (vuln.code_snippet or "").strip()
        if snippet:
            lines.append(f"```{lang}")
            lines.append(snippet)
            lines.append("```")
        else:
            lines.append(f"`{vuln.file_path}:{vuln.line_number}` — see source file.")

        lines.append("")
        lines.append("---")
        lines.append("")

        return lines


def _detect_language(file_path: str) -> str:
    import os as _os
    ext = _os.path.splitext(file_path)[1].lower()
    return {
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".h": "c",
    }.get(ext, "text")
