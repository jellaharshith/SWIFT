"""Bug-bounty automation core (claude-bug-bounty port).

Public surface:

* :mod:`bounty.hunt_memory`   -- cross-engagement memory (audit/patterns/journal)
* :mod:`bounty.auth_session`  -- session-token propagation to httpx/katana/ffuf/nuclei
* :mod:`bounty.validator`     -- 7-question gate + 4-gate validation
* :mod:`bounty.report_formats` -- H1 / Bugcrowd / Intigriti / Immunefi formatters
* :mod:`bounty.web3`          -- smart-contract auditor (slither / mythril)
"""
from bounty.auth_session import AuthSession, env_for_tool
from bounty.hunt_memory import HuntMemory
from bounty.report_formats import format_report
from bounty.validator import Finding, Verdict, validate

__all__ = [
    "AuthSession", "env_for_tool",
    "HuntMemory",
    "Finding", "Verdict", "validate",
    "format_report",
]
