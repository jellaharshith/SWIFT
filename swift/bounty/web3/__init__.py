"""Smart-contract auditor.

Subprocess wrappers around ``slither`` and ``mythril`` plus a small library
of grep-able patterns derived from the claude-bug-bounty ``web3/`` skill set
(reentrancy, oracle, access-control, ERC4626, flash-loan, signature replay).

Heavy lifting is done by the external tools; this package's job is to make
their output flow into SWIFT's :class:`security.roe.ROE` gate and emit
findings in the shape :func:`output.report_normalizer.normalize` expects.
"""
from bounty.web3 import mythril, patterns, slither

__all__ = ["mythril", "patterns", "slither"]
