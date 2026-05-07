"""CLI handlers for audit verify and audit export commands."""
import sys
from pathlib import Path


def run_verify(args) -> None:
    """Verify the hash chain integrity of an audit log."""
    from audit.immutable_log import HashChainLogger
    log_path = Path(args.log)
    if not log_path.exists():
        print(f"[audit] ERROR: log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    logger = HashChainLogger.__new__(HashChainLogger)
    result = logger.verify_chain(log_path)
    if result.valid:
        print(f"✓ Chain intact — {result.entries_checked} entries verified")
    else:
        print(
            f"✗ CHAIN BROKEN at entry #{result.first_tampered_entry}"
            f" (fields: {result.tampered_fields})",
            file=sys.stderr,
        )
        sys.exit(2)


def run_export(args) -> None:
    """Export audit log as human-readable Markdown."""
    from audit.reporter import write_markdown
    log_path = Path(args.log)
    out_path = Path(args.out)
    if not log_path.exists():
        print(f"[audit] ERROR: log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    write_markdown(log_path, out_path)
    print(f"✓ Audit report written to {out_path}")
