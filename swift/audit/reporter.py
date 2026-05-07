"""Human-readable Markdown export from audit JSONL log."""
import json
from pathlib import Path


def write_markdown(log_path: Path, output: Path) -> None:
    """Write a Markdown timeline from an audit JSONL log file."""
    log_path = Path(log_path)
    output = Path(output)
    lines = ["# SWIFT Audit Report", ""]
    with log_path.open() as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            e = json.loads(raw)
            lines.append(
                f"- `{e['timestamp']}` **{e['event_type']}** (seq {e['seq']}) — `{e['data']}`"
            )
    output.write_text("\n".join(lines) + "\n")
