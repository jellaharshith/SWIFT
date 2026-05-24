"""
import_cbh_patterns.py — One-off extraction script.

Walks swift/skills/cbh/skills/ recursively, parses YAML front-matter and
markdown body from each .md file, and emits one JSONL record per skill to
swift/intel/data/cbh_patterns.jsonl.

Usage:
    python swift/intel/import_cbh_patterns.py

Importable for future integration:
    from swift.intel.import_cbh_patterns import extract_patterns, main
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).resolve().parent          # swift/intel/
_CBH_SKILLS_DIR = _THIS_DIR.parent / "skills" / "cbh" / "skills"
_OUTPUT_DIR = _THIS_DIR / "data"
_OUTPUT_FILE = _OUTPUT_DIR / "cbh_patterns.jsonl"

# ---------------------------------------------------------------------------
# Front-matter helpers
# ---------------------------------------------------------------------------

# Matches the opening and closing --- delimiters
_FM_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
# Matches a simple key: value line (no nested YAML)
_KV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", re.MULTILINE)


def _parse_front_matter(text: str) -> tuple[dict, str]:
    """
    Returns (meta_dict, body_text).

    Parses only the first --- ... --- block. All values are kept as strings
    except report_count which is coerced to int. If no front-matter block is
    found, returns ({}, full text).
    """
    m = _FM_RE.match(text)
    if not m:
        return {}, text

    fm_block = m.group(1)
    body = text[m.end():]

    meta: dict = {}
    for key, value in _KV_RE.findall(fm_block):
        meta[key.strip()] = value.strip()

    return meta, body


def _infer_bug_class(name: str) -> str:
    """
    Derive a short bug-class label from the skill name.

    Examples:
        hunt-sqli           -> sqli
        hunt-xss            -> xss
        triage-validation   -> triage
        bb-methodology      -> methodology
        cloud-iam-deep      -> cloud-iam
        apk-redteam-pipeline-> redteam
    """
    # Strip known prefixes so the remainder is the bug class
    prefixes = ("hunt-", "triage-", "bb-", "web3-", "web2-", "m365-",
                "mid-engagement-", "offensive-", "supply-chain-")
    slug = name
    for prefix in prefixes:
        if slug.startswith(prefix):
            slug = slug[len(prefix):]
            break

    # Collapse trailing qualifiers like "-deep", "-pipeline", "-attack", "-recon"
    for suffix in ("-deep", "-pipeline", "-attack", "-recon", "-full", "-ir-detection"):
        if slug.endswith(suffix):
            slug = slug[: -len(suffix)]
            break

    return slug or name


# ---------------------------------------------------------------------------
# Body extraction helpers
# ---------------------------------------------------------------------------

_CODE_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_BULLET_RE = re.compile(r"^[ \t]*[-*+] .+", re.MULTILINE)


def _extract_code_blocks(body: str) -> list[str]:
    """Return the content (not fences) of every ``` ... ``` block."""
    return [m.group(1).strip() for m in _CODE_BLOCK_RE.finditer(body) if m.group(1).strip()]


def _extract_bullet_points(body: str) -> list[str]:
    """Return every bullet-point line (stripped)."""
    return [m.group(0).strip() for m in _BULLET_RE.finditer(body)]


# ---------------------------------------------------------------------------
# Per-file record builder
# ---------------------------------------------------------------------------

def _build_record(md_path: Path, skills_root: Path) -> dict:
    """Parse one .md file and return a JSONL-ready dict."""
    text = md_path.read_text(encoding="utf-8", errors="replace")
    meta, body = _parse_front_matter(text)

    name = meta.get("name", "")
    # Fall back: derive name from directory name if missing from front-matter
    if not name:
        name = md_path.parent.name

    # report_count: coerce to int, default 0
    try:
        report_count = int(meta.get("report_count", 0))
    except (ValueError, TypeError):
        report_count = 0

    # Normalise sources: strip spaces around commas
    raw_sources = meta.get("sources", "")
    sources = ",".join(s.strip() for s in raw_sources.split(",") if s.strip())

    # Relative path from repo root for portability
    try:
        rel_path = md_path.relative_to(skills_root.parent.parent.parent)
    except ValueError:
        rel_path = md_path

    return {
        "name": name,
        "bug_class": _infer_bug_class(name),
        "description": meta.get("description", ""),
        "sources": sources,
        "report_count": report_count,
        "skill_path": str(rel_path),
        "code_blocks": _extract_code_blocks(body),
        "bullet_points": _extract_bullet_points(body),
        "body_preview": body.strip()[:500],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_patterns(
    skills_dir: Path | None = None,
    output_file: Path | None = None,
) -> list[dict]:
    """
    Walk *skills_dir* for .md files, build records, write JSONL to *output_file*.

    Returns the list of records so callers can inspect without touching disk.
    """
    skills_dir = skills_dir or _CBH_SKILLS_DIR
    output_file = output_file or _OUTPUT_FILE

    md_files = sorted(skills_dir.rglob("*.md"))
    records: list[dict] = []
    for md_path in md_files:
        try:
            record = _build_record(md_path, skills_dir)
            records.append(record)
        except Exception as exc:  # noqa: BLE001
            print(f"  [WARN] skipping {md_path}: {exc}", file=sys.stderr)

    # Write output
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    return records


def main() -> None:
    records = extract_patterns()
    n_patterns = len(records)
    # Count unique source files (skill_path values)
    m_files = len({r["skill_path"] for r in records})
    print(
        f"Extracted {n_patterns} patterns from {m_files} skill files"
        f" → {_OUTPUT_FILE}"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
    sys.exit(0)
