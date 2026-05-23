"""
SWIFT doctrine loader.

Provides:
  load_doctrine(name)          -> str   — load a single doctrine file by stem name
  compose_persona(specialist)  -> str   — concatenate doctrine texts for a specialist
"""
from __future__ import annotations

from pathlib import Path

_DOCTRINE_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_yaml_persona_map() -> dict[str, list[str]]:
    """Parse persona_map.yaml without requiring PyYAML; falls back to {} on any error."""
    yaml_path = _DOCTRINE_DIR / "persona_map.yaml"
    if not yaml_path.exists():
        return {}
    try:
        import yaml  # type: ignore[import]
        with yaml_path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            return {k: list(v) for k, v in data.items()}
        return {}
    except Exception:
        pass
    # Minimal hand-rolled fallback: parse "key: [a, b]" lines without yaml
    try:
        mapping: dict[str, list[str]] = {}
        text = yaml_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip().strip("[]")
            items = [item.strip() for item in val.split(",") if item.strip()]
            if key and items:
                mapping[key] = items
        return mapping
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_doctrine(name: str) -> str:
    """
    Load a single doctrine file by stem name (e.g. "mitnick", "haddix", "rosen", "ptes").

    Returns "" if the file does not exist or cannot be read — never raises.
    """
    if not name:
        return ""
    try:
        path = _DOCTRINE_DIR / f"{name}.md"
        if path.exists():
            return path.read_text(encoding="utf-8")
    except Exception:
        pass
    return ""


def compose_persona(specialist_name: str) -> str:
    """
    Build a persona preamble for *specialist_name* by concatenating the doctrine
    texts listed in persona_map.yaml under that key.

    Returns "" if the specialist is not found or all doctrine files are missing.
    Never raises.
    """
    try:
        persona_map = _read_yaml_persona_map()
        doctrine_keys: list[str] = persona_map.get(specialist_name, [])
        if not doctrine_keys:
            return ""
        parts: list[str] = []
        for key in doctrine_keys:
            text = load_doctrine(key)
            if text:
                parts.append(f"--- DOCTRINE: {key.upper()} ---\n{text.strip()}")
        return "\n\n".join(parts)
    except Exception:
        return ""
