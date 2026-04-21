"""Safe JSON parsing utilities with error handling.

Prevents invalid JSON from crashing pipeline. Returns None on parse failure,
allowing partial results to flow downstream.
"""
import json
from typing import Any, Optional


def safe_parse_json(text: str) -> Optional[Any]:
    """Safely parse JSON string without raising exceptions.

    Args:
        text: String to parse as JSON.

    Returns:
        Parsed JSON object/array, or None if parse fails.
    """
    if not text or not isinstance(text, str):
        return None

    text = text.strip()
    if not text:
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
    except Exception:
        return None


def safe_parse_json_array(text: str) -> list:
    """Safely parse JSON array, returning empty list on failure.

    Args:
        text: String expected to contain JSON array.

    Returns:
        Parsed array, or empty list if parse fails.
    """
    result = safe_parse_json(text)
    if isinstance(result, list):
        return result
    return []


def safe_parse_json_object(text: str) -> dict:
    """Safely parse JSON object, returning empty dict on failure.

    Args:
        text: String expected to contain JSON object.

    Returns:
        Parsed object, or empty dict if parse fails.
    """
    result = safe_parse_json(text)
    if isinstance(result, dict):
        return result
    return {}
