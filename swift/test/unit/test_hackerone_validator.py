"""Unit tests for HackerOne scope validator."""
import json
import pytest
from pathlib import Path

from config.hackerone_validator import (
    extract_in_scope_domains,
    load_scope,
    validate_target,
)


@pytest.fixture
def tmp_program_json(tmp_path: Path) -> Path:
    """Write a minimal HackerOne program JSON file."""
    data = {
        "targets": {
            "in_scope": [
                {"asset_identifier": "*.example.com"},
                {"asset_identifier": "api.example.com"},
            ]
        }
    }
    p = tmp_path / "program.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.fixture
def tmp_scope_json(tmp_path: Path) -> Path:
    """Write a program JSON using the 'scope' key format."""
    data = {
        "scope": [
            {"value": "shop.example.com"},
            {"value": "*.api.example.com"},
        ]
    }
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_load_scope_success(tmp_program_json: Path) -> None:
    data = load_scope(str(tmp_program_json))
    assert "targets" in data


def test_load_scope_file_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        load_scope("/nonexistent/path/program.json")


def test_load_scope_missing_keys(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    with pytest.raises(ValueError, match="missing 'targets' or 'scope' key"):
        load_scope(str(bad))


def test_extract_in_scope_domains_targets_format(tmp_program_json: Path) -> None:
    data = load_scope(str(tmp_program_json))
    domains = extract_in_scope_domains(data)
    assert "*.example.com" in domains
    assert "api.example.com" in domains


def test_extract_in_scope_domains_scope_format(tmp_scope_json: Path) -> None:
    data = load_scope(str(tmp_scope_json))
    domains = extract_in_scope_domains(data)
    assert "shop.example.com" in domains
    assert "*.api.example.com" in domains


def test_validate_target_exact_match() -> None:
    domains = ["api.example.com", "shop.example.com"]
    assert validate_target("api.example.com", domains) is True


def test_validate_target_wildcard_match() -> None:
    domains = ["*.example.com"]
    assert validate_target("sub.example.com", domains) is True
    assert validate_target("other.example.com", domains) is True


def test_validate_target_no_match() -> None:
    domains = ["*.example.com", "api.example.com"]
    assert validate_target("evil.attacker.com", domains) is False


def test_validate_target_fail_closed_on_empty() -> None:
    assert validate_target("anything.com", []) is False


def test_validate_target_wildcard_does_not_match_parent() -> None:
    # fnmatch: *.example.com does NOT match example.com (no dot before star consumed)
    domains = ["*.example.com"]
    result = validate_target("example.com", domains)
    # fnmatch("example.com", "*.example.com") → False (correct fail-closed behaviour)
    assert result is False
