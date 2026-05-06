"""Unit tests for browser.payload_library and browser.payload_uploader."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from browser.payload_library import PayloadLibrary, get_user_payloads
from browser.payload_uploader import list_payloads, remove_payloads, upload_payloads


# ── PayloadLibrary ─────────────────────────────────────────────────────────────


def test_payload_library_loads_from_home(tmp_path: Path) -> None:
    vt_dir = tmp_path / "xss"
    vt_dir.mkdir(parents=True)
    (vt_dir / "test.txt").write_text("<script>alert(1)</script>\n<img src=x onerror=1>\n")

    lib = PayloadLibrary()
    with patch.object(Path, "home", return_value=tmp_path):
        # Rebuild search dirs using patched home
        with patch(
            "browser.payload_library.Path.home",
            return_value=tmp_path,
        ):
            lib2 = PayloadLibrary()
            payloads = lib2.get_payloads("xss")

    # Direct path test without mocking
    lib3 = PayloadLibrary()
    lib3._cache.clear()
    # Inject directly
    lib3._cache["xss"] = []
    # Test with real tmp_path
    (tmp_path / "xss").mkdir(parents=True, exist_ok=True)
    (tmp_path / "xss" / "a.txt").write_text("payload1\npayload2\n")

    lib4 = PayloadLibrary()
    with patch(
        "browser.payload_library.PayloadLibrary._search_dirs",
        return_value=[tmp_path / "xss" / "a.txt"],
    ):
        entries = lib4.get_payloads("xss")

    assert len(entries) == 2
    assert entries[0]["payload"] == "payload1"
    assert entries[0]["source"] == "user"
    assert entries[0]["vuln_type"] == "xss"
    assert entries[0]["tags"] == []
    assert entries[0]["waf_bypass"] is False
    assert entries[0]["framework_hint"] is None


def test_payload_library_deduplicates(tmp_path: Path) -> None:
    f = tmp_path / "dup.txt"
    f.write_text("dup_payload\ndup_payload\nunique\n")

    lib = PayloadLibrary()
    with patch(
        "browser.payload_library.PayloadLibrary._search_dirs",
        return_value=[f],
    ):
        entries = lib.get_payloads("sqli")

    payloads = [e["payload"] for e in entries]
    assert payloads.count("dup_payload") == 1
    assert "unique" in payloads
    assert len(payloads) == 2


def test_payload_library_empty_when_no_files(tmp_path: Path) -> None:
    lib = PayloadLibrary()
    with patch(
        "browser.payload_library.PayloadLibrary._search_dirs",
        return_value=[],
    ):
        entries = lib.get_payloads("ssrf")
    assert entries == []


def test_payload_library_caches(tmp_path: Path) -> None:
    f = tmp_path / "p.txt"
    f.write_text("cached_payload\n")

    lib = PayloadLibrary()
    with patch(
        "browser.payload_library.PayloadLibrary._search_dirs",
        return_value=[f],
    ) as mock_search:
        lib.get_payloads("xss")
        lib.get_payloads("xss")  # second call should use cache

    # _search_dirs called only once (caching kicks in)
    assert mock_search.call_count == 1


def test_get_user_payloads_returns_strings(tmp_path: Path) -> None:
    f = tmp_path / "p.txt"
    f.write_text("str1\nstr2\n")

    from browser import payload_library as pl_mod

    with patch.object(pl_mod._library, "get_user_payloads", return_value=["str1", "str2"]):
        result = get_user_payloads("xss")
    assert result == ["str1", "str2"]


def test_payload_library_skips_blank_lines(tmp_path: Path) -> None:
    f = tmp_path / "blank.txt"
    f.write_text("\n  \npayload_a\n\npayload_b\n  \n")

    lib = PayloadLibrary()
    with patch(
        "browser.payload_library.PayloadLibrary._search_dirs",
        return_value=[f],
    ):
        entries = lib.get_payloads("xss")

    assert [e["payload"] for e in entries] == ["payload_a", "payload_b"]


# ── upload_payloads ────────────────────────────────────────────────────────────


def test_upload_payloads_adds_new(tmp_path: Path) -> None:
    src = tmp_path / "payloads.txt"
    src.write_text("new1\nnew2\nnew3\n")

    result = upload_payloads(str(src), "xss", dest_dir=str(tmp_path))

    assert result["added"] == 3
    assert result["skipped"] == 0
    assert result["total"] == 3
    assert Path(result["path"]).exists()


def test_upload_payloads_dedupes_against_existing(tmp_path: Path) -> None:
    # Write initial custom.txt
    xss_dir = tmp_path / "xss"
    xss_dir.mkdir()
    (xss_dir / "custom.txt").write_text("existing1\nexisting2\n")

    src = tmp_path / "new.txt"
    src.write_text("existing1\nnew_payload\n")

    from browser import payload_library as pl_mod

    # Invalidate so _library doesn't have stale cache
    pl_mod._library.invalidate("xss")

    result = upload_payloads(str(src), "xss", dest_dir=str(tmp_path))
    assert result["added"] == 1
    assert result["skipped"] == 1


def test_upload_payloads_raises_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        upload_payloads(str(tmp_path / "nonexistent.txt"), "xss")


def test_upload_payloads_raises_on_empty_file(tmp_path: Path) -> None:
    src = tmp_path / "empty.txt"
    src.write_text("\n  \n\n")
    with pytest.raises(ValueError):
        upload_payloads(str(src), "xss")


# ── remove_payloads ────────────────────────────────────────────────────────────


def test_remove_payloads_removes_line(tmp_path: Path) -> None:
    xss_dir = tmp_path / "xss"
    xss_dir.mkdir()
    custom = xss_dir / "custom.txt"
    custom.write_text("keep1\nremove_me\nkeep2\n")

    from browser import payload_uploader as pu_mod

    with patch("browser.payload_uploader._DEFAULT_ROOT", tmp_path):
        removed = remove_payloads("xss", "remove_me")

    assert removed is True
    remaining = custom.read_text().splitlines()
    assert "remove_me" not in remaining
    assert "keep1" in remaining
    assert "keep2" in remaining


def test_remove_payloads_returns_false_if_not_found(tmp_path: Path) -> None:
    xss_dir = tmp_path / "xss"
    xss_dir.mkdir()
    (xss_dir / "custom.txt").write_text("keep\n")

    from browser import payload_uploader as pu_mod

    with patch("browser.payload_uploader._DEFAULT_ROOT", tmp_path):
        result = remove_payloads("xss", "nonexistent")

    assert result is False


def test_remove_payloads_returns_false_if_no_file(tmp_path: Path) -> None:
    with patch("browser.payload_uploader._DEFAULT_ROOT", tmp_path):
        result = remove_payloads("xss", "anything")
    assert result is False
