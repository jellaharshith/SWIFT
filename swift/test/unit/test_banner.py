"""Tests for CLI startup banner suppression logic."""
import os
import sys
from argparse import Namespace
from unittest.mock import patch

import pytest

from cli.banner import should_show_banner


def _args(**kwargs):
    defaults = {"no_banner": False, "quiet": False, "command": "scan", "output": "json"}
    defaults.update(kwargs)
    return Namespace(**defaults)


def test_suppressed_by_no_banner():
    assert should_show_banner(_args(no_banner=True), ["swiftsec", "scan", "."]) is False


def test_suppressed_by_quiet():
    assert should_show_banner(_args(quiet=True), ["swiftsec", "scan", "."]) is False


def test_suppressed_by_env(monkeypatch):
    monkeypatch.setenv("SWIFT_NO_BANNER", "1")
    assert should_show_banner(_args(), ["swiftsec", "scan", "."]) is False


def test_suppressed_by_version_flag():
    assert should_show_banner(None, ["swiftsec", "--version"]) is False


def test_suppressed_by_help_flag():
    assert should_show_banner(None, ["swiftsec", "--help"]) is False
    assert should_show_banner(None, ["swiftsec", "-h"]) is False


def test_suppressed_non_tty(monkeypatch):
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    assert should_show_banner(_args(), ["swiftsec", "scan", "."]) is False


def test_suppressed_json_output():
    assert should_show_banner(_args(command="scan", output="json"), ["swiftsec", "scan", "."]) is False


def test_shown_in_tty(monkeypatch):
    monkeypatch.delenv("SWIFT_NO_BANNER", raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    assert should_show_banner(_args(command="wizard", output=None), ["swiftsec", "wizard"]) is True


def test_print_banner_writes_to_stderr(monkeypatch, capsys):
    monkeypatch.delenv("SWIFT_NO_BANNER", raising=False)
    from cli.banner import print_banner
    import io
    buf = io.StringIO()
    print_banner(stream=buf)
    output = buf.getvalue()
    assert "SWIFT" in output or len(output) > 10  # banner has content
    # stdout must be empty
    captured = capsys.readouterr()
    assert captured.out == ""
