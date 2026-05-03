"""Unit tests for config/consent.py — one-time consent gate."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from config.consent import check_consent, prompt_and_save_consent, require_consent


@pytest.fixture()
def consent_file(tmp_path, monkeypatch):
    """Redirect CONSENT_FILE to a temp path for test isolation."""
    fake_file = tmp_path / ".swift" / "consent.json"
    monkeypatch.setattr("config.consent.CONSENT_FILE", fake_file)
    return fake_file


def test_check_consent_returns_false_when_missing(consent_file):
    assert check_consent() is False


def test_check_consent_returns_false_on_malformed_json(consent_file):
    consent_file.parent.mkdir(parents=True)
    consent_file.write_text("{not valid json}", encoding="utf-8")
    assert check_consent() is False


def test_check_consent_returns_false_when_accepted_is_false(consent_file):
    consent_file.parent.mkdir(parents=True)
    consent_file.write_text(json.dumps({"accepted": False}), encoding="utf-8")
    assert check_consent() is False


def test_check_consent_returns_true_when_accepted(consent_file):
    consent_file.parent.mkdir(parents=True)
    consent_file.write_text(json.dumps({"accepted": True}), encoding="utf-8")
    assert check_consent() is True


def test_prompt_and_save_consent_returns_true_and_writes_file(consent_file):
    with patch("builtins.input", return_value="I ACCEPT"):
        result = prompt_and_save_consent()
    assert result is True
    assert consent_file.exists()
    data = json.loads(consent_file.read_text())
    assert data["accepted"] is True


def test_prompt_and_save_consent_returns_false_on_wrong_input(consent_file):
    with patch("builtins.input", return_value="yes"):
        result = prompt_and_save_consent()
    assert result is False
    assert not consent_file.exists()


def test_require_consent_raises_systemexit_when_declined(consent_file):
    with patch("builtins.input", return_value="no"):
        with pytest.raises(SystemExit):
            require_consent()


def test_require_consent_passes_silently_when_already_accepted(consent_file):
    consent_file.parent.mkdir(parents=True)
    consent_file.write_text(json.dumps({"accepted": True}), encoding="utf-8")
    require_consent()  # should not raise


def test_require_consent_prompts_and_passes_on_accept(consent_file):
    with patch("builtins.input", return_value="I ACCEPT"):
        require_consent()  # should not raise
    assert check_consent() is True
