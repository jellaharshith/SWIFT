"""Unit tests for CTF_TARGETS config dict."""
import pytest

from config.ctf_targets import CTF_TARGETS


REQUIRED_KEYS = {"name", "default_url", "docker_hint", "techniques", "roe_template"}
REQUIRED_ROE_KEYS = {"scope", "allow_web_probes", "allow_chain_execution"}


def test_ctf_targets_not_empty() -> None:
    assert len(CTF_TARGETS) > 0, "CTF_TARGETS must define at least one target"


def test_juice_shop_present() -> None:
    assert "juice-shop" in CTF_TARGETS


def test_dvwa_present() -> None:
    assert "dvwa" in CTF_TARGETS


def test_metasploitable_present() -> None:
    assert "metasploitable" in CTF_TARGETS


@pytest.mark.parametrize("target_key", list(CTF_TARGETS.keys()))
def test_required_keys(target_key: str) -> None:
    cfg = CTF_TARGETS[target_key]
    missing = REQUIRED_KEYS - set(cfg.keys())
    assert not missing, f"{target_key} missing keys: {missing}"


@pytest.mark.parametrize("target_key", list(CTF_TARGETS.keys()))
def test_roe_template_keys(target_key: str) -> None:
    roe = CTF_TARGETS[target_key]["roe_template"]
    missing = REQUIRED_ROE_KEYS - set(roe.keys())
    assert not missing, f"{target_key} roe_template missing keys: {missing}"


@pytest.mark.parametrize("target_key", list(CTF_TARGETS.keys()))
def test_techniques_is_list(target_key: str) -> None:
    techniques = CTF_TARGETS[target_key]["techniques"]
    assert isinstance(techniques, list) and len(techniques) > 0


@pytest.mark.parametrize("target_key", list(CTF_TARGETS.keys()))
def test_default_url_is_http(target_key: str) -> None:
    url = CTF_TARGETS[target_key]["default_url"]
    assert url.startswith("http"), f"{target_key} default_url must start with http"


@pytest.mark.parametrize("target_key", list(CTF_TARGETS.keys()))
def test_docker_hint_nonempty(target_key: str) -> None:
    hint = CTF_TARGETS[target_key]["docker_hint"]
    assert isinstance(hint, str) and "docker" in hint
