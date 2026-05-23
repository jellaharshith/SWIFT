import os
import pytest
from unittest.mock import patch
from config import get_config, Config, reset_config


def setup_function():
    reset_config()


def teardown_function():
    reset_config()


def test_config_loads_defaults():
    config = get_config()
    assert config.confidence_threshold == 0.95
    assert config.sandbox_timeout == 30
    assert config.max_retries == 3


def test_config_no_api_key_required():
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    with patch.dict(os.environ, env, clear=True):
        config = get_config()
        assert config is not None


def test_config_defaults():
    config = get_config()
    assert config.confidence_threshold == 0.95
    assert config.sandbox_timeout == 30
    assert config.max_retries == 3


def test_config_override_from_env():
    reset_config()
    with patch.dict(os.environ, {"SWIFT_CONFIDENCE_THRESHOLD": "0.97"}):
        config = get_config()
        assert config.confidence_threshold == 0.97


def test_importing_config_without_key_does_not_raise():
    import config  # noqa: F401


def test_validate_config_bad_threshold():
    reset_config()
    with patch.dict(os.environ, {"SWIFT_CONFIDENCE_THRESHOLD": "1.5"}):
        with pytest.raises(ValueError, match="confidence_threshold"):
            get_config()
