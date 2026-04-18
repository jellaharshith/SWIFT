import os
import pytest
from unittest.mock import patch
from config import get_config, Config


def test_config_loads_from_env():
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test-key"}):
        config = get_config()
        assert config.api_key == "sk-ant-test-key"


def test_missing_api_key_raises():
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            get_config()


def test_config_defaults():
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-x"}):
        config = get_config()
        assert config.confidence_threshold == 0.95
        assert config.sandbox_timeout == 30
        assert config.max_retries == 3


def test_config_override_from_env():
    env = {"ANTHROPIC_API_KEY": "sk-ant-x", "SWIFT_CONFIDENCE_THRESHOLD": "0.97"}
    with patch.dict(os.environ, env):
        config = get_config()
        assert config.confidence_threshold == 0.97


def test_importing_config_without_key_does_not_raise():
    import config  # noqa: F401


def test_validate_config_bad_threshold():
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-x", "SWIFT_CONFIDENCE_THRESHOLD": "1.5"}):
        with pytest.raises(ValueError, match="confidence_threshold"):
            get_config()
