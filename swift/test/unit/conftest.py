from unittest.mock import patch

import pytest

import config.settings as _settings


@pytest.fixture(autouse=True)
def reset_config_cache():
    """Reset config cache and suppress .env loading so env-var patches work.

    load_dotenv() would otherwise populate os.environ from the project's .env
    file, making it impossible to test the missing-key error path.
    """
    _settings._config = None
    with patch("config.settings.load_dotenv"):
        yield
    _settings._config = None
