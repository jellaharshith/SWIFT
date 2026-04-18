import pytest
import config.settings as _settings


@pytest.fixture(autouse=True)
def reset_config_cache():
    """Reset the module-level config cache before and after every test.

    Without this fixture the lazy-loading cache in settings._config would
    leak between tests: whichever test runs first would 'win' and all
    subsequent tests would see a stale Config, making env-var patches
    invisible and turning the test suite order-dependent.
    """
    _settings._config = None
    yield
    _settings._config = None
