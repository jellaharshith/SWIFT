"""Tests for sdk.registry and sdk.migration."""
import pytest
from sdk.base import BaseModule, Phase, VulnType, Severity, Finding
from sdk.registry import PluginRegistry, ValidationResult


class _ValidModule(BaseModule):
    name = "valid_mod"; phase = Phase.ACTIVE; vuln_types = [VulnType.XSS]
    author = "test"; version = "1.0"
    async def probe(self, target, session, roe): return []


class _InvalidModule(BaseModule):
    async def probe(self, target, session, roe): return []


def test_register_valid_module():
    reg = PluginRegistry()
    reg.register(_ValidModule)
    assert "valid_mod" in reg.names()


def test_register_invalid_raises():
    reg = PluginRegistry()
    with pytest.raises(NotImplementedError):
        reg.register(_InvalidModule)


def test_get_returns_instance():
    reg = PluginRegistry()
    reg.register(_ValidModule)
    m = reg.get("valid_mod")
    assert isinstance(m, _ValidModule)


def test_list_by_phase():
    reg = PluginRegistry()
    reg.register(_ValidModule)
    actives = reg.list_by_phase(Phase.ACTIVE)
    assert any(isinstance(m, _ValidModule) for m in actives)


def test_validate_valid():
    reg = PluginRegistry()
    result = reg.validate(_ValidModule)
    assert result.valid
    assert result.errors == []


def test_validate_invalid():
    reg = PluginRegistry()
    result = reg.validate(_InvalidModule)
    assert not result.valid
    assert len(result.errors) > 0


def test_migration_adapters_valid():
    from sdk.migration import ALL_ADAPTERS
    reg = PluginRegistry()
    for cls in ALL_ADAPTERS:
        reg.register(cls)
    assert len(reg.names()) == len(ALL_ADAPTERS)
