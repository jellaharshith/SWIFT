"""Tests for sdk.base — Finding, BaseModule, Phase, VulnType, Severity."""
import pytest
from sdk.base import BaseModule, Finding, Phase, VulnType, Severity


def test_finding_default_id_is_uuid():
    f = Finding(module="x", vuln_type=VulnType.SSRF, severity=Severity.HIGH,
                title="t", description="d", target_url="u", confidence=0.95)
    assert len(f.id) == 36 and f.id.count("-") == 4


def test_finding_ids_unique():
    f1 = Finding(module="x", vuln_type=VulnType.XSS, severity=Severity.MEDIUM,
                 title="t", description="d", target_url="u", confidence=0.9)
    f2 = Finding(module="x", vuln_type=VulnType.XSS, severity=Severity.MEDIUM,
                 title="t", description="d", target_url="u", confidence=0.9)
    assert f1.id != f2.id


def test_finding_oob_confirmed_default_false():
    f = Finding(module="x", vuln_type=VulnType.OOB_SSRF, severity=Severity.CRITICAL,
                title="t", description="d", target_url="u", confidence=1.0)
    assert f.oob_confirmed is False


def test_finding_chain_primitive():
    f = Finding(module="x", vuln_type=VulnType.OOB_SSRF, severity=Severity.CRITICAL,
                title="t", description="d", target_url="u", confidence=1.0,
                oob_confirmed=True, chain_primitive="ssrf")
    assert f.chain_primitive == "ssrf"


def test_basemodule_requires_name():
    class M(BaseModule):
        async def probe(self, target, session, roe): return []
    with pytest.raises(NotImplementedError, match="name"):
        M.validate_subclass()


def test_basemodule_requires_author():
    class M(BaseModule):
        name = "m"; phase = Phase.ACTIVE; vuln_types = [VulnType.XSS]; version = "1.0"
        async def probe(self, target, session, roe): return []
    with pytest.raises(NotImplementedError, match="author"):
        M.validate_subclass()


def test_basemodule_valid_passes():
    class M(BaseModule):
        name = "m"; phase = Phase.ACTIVE; vuln_types = [VulnType.SQLI]
        author = "tester"; version = "1.0"
        async def probe(self, target, session, roe): return []
    M.validate_subclass()


def test_basemodule_is_abstract():
    with pytest.raises(TypeError):
        BaseModule()  # type: ignore


def test_phase_values():
    assert Phase.OSINT == "osint"
    assert Phase.ACTIVE == "active"
    assert Phase.POST_EXPLOIT == "post_exploit"


def test_all_severity_values():
    assert set(Severity) == {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                              Severity.LOW, Severity.INFO}
