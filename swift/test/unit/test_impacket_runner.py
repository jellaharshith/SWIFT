"""Unit tests for ImpacketRunner."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_roe():
    roe = MagicMock()
    roe.allowed_techniques = {"exploit", "ad_enum", "active_scan"}
    roe.simulate_only = False
    return roe


@pytest.mark.asyncio
async def test_kerberoasting_parses_spns(mock_roe):
    from kali.impacket_runner import ImpacketRunner
    runner = ImpacketRunner(mock_roe)
    fake_output = (
        "ServicePrincipalName   Name\n"
        "http/dc01.corp.local   svc-sql\n"
        "$krb5tgs$23$*svc-sql$CORP.LOCAL$http/dc01.corp.local*$abcdef1234\n"
    )
    with patch("kali.impacket_runner._kali_run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = fake_output
        result = await runner.run_kerberoasting("10.0.0.1", "corp.local")
    assert len(result["spns"]) >= 1
    assert "$krb5tgs$" in result["spns"][0]


@pytest.mark.asyncio
async def test_ldap_enum_parses_users(mock_roe):
    from kali.impacket_runner import ImpacketRunner
    runner = ImpacketRunner(mock_roe)
    fake_output = "Name: Administrator\nName: john.doe\nName: service-account\n"
    with patch("kali.impacket_runner._kali_run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = fake_output
        result = await runner.run_ldap_enum("10.0.0.1", "corp.local")
    assert "Administrator" in result["users"]
    assert len(result["users"]) == 3


@pytest.mark.asyncio
async def test_roe_blocks_exploit():
    from kali.impacket_runner import ImpacketRunner
    roe = MagicMock()
    roe.allowed_techniques = {"osint"}
    runner = ImpacketRunner(roe)
    with pytest.raises((SystemExit, Exception)):
        await runner.run_kerberoasting("10.0.0.1", "corp.local")
