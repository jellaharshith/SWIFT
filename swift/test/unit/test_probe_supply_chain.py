"""Unit tests for SupplyChainProbe."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sdk.base import Severity, VulnType


@pytest.mark.asyncio
async def test_pypi_404_creates_dependency_confusion_finding():
    from probes.supply_chain import SupplyChainProbe
    probe = SupplyChainProbe()

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    finding = await probe._check_pypi(mock_client, "myorg-internal-pkg", "https://example.com")
    assert finding is not None
    assert finding.vuln_type == VulnType.DEPENDENCY_CONFUSION
    assert finding.severity == Severity.HIGH
    assert finding.confidence >= 0.95


@pytest.mark.asyncio
async def test_pypi_200_returns_none():
    from probes.supply_chain import SupplyChainProbe
    probe = SupplyChainProbe()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    finding = await probe._check_pypi(mock_client, "requests", "https://example.com")
    assert finding is None


@pytest.mark.asyncio
async def test_npm_404_creates_finding():
    from probes.supply_chain import SupplyChainProbe
    probe = SupplyChainProbe()

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    finding = await probe._check_npm(mock_client, "internal-package", "https://example.com")
    assert finding is not None
    assert finding.vuln_type == VulnType.DEPENDENCY_CONFUSION
