"""Unit tests for AWSMetadataSSRFProbe."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sdk.base import Severity, VulnType


@pytest.mark.asyncio
async def test_cloud_aws_detects_imds_in_response():
    from probes.cloud_aws import AWSMetadataSSRFProbe
    probe = AWSMetadataSSRFProbe()

    mock_resp = MagicMock()
    mock_resp.text = "ami-id: ami-0abcdef1234567890\ninstance-id: i-0abc"
    mock_resp.status_code = 200

    with patch("probes.cloud_aws.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)
        findings = await probe._ssrf_imds("https://example.com")

    assert len(findings) >= 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].confidence >= 0.95
    assert findings[0].vuln_type == VulnType.CLOUD_MISCONFIGURATION


@pytest.mark.asyncio
async def test_cloud_aws_no_finding_on_normal_html():
    from probes.cloud_aws import AWSMetadataSSRFProbe
    probe = AWSMetadataSSRFProbe()

    mock_resp = MagicMock()
    mock_resp.text = "<html><body>Hello World normal response</body></html>"
    mock_resp.status_code = 200

    with patch("probes.cloud_aws.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)
        findings = await probe._ssrf_imds("https://example.com")

    assert findings == []


@pytest.mark.asyncio
async def test_cloud_aws_network_error_returns_empty():
    from probes.cloud_aws import AWSMetadataSSRFProbe
    probe = AWSMetadataSSRFProbe()

    with patch("probes.cloud_aws.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("connection refused"))
        findings = await probe._ssrf_imds("https://example.com")

    assert findings == []
