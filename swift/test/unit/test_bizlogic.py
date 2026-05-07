"""Tests for Business Logic probe."""
import datetime
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from probes.bizlogic import (
    BusinessLogicProbe, AppFlowMapper, FlowAnalyzer,
    AppFlow, FlowStep, Field, BusinessLogicAttack, ANALYZER_PROMPT,
)
from sdk.base import VulnType, Severity
from sdk.testing import DEFAULT_TEST_ROE
from security.roe import ROE, ROEViolation


def test_analyzer_prompt_contains_required_terms():
    """Verify CISSP prompt is embedded verbatim (key phrases)."""
    assert "CISSP-certified" in ANALYZER_PROMPT
    assert "negative quantities" in ANALYZER_PROMPT
    assert "price manipulation" in ANALYZER_PROMPT
    assert "workflow step skipping" in ANALYZER_PROMPT
    assert "Respond as a JSON array only" in ANALYZER_PROMPT


def test_field_defaults():
    f = Field(name="qty", type="number")
    assert f.is_numeric is False
    assert f.value == ""


def test_flowstep_defaults():
    s = FlowStep(url="http://x.com", method="POST")
    assert s.step_number is None
    assert s.fields == []


def test_appflow_defaults():
    flow = AppFlow()
    assert flow.steps == []
    assert flow.numeric_fields == []


async def test_bizlogic_probe_simulate_only():
    roe = ROE(
        engagement_id="t", authorized_targets=["*"],
        allowed_techniques={"bizlogic"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2035, 1, 1),
        contact="t", simulate_only=True,
    )
    results = await BusinessLogicProbe().probe("http://target.com", None, roe)
    assert len(results) == 1
    assert results[0].severity == Severity.INFO


async def test_bizlogic_probe_roe_denied():
    roe = ROE(
        engagement_id="t", authorized_targets=["*"],
        allowed_techniques={"osint"},
        window_start=datetime.datetime(2025, 1, 1),
        window_end=datetime.datetime(2035, 1, 1),
        contact="t",
    )
    with pytest.raises(ROEViolation):
        await BusinessLogicProbe().probe("http://target.com", None, roe)


async def test_flow_analyzer_no_client():
    """FlowAnalyzer returns empty list when no API key."""
    with patch("probes.bizlogic._get_client", return_value=None):
        analyzer = FlowAnalyzer()
        result = await analyzer.analyze(AppFlow())
    assert result == []


async def test_flow_analyzer_parses_sonnet_response():
    """FlowAnalyzer correctly parses Sonnet JSON response."""
    mock_attack = {
        "attack_type": "negative_quantity",
        "target_step": 1,
        "target_field": "qty",
        "normal_value": "1",
        "attack_value": "-1",
        "hypothesis": "negative qty accepted",
        "severity_estimate": "CRITICAL",
    }
    mock_msg = MagicMock()
    mock_msg.content = [MagicMock(text=json.dumps([mock_attack]))]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_msg

    with patch("probes.bizlogic._get_client", return_value=mock_client):
        analyzer = FlowAnalyzer()
        result = await analyzer.analyze(AppFlow(steps=[FlowStep(url="u", method="GET")]))

    assert len(result) == 1
    assert result[0].attack_type == "negative_quantity"
    assert result[0].attack_value == "-1"


async def test_negative_quantity_finding():
    """_negative_quantity returns CRITICAL finding when order succeeds."""
    flow = AppFlow(
        steps=[FlowStep(url="http://shop.com/cart", method="POST",
                        fields=[Field(name="qty", type="number", is_numeric=True)])],
        numeric_fields=[Field(name="qty", type="number", is_numeric=True)],
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "Thank you for your order!"
    probe = BusinessLogicProbe()

    with patch("probes.bizlogic.httpx.AsyncClient") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=False)
        mock_cm.post = AsyncMock(return_value=mock_resp)
        MockClient.return_value = mock_cm
        findings = await probe._negative_quantity(flow, "http://shop.com")

    assert len(findings) >= 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].vuln_type == VulnType.BIZLOGIC


async def test_workflow_step_skip_finding():
    """_workflow_step_skip finds issue when final step accessible directly."""
    flow = AppFlow(steps=[
        FlowStep(url="http://shop.com/step1", method="GET"),
        FlowStep(url="http://shop.com/step2", method="GET"),
        FlowStep(url="http://shop.com/confirm", method="GET"),
    ])
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "Welcome to checkout"
    probe = BusinessLogicProbe()

    with patch("probes.bizlogic.httpx.AsyncClient") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=False)
        mock_cm.get = AsyncMock(return_value=mock_resp)
        MockClient.return_value = mock_cm
        findings = await probe._workflow_step_skip(flow, "http://shop.com", None)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


async def test_sonnet_call_budget_cap():
    """FlowAnalyzer stops calling Sonnet after max_sonnet_calls."""
    mock_client = MagicMock()
    mock_msg = MagicMock()
    mock_msg.content = [MagicMock(text="[]")]
    mock_client.messages.create.return_value = mock_msg

    with patch("probes.bizlogic._get_client", return_value=mock_client):
        analyzer = FlowAnalyzer()
        analyzer._max_sonnet_calls = 2
        for _ in range(5):
            await analyzer.analyze(AppFlow())

    assert mock_client.messages.create.call_count == 2
