"""Unit tests for intel source modules."""
from __future__ import annotations

import hashlib
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def test_intel_document_hash():
    from intel.sources.models import IntelDocument
    doc = IntelDocument(doc_id="test", source="mitre_attack", title="Test", content="hello")
    assert doc.content_hash == hashlib.sha256(b"hello").hexdigest()


def test_intel_document_same_content_same_hash():
    from intel.sources.models import IntelDocument
    doc1 = IntelDocument(doc_id="a", source="x", title="t", content="same")
    doc2 = IntelDocument(doc_id="b", source="x", title="t", content="same")
    assert doc1.content_hash == doc2.content_hash


@pytest.mark.asyncio
async def test_mitre_attack_source_fetch():
    from intel.sources.mitre_attack import MitreAttackSource
    fake_bundle = {
        "objects": [{
            "type": "attack-pattern",
            "name": "Phishing",
            "description": "Adversaries send phishing emails.",
            "kill_chain_phases": [{"phase_name": "initial-access"}],
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": "T1566",
                "url": "https://attack.mitre.org/techniques/T1566",
            }],
        }]
    }
    with patch("intel.sources.mitre_attack.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_resp = MagicMock()
        mock_resp.json.return_value = fake_bundle
        mock_resp.raise_for_status = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        docs = await MitreAttackSource().fetch()
    assert len(docs) == 1
    assert docs[0].doc_id == "mitre_T1566"
    assert "T1566" in docs[0].title


@pytest.mark.asyncio
async def test_exploitdb_source_fetch():
    from intel.sources.exploitdb import ExploitDBSource
    fake_csv = "id,description,date_published,platform,type\n1337,Remote Code Execution,2024-01-01,linux,webapps\n"
    with patch("intel.sources.exploitdb.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_resp = MagicMock()
        mock_resp.text = fake_csv
        mock_resp.raise_for_status = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        docs = await ExploitDBSource().fetch()
    assert len(docs) == 1
    assert docs[0].doc_id == "edb_1337"


@pytest.mark.asyncio
async def test_source_error_returns_empty():
    from intel.sources.mitre_attack import MitreAttackSource
    with patch("intel.sources.mitre_attack.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("network error"))
        docs = await MitreAttackSource().fetch()
    assert docs == []
