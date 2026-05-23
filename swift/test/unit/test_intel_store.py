"""Unit tests for intel store (embedder + metadata index)."""
from __future__ import annotations

import pytest
from intel.sources.models import IntelDocument


@pytest.fixture
def sample_doc():
    return IntelDocument(doc_id="test_001", source="test", title="Test Doc", content="SQL injection payload")


def test_metadata_index_upsert_and_known(tmp_path):
    from intel.store.metadata_index import MetadataIndex
    idx = MetadataIndex(db_path=tmp_path / "meta.db")
    doc = IntelDocument(doc_id="x", source="test", title="T", content="content")
    assert not idx.is_known(doc.content_hash)
    idx.upsert(doc)
    assert idx.is_known(doc.content_hash)


def test_metadata_index_sync_log(tmp_path):
    from intel.store.metadata_index import MetadataIndex
    idx = MetadataIndex(db_path=tmp_path / "meta.db")
    assert idx.get_last_sync("mitre_attack") is None
    idx.mark_synced("mitre_attack")
    ts = idx.get_last_sync("mitre_attack")
    assert ts is not None


def test_metadata_index_upsert_idempotent(tmp_path):
    from intel.store.metadata_index import MetadataIndex
    idx = MetadataIndex(db_path=tmp_path / "meta.db")
    doc = IntelDocument(doc_id="dup", source="test", title="T", content="dup content")
    idx.upsert(doc)
    idx.upsert(doc)  # should not raise
    assert idx.is_known(doc.content_hash)


def test_embedder_graceful_when_deps_missing(sample_doc):
    from unittest.mock import patch
    from intel.store.embedder import IntelEmbedder
    with patch.object(IntelEmbedder, "_init", return_value=False):
        embedder = IntelEmbedder()
        result = embedder.embed_batch([sample_doc])
    assert result == 0
