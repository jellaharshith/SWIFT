"""Unit tests for IntelSyncScheduler."""
from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from intel.sources.models import IntelDocument


@pytest.mark.asyncio
async def test_sync_all_skips_recent_source():
    from intel.sync.scheduler import IntelSyncScheduler
    with patch("intel.sync.scheduler.MetadataIndex") as mock_idx_cls, \
         patch("intel.sync.scheduler.IntelEmbedder"):
        mock_idx = MagicMock()
        mock_idx.get_last_sync.return_value = datetime.now(timezone.utc)
        mock_idx_cls.return_value = mock_idx
        scheduler = IntelSyncScheduler()
        report = await scheduler.sync_all(sources=["mitre_attack"], force=False)
    assert report.sources_synced == 0


@pytest.mark.asyncio
async def test_sync_all_force_bypasses_skip():
    from intel.sync.scheduler import IntelSyncScheduler
    fake_doc = IntelDocument(doc_id="x", source="test", title="T", content="c")
    with patch("intel.sync.scheduler.MetadataIndex") as mock_idx_cls, \
         patch("intel.sync.scheduler.IntelEmbedder") as mock_emb_cls, \
         patch("intel.sync.scheduler.MitreAttackSource") as mock_src:
        mock_idx = MagicMock()
        mock_idx.is_known.return_value = False
        mock_idx.get_last_sync.return_value = datetime.now(timezone.utc)
        mock_idx_cls.return_value = mock_idx
        mock_emb = MagicMock()
        mock_emb.embed_batch.return_value = 1
        mock_emb_cls.return_value = mock_emb
        inst = AsyncMock()
        inst.fetch = AsyncMock(return_value=[fake_doc])
        mock_src.return_value = inst
        scheduler = IntelSyncScheduler()
        report = await scheduler.sync_all(sources=["mitre_attack"], force=True)
    assert report.sources_synced >= 1


@pytest.mark.asyncio
async def test_sync_unknown_source_adds_error():
    from intel.sync.scheduler import IntelSyncScheduler
    with patch("intel.sync.scheduler.MetadataIndex"), \
         patch("intel.sync.scheduler.IntelEmbedder"):
        scheduler = IntelSyncScheduler()
        report = await scheduler.sync_all(sources=["nonexistent_source"])
    assert any("nonexistent_source" in e for e in report.errors)
