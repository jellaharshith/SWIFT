"""Intel sync scheduler — orchestrates all 10 intel sources."""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from intel.sources.mitre_attack import MitreAttackSource
from intel.sources.exploitdb import ExploitDBSource
from intel.sources.github_advisories import GitHubAdvisoriesSource
from intel.sources.nuclei_templates import NucleiTemplateSource
from intel.sources.payloads_all_things import PayloadsAllThingsSource
from intel.sources.seclists_sync import SecListsSource
from intel.sources.hackerone_reports import HackerOneReportsSource
from intel.sources.owasp_testing_guide import OWASPTestingGuideSource
from intel.sources.rss_blogs import SecurityBlogSource
from intel.sources.snyk_db import SnykVulnDBSource
from intel.store.embedder import IntelEmbedder
from intel.store.metadata_index import MetadataIndex

SOURCE_REGISTRY: dict[str, type] = {
    "mitre_attack": MitreAttackSource,
    "exploitdb": ExploitDBSource,
    "github_advisories": GitHubAdvisoriesSource,
    "nuclei_templates": NucleiTemplateSource,
    "payloads_all_things": PayloadsAllThingsSource,
    "seclists": SecListsSource,
    "hackerone_reports": HackerOneReportsSource,
    "owasp_testing_guide": OWASPTestingGuideSource,
    "rss_blogs": SecurityBlogSource,
    "snyk_db": SnykVulnDBSource,
}

SYNC_INTERVAL_HOURS = int(os.getenv("INTEL_SYNC_INTERVAL_HOURS", "24"))


@dataclass
class SyncReport:
    sources_synced: int = 0
    docs_added: int = 0
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class IntelSyncScheduler:
    def __init__(self) -> None:
        self._embedder = IntelEmbedder()
        self._index = MetadataIndex()

    async def sync_all(self, sources: list[str] | None = None, force: bool = False) -> SyncReport:
        report = SyncReport()
        targets = sources or list(SOURCE_REGISTRY.keys())
        tasks = []
        for name in targets:
            if name not in SOURCE_REGISTRY:
                report.errors.append(f"Unknown source: {name}")
                continue
            if not force:
                last = self._index.get_last_sync(name)
                if last and (datetime.now(timezone.utc) - last) < timedelta(hours=SYNC_INTERVAL_HOURS):
                    continue
            tasks.append(self._sync_one(name, report))
        await asyncio.gather(*tasks, return_exceptions=True)
        return report

    async def _sync_one(self, name: str, report: SyncReport) -> None:
        try:
            docs = await SOURCE_REGISTRY[name]().fetch()
            new_docs = [d for d in docs if not self._index.is_known(d.content_hash)]
            if new_docs:
                added = self._embedder.embed_batch(new_docs)
                for doc in new_docs:
                    self._index.upsert(doc)
                report.docs_added += added
            self._index.mark_synced(name)
            report.sources_synced += 1
        except Exception as exc:
            report.errors.append(f"{name}: {exc}")

    async def sync_source(self, name: str, force: bool = False) -> int:
        report = SyncReport()
        await self._sync_one(name, report)
        return report.docs_added
