"""Security blog RSS feed source — PortSwigger, NCC, Project Zero, Assetnote, Snyk."""
from __future__ import annotations

import asyncio
import hashlib

from intel.sources.models import IntelDocument

FEEDS = [
    ("portswigger", "https://portswigger.net/daily-swig/rss"),
    ("nccgroup", "https://research.nccgroup.com/feed/"),
    ("project_zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("assetnote", "https://blog.assetnote.io/feed.xml"),
    ("snyk", "https://security.snyk.io/rss.xml"),
]


class SecurityBlogSource:
    name = "rss_blogs"

    async def fetch(self) -> list[IntelDocument]:
        try:
            import feedparser  # type: ignore
        except ImportError:
            return []
        docs = []
        loop = asyncio.get_event_loop()
        for feed_name, url in FEEDS:
            try:
                feed = await loop.run_in_executor(None, feedparser.parse, url)
                for entry in feed.entries[:20]:
                    title = entry.get("title", "")
                    summary = entry.get("summary", "")[:1500]
                    link = entry.get("link", "")
                    doc_id = f"blog_{feed_name}_{hashlib.sha256(link.encode()).hexdigest()[:8]}"
                    content = f"Source: {feed_name}\nTitle: {title}\nURL: {link}\n\n{summary}"
                    docs.append(IntelDocument(
                        doc_id=doc_id,
                        source=self.name,
                        title=title[:200],
                        content=content,
                        metadata={"feed": feed_name},
                        url=link,
                    ))
            except Exception:
                continue
        return docs
