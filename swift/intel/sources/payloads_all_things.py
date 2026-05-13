"""PayloadsAllTheThings source — extract fenced code blocks from markdown."""
from __future__ import annotations

import re

import httpx

from intel.sources.models import IntelDocument

BASE_URL = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/"
CATEGORIES = {
    "SQL Injection": "SQL%20Injection/README.md",
    "XSS": "XSS%20Injection/README.md",
    "SSRF": "Server%20Side%20Request%20Forgery/README.md",
    "SSTI": "Server%20Side%20Template%20Injection/README.md",
    "XXE": "XXE%20Injection/README.md",
    "IDOR": "Insecure%20Direct%20Object%20References/README.md",
}


class PayloadsAllThingsSource:
    name = "payloads_all_things"

    async def fetch(self) -> list[IntelDocument]:
        docs = []
        async with httpx.AsyncClient(timeout=30) as client:
            for category, path in CATEGORIES.items():
                try:
                    resp = await client.get(BASE_URL + path)
                    if resp.status_code != 200:
                        continue
                    blocks = re.findall(r"```[^\n]*\n(.*?)```", resp.text, re.DOTALL)
                    payloads = [b.strip() for b in blocks if b.strip()]
                    content = f"Category: {category}\nPayloads:\n" + "\n---\n".join(payloads[:50])
                    docs.append(IntelDocument(
                        doc_id=f"pat_{category.lower().replace(' ', '_')}",
                        source=self.name,
                        title=f"PayloadsAllTheThings: {category}",
                        content=content[:3000],
                        metadata={"category": category, "payload_count": len(payloads)},
                        url=BASE_URL + path,
                    ))
                except Exception:
                    continue
        return docs
