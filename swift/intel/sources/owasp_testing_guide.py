"""OWASP Web Security Testing Guide source."""
from __future__ import annotations

import httpx

from intel.sources.models import IntelDocument

BASE = "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/"
CHAPTERS = [
    "01-Information_Gathering",
    "02-Configuration_and_Deployment_Management_Testing",
    "05-Authorization_Testing",
    "06-Session_Management_Testing",
    "07-Input_Validation_Testing",
]


class OWASPTestingGuideSource:
    name = "owasp_testing_guide"

    async def fetch(self) -> list[IntelDocument]:
        docs = []
        async with httpx.AsyncClient(timeout=30) as client:
            for chapter in CHAPTERS:
                url = f"{BASE}{chapter}/README.md"
                try:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue
                    content = resp.text[:3000]
                    docs.append(IntelDocument(
                        doc_id=f"owasp_{chapter}",
                        source=self.name,
                        title=f"WSTG: {chapter.replace('-', ' ')}",
                        content=content,
                        metadata={"chapter": chapter},
                        url=url,
                    ))
                except Exception:
                    continue
        return docs
