"""SecLists source — selective wordlist download."""
from __future__ import annotations

import httpx

from intel.sources.models import IntelDocument

BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
WORDLISTS = {
    "sqli_fuzzing": "Fuzzing/SQLi/Generic-SQLi.txt",
    "xss_fuzzing": "Fuzzing/XSS/XSS-BruteLogic.txt",
    "dns_subdomains": "Discovery/DNS/subdomains-top1million-5000.txt",
    "passwords_common": "Passwords/Common-Credentials/10-million-password-list-top-100.txt",
}


class SecListsSource:
    name = "seclists"

    async def fetch(self) -> list[IntelDocument]:
        docs = []
        async with httpx.AsyncClient(timeout=30) as client:
            for name, path in WORDLISTS.items():
                try:
                    resp = await client.get(BASE + path)
                    if resp.status_code != 200:
                        continue
                    content = resp.text[:5000]
                    docs.append(IntelDocument(
                        doc_id=f"seclists_{name}",
                        source=self.name,
                        title=f"SecLists: {name}",
                        content=content,
                        metadata={"wordlist": name, "path": path},
                        url=BASE + path,
                    ))
                except Exception:
                    continue
        return docs
