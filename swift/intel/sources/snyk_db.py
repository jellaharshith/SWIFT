"""Snyk vulnerability database source."""
from __future__ import annotations

import httpx

from intel.sources.models import IntelDocument

API_URL = "https://security.snyk.io/api/v1/vulns"


class SnykVulnDBSource:
    name = "snyk_db"

    async def fetch(self) -> list[IntelDocument]:
        docs = []
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                for pkg_type in ["npm", "pip", "maven"]:
                    try:
                        resp = await client.get(API_URL, params={"type": pkg_type, "page": "1"})
                        if resp.status_code != 200:
                            continue
                        data = resp.json()
                        vulns = (
                            data if isinstance(data, list)
                            else data.get("vulnerabilities", data.get("data", []))
                        )
                        for vuln in vulns[:50]:
                            if not isinstance(vuln, dict):
                                continue
                            vuln_id = vuln.get("id", vuln.get("CVE", "unknown"))
                            title = vuln.get("title", vuln.get("name", ""))
                            severity = vuln.get("severity", "")
                            desc = str(vuln.get("description", vuln.get("overview", "")))[:1000]
                            content = f"Snyk ID: {vuln_id}\nType: {pkg_type}\nSeverity: {severity}\nTitle: {title}\n\n{desc}"
                            docs.append(IntelDocument(
                                doc_id=f"snyk_{vuln_id}",
                                source=self.name,
                                title=f"{title} ({severity})",
                                content=content,
                                metadata={"vuln_id": vuln_id, "severity": severity, "type": pkg_type},
                                url=f"https://security.snyk.io/vuln/{vuln_id}",
                            ))
                    except Exception:
                        continue
        except Exception:
            pass
        return docs
