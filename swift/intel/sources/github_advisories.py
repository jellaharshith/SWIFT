"""GitHub Security Advisory source via GHSA GraphQL API."""
from __future__ import annotations

import os

import httpx

from intel.sources.models import IntelDocument

GH_GRAPHQL = "https://api.github.com/graphql"
QUERY = """
query($cursor: String) {
  securityAdvisories(first: 100, after: $cursor, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      references { url }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


class GitHubAdvisoriesSource:
    name = "github_advisories"

    async def fetch(self) -> list[IntelDocument]:
        token = os.getenv("GITHUB_TOKEN", "")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        docs = []
        cursor = None
        try:
            async with httpx.AsyncClient(timeout=30, headers=headers) as client:
                for _ in range(5):
                    variables = {"cursor": cursor} if cursor else {}
                    resp = await client.post(GH_GRAPHQL, json={"query": QUERY, "variables": variables})
                    resp.raise_for_status()
                    sa = resp.json().get("data", {}).get("securityAdvisories", {})
                    for node in sa.get("nodes", []):
                        ghsa_id = node.get("ghsaId", "")
                        summary = node.get("summary", "")
                        desc = node.get("description", "")[:1500]
                        severity = node.get("severity", "")
                        refs = node.get("references", [])
                        url = refs[0].get("url", "") if refs else ""
                        content = f"GHSA: {ghsa_id}\nSeverity: {severity}\nSummary: {summary}\n\n{desc}"
                        docs.append(IntelDocument(
                            doc_id=f"ghsa_{ghsa_id}",
                            source=self.name,
                            title=f"{ghsa_id}: {summary[:100]}",
                            content=content,
                            metadata={"ghsa_id": ghsa_id, "severity": severity},
                            url=url,
                        ))
                    page_info = sa.get("pageInfo", {})
                    if not page_info.get("hasNextPage"):
                        break
                    cursor = page_info.get("endCursor")
        except Exception:
            pass
        return docs
