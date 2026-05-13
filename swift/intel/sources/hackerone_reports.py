"""HackerOne public disclosed reports source via GraphQL API."""
from __future__ import annotations

import os

import httpx

from intel.sources.models import IntelDocument

GQL_URL = "https://hackerone.com/graphql"
QUERY = """
query {
  hacktivity_items(
    first: 100
    order_by: { field: popular, direction: DESC }
    where: { disclosed_at: { _is_null: false } }
  ) {
    edges {
      node {
        id
        report { title }
        reporter { username }
        team { name handle }
        severity_rating
        disclosed_at
      }
    }
  }
}
"""


class HackerOneReportsSource:
    name = "hackerone_reports"

    async def fetch(self) -> list[IntelDocument]:
        identifier = os.getenv("H1_API_KEY_IDENTIFIER", "")
        token = os.getenv("H1_API_KEY", "")
        if not (identifier and token):
            return []
        docs = []
        try:
            async with httpx.AsyncClient(timeout=30, auth=(identifier, token)) as client:
                resp = await client.post(GQL_URL, json={"query": QUERY})
                resp.raise_for_status()
                edges = resp.json().get("data", {}).get("hacktivity_items", {}).get("edges", [])
                for edge in edges:
                    node = edge.get("node", {})
                    report_id = node.get("id", "")
                    title_obj = node.get("report") or {}
                    title = title_obj.get("title", "") if isinstance(title_obj, dict) else ""
                    severity = node.get("severity_rating", "")
                    team = (node.get("team") or {}).get("handle", "")
                    reporter = (node.get("reporter") or {}).get("username", "")
                    content = f"H1 Report #{report_id}\nProgram: {team}\nSeverity: {severity}\nReporter: {reporter}\nTitle: {title}"
                    docs.append(IntelDocument(
                        doc_id=f"h1_{report_id}",
                        source=self.name,
                        title=title[:200] or f"Report {report_id}",
                        content=content,
                        metadata={"report_id": report_id, "severity": severity, "program": team},
                        url=f"https://hackerone.com/reports/{report_id}",
                    ))
        except Exception:
            pass
        return docs
