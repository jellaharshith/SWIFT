"""ChromaDB retriever for RAG injection into SWIFT probe prompts."""
from __future__ import annotations

import os
import re
from pathlib import Path

CHROMA_PATH = Path(os.path.expanduser(os.getenv("INTEL_DB_PATH", "~/.swift/intel/chromadb")))
COLLECTION_NAME = "swift_intel"


class IntelRetriever:
    def __init__(self) -> None:
        self._collection = None

    def _init(self) -> bool:
        try:
            import chromadb  # type: ignore
            client = chromadb.PersistentClient(path=str(CHROMA_PATH))
            self._collection = client.get_or_create_collection(COLLECTION_NAME)
            return True
        except Exception:
            return False

    def query(self, text: str, n: int = 10) -> list[dict]:
        if not self._init() or not self._collection:
            return []
        try:
            results = self._collection.query(query_texts=[text], n_results=min(n, 10))
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            return [{"content": d, "metadata": m} for d, m in zip(docs, metas)]
        except Exception:
            return []

    def query_for_target(
        self,
        tech_stack: list[str],
        vuln_types: list[str],
        target_url: str,
        budget_tokens: int = 2000,
    ) -> str:
        query_text = f"vulnerabilities {' '.join(vuln_types)} {' '.join(tech_stack)} {target_url}"
        results = self.query(query_text, n=20)
        if not results:
            return ""

        try:
            import tiktoken  # type: ignore
            enc = tiktoken.get_encoding("cl100k_base")
            lines = []
            used = 0
            for r in results:
                content = r["content"]
                tokens = len(enc.encode(content))
                if used + tokens > budget_tokens:
                    break
                lines.append(content)
                used += tokens
            return "\n\n---\n\n".join(lines)
        except Exception:
            combined = "\n\n".join(r["content"] for r in results)
            return combined[:budget_tokens * 4]

    def get_payloads(self, vuln_type: str, n: int = 20) -> list[str]:
        results = self.query(f"{vuln_type} payload exploit", n=n * 2)
        payloads: list[str] = []
        for r in results:
            source = (r.get("metadata") or {}).get("source", "")
            if source in ("payloads_all_things", "seclists"):
                blocks = re.findall(r"```[^\n]*\n(.*?)```", r["content"], re.DOTALL)
                payloads.extend(b.strip() for b in blocks if b.strip())
            if len(payloads) >= n:
                break
        return payloads[:n]
