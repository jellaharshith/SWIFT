"""ChromaDB embedder for intel documents — sentence-transformers + delta skip."""
from __future__ import annotations

import os
from pathlib import Path

from intel.sources.models import IntelDocument

CHROMA_PATH = Path(os.path.expanduser(os.getenv("INTEL_DB_PATH", "~/.swift/intel/chromadb")))
COLLECTION_NAME = "swift_intel"
CHUNK_SIZE = 512
CHUNK_OVERLAP = 64


class IntelEmbedder:
    def __init__(self) -> None:
        self._client = None
        self._collection = None
        self._model = None
        self._tokenizer = None

    def _init(self) -> bool:
        try:
            import chromadb  # type: ignore
            from sentence_transformers import SentenceTransformer  # type: ignore
            import tiktoken  # type: ignore
            CHROMA_PATH.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=str(CHROMA_PATH))
            self._collection = self._client.get_or_create_collection(
                COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            self._tokenizer = tiktoken.get_encoding("cl100k_base")
            return True
        except Exception:
            return False

    def _chunk(self, text: str) -> list[str]:
        if not self._tokenizer:
            return [text[:2000]]
        tokens = self._tokenizer.encode(text)
        chunks = []
        start = 0
        while start < len(tokens):
            end = min(start + CHUNK_SIZE, len(tokens))
            chunks.append(self._tokenizer.decode(tokens[start:end]))
            start += CHUNK_SIZE - CHUNK_OVERLAP
        return chunks or [text[:2000]]

    def embed_batch(self, docs: list[IntelDocument]) -> int:
        if not self._init():
            import logging
            logging.warning("IntelEmbedder: chromadb/sentence-transformers not available — skipping embed")
            return 0

        existing: set[str] = set()
        try:
            results = self._collection.get(include=["metadatas"])
            for m in results.get("metadatas", []):
                if isinstance(m, dict):
                    existing.add(m.get("content_hash", ""))
        except Exception:
            pass

        count = 0
        for doc in docs:
            if doc.content_hash in existing:
                continue
            try:
                chunks = self._chunk(doc.content)
                embeddings = self._model.encode(chunks).tolist()
                ids = [f"{doc.doc_id}_chunk_{i}" for i in range(len(chunks))]
                metas = [
                    {
                        "source": doc.source, "doc_id": doc.doc_id,
                        "content_hash": doc.content_hash,
                        "title": doc.title, "url": doc.url, "chunk": i,
                    }
                    for i in range(len(chunks))
                ]
                self._collection.upsert(ids=ids, documents=chunks, embeddings=embeddings, metadatas=metas)
                count += 1
                existing.add(doc.content_hash)
            except Exception:
                continue
        return count
