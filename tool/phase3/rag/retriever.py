from __future__ import annotations


import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

INDEX_DIR = Path(__file__).parent.parent / "knowledge" / "kb_index"
INDEX_PATH = INDEX_DIR / "kb.faiss"
METADATA_PATH = INDEX_DIR / "kb_metadata.json"


@dataclass
class RetrievedChunk:
    chunk_id: int
    text: str
    source: str
    category: str
    related_actions: List[str] = field(default_factory=list)
    authoritative: bool = False
    score: float = 0.0

    def to_context_string(self) -> str:
        prefix = f"[{self.category.upper()} — {self.source}]"
        return f"{prefix}\n{self.text}"


class KnowledgeRetriever:
    def __init__(self, top_k: int = 5):
        self.top_k = top_k
        self._index = None
        self._metadata: List[dict] = []
        self._model = None
        self._ready = False
        self._load()

    def _load(self) -> None:
        if not INDEX_PATH.exists() or not METADATA_PATH.exists():
            logger.info(
                "Knowledge base index not found. "
                "Run `python -m phase3.knowledge.build_kb` to build it. RAG disabled."
            )
            return

        try:
            import faiss
            from sentence_transformers import SentenceTransformer

            self._index = faiss.read_index(str(INDEX_PATH))
            with METADATA_PATH.open("r", encoding="utf-8") as fh:
                self._metadata = json.load(fh)

            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            self._ready = True
            logger.info("Knowledge base loaded: %d chunks", len(self._metadata))

        except ImportError:
            logger.warning(
                "faiss-cpu or sentence-transformers not installed. RAG disabled."
            )
        except Exception:
            logger.exception("Failed to load knowledge base")

    def retrieve(self, query: str, top_k: Optional[int] = None) -> List[RetrievedChunk]:
        if not self._ready or not query.strip():
            return []

        import numpy as np

        k = top_k or self.top_k
        query_vec = self._model.encode([query], normalize_embeddings=True)
        query_vec = np.array(query_vec, dtype="float32")

        scores, indices = self._index.search(query_vec, k)

        results: List[RetrievedChunk] = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self._metadata):
                continue

            meta = self._metadata[idx]
            results.append(
                RetrievedChunk(
                    chunk_id=int(idx),
                    text=meta.get("text", ""),
                    source=meta.get("source", ""),
                    category=meta.get("category", "general"),
                    related_actions=meta.get("related_actions", []),
                    authoritative=meta.get("authoritative", False),
                    score=float(score),
                )
            )

        results.sort(key=lambda c: c.score, reverse=True)
        return results[:k]

    def retrieve_for_actions(
        self,
        actions: List[str],
        top_k: Optional[int] = None,
    ) -> List[RetrievedChunk]:
        if not self._ready:
            return []

        action_lower = {a.lower() for a in actions}
        matched: List[RetrievedChunk] = []

        for idx, meta in enumerate(self._metadata):
            related = {a.lower() for a in meta.get("related_actions", [])}
            if related & action_lower:
                matched.append(
                    RetrievedChunk(
                        chunk_id=int(meta.get("chunk_id", idx)),
                        text=meta.get("text", ""),
                        source=meta.get("source", ""),
                        category=meta.get("category", "general"),
                        related_actions=meta.get("related_actions", []),
                        authoritative=meta.get("authoritative", False),
                        score=1.0,
                    )
                )

        return matched[: (top_k or self.top_k)]

    @property
    def is_ready(self) -> bool:
        return self._ready