from __future__ import annotations


import json
import sys
from pathlib import Path
from typing import Any, Dict, List

SOURCES_DIR = Path(__file__).parent / "sources"
INDEX_DIR = Path(__file__).parent / "kb_index"
CHUNK_MIN_TOKENS = 80
CHUNK_MAX_TOKENS = 400


def chunk_document(text: str, source_meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    text = text.strip()
    if not text:
        return []

    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: List[Dict[str, Any]] = []
    current: List[str] = []
    current_len = 0

    for para in paragraphs:
        word_count = len(para.split())

        if current_len + word_count > CHUNK_MAX_TOKENS and current:
            chunk_text = "\n\n".join(current).strip()
            if len(chunk_text.split()) >= CHUNK_MIN_TOKENS:
                chunks.append(
                    {
                        "text": chunk_text,
                        **source_meta,
                    }
                )
            current = [para]
            current_len = word_count
        else:
            current.append(para)
            current_len += word_count

    if current:
        chunk_text = "\n\n".join(current).strip()
        if len(chunk_text.split()) >= CHUNK_MIN_TOKENS:
            chunks.append(
                {
                    "text": chunk_text,
                    **source_meta,
                }
            )

    if not chunks:
        chunks.append(
            {
                "text": text,
                **source_meta,
            }
        )

    return chunks


def load_sources() -> List[Dict[str, Any]]:
    chunks: List[Dict[str, Any]] = []

    if not SOURCES_DIR.exists():
        print(f"[KB] Sources directory not found: {SOURCES_DIR}")
        return chunks

    category_map = {
        "mitre": "mitre",
        "cis": "cis",
        "aws": "aws",
        "privesc": "privesc",
        "remediation": "remediation",
    }

    for category_dir in sorted(SOURCES_DIR.iterdir()):
        if not category_dir.is_dir():
            continue

        category = category_map.get(category_dir.name, "general")
        doc_paths = sorted(category_dir.glob("*.txt")) + sorted(category_dir.glob("*.md"))

        for doc_path in doc_paths:
            text = doc_path.read_text(encoding="utf-8", errors="replace")

            related_actions: List[str] = []
            lines = text.splitlines()
            if lines and lines[0].startswith("# actions:"):
                related_actions = [a.strip() for a in lines[0][len("# actions:"):].split(",") if a.strip()]
                text = "\n".join(lines[1:])

            relative_source = str(doc_path.relative_to(SOURCES_DIR))

            source_meta = {
                "source": relative_source,
                "category": category,
                "related_actions": related_actions,
                "authoritative": category in {"mitre", "cis", "aws"},
            }

            doc_chunks = chunk_document(text, source_meta)
            chunks.extend(doc_chunks)
            print(f"[KB] {relative_source}: {len(doc_chunks)} chunk(s)")

    return chunks


def build_index(chunks: List[Dict[str, Any]]) -> None:
    try:
        import faiss
        import numpy as np
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("[KB] Required packages missing. Install with:")
        print("     pip install faiss-cpu sentence-transformers --break-system-packages")
        sys.exit(1)

    if not chunks:
        print("[KB] No chunks provided; index build skipped.")
        return

    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    texts = [c["text"] for c in chunks]

    print(f"[KB] Embedding {len(texts)} chunks with all-MiniLM-L6-v2...")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)
    embeddings = np.array(embeddings, dtype="float32")

    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)

    faiss.write_index(index, str(INDEX_DIR / "kb.faiss"))

    metadata = [
        {k: v for k, v in chunk.items() if k != "text"} | {"text": chunk["text"], "chunk_id": i}
        for i, chunk in enumerate(chunks)
    ]

    with (INDEX_DIR / "kb_metadata.json").open("w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2)

    print(f"[KB] Index built: {len(chunks)} chunks, dim={dim}")
    print(f"[KB] Saved to: {INDEX_DIR}")


def main() -> None:
    print("[KB] Loading knowledge sources...")
    chunks = load_sources()
    if not chunks:
        print("[KB] No chunks found. Add source documents to phase3/knowledge/sources/")
        print("[KB] Directory structure expected:")
        print("     sources/mitre/        — MITRE ATT&CK cloud techniques")
        print("     sources/cis/          — CIS AWS Foundations IAM controls")
        print("     sources/aws/          — AWS IAM/STS reference")
        print("     sources/privesc/      — privilege escalation techniques")
        print("     sources/remediation/  — remediation guidance")
        return

    print(f"[KB] Total chunks: {len(chunks)}")
    build_index(chunks)


if __name__ == "__main__":
    main()