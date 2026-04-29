from pathlib import Path

from lazysre.cli.knowledge import KnowledgeBaseStore, format_knowledge_context


def test_knowledge_store_ingest_search_and_show(tmp_path: Path) -> None:
    db = tmp_path / "kb.db"
    source = tmp_path / "ops.md"
    source.write_text(
        "# payment timeout\n排查 payment 服务超时可先看 kube events，再查 nginx upstream 5xx。\n",
        encoding="utf-8",
    )
    store = KnowledgeBaseStore(db)
    result = store.ingest_path(source)
    assert result["documents"] == 1
    assert result["chunks"] >= 1

    docs = store.list_docs(limit=5)
    assert len(docs) == 1
    doc = docs[0]
    assert doc.title == "ops.md"
    assert doc.chunk_count >= 1

    hits = store.search("payment 服务超时", limit=3)
    assert hits
    assert hits[0].doc_id == doc.id
    assert "payment" in hits[0].excerpt.lower()

    chunks = store.get_doc_chunks(doc.id, limit=3)
    assert chunks
    assert "payment" in chunks[0].lower()

    context = format_knowledge_context(hits)
    assert "Internal knowledge references" in context


def test_knowledge_store_ingest_directory(tmp_path: Path) -> None:
    db = tmp_path / "kb.db"
    root = tmp_path / "docs"
    root.mkdir(parents=True, exist_ok=True)
    (root / "a.md").write_text("k8s pod crashloop", encoding="utf-8")
    (root / "b.txt").write_text("swarm replica insufficient", encoding="utf-8")
    (root / "c.bin").write_bytes(b"\x00\x01\x02")
    store = KnowledgeBaseStore(db)
    result = store.ingest_path(root)
    assert result["documents"] == 2


def test_knowledge_store_weighted_ranking_prefers_exact_phrase(tmp_path: Path) -> None:
    db = tmp_path / "kb.db"
    root = tmp_path / "docs"
    root.mkdir(parents=True, exist_ok=True)
    (root / "generic.md").write_text(
        "service unstable issue incident check logs and restart if needed",
        encoding="utf-8",
    )
    (root / "specific.md").write_text(
        "docker swarm replica insufficient root cause: image pull backoff on worker node",
        encoding="utf-8",
    )
    store = KnowledgeBaseStore(db)
    result = store.ingest_path(root)
    assert result["documents"] == 2

    hits = store.search("swarm replica insufficient", limit=2)
    assert hits
    assert "specific.md" in hits[0].source_path
