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


def test_knowledge_store_incremental_upsert_and_skip(tmp_path: Path) -> None:
    db = tmp_path / "kb.db"
    source = tmp_path / "ops.md"
    source.write_text("first line\ncheck payment latency\n", encoding="utf-8")
    store = KnowledgeBaseStore(db)

    first = store.ingest_path(source)
    assert first["documents"] == 1
    assert first["added"] == 1
    assert first["updated"] == 0
    assert first["skipped"] == 0
    docs1 = store.list_docs(limit=5)
    assert len(docs1) == 1
    doc_id = docs1[0].id

    second = store.ingest_path(source)
    assert second["documents"] == 0
    assert second["added"] == 0
    assert second["updated"] == 0
    assert second["skipped"] == 1
    docs2 = store.list_docs(limit=5)
    assert len(docs2) == 1
    assert docs2[0].id == doc_id

    source.write_text("first line\ncheck payment timeout\n", encoding="utf-8")
    third = store.ingest_path(source)
    assert third["documents"] == 1
    assert third["added"] == 0
    assert third["updated"] == 1
    assert third["skipped"] == 0
    docs3 = store.list_docs(limit=5)
    assert len(docs3) == 1
    assert docs3[0].id == doc_id
    new_hits = store.search("payment timeout", limit=3)
    assert new_hits


def test_knowledge_store_delete_and_prune_and_stats(tmp_path: Path) -> None:
    db = tmp_path / "kb.db"
    existing = tmp_path / "exists.md"
    missing = tmp_path / "missing.md"
    existing.write_text("k8s healthy", encoding="utf-8")
    missing.write_text("swarm unhealthy", encoding="utf-8")
    store = KnowledgeBaseStore(db)
    store.ingest_path(existing)
    store.ingest_path(missing)

    stats_before = store.stats()
    assert stats_before["docs"] == 2
    assert stats_before["chunks"] >= 2

    docs = store.list_docs(limit=10)
    existing_doc = next(item for item in docs if item.source_path.endswith("exists.md"))
    missing_doc = next(item for item in docs if item.source_path.endswith("missing.md"))
    removed = store.delete_doc(existing_doc.id)
    assert removed["deleted_docs"] == 1
    assert removed["deleted_chunks"] >= 1

    missing.unlink()
    pruned = store.prune_missing_sources()
    assert pruned["pruned_docs"] == 1
    assert pruned["pruned_chunks"] >= 1

    stats_after = store.stats()
    assert stats_after["docs"] == 0
    assert stats_after["chunks"] == 0


def test_knowledge_store_rebuild_dedup_and_drop_missing(tmp_path: Path) -> None:
    db = tmp_path / "kb.db"
    source = tmp_path / "dup.md"
    source.write_text("version one", encoding="utf-8")
    store = KnowledgeBaseStore(db)
    store.ingest_path(source)
    store.ingest_path(source, title="dup-v2")
    # Force a legacy duplicate row by manually inserting another record.
    with store._connect() as conn:  # noqa: SLF001 - test-only direct DB shaping
        conn.execute(
            """
            INSERT INTO kb_docs (created_at, updated_at, title, source_path, content_hash, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
                "legacy-dup",
                str(source),
                "",
                "{}",
            ),
        )
        conn.commit()
    docs_before = store.list_docs(limit=10)
    assert len(docs_before) >= 2

    source.write_text("version two", encoding="utf-8")
    rebuilt = store.rebuild(chunk_size=300, overlap=50, drop_missing=False)
    assert rebuilt["scanned"] >= 1
    assert rebuilt["deleted"] >= 1
    assert rebuilt["updated"] >= 1
    docs_after = store.list_docs(limit=10)
    assert len(docs_after) == 1

    source.unlink()
    rebuilt_drop = store.rebuild(drop_missing=True)
    assert rebuilt_drop["missing"] >= 1
    assert rebuilt_drop["deleted"] >= 1
    final_stats = store.stats()
    assert final_stats["docs"] == 0
