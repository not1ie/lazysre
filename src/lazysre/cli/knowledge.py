from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _default_db_path() -> Path:
    return Path.home() / ".lazysre" / "knowledge_db"


@dataclass(slots=True)
class KnowledgeDoc:
    id: int
    created_at: str
    title: str
    source_path: str
    chunk_count: int
    metadata: dict[str, Any]


@dataclass(slots=True)
class KnowledgeHit:
    doc_id: int
    title: str
    source_path: str
    chunk_id: int
    score: float
    excerpt: str
    metadata: dict[str, Any]


class KnowledgeBaseStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS kb_docs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    title TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS kb_chunks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    doc_id INTEGER NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    token_json TEXT NOT NULL,
                    FOREIGN KEY(doc_id) REFERENCES kb_docs(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_kb_chunks_doc_id ON kb_chunks(doc_id)")
            self._ensure_column(conn, "kb_docs", "updated_at", "TEXT", default_sql="''")
            self._ensure_column(conn, "kb_docs", "content_hash", "TEXT", default_sql="''")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_kb_docs_source_path ON kb_docs(source_path)")
            conn.commit()

    def _ensure_column(
        self,
        conn: sqlite3.Connection,
        table: str,
        column: str,
        column_type: str,
        *,
        default_sql: str,
    ) -> None:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        names = {str(row[1]) for row in rows}
        if column in names:
            return
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type} NOT NULL DEFAULT {default_sql}")

    def ingest_path(
        self,
        source: Path,
        *,
        title: str = "",
        chunk_size: int = 900,
        overlap: int = 120,
    ) -> dict[str, int]:
        path = source.expanduser()
        docs = list(_iter_kb_files(path))
        if path.is_file():
            docs = [path]
        if not docs:
            return {"documents": 0, "chunks": 0, "added": 0, "updated": 0, "skipped": 0}
        total_docs = 0
        total_chunks = 0
        added = 0
        updated = 0
        skipped = 0
        for file_path in docs:
            text = _read_text_file(file_path)
            if not text.strip():
                continue
            doc_title = title.strip() or file_path.name
            doc_chunks = _split_text_chunks(text, chunk_size=chunk_size, overlap=overlap)
            if not doc_chunks:
                continue
            content_hash = _sha256_text(text)
            metadata = {
                "source_path": str(file_path),
                "bytes": file_path.stat().st_size if file_path.exists() else 0,
                "content_hash": content_hash,
            }
            upserted = self._upsert_doc_with_chunks(
                title=doc_title,
                source_path=str(file_path),
                content_hash=content_hash,
                metadata=metadata,
                chunks=doc_chunks,
            )
            if upserted == "skipped":
                skipped += 1
                continue
            total_docs += 1
            total_chunks += len(doc_chunks)
            if upserted == "added":
                added += 1
            elif upserted == "updated":
                updated += 1
        return {
            "documents": total_docs,
            "chunks": total_chunks,
            "added": added,
            "updated": updated,
            "skipped": skipped,
        }

    def list_docs(self, *, limit: int = 20) -> list[KnowledgeDoc]:
        cap = max(1, min(limit, 200))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT d.id, d.created_at, d.title, d.source_path, d.metadata_json, COUNT(c.id) AS chunk_count
                FROM kb_docs d
                LEFT JOIN kb_chunks c ON d.id = c.doc_id
                GROUP BY d.id
                ORDER BY d.id DESC
                LIMIT ?
                """,
                (cap,),
            ).fetchall()
        out: list[KnowledgeDoc] = []
        for row in rows:
            out.append(
                KnowledgeDoc(
                    id=int(row["id"]),
                    created_at=str(row["created_at"]),
                    title=str(row["title"]),
                    source_path=str(row["source_path"]),
                    chunk_count=int(row["chunk_count"] or 0),
                    metadata=_safe_dict(row["metadata_json"]),
                )
            )
        return out

    def get_doc(self, doc_id: int) -> KnowledgeDoc | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT d.id, d.created_at, d.title, d.source_path, d.metadata_json, COUNT(c.id) AS chunk_count
                FROM kb_docs d
                LEFT JOIN kb_chunks c ON d.id = c.doc_id
                WHERE d.id = ?
                GROUP BY d.id
                """,
                (int(doc_id),),
            ).fetchone()
        if not row:
            return None
        return KnowledgeDoc(
            id=int(row["id"]),
            created_at=str(row["created_at"]),
            title=str(row["title"]),
            source_path=str(row["source_path"]),
            chunk_count=int(row["chunk_count"] or 0),
            metadata=_safe_dict(row["metadata_json"]),
        )

    def get_doc_chunks(self, doc_id: int, *, limit: int = 8) -> list[str]:
        cap = max(1, min(limit, 100))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT content
                FROM kb_chunks
                WHERE doc_id = ?
                ORDER BY chunk_index ASC
                LIMIT ?
                """,
                (int(doc_id), cap),
            ).fetchall()
        return [str(row["content"]) for row in rows if str(row["content"]).strip()]

    def stats(self) -> dict[str, int]:
        with self._connect() as conn:
            docs_row = conn.execute("SELECT COUNT(*) FROM kb_docs").fetchone()
            chunks_row = conn.execute("SELECT COUNT(*) FROM kb_chunks").fetchone()
        return {
            "docs": int(docs_row[0]) if docs_row else 0,
            "chunks": int(chunks_row[0]) if chunks_row else 0,
        }

    def delete_doc(self, doc_id: int) -> dict[str, int]:
        target = int(doc_id)
        if target <= 0:
            return {"deleted_docs": 0, "deleted_chunks": 0}
        with self._connect() as conn:
            chunk_row = conn.execute("SELECT COUNT(*) FROM kb_chunks WHERE doc_id = ?", (target,)).fetchone()
            deleted_chunks = int(chunk_row[0]) if chunk_row else 0
            conn.execute("DELETE FROM kb_chunks WHERE doc_id = ?", (target,))
            cur = conn.execute("DELETE FROM kb_docs WHERE id = ?", (target,))
            conn.commit()
            deleted_docs = int(cur.rowcount or 0)
        return {"deleted_docs": deleted_docs, "deleted_chunks": deleted_chunks if deleted_docs else 0}

    def prune_missing_sources(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, source_path
                FROM kb_docs
                ORDER BY id ASC
                """
            ).fetchall()
            remove_ids: list[int] = []
            for row in rows:
                doc_id = int(row["id"])
                source = Path(str(row["source_path"] or "")).expanduser()
                if not source.exists():
                    remove_ids.append(doc_id)
            if not remove_ids:
                return {"pruned_docs": 0, "pruned_chunks": 0}
            chunk_row = conn.execute(
                f"SELECT COUNT(*) FROM kb_chunks WHERE doc_id IN ({','.join('?' for _ in remove_ids)})",
                tuple(remove_ids),
            ).fetchone()
            pruned_chunks = int(chunk_row[0]) if chunk_row else 0
            conn.execute(f"DELETE FROM kb_chunks WHERE doc_id IN ({','.join('?' for _ in remove_ids)})", tuple(remove_ids))
            conn.execute(f"DELETE FROM kb_docs WHERE id IN ({','.join('?' for _ in remove_ids)})", tuple(remove_ids))
            conn.commit()
        return {"pruned_docs": len(remove_ids), "pruned_chunks": pruned_chunks}

    def rebuild(
        self,
        *,
        chunk_size: int = 900,
        overlap: int = 120,
        drop_missing: bool = False,
    ) -> dict[str, int]:
        size = max(200, min(int(chunk_size), 3000))
        ov = max(0, min(int(overlap), 1200))
        scanned = 0
        added = 0
        updated = 0
        skipped = 0
        missing = 0
        deleted = 0
        total_chunks = 0
        dedup_deleted = self._deduplicate_source_docs()
        if dedup_deleted > 0:
            deleted += dedup_deleted
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, title, source_path
                FROM kb_docs
                ORDER BY id ASC
                """
            ).fetchall()
        for row in rows:
            scanned += 1
            doc_id = int(row["id"])
            title = str(row["title"] or "").strip()
            source_path = str(row["source_path"] or "").strip()
            path = Path(source_path).expanduser()
            if not source_path or (not path.exists()):
                missing += 1
                if drop_missing:
                    removed = self.delete_doc(doc_id)
                    deleted += int(removed.get("deleted_docs", 0))
                continue
            text = _read_text_file(path)
            if not text.strip():
                skipped += 1
                continue
            chunks = _split_text_chunks(text, chunk_size=size, overlap=ov)
            if not chunks:
                skipped += 1
                continue
            content_hash = _sha256_text(text)
            metadata = {
                "source_path": str(path),
                "bytes": path.stat().st_size if path.exists() else 0,
                "content_hash": content_hash,
            }
            state = self._upsert_doc_with_chunks(
                title=title or path.name,
                source_path=str(path),
                content_hash=content_hash,
                metadata=metadata,
                chunks=chunks,
            )
            if state == "added":
                added += 1
                total_chunks += len(chunks)
            elif state == "updated":
                updated += 1
                total_chunks += len(chunks)
            else:
                skipped += 1
        return {
            "scanned": scanned,
            "added": added,
            "updated": updated,
            "skipped": skipped,
            "missing": missing,
            "deleted": deleted,
            "chunks": total_chunks,
        }

    def search(
        self,
        query: str,
        *,
        limit: int = 5,
        source_contains: str = "",
        min_score: float = 0.0,
    ) -> list[KnowledgeHit]:
        q = str(query or "").strip()
        if not q:
            return []
        q_tokens = _tokenize(q)
        if not q_tokens:
            return []
        source_filter = str(source_contains or "").strip().lower()
        threshold = max(0.0, min(float(min_score), 1.0))
        q_norm = " ".join(_tokenize_in_order(q))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT c.id AS chunk_id, c.doc_id, c.content, c.token_json, d.title, d.source_path, d.metadata_json
                FROM kb_chunks c
                JOIN kb_docs d ON d.id = c.doc_id
                ORDER BY c.id DESC
                LIMIT 1000
                """
            ).fetchall()
        candidates: list[tuple[sqlite3.Row, set[str], int]] = []
        for row in rows:
            tokens = _safe_token_set(row["token_json"])
            if not tokens:
                continue
            candidates.append((row, tokens, len(tokens)))
        if not candidates:
            return []
        idf = _build_idf(candidates, q_tokens)
        ranked: list[KnowledgeHit] = []
        for row, tokens, token_len in candidates:
            source_path = str(row["source_path"])
            if source_filter and source_filter not in source_path.lower():
                continue
            score = _hybrid_score(
                query_tokens=q_tokens,
                chunk_tokens=tokens,
                idf=idf,
                chunk_len=token_len,
                query_norm=q_norm,
                content=str(row["content"]),
            )
            if score <= 0 or score < threshold:
                continue
            excerpt = str(row["content"]).strip().replace("\n", " ")
            ranked.append(
                KnowledgeHit(
                    doc_id=int(row["doc_id"]),
                    title=str(row["title"]),
                    source_path=source_path,
                    chunk_id=int(row["chunk_id"]),
                    score=score,
                    excerpt=excerpt[:220],
                    metadata=_safe_dict(row["metadata_json"]),
                )
            )
        ranked.sort(key=lambda x: x.score, reverse=True)
        return ranked[: max(1, min(limit, 20))]

    def _insert_doc(
        self,
        *,
        title: str,
        source_path: str,
        content_hash: str,
        metadata: dict[str, Any],
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            row = conn.execute(
                """
                INSERT INTO kb_docs (created_at, updated_at, title, source_path, content_hash, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                RETURNING id
                """,
                (
                    now,
                    now,
                    title.strip(),
                    source_path.strip(),
                    content_hash.strip(),
                    json.dumps(metadata, ensure_ascii=False),
                ),
            ).fetchone()
            conn.commit()
        return int(row["id"]) if row else 0

    def _upsert_doc_with_chunks(
        self,
        *,
        title: str,
        source_path: str,
        content_hash: str,
        metadata: dict[str, Any],
        chunks: list[str],
    ) -> str:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, content_hash
                FROM kb_docs
                WHERE source_path = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (source_path.strip(),),
            ).fetchone()
        if not row:
            doc_id = self._insert_doc(
                title=title,
                source_path=source_path,
                content_hash=content_hash,
                metadata=metadata,
            )
            self._insert_chunks(doc_id=doc_id, chunks=chunks)
            return "added"
        doc_id = int(row["id"])
        existing_hash = str(row["content_hash"] or "").strip()
        if existing_hash and existing_hash == content_hash:
            return "skipped"
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE kb_docs
                SET updated_at = ?, title = ?, content_hash = ?, metadata_json = ?
                WHERE id = ?
                """,
                (
                    now,
                    title.strip(),
                    content_hash.strip(),
                    json.dumps(metadata, ensure_ascii=False),
                    doc_id,
                ),
            )
            conn.execute("DELETE FROM kb_chunks WHERE doc_id = ?", (doc_id,))
            for idx, chunk in enumerate(chunks):
                tokens = sorted(_tokenize(chunk))
                conn.execute(
                    """
                    INSERT INTO kb_chunks (doc_id, chunk_index, content, token_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        int(doc_id),
                        int(idx),
                        chunk,
                        json.dumps(tokens, ensure_ascii=False),
                    ),
                )
            conn.commit()
        return "updated"

    def _insert_chunks(self, *, doc_id: int, chunks: list[str]) -> None:
        with self._connect() as conn:
            for idx, chunk in enumerate(chunks):
                tokens = sorted(_tokenize(chunk))
                conn.execute(
                    """
                    INSERT INTO kb_chunks (doc_id, chunk_index, content, token_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        int(doc_id),
                        int(idx),
                        chunk,
                        json.dumps(tokens, ensure_ascii=False),
                    ),
                )
            conn.commit()

    def _deduplicate_source_docs(self) -> int:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT source_path, GROUP_CONCAT(id) AS ids, COUNT(*) AS total
                FROM kb_docs
                WHERE source_path <> ''
                GROUP BY source_path
                HAVING COUNT(*) > 1
                """
            ).fetchall()
            remove_ids: list[int] = []
            for row in rows:
                raw_ids = str(row["ids"] or "").strip()
                if not raw_ids:
                    continue
                ids = [int(part) for part in raw_ids.split(",") if part.strip().isdigit()]
                if len(ids) <= 1:
                    continue
                keep_id = max(ids)
                remove_ids.extend([item for item in ids if item != keep_id])
            if not remove_ids:
                return 0
            conn.execute(
                f"DELETE FROM kb_chunks WHERE doc_id IN ({','.join('?' for _ in remove_ids)})",
                tuple(remove_ids),
            )
            conn.execute(
                f"DELETE FROM kb_docs WHERE id IN ({','.join('?' for _ in remove_ids)})",
                tuple(remove_ids),
            )
            conn.commit()
        return len(remove_ids)


def format_knowledge_context(hits: list[KnowledgeHit]) -> str:
    if not hits:
        return ""
    lines = ["Internal knowledge references:"]
    for idx, hit in enumerate(hits, 1):
        lines.append(
            f"[kb {idx}] score={hit.score:.2f} doc={hit.title[:80]} source={hit.source_path[:120]}"
        )
        lines.append(f"[kb {idx}] excerpt={hit.excerpt[:220]}")
    return "\n".join(lines)


def _iter_kb_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    if path.is_file():
        return [path]
    allow = {".md", ".txt", ".log", ".json", ".yaml", ".yml", ".ini", ".conf"}
    out: list[Path] = []
    for item in sorted(path.rglob("*")):
        if not item.is_file():
            continue
        if item.suffix.lower() not in allow:
            continue
        out.append(item)
    return out[:2000]


def _read_text_file(path: Path) -> str:
    for encoding in ("utf-8", "utf-8-sig", "gbk", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except Exception:
            continue
    return ""


def _split_text_chunks(text: str, *, chunk_size: int, overlap: int) -> list[str]:
    value = str(text or "").strip()
    if not value:
        return []
    size = max(200, min(chunk_size, 3000))
    ov = max(0, min(overlap, size // 2))
    parts: list[str] = []
    start = 0
    while start < len(value):
        end = min(len(value), start + size)
        chunk = value[start:end].strip()
        if chunk:
            parts.append(chunk)
        if end >= len(value):
            break
        start = max(start + 1, end - ov)
    return parts


def _safe_dict(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str):
        return {}
    try:
        payload = json.loads(raw)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _safe_token_set(raw: Any) -> set[str]:
    if not isinstance(raw, str):
        return set()
    try:
        payload = json.loads(raw)
    except Exception:
        return set()
    if not isinstance(payload, list):
        return set()
    return {str(x).strip() for x in payload if str(x).strip()}


def _tokenize(text: str) -> set[str]:
    normalized = "".join(
        ch.lower() if (ch.isalnum() or ch in {"_", "-"} or "\u4e00" <= ch <= "\u9fff") else " " for ch in text
    )
    return {part for part in normalized.split() if len(part) >= 2}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    if union <= 0:
        return 0.0
    return inter / union


def _tokenize_in_order(text: str) -> list[str]:
    normalized = "".join(
        ch.lower() if (ch.isalnum() or ch in {"_", "-"} or "\u4e00" <= ch <= "\u9fff") else " " for ch in text
    )
    return [part for part in normalized.split() if len(part) >= 2]


def _build_idf(candidates: list[tuple[sqlite3.Row, set[str], int]], query_tokens: set[str]) -> dict[str, float]:
    total = max(1, len(candidates))
    df: dict[str, int] = {token: 0 for token in query_tokens}
    for _, tokens, _ in candidates:
        for token in query_tokens:
            if token in tokens:
                df[token] = df.get(token, 0) + 1
    out: dict[str, float] = {}
    for token in query_tokens:
        count = max(0, int(df.get(token, 0)))
        out[token] = math.log(1.0 + ((total - count + 0.5) / (count + 0.5)))
    return out


def _hybrid_score(
    *,
    query_tokens: set[str],
    chunk_tokens: set[str],
    idf: dict[str, float],
    chunk_len: int,
    query_norm: str,
    content: str,
) -> float:
    if not query_tokens or not chunk_tokens:
        return 0.0
    inter = query_tokens & chunk_tokens
    if not inter:
        return 0.0
    base = _jaccard(query_tokens, chunk_tokens) * 0.35
    weighted_hit = sum(idf.get(token, 1.0) for token in inter)
    weighted_total = sum(idf.get(token, 1.0) for token in query_tokens)
    idf_score = (weighted_hit / weighted_total) if weighted_total > 0 else 0.0
    coverage = len(inter) / max(1, len(query_tokens))
    length_penalty = 1.0 / (1.0 + max(0, chunk_len - 80) / 400.0)
    phrase_bonus = 0.0
    text_norm = " ".join(_tokenize_in_order(content))
    if query_norm and query_norm in text_norm:
        phrase_bonus = 0.12
    elif any(len(token) >= 6 and token in text_norm for token in query_tokens):
        phrase_bonus = 0.05
    score = base + (idf_score * 0.45) + (coverage * 0.15) + (length_penalty * 0.05) + phrase_bonus
    return max(0.0, min(score, 1.0))


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
