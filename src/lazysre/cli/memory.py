from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _default_db_path() -> Path:
    return Path.home() / ".lazysre" / "history_db"


@dataclass(slots=True)
class MemoryCase:
    id: int
    created_at: str
    symptom: str
    root_cause: str
    fix_commands: list[str]
    rollback_commands: list[str]
    metadata: dict[str, Any]
    score: float


class IncidentMemoryStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    symptom TEXT NOT NULL,
                    root_cause TEXT NOT NULL,
                    fix_commands_json TEXT NOT NULL,
                    rollback_commands_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def add_case(
        self,
        *,
        symptom: str,
        root_cause: str,
        fix_commands: list[str],
        rollback_commands: list[str],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO incident_memory
                (created_at, symptom, root_cause, fix_commands_json, rollback_commands_json, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    symptom.strip(),
                    root_cause.strip(),
                    json.dumps(fix_commands, ensure_ascii=False),
                    json.dumps(rollback_commands, ensure_ascii=False),
                    json.dumps(metadata or {}, ensure_ascii=False),
                ),
            )
            conn.commit()

    def search_similar(self, query: str, *, limit: int = 3) -> list[MemoryCase]:
        q = query.strip()
        if not q:
            return []
        tokens = _tokenize(q)
        if not tokens:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, symptom, root_cause, fix_commands_json, rollback_commands_json, metadata_json
                FROM incident_memory
                ORDER BY id DESC
                LIMIT 120
                """
            ).fetchall()
        ranked: list[MemoryCase] = []
        for row in rows:
            symptom = str(row["symptom"])
            root_cause = str(row["root_cause"])
            corpus = f"{symptom}\n{root_cause}"
            score = _jaccard(tokens, _tokenize(corpus))
            if score <= 0:
                continue
            ranked.append(
                MemoryCase(
                    id=int(row["id"]),
                    created_at=str(row["created_at"]),
                    symptom=symptom,
                    root_cause=root_cause,
                    fix_commands=_safe_list(row["fix_commands_json"]),
                    rollback_commands=_safe_list(row["rollback_commands_json"]),
                    metadata=_safe_dict(row["metadata_json"]),
                    score=score,
                )
            )
        ranked.sort(key=lambda x: x.score, reverse=True)
        return ranked[: max(1, min(limit, 8))]


def format_memory_context(cases: list[MemoryCase]) -> str:
    if not cases:
        return ""
    lines = ["Similar historical incidents:"]
    for idx, case in enumerate(cases, 1):
        lines.append(f"[case {idx}] score={case.score:.2f} symptom={case.symptom[:140]}")
        lines.append(f"[case {idx}] root_cause={case.root_cause[:160]}")
        if case.fix_commands:
            lines.append(f"[case {idx}] fix={' | '.join(case.fix_commands[:3])[:220]}")
        if case.rollback_commands:
            lines.append(f"[case {idx}] rollback={' | '.join(case.rollback_commands[:2])[:180]}")
    return "\n".join(lines)


def _safe_list(raw: Any) -> list[str]:
    if not isinstance(raw, str):
        return []
    try:
        obj = json.loads(raw)
    except Exception:
        return []
    if not isinstance(obj, list):
        return []
    return [str(x).strip() for x in obj if str(x).strip()]


def _safe_dict(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str):
        return {}
    try:
        obj = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    return obj


def _tokenize(text: str) -> set[str]:
    cleaned = "".join(ch.lower() if (ch.isalnum() or ch in {"_", "-"} or "\u4e00" <= ch <= "\u9fff") else " " for ch in text)
    return {part for part in cleaned.split() if len(part) >= 2}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    if union == 0:
        return 0.0
    return inter / union
