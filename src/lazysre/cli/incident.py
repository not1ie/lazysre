from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _build_incident_id(ts: str) -> str:
    compact = ts.replace("-", "").replace(":", "").replace("+00:00", "Z").replace("T", "-")
    return f"INC-{compact}"


@dataclass
class IncidentRecord:
    id: str
    title: str
    severity: str
    status: str
    assignee: str
    summary: str
    source: str
    tags: list[str]
    opened_at_utc: str
    updated_at_utc: str
    closed_at_utc: str
    resolution: str
    timeline: list[dict[str, str]]

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "IncidentRecord":
        timeline = payload.get("timeline", [])
        if not isinstance(timeline, list):
            timeline = []
        return cls(
            id=str(payload.get("id", "")).strip(),
            title=str(payload.get("title", "")).strip(),
            severity=str(payload.get("severity", "medium")).strip() or "medium",
            status=str(payload.get("status", "open")).strip() or "open",
            assignee=str(payload.get("assignee", "-")).strip() or "-",
            summary=str(payload.get("summary", "")).strip(),
            source=str(payload.get("source", "manual")).strip() or "manual",
            tags=[str(x).strip() for x in payload.get("tags", []) if str(x).strip()] if isinstance(payload.get("tags", []), list) else [],
            opened_at_utc=str(payload.get("opened_at_utc", "")).strip(),
            updated_at_utc=str(payload.get("updated_at_utc", "")).strip(),
            closed_at_utc=str(payload.get("closed_at_utc", "")).strip(),
            resolution=str(payload.get("resolution", "")).strip(),
            timeline=[
                {
                    "at_utc": str(item.get("at_utc", "")).strip(),
                    "kind": str(item.get("kind", "")).strip(),
                    "message": str(item.get("message", "")).strip(),
                }
                for item in timeline
                if isinstance(item, dict)
            ],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "assignee": self.assignee,
            "summary": self.summary,
            "source": self.source,
            "tags": list(self.tags),
            "opened_at_utc": self.opened_at_utc,
            "updated_at_utc": self.updated_at_utc,
            "closed_at_utc": self.closed_at_utc,
            "resolution": self.resolution,
            "timeline": list(self.timeline),
        }

    def add_event(self, kind: str, message: str) -> None:
        ts = _now_utc_iso()
        self.timeline.append(
            {
                "at_utc": ts,
                "kind": kind.strip() or "note",
                "message": message.strip(),
            }
        )
        self.updated_at_utc = ts


class IncidentStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load_raw(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"active": None, "archive": []}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {"active": None, "archive": []}
        if not isinstance(payload, dict):
            return {"active": None, "archive": []}
        archive = payload.get("archive", [])
        if not isinstance(archive, list):
            archive = []
        return {"active": payload.get("active"), "archive": archive}

    def _save_raw(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def active(self) -> IncidentRecord | None:
        raw = self._load_raw().get("active")
        if not isinstance(raw, dict):
            return None
        record = IncidentRecord.from_dict(raw)
        return record if record.id else None

    def list_recent(self, *, limit: int = 10) -> list[IncidentRecord]:
        payload = self._load_raw()
        rows: list[IncidentRecord] = []
        active = payload.get("active")
        if isinstance(active, dict):
            rec = IncidentRecord.from_dict(active)
            if rec.id:
                rows.append(rec)
        archive = payload.get("archive", [])
        if isinstance(archive, list):
            for item in archive:
                if not isinstance(item, dict):
                    continue
                rec = IncidentRecord.from_dict(item)
                if rec.id:
                    rows.append(rec)
        rows.sort(key=lambda item: item.updated_at_utc, reverse=True)
        return rows[: max(1, limit)]

    def open_incident(
        self,
        *,
        title: str,
        severity: str = "medium",
        assignee: str = "-",
        summary: str = "",
        source: str = "manual",
        tags: list[str] | None = None,
    ) -> IncidentRecord:
        payload = self._load_raw()
        existing = payload.get("active")
        if isinstance(existing, dict):
            active = IncidentRecord.from_dict(existing)
            if active.id and active.status != "closed":
                raise RuntimeError(f"active incident exists: {active.id} ({active.title})")
        ts = _now_utc_iso()
        rec = IncidentRecord(
            id=_build_incident_id(ts),
            title=title.strip() or "Untitled Incident",
            severity=(severity.strip() or "medium").lower(),
            status="open",
            assignee=assignee.strip() or "-",
            summary=summary.strip(),
            source=source.strip() or "manual",
            tags=[str(x).strip() for x in (tags or []) if str(x).strip()],
            opened_at_utc=ts,
            updated_at_utc=ts,
            closed_at_utc="",
            resolution="",
            timeline=[],
        )
        rec.add_event("opened", f"opened by {rec.source}; severity={rec.severity}; assignee={rec.assignee}")
        if rec.summary:
            rec.add_event("summary", rec.summary)
        payload["active"] = rec.to_dict()
        self._save_raw(payload)
        return rec

    def add_note(self, note: str, *, author: str = "user") -> IncidentRecord:
        rec, payload = self._require_active()
        rec.add_event("note", f"{author}: {note.strip()}")
        payload["active"] = rec.to_dict()
        self._save_raw(payload)
        return rec

    def set_assignee(self, assignee: str) -> IncidentRecord:
        rec, payload = self._require_active()
        rec.assignee = assignee.strip() or "-"
        rec.add_event("assign", f"assignee={rec.assignee}")
        payload["active"] = rec.to_dict()
        self._save_raw(payload)
        return rec

    def set_severity(self, severity: str) -> IncidentRecord:
        rec, payload = self._require_active()
        rec.severity = severity.strip().lower() or "medium"
        rec.add_event("severity", f"severity={rec.severity}")
        payload["active"] = rec.to_dict()
        self._save_raw(payload)
        return rec

    def set_status(self, status: str) -> IncidentRecord:
        rec, payload = self._require_active()
        rec.status = status.strip().lower() or "open"
        rec.add_event("status", f"status={rec.status}")
        payload["active"] = rec.to_dict()
        self._save_raw(payload)
        return rec

    def close_incident(self, *, resolution: str = "") -> IncidentRecord:
        rec, payload = self._require_active()
        rec.status = "closed"
        rec.closed_at_utc = _now_utc_iso()
        rec.updated_at_utc = rec.closed_at_utc
        rec.resolution = resolution.strip()
        rec.add_event("closed", rec.resolution or "closed without explicit resolution")
        archive = payload.get("archive", [])
        if not isinstance(archive, list):
            archive = []
        archive.insert(0, rec.to_dict())
        payload["archive"] = archive[:200]
        payload["active"] = None
        self._save_raw(payload)
        return rec

    def _require_active(self) -> tuple[IncidentRecord, dict[str, Any]]:
        payload = self._load_raw()
        active = payload.get("active")
        if not isinstance(active, dict):
            raise RuntimeError("no active incident")
        rec = IncidentRecord.from_dict(active)
        if not rec.id:
            raise RuntimeError("no active incident")
        return rec, payload


def render_incident_markdown(record: IncidentRecord) -> str:
    lines = [
        "# LazySRE Incident",
        "",
        f"- ID: `{record.id}`",
        f"- Title: {record.title}",
        f"- Status: `{record.status}`",
        f"- Severity: `{record.severity}`",
        f"- Assignee: `{record.assignee}`",
        f"- Opened: `{record.opened_at_utc}`",
        f"- Updated: `{record.updated_at_utc}`",
        f"- Closed: `{record.closed_at_utc or '-'}`",
        f"- Source: `{record.source}`",
        f"- Tags: {', '.join(record.tags) if record.tags else '-'}",
    ]
    if record.summary:
        lines.extend(["", "## Summary", record.summary])
    if record.resolution:
        lines.extend(["", "## Resolution", record.resolution])
    lines.extend(["", "## Timeline"])
    if not record.timeline:
        lines.append("- (empty)")
    else:
        for item in record.timeline:
            lines.append(
                f"- `{item.get('at_utc', '-')}` `{item.get('kind', '-')}` {item.get('message', '')}"
            )
    lines.append("")
    return "\n".join(lines)

