from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class TimelineEvent:
    ts: datetime
    phase: str
    status: str
    duration_ms: int
    summary: str
    source: str
    marks: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.ts.isoformat(),
            "phase": self.phase,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "summary": self.summary,
            "source": self.source,
            "marks": list(self.marks),
        }


@dataclass(slots=True)
class TimelineDataset:
    label: str
    source_path: str
    events: list[TimelineEvent]
    root_cause_at: datetime | None
    first_fix_at: datetime | None
    mttd_sec: float | None
    mttr_sec: float | None

    def to_dict(self) -> dict[str, Any]:
        phase_counts: dict[str, int] = {}
        for event in self.events:
            phase_counts[event.phase] = phase_counts.get(event.phase, 0) + 1
        failed_events = sum(1 for event in self.events if event.status == "failed")
        total_duration_ms = sum(max(0, int(event.duration_ms)) for event in self.events)
        return {
            "label": self.label,
            "source_path": self.source_path,
            "event_count": len(self.events),
            "failed_event_count": failed_events,
            "total_duration_ms": total_duration_ms,
            "phase_counts": phase_counts,
            "root_cause_at": self.root_cause_at.isoformat() if self.root_cause_at else None,
            "first_fix_at": self.first_fix_at.isoformat() if self.first_fix_at else None,
            "mttd_sec": self.mttd_sec,
            "mttr_sec": self.mttr_sec,
            "events": [x.to_dict() for x in self.events],
        }


def collect_timeline_datasets(
    *,
    evidence_file: str = "",
    incident_id: str = "",
    compare: list[str] | None = None,
    default_data_dir: Path | None = None,
) -> list[TimelineDataset]:
    data_dir = (default_data_dir or Path(".data")).expanduser()
    candidates = _resolve_input_paths(
        evidence_file=evidence_file,
        incident_id=incident_id,
        compare=compare or [],
        data_dir=data_dir,
    )
    datasets: list[TimelineDataset] = []
    for path in candidates:
        payload = _read_json(path)
        if not isinstance(payload, dict):
            continue
        events = _extract_events(payload, source_path=path)
        if not events:
            continue
        events.sort(key=lambda x: x.ts)
        root_cause_at, first_fix_at = _detect_key_moments(events)
        mttd_sec, mttr_sec = _compute_metrics(events, root_cause_at=root_cause_at, first_fix_at=first_fix_at)
        label = path.stem
        datasets.append(
            TimelineDataset(
                label=label,
                source_path=str(path),
                events=events,
                root_cause_at=root_cause_at,
                first_fix_at=first_fix_at,
                mttd_sec=mttd_sec,
                mttr_sec=mttr_sec,
            )
        )
    return datasets


def render_timeline_json(datasets: list[TimelineDataset]) -> str:
    payload = {
        "count": len(datasets),
        "datasets": [x.to_dict() for x in datasets],
        "comparison": _build_comparison(datasets),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_timeline_mermaid(datasets: list[TimelineDataset]) -> str:
    lines = ["```mermaid", "gantt", "  title LazySRE Incident Timeline", "  dateFormat  YYYY-MM-DDTHH:mm:ss"]
    for ds in datasets:
        lines.append(f"  section { _escape_mermaid_text(ds.label) }")
        for idx, event in enumerate(ds.events[:80], start=1):
            start = event.ts.replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%S")
            sec = max(1, int(round(event.duration_ms / 1000.0)))
            status_tag = "crit" if event.status == "failed" else "done"
            marks = f" ({'/'.join(event.marks)})" if event.marks else ""
            name = _escape_mermaid_text(f"{idx}. {event.phase} {event.status}{marks}")
            lines.append(f"  {name} :{status_tag}, {start}, {sec}s")
        if ds.root_cause_at:
            root_at = ds.root_cause_at.replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%S")
            lines.append(f"  {_escape_mermaid_text('Root Cause Inferred')} :milestone, {root_at}, 1s")
        if ds.first_fix_at:
            fix_at = ds.first_fix_at.replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%S")
            lines.append(f"  {_escape_mermaid_text('First Fix Action')} :milestone, {fix_at}, 1s")
    lines.append("```")
    return "\n".join(lines)


def render_timeline_rich_text(datasets: list[TimelineDataset]) -> str:
    rows: list[str] = []
    rows.append("LazySRE Timeline")
    rows.append("")
    for ds in datasets:
        rows.append(f"[dataset] {ds.label}")
        rows.append(f"- source: {ds.source_path}")
        rows.append(f"- events: {len(ds.events)}")
        rows.append(f"- root_cause_at: {ds.root_cause_at.isoformat() if ds.root_cause_at else '-'}")
        rows.append(f"- first_fix_at: {ds.first_fix_at.isoformat() if ds.first_fix_at else '-'}")
        rows.append(f"- MTTD: {_fmt_sec(ds.mttd_sec)}")
        rows.append(f"- MTTR: {_fmt_sec(ds.mttr_sec)}")
        rows.append("")
        rows.append("  time                       phase        status   duration   note")
        for ev in ds.events[:120]:
            note = f"{ev.summary[:84]}"
            if ev.marks:
                note = f"{note} [{','.join(ev.marks)}]"
            rows.append(
                "  "
                f"{ev.ts.isoformat():26} "
                f"{ev.phase[:11]:11} "
                f"{ev.status[:7]:7} "
                f"{(str(ev.duration_ms) + 'ms')[:9]:9} "
                f"{note}"
            )
        rows.append("")
    comparison = _build_comparison(datasets)
    if comparison:
        rows.append("[comparison]")
        baseline = str(comparison.get("baseline", "")).strip()
        if baseline:
            rows.append(f"- baseline: {baseline}")
        rows.append(f"- candidates: {len(comparison.get('candidates', []))}")
        if "best_mttr_candidate" in comparison:
            rows.append(f"- best_mttr_candidate: {comparison.get('best_mttr_candidate')}")
        if "worst_mttr_candidate" in comparison:
            rows.append(f"- worst_mttr_candidate: {comparison.get('worst_mttr_candidate')}")
        for item in comparison.get("candidates", []):
            if not isinstance(item, dict):
                continue
            rows.append(
                "- "
                f"{item.get('candidate', '-')}: "
                f"delta_events={item.get('delta_events')} "
                f"delta_failed={item.get('delta_failed_events')} "
                f"delta_mttd={_fmt_sec(item.get('delta_mttd_sec'))} "
                f"delta_mttr={_fmt_sec(item.get('delta_mttr_sec'))}"
            )
    return "\n".join(rows).strip()


def _resolve_input_paths(*, evidence_file: str, incident_id: str, compare: list[str], data_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for raw in [evidence_file, *compare]:
        text = str(raw or "").strip()
        if not text:
            continue
        path = Path(text).expanduser()
        if path.exists():
            paths.append(path)
    if incident_id.strip():
        matched = _find_artifact_by_incident_id(incident_id.strip(), data_dir=data_dir)
        if matched:
            paths.append(matched)
    if not paths:
        default_skill = data_dir / "skill-evidence.json"
        if default_skill.exists():
            paths.append(default_skill)
        else:
            channel_runs = sorted((data_dir / "channel-runs").glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if channel_runs:
                paths.append(channel_runs[0])
    out: list[Path] = []
    seen: set[str] = set()
    for item in paths:
        key = str(item.resolve()) if item.exists() else str(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _find_artifact_by_incident_id(incident_id: str, *, data_dir: Path) -> Path | None:
    value = incident_id.strip().lower()
    direct = (data_dir / "channel-runs" / f"{incident_id}.json").expanduser()
    if direct.exists():
        return direct
    for path in sorted((data_dir / "channel-runs").glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        if value in path.stem.lower():
            return path
        payload = _read_json(path)
        if not isinstance(payload, dict):
            continue
        trace_id = str(payload.get("trace_id", "")).strip().lower()
        if trace_id and value in trace_id:
            return path
    return None


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _extract_events(payload: dict[str, Any], *, source_path: Path) -> list[TimelineEvent]:
    if isinstance(payload.get("outputs"), list):
        return _extract_skill_events(payload, source_path=source_path)
    if isinstance(payload.get("timeline"), list):
        return _extract_channel_events(payload, source_path=source_path)
    return []


def _extract_skill_events(payload: dict[str, Any], *, source_path: Path) -> list[TimelineEvent]:
    rows = payload.get("outputs", [])
    if not isinstance(rows, list):
        return []
    events: list[TimelineEvent] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        phase = _map_skill_phase(str(row.get("phase", "")).strip().lower())
        started = _parse_time(str(row.get("started_at", "")).strip())
        finished = _parse_time(str(row.get("finished_at", "")).strip())
        if not started:
            continue
        duration_ms = _duration_ms(started, finished)
        code = _safe_int(row.get("exit_code", 1))
        status = "ok" if code == 0 else "failed"
        summary = str(row.get("command", "")).strip()[:160]
        marks: list[str] = []
        if phase in {"apply", "rollback"} and not marks:
            marks.append("first_fix_candidate")
        events.append(
            TimelineEvent(
                ts=started,
                phase=phase,
                status=status,
                duration_ms=duration_ms,
                summary=summary,
                source=str(source_path),
                marks=marks,
            )
        )
    return events


def _extract_channel_events(payload: dict[str, Any], *, source_path: Path) -> list[TimelineEvent]:
    rows = payload.get("timeline", [])
    if not isinstance(rows, list):
        return []
    created = _parse_time(str(payload.get("created_at", "")).strip()) or datetime.now(UTC)
    events: list[TimelineEvent] = []
    offset = timedelta(milliseconds=0)
    for row in rows:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("kind", "")).strip().lower()
        phase = _map_channel_kind(kind)
        duration_ms = _safe_int(row.get("duration_ms", 0))
        message = str(row.get("message", "")).strip()[:160]
        preview = str(row.get("preview", "")).strip()[:120]
        summary = f"{message} {preview}".strip()
        status = "ok"
        if "fail" in summary.lower() or "error" in summary.lower():
            status = "failed"
        marks: list[str] = []
        text = summary.lower()
        if ("root cause" in text) or ("root-cause" in text) or ("根因" in summary):
            marks.append("root_cause_inference")
        ts = created + offset
        events.append(
            TimelineEvent(
                ts=ts,
                phase=phase,
                status=status,
                duration_ms=max(0, duration_ms),
                summary=summary,
                source=str(source_path),
                marks=marks,
            )
        )
        offset += timedelta(milliseconds=max(1, duration_ms))
    templates = payload.get("execution_templates", {})
    if isinstance(templates, dict):
        items = templates.get("items", [])
        if isinstance(items, list):
            for item in items[:3]:
                if not isinstance(item, dict):
                    continue
                task = item.get("task_sheet", {})
                if not isinstance(task, dict):
                    continue
                for phase_name, keys in (
                    ("apply", ("execute", "dry_run")),
                    ("verify", ("verify_commands",)),
                    ("rollback", ("rollback",)),
                ):
                    commands: list[str] = []
                    for key in keys:
                        val = task.get(key)
                        if isinstance(val, list):
                            commands.extend([str(x).strip() for x in val if str(x).strip()])
                    for command in commands[:2]:
                        ts = created + offset
                        status = "ok"
                        marks: list[str] = []
                        if phase_name == "apply":
                            marks.append("first_fix_candidate")
                        events.append(
                            TimelineEvent(
                                ts=ts,
                                phase=phase_name,
                                status=status,
                                duration_ms=1,
                                summary=command[:160],
                                source=str(source_path),
                                marks=marks,
                            )
                        )
                        offset += timedelta(milliseconds=1)
    return events


def _map_skill_phase(phase: str) -> str:
    if phase in {"precheck"}:
        return "precheck"
    if phase in {"read", "tool_call"}:
        return "tool_call"
    if phase in {"apply"}:
        return "apply"
    if phase in {"verify", "postcheck"}:
        return "verify"
    if phase in {"rollback"}:
        return "rollback"
    return "tool_call"


def _map_channel_kind(kind: str) -> str:
    if kind == "llm_turn":
        return "llm_response"
    if kind in {"tool_call", "tool_output", "auto_retry"}:
        return "tool_call"
    if kind == "final":
        return "llm_response"
    return "tool_call"


def _detect_key_moments(events: list[TimelineEvent]) -> tuple[datetime | None, datetime | None]:
    root: datetime | None = None
    first_fix: datetime | None = None
    for ev in events:
        lower = ev.summary.lower()
        if root is None and (
            ("root cause" in lower)
            or ("root-cause" in lower)
            or ("根因" in ev.summary)
            or (ev.phase == "llm_response" and ("diagnos" in lower or "分析" in ev.summary))
        ):
            root = ev.ts
            ev.marks.append("root_cause_inference")
        if first_fix is None and ev.phase in {"apply", "rollback"}:
            first_fix = ev.ts
            ev.marks.append("first_fix_action")
    return root, first_fix


def _compute_metrics(
    events: list[TimelineEvent],
    *,
    root_cause_at: datetime | None,
    first_fix_at: datetime | None,
) -> tuple[float | None, float | None]:
    if not events:
        return None, None
    start = events[0].ts
    mttd: float | None = None
    mttr: float | None = None
    if root_cause_at:
        mttd = max(0.0, (root_cause_at - start).total_seconds())
    if root_cause_at and first_fix_at:
        mttr = max(0.0, (first_fix_at - root_cause_at).total_seconds())
    return mttd, mttr


def _build_comparison(datasets: list[TimelineDataset]) -> dict[str, Any]:
    if len(datasets) < 2:
        return {}
    baseline = datasets[0]
    baseline_fail = sum(1 for x in baseline.events if x.status == "failed")
    candidates: list[dict[str, Any]] = []
    for candidate in datasets[1:]:
        candidate_fail = sum(1 for x in candidate.events if x.status == "failed")
        candidates.append(
            {
                "candidate": candidate.label,
                "delta_events": len(candidate.events) - len(baseline.events),
                "delta_failed_events": candidate_fail - baseline_fail,
                "delta_mttd_sec": _delta(candidate.mttd_sec, baseline.mttd_sec),
                "delta_mttr_sec": _delta(candidate.mttr_sec, baseline.mttr_sec),
            }
        )
    out: dict[str, Any] = {
        "baseline": baseline.label,
        "candidates": candidates,
    }
    if candidates:
        mttr_rankable = [x for x in candidates if isinstance(x.get("delta_mttr_sec"), (int, float))]
        if mttr_rankable:
            best = min(mttr_rankable, key=lambda x: float(x.get("delta_mttr_sec", 0.0)))
            worst = max(mttr_rankable, key=lambda x: float(x.get("delta_mttr_sec", 0.0)))
            out["best_mttr_candidate"] = best.get("candidate")
            out["worst_mttr_candidate"] = worst.get("candidate")
        first = candidates[0]
        out["candidate"] = first.get("candidate")
        out["delta_events"] = first.get("delta_events")
        out["delta_failed_events"] = first.get("delta_failed_events")
        out["delta_mttd_sec"] = first.get("delta_mttd_sec")
        out["delta_mttr_sec"] = first.get("delta_mttr_sec")
    return out


def _delta(current: float | None, baseline: float | None) -> float | None:
    if current is None or baseline is None:
        return None
    return round(current - baseline, 3)


def _parse_time(text: str) -> datetime | None:
    raw = str(text or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _duration_ms(started: datetime | None, finished: datetime | None) -> int:
    if not started or not finished:
        return 0
    return max(0, int(round((finished - started).total_seconds() * 1000)))


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _fmt_sec(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.3f}s"


def _escape_mermaid_text(text: str) -> str:
    value = str(text or "").strip()
    return value.replace(":", "-").replace("#", "").replace('"', "'")
