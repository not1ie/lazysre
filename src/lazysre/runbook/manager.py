from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import unified_diff
from pathlib import Path
from typing import Any

from lazysre.cli.incident import IncidentRecord, IncidentStore
from lazysre.cli.policy import assess_command

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


def default_generated_runbook_dir() -> Path:
    return (Path.home() / ".lazysre" / "runbooks").expanduser()


@dataclass(slots=True)
class GeneratedRunbookVersion:
    name: str
    version: str
    path: Path
    created_at: str
    source_incident_id: str
    payload: dict[str, Any]


class GeneratedRunbookStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or default_generated_runbook_dir()).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)

    def list_names(self) -> list[str]:
        if not self.root.exists():
            return []
        output: list[str] = []
        for item in sorted(self.root.iterdir()):
            if item.is_dir():
                output.append(item.name)
        return output

    def list_versions(self, name: str) -> list[str]:
        directory = self._name_dir(name)
        if not directory.exists():
            return []
        items: list[tuple[int, str]] = []
        for path in directory.glob("v*.yaml"):
            version = path.stem
            seq = _version_number(version)
            if seq > 0:
                items.append((seq, version))
        items.sort(key=lambda x: x[0])
        return [x[1] for x in items]

    def latest_version(self, name: str) -> str | None:
        versions = self.list_versions(name)
        return versions[-1] if versions else None

    def load(self, name: str, version: str | None = None) -> GeneratedRunbookVersion | None:
        target = normalize_runbook_name(name)
        if not target:
            return None
        selected = version or self.latest_version(target)
        if not selected:
            return None
        path = self._name_dir(target) / f"{selected}.yaml"
        if not path.exists():
            return None
        payload = _read_yaml(path)
        if not isinstance(payload, dict):
            return None
        created_at = str(payload.get("created_at", "")).strip()
        incident_id = str(payload.get("source_incident_id", "")).strip()
        return GeneratedRunbookVersion(
            name=target,
            version=selected,
            path=path,
            created_at=created_at,
            source_incident_id=incident_id,
            payload=payload,
        )

    def save_new_version(self, name: str, payload: dict[str, Any]) -> GeneratedRunbookVersion:
        target = normalize_runbook_name(name)
        if not target:
            raise ValueError("runbook name is required")
        version = self._next_version(target)
        directory = self._name_dir(target)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{version}.yaml"
        row = dict(payload)
        row["name"] = target
        row["version"] = version
        if not str(row.get("created_at", "")).strip():
            row["created_at"] = _now_iso()
        _write_yaml(path, row)
        return GeneratedRunbookVersion(
            name=target,
            version=version,
            path=path,
            created_at=str(row.get("created_at", "")),
            source_incident_id=str(row.get("source_incident_id", "")),
            payload=row,
        )

    def _next_version(self, name: str) -> str:
        versions = self.list_versions(name)
        if not versions:
            return "v1"
        latest = max(_version_number(x) for x in versions)
        return f"v{latest + 1}"

    def _name_dir(self, name: str) -> Path:
        return self.root / normalize_runbook_name(name)


def find_incident_by_id(store: IncidentStore, incident_id: str) -> IncidentRecord | None:
    target = str(incident_id or "").strip().lower()
    if not target:
        return None
    active = store.active()
    if active and target in active.id.lower():
        return active
    for item in store.list_recent(limit=200):
        if target in item.id.lower():
            return item
    return None


def build_runbook_payload_from_incident(
    *,
    incident: IncidentRecord,
    evidence_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    trigger_patterns = _build_trigger_patterns(incident, evidence_payload or {})
    diagnosis_steps = _build_diagnosis_steps(incident, evidence_payload or {})
    remediation_steps = _build_remediation_steps(evidence_payload or {})
    verify_steps = _build_verify_steps(evidence_payload or {})
    rollback_steps = _build_rollback_steps(evidence_payload or {})
    if not diagnosis_steps:
        diagnosis_steps = [
            {
                "action": "review_incident_timeline",
                "command": "lazysre incident timeline",
                "expected_output": "关键异常时间线与变化点",
            }
        ]
    if not remediation_steps:
        remediation_steps = [
            {
                "action": "draft_fix_plan",
                "command": "lazysre fix plan \"根据当前证据生成修复方案\"",
                "risk_level": "medium",
                "requires_approval": True,
            }
        ]
    return {
        "schema_version": 1,
        "source_incident_id": incident.id,
        "incident_title": incident.title,
        "incident_summary": incident.summary,
        "created_at": _now_iso(),
        "trigger_patterns": trigger_patterns,
        "diagnosis_steps": diagnosis_steps,
        "remediation_steps": remediation_steps,
        "verify_steps": verify_steps,
        "rollback_steps": rollback_steps,
    }


def diff_runbook_versions(store: GeneratedRunbookStore, *, name: str, version_a: str, version_b: str) -> list[str]:
    left = store.load(name, version_a)
    right = store.load(name, version_b)
    if left is None:
        raise ValueError(f"runbook version not found: {name} {version_a}")
    if right is None:
        raise ValueError(f"runbook version not found: {name} {version_b}")
    left_text = _yaml_text(left.payload).splitlines()
    right_text = _yaml_text(right.payload).splitlines()
    return list(
        unified_diff(
            left_text,
            right_text,
            fromfile=f"{left.name}/{left.version}",
            tofile=f"{right.name}/{right.version}",
            lineterm="",
        )
    )


def render_runbook_diff_text(lines: list[str]) -> str:
    if not lines:
        return "No differences."
    return "\n".join(lines)


def find_best_matching_runbook(store: GeneratedRunbookStore, *, query: str) -> tuple[GeneratedRunbookVersion, float] | None:
    query_tokens = _tokenize_text(query)
    if not query_tokens:
        return None
    best: tuple[GeneratedRunbookVersion, float] | None = None
    for name in store.list_names():
        latest = store.load(name)
        if latest is None:
            continue
        payload = latest.payload
        patterns = payload.get("trigger_patterns", [])
        parts: list[str] = []
        if isinstance(patterns, list):
            parts.extend([str(x) for x in patterns[:12]])
        parts.append(str(payload.get("incident_title", "")))
        parts.append(str(payload.get("incident_summary", "")))
        score = _jaccard_score(query_tokens, _tokenize_text(" ".join(parts)))
        if best is None or score > best[1]:
            best = (latest, score)
    if best is None or best[1] <= 0.0:
        return None
    return best


def normalize_runbook_name(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    return text[:64]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _version_number(version: str) -> int:
    text = str(version or "").strip().lower()
    if not text.startswith("v"):
        return 0
    try:
        return int(text[1:])
    except Exception:
        return 0


def _read_yaml(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception:
        return None
    if yaml is None:
        try:
            payload = json.loads(raw)
        except Exception:
            return None
        return payload if isinstance(payload, dict) else None
    try:
        payload = yaml.safe_load(raw)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _write_yaml(path: Path, payload: dict[str, Any]) -> None:
    text = _yaml_text(payload)
    path.write_text(text, encoding="utf-8")


def _yaml_text(payload: dict[str, Any]) -> str:
    if yaml is None:
        return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    return str(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False))


def _build_trigger_patterns(incident: IncidentRecord, evidence_payload: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    title = incident.title.strip()
    summary = incident.summary.strip()
    if title:
        candidates.append(title[:80])
    if summary:
        candidates.append(summary[:120])
    metric_match = re.findall(r"(p\d{2,3}\s*[<>]?\s*\d+ms|\d+%|\d+ms)", f"{title} {summary}", flags=re.IGNORECASE)
    candidates.extend(metric_match[:4])
    commands = _collect_commands_from_evidence(evidence_payload)
    for command in commands[:8]:
        parts = command.split()
        if len(parts) >= 3:
            candidates.append(" ".join(parts[:3]))
    timeline_rows = incident.timeline if isinstance(incident.timeline, list) else []
    for item in timeline_rows[:6]:
        if not isinstance(item, dict):
            continue
        msg = str(item.get("message", "")).strip()
        if msg:
            candidates.append(msg[:80])
    output: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        text = str(item).strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        output.append(text)
        if len(output) >= 10:
            break
    return output


def _build_diagnosis_steps(incident: IncidentRecord, evidence_payload: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for row in _collect_skill_output_rows(evidence_payload):
        phase = str(row.get("phase", "")).strip().lower()
        command = str(row.get("command", "")).strip()
        if not command:
            continue
        if phase in {"precheck", "read", "diagnose", "tool_call", "llm_response", "verify"}:
            steps.append(
                {
                    "action": phase or "diagnose",
                    "command": command,
                    "expected_output": _expected_from_phase(phase),
                }
            )
    if steps:
        return _dedupe_dict_rows(steps, limit=16, key_fields=("action", "command"))
    for item in incident.timeline:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind", "")).strip().lower()
        message = str(item.get("message", "")).strip()
        if not message:
            continue
        if kind in {"summary", "note", "opened", "status", "severity"}:
            steps.append(
                {
                    "action": kind or "note",
                    "command": f"echo {message}",
                    "expected_output": message[:120],
                }
            )
    return _dedupe_dict_rows(steps, limit=12, key_fields=("action", "command"))


def _build_remediation_steps(evidence_payload: dict[str, Any]) -> list[dict[str, Any]]:
    commands: list[str] = []
    for row in _collect_skill_output_rows(evidence_payload):
        phase = str(row.get("phase", "")).strip().lower()
        command = str(row.get("command", "")).strip()
        if phase in {"apply", "fix"} and command:
            commands.append(command)
    commands.extend(_collect_template_commands(evidence_payload, keys=("execute_command", "execute")))
    output: list[dict[str, Any]] = []
    for command in commands:
        argv = [x for x in command.split(" ") if x]
        decision = assess_command(argv, approval_mode="balanced")
        output.append(
            {
                "action": "apply_fix",
                "command": command,
                "risk_level": decision.risk_level,
                "requires_approval": decision.risk_level in {"high", "critical"},
            }
        )
    return _dedupe_dict_rows(output, limit=12, key_fields=("command",))


def _build_verify_steps(evidence_payload: dict[str, Any]) -> list[dict[str, Any]]:
    commands: list[str] = []
    for row in _collect_skill_output_rows(evidence_payload):
        phase = str(row.get("phase", "")).strip().lower()
        command = str(row.get("command", "")).strip()
        if phase in {"verify", "postcheck"} and command:
            commands.append(command)
    commands.extend(_collect_template_commands(evidence_payload, keys=("verify_commands",)))
    output = [
        {
            "action": "verify",
            "command": command,
            "expected_output": "service healthy / rollout complete",
        }
        for command in commands
        if command
    ]
    return _dedupe_dict_rows(output, limit=12, key_fields=("command",))


def _build_rollback_steps(evidence_payload: dict[str, Any]) -> list[dict[str, Any]]:
    commands: list[str] = []
    for row in _collect_skill_output_rows(evidence_payload):
        phase = str(row.get("phase", "")).strip().lower()
        command = str(row.get("command", "")).strip()
        if phase == "rollback" and command:
            commands.append(command)
    commands.extend(_collect_template_commands(evidence_payload, keys=("rollback_command", "rollback")))
    output = [
        {
            "action": "rollback",
            "command": command,
            "expected_output": "service restored",
        }
        for command in commands
        if command
    ]
    return _dedupe_dict_rows(output, limit=10, key_fields=("command",))


def _collect_skill_output_rows(evidence_payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = evidence_payload.get("outputs", [])
    if isinstance(rows, list):
        return [x for x in rows if isinstance(x, dict)]
    return []


def _collect_commands_from_evidence(evidence_payload: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    for row in _collect_skill_output_rows(evidence_payload):
        command = str(row.get("command", "")).strip()
        if command:
            commands.append(command)
    commands.extend(_collect_template_commands(evidence_payload, keys=("execute_command", "verify_commands", "rollback_command")))
    return commands


def _collect_template_commands(evidence_payload: dict[str, Any], *, keys: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    execution_templates = evidence_payload.get("execution_templates")
    if not isinstance(execution_templates, dict):
        return out
    items = execution_templates.get("items", [])
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, dict):
            continue
        task_sheet = item.get("task_sheet", {})
        sources = [item, task_sheet] if isinstance(task_sheet, dict) else [item]
        for source in sources:
            if not isinstance(source, dict):
                continue
            for key in keys:
                value = source.get(key)
                if isinstance(value, str) and value.strip():
                    out.append(value.strip())
                elif isinstance(value, list):
                    for row in value:
                        text = str(row).strip()
                        if text:
                            out.append(text)
    return out


def _expected_from_phase(phase: str) -> str:
    mapping = {
        "precheck": "cluster/service 状态已采集",
        "read": "采样指标/日志返回",
        "diagnose": "定位异常候选根因",
        "tool_call": "工具调用成功并返回结构化结果",
        "llm_response": "AI 汇总阶段结论",
        "verify": "修复后健康状态恢复",
    }
    return mapping.get(phase, "步骤成功执行")


def _dedupe_dict_rows(rows: list[dict[str, Any]], *, limit: int, key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = "|".join(str(row.get(field, "")).strip().lower() for field in key_fields)
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(row)
        if len(output) >= limit:
            break
    return output


def _tokenize_text(text: str) -> set[str]:
    parts = re.findall(r"[a-zA-Z0-9_.:/-]+", str(text or "").lower())
    return {x for x in parts if len(x) >= 2}


def _jaccard_score(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    inter = len(left & right)
    if inter <= 0:
        return 0.0
    union = len(left | right)
    if union <= 0:
        return 0.0
    return inter / union
