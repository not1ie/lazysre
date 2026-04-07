from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from string import Formatter
from typing import Any

from lazysre.config import settings


@dataclass(slots=True)
class RunbookTemplate:
    name: str
    title: str
    mode: str  # diagnose | fix
    instruction: str
    description: str
    variables: dict[str, str] = field(default_factory=dict)
    source: str = "builtin"  # builtin | custom


def builtin_runbooks() -> list[RunbookTemplate]:
    return [
        RunbookTemplate(
            name="k8s-latency-diagnose",
            title="K8s 延迟诊断",
            mode="diagnose",
            instruction=(
                "检查 {namespace} 命名空间中 {service} 服务响应延迟上升问题，"
                "先用 metrics / events / logs 取证，再给出根因与后续建议。"
            ),
            description="通用延迟问题诊断模板，适合先排查再决定是否修复。",
            variables={"service": "payment", "namespace": "default"},
        ),
        RunbookTemplate(
            name="payment-latency-fix",
            title="支付服务延迟修复",
            mode="fix",
            instruction=(
                "为什么 {namespace} 命名空间里的 {service} 服务响应变慢了？"
                "目标 p95 阈值为 {p95_ms}ms。请自动取证并给出修复与回滚计划。"
            ),
            description="面向支付链路的修复模板，会产出 apply/rollback 命令。",
            variables={"service": "payment", "namespace": "default", "p95_ms": "300"},
        ),
        RunbookTemplate(
            name="pod-crashloop-fix",
            title="CrashLoopBackOff 修复",
            mode="fix",
            instruction=(
                "定位 {namespace} 命名空间中 {workload} 的 CrashLoopBackOff 根因，"
                "生成最小影响修复命令和回滚命令。"
            ),
            description="用于容器反复重启问题，强调风险和回滚。",
            variables={"namespace": "default", "workload": "deployment/app"},
        ),
    ]


@dataclass(slots=True)
class RunbookStore:
    path: Path

    @classmethod
    def default(cls) -> "RunbookStore":
        return cls(Path(settings.runbook_store_file))

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"runbooks": {}}
        raw = self.path.read_text(encoding="utf-8").strip()
        if not raw:
            return {"runbooks": {}}
        try:
            payload = json.loads(raw)
        except Exception:
            return {"runbooks": {}}
        if not isinstance(payload, dict):
            return {"runbooks": {}}
        runbooks = payload.get("runbooks", {})
        if not isinstance(runbooks, dict):
            runbooks = {}
        return {"runbooks": runbooks}

    def save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.path)

    def list_custom(self) -> list[RunbookTemplate]:
        payload = self.load()
        raw = payload.get("runbooks", {})
        if not isinstance(raw, dict):
            return []
        items: list[RunbookTemplate] = []
        for name, row in raw.items():
            key = str(name).strip().lower()
            if not key or (not isinstance(row, dict)):
                continue
            item = _template_from_dict(key, row, source="custom")
            if item:
                items.append(item)
        return sorted(items, key=lambda x: x.name)

    def get_custom(self, name: str) -> RunbookTemplate | None:
        key = name.strip().lower()
        if not key:
            return None
        payload = self.load()
        raw = payload.get("runbooks", {})
        if not isinstance(raw, dict):
            return None
        row = raw.get(key, {})
        if not isinstance(row, dict):
            return None
        return _template_from_dict(key, row, source="custom")

    def upsert(self, template: RunbookTemplate) -> None:
        _validate_template(template)
        payload = self.load()
        runbooks = payload.get("runbooks", {})
        if not isinstance(runbooks, dict):
            runbooks = {}
        row = asdict(template)
        row.pop("name", None)
        row.pop("source", None)
        row["mode"] = str(row.get("mode", "")).strip().lower()
        row["variables"] = {str(k): str(v) for k, v in dict(row.get("variables", {})).items()}
        runbooks[template.name.strip().lower()] = row
        payload["runbooks"] = runbooks
        self.save(payload)

    def remove(self, name: str) -> bool:
        key = name.strip().lower()
        if not key:
            return False
        payload = self.load()
        runbooks = payload.get("runbooks", {})
        if not isinstance(runbooks, dict) or key not in runbooks:
            return False
        del runbooks[key]
        payload["runbooks"] = runbooks
        self.save(payload)
        return True


def all_runbooks(*, store: RunbookStore | None = None) -> list[RunbookTemplate]:
    merged: dict[str, RunbookTemplate] = {item.name: item for item in builtin_runbooks()}
    if store:
        for item in store.list_custom():
            merged[item.name] = item
    return [merged[k] for k in sorted(merged.keys())]


def find_runbook(name: str, *, store: RunbookStore | None = None) -> RunbookTemplate | None:
    target = name.strip().lower()
    if not target:
        return None
    if store:
        custom = store.get_custom(target)
        if custom:
            return custom
    for item in builtin_runbooks():
        if item.name == target:
            return item
    return None


def parse_runbook_vars(items: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in items:
        text = raw.strip()
        if not text:
            continue
        if "=" not in text:
            raise ValueError(f"invalid --var value: {raw} (expected key=value)")
        key, value = text.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"invalid --var value: {raw} (empty key)")
        if not value:
            raise ValueError(f"invalid --var value: {raw} (empty value)")
        values[key] = value
    return values


def render_runbook_instruction(
    template: RunbookTemplate,
    *,
    overrides: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    values: dict[str, str] = dict(template.variables)
    if overrides:
        values.update({str(k): str(v) for k, v in overrides.items()})

    required_keys = {
        field_name
        for _, field_name, _, _ in Formatter().parse(template.instruction)
        if field_name
    }
    missing = sorted(k for k in required_keys if not str(values.get(k, "")).strip())
    if missing:
        raise ValueError(f"missing runbook vars: {', '.join(missing)}")

    resolved = {k: str(v) for k, v in values.items()}
    return template.instruction.format(**resolved), resolved


def _template_from_dict(name: str, raw: dict[str, Any], *, source: str) -> RunbookTemplate | None:
    title = str(raw.get("title", "")).strip()
    mode = str(raw.get("mode", "")).strip().lower()
    instruction = str(raw.get("instruction", "")).strip()
    description = str(raw.get("description", "")).strip()
    variables_raw = raw.get("variables", {})
    variables: dict[str, str] = {}
    if isinstance(variables_raw, dict):
        variables = {
            str(k).strip(): str(v).strip()
            for k, v in variables_raw.items()
            if str(k).strip() and str(v).strip()
        }
    item = RunbookTemplate(
        name=name,
        title=title,
        mode=mode,
        instruction=instruction,
        description=description,
        variables=variables,
        source=source,
    )
    try:
        _validate_template(item)
    except ValueError:
        return None
    return item


def _validate_template(template: RunbookTemplate) -> None:
    name = template.name.strip().lower()
    mode = template.mode.strip().lower()
    if not name:
        raise ValueError("runbook name is required")
    if mode not in {"diagnose", "fix"}:
        raise ValueError("runbook mode must be diagnose or fix")
    if not template.title.strip():
        raise ValueError("runbook title is required")
    if not template.instruction.strip():
        raise ValueError("runbook instruction is required")
