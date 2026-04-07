from __future__ import annotations

from dataclasses import dataclass, field
from string import Formatter


@dataclass(slots=True)
class RunbookTemplate:
    name: str
    title: str
    mode: str  # diagnose | fix
    instruction: str
    description: str
    variables: dict[str, str] = field(default_factory=dict)


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


def find_runbook(name: str) -> RunbookTemplate | None:
    target = name.strip().lower()
    if not target:
        return None
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
