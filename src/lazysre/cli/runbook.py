from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class RunbookTemplate:
    name: str
    title: str
    mode: str  # diagnose | fix
    instruction: str
    description: str


def builtin_runbooks() -> list[RunbookTemplate]:
    return [
        RunbookTemplate(
            name="k8s-latency-diagnose",
            title="K8s 延迟诊断",
            mode="diagnose",
            instruction="检查当前集群中响应延迟上升的服务，先用 metrics / events / logs 取证，再给出根因与后续建议。",
            description="通用延迟问题诊断模板，适合先排查再决定是否修复。",
        ),
        RunbookTemplate(
            name="payment-latency-fix",
            title="支付服务延迟修复",
            mode="fix",
            instruction="为什么支付服务响应变慢了？请自动取证并给出修复与回滚计划。",
            description="面向支付链路的修复模板，会产出 apply/rollback 命令。",
        ),
        RunbookTemplate(
            name="pod-crashloop-fix",
            title="CrashLoopBackOff 修复",
            mode="fix",
            instruction="定位 CrashLoopBackOff 的根因，生成最小影响修复命令和回滚命令。",
            description="用于容器反复重启问题，强调风险和回滚。",
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
