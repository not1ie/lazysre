from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class RemediationTemplate:
    name: str
    title: str
    description: str
    aliases: tuple[str, ...]
    trigger_keywords: tuple[str, ...]
    risk_level: str
    variables: dict[str, str]
    diagnose_commands: tuple[str, ...]
    apply_commands: tuple[str, ...]
    rollback_commands: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "aliases": list(self.aliases),
            "trigger_keywords": list(self.trigger_keywords),
            "risk_level": self.risk_level,
            "variables": dict(self.variables),
            "diagnose_commands": list(self.diagnose_commands),
            "apply_commands": list(self.apply_commands),
            "rollback_commands": list(self.rollback_commands),
        }


_TEMPLATES: tuple[RemediationTemplate, ...] = (
    RemediationTemplate(
        name="k8s-crashloopbackoff",
        title="CrashLoopBackOff 快速恢复",
        description="针对 Pod 反复崩溃场景，先采集证据，再执行有回滚的重启恢复。",
        aliases=("crashloop", "pod-crash", "崩溃重启"),
        trigger_keywords=("crashloopbackoff", "crashloop", "崩溃", "反复重启"),
        risk_level="high",
        variables={
            "namespace": "default",
            "pod": "payment-xxx",
            "workload": "deploy/payment",
        },
        diagnose_commands=(
            "kubectl -n {namespace} get pod {pod} -o wide",
            "kubectl -n {namespace} describe pod {pod}",
            "kubectl -n {namespace} logs {pod} --previous --tail=200",
        ),
        apply_commands=(
            "kubectl -n {namespace} rollout restart {workload}",
            "kubectl -n {namespace} rollout status {workload} --timeout=180s",
        ),
        rollback_commands=(
            "kubectl -n {namespace} rollout undo {workload}",
            "kubectl -n {namespace} rollout status {workload} --timeout=180s",
        ),
    ),
    RemediationTemplate(
        name="k8s-imagepullbackoff",
        title="ImagePullBackOff 快速恢复",
        description="针对镜像拉取失败场景，检查拉取错误并替换可用镜像。",
        aliases=("imagepull", "镜像拉取失败"),
        trigger_keywords=("imagepullbackoff", "errimagepull", "镜像拉取", "镜像拉不下来"),
        risk_level="high",
        variables={
            "namespace": "default",
            "pod": "payment-xxx",
            "workload": "deploy/payment",
            "container": "payment",
            "image": "your-registry/payment:stable",
        },
        diagnose_commands=(
            "kubectl -n {namespace} describe pod {pod}",
            "kubectl -n {namespace} get secret | head -n 20",
        ),
        apply_commands=(
            "kubectl -n {namespace} set image {workload} {container}={image}",
            "kubectl -n {namespace} rollout status {workload} --timeout=180s",
        ),
        rollback_commands=(
            "kubectl -n {namespace} rollout undo {workload}",
            "kubectl -n {namespace} rollout status {workload} --timeout=180s",
        ),
    ),
    RemediationTemplate(
        name="k8s-high-cpu",
        title="Pod CPU 过高快速缓解",
        description="针对突发高 CPU，先确认热点，再临时扩容缓解并保留回退命令。",
        aliases=("cpu-hotspot", "cpu高"),
        trigger_keywords=("cpu高", "cpu 100", "high cpu", "throttle", "限流"),
        risk_level="medium",
        variables={
            "namespace": "default",
            "workload": "deploy/payment",
            "replicas": "4",
            "rollback_replicas": "2",
        },
        diagnose_commands=(
            "kubectl -n {namespace} top pod | head -n 20",
            "kubectl -n {namespace} get hpa",
        ),
        apply_commands=(
            "kubectl -n {namespace} scale {workload} --replicas={replicas}",
            "kubectl -n {namespace} rollout status {workload} --timeout=180s",
        ),
        rollback_commands=(
            "kubectl -n {namespace} scale {workload} --replicas={rollback_replicas}",
            "kubectl -n {namespace} rollout status {workload} --timeout=180s",
        ),
    ),
    RemediationTemplate(
        name="k8s-oomkill",
        title="OOMKilled 快速恢复",
        description="针对内存溢出导致容器被杀，快速重启工作负载并留回滚路径。",
        aliases=("oom", "memory-leak", "oomkilled"),
        trigger_keywords=("oomkilled", "oom", "内存溢出", "memory leak"),
        risk_level="high",
        variables={
            "namespace": "default",
            "pod": "payment-xxx",
            "workload": "deploy/payment",
        },
        diagnose_commands=(
            "kubectl -n {namespace} describe pod {pod}",
            "kubectl -n {namespace} logs {pod} --tail=200",
        ),
        apply_commands=(
            "kubectl -n {namespace} rollout restart {workload}",
            "kubectl -n {namespace} rollout status {workload} --timeout=180s",
        ),
        rollback_commands=(
            "kubectl -n {namespace} rollout undo {workload}",
            "kubectl -n {namespace} rollout status {workload} --timeout=180s",
        ),
    ),
)


def list_templates() -> list[RemediationTemplate]:
    return list(_TEMPLATES)


def get_template(name_or_alias: str) -> RemediationTemplate | None:
    needle = (name_or_alias or "").strip().lower()
    if not needle:
        return None
    for template in _TEMPLATES:
        if template.name.lower() == needle:
            return template
        if needle in {alias.lower() for alias in template.aliases}:
            return template
    return None


def match_template_for_text(text: str, *, min_score: int = 2) -> RemediationTemplate | None:
    lowered = (text or "").strip().lower()
    if not lowered:
        return None
    best: tuple[int, RemediationTemplate] | None = None
    for template in _TEMPLATES:
        score = _score_template_match(template, lowered)
        if score < min_score:
            continue
        if (best is None) or (score > best[0]):
            best = (score, template)
    return best[1] if best else None


def parse_var_items(var_items: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in var_items:
        text = str(raw or "").strip()
        if (not text) or ("=" not in text):
            continue
        key, value = text.split("=", 1)
        k = key.strip()
        if not k:
            continue
        values[k] = value.strip()
    return values


def render_template(
    template: RemediationTemplate,
    *,
    overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    vars_map = dict(template.variables)
    if overrides:
        for key, value in overrides.items():
            k = str(key or "").strip()
            if not k:
                continue
            vars_map[k] = str(value)

    diagnose = [_safe_format(command, vars_map) for command in template.diagnose_commands]
    apply_cmds = [_safe_format(command, vars_map) for command in template.apply_commands]
    rollback = [_safe_format(command, vars_map) for command in template.rollback_commands]
    return {
        "template": template.to_dict(),
        "variables": vars_map,
        "diagnose_commands": diagnose,
        "apply_commands": apply_cmds,
        "rollback_commands": rollback,
    }


def maybe_detect_quick_fix_intent(text: str) -> tuple[RemediationTemplate | None, bool]:
    lowered = (text or "").strip().lower()
    if not lowered:
        return None, False
    template = match_template_for_text(lowered)
    if not template:
        return None, False
    apply_keywords = (
        "一键修复",
        "快速修复",
        "直接修复",
        "马上修复",
        "自动修复",
        "apply template",
        "quick fix",
        "run template",
    )
    apply_requested = any(keyword in lowered for keyword in apply_keywords)
    return template, apply_requested


def _score_template_match(template: RemediationTemplate, lowered_text: str) -> int:
    score = 0
    if template.name.lower() in lowered_text:
        score += 4
    for alias in template.aliases:
        if alias.lower() in lowered_text:
            score += 3
    for keyword in template.trigger_keywords:
        if keyword.lower() in lowered_text:
            score += 1
    return score


def _safe_format(command: str, values: dict[str, str]) -> str:
    rendered = str(command)
    for key, value in values.items():
        rendered = rendered.replace("{" + key + "}", str(value))
    return rendered

