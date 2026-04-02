from __future__ import annotations

from dataclasses import dataclass, field


RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(slots=True)
class PolicyDecision:
    risk_level: str = "low"
    reasons: list[str] = field(default_factory=list)
    requires_approval: bool = False
    blocked: bool = False
    blocked_reason: str = ""


def assess_command(command: list[str], approval_mode: str = "balanced") -> PolicyDecision:
    if not command:
        return PolicyDecision(
            risk_level="critical",
            blocked=True,
            blocked_reason="empty command",
            reasons=["空命令不允许执行。"],
        )

    binary = command[0]
    args = [x.lower() for x in command[1:]]
    joined = " ".join(args)

    level = "low"
    reasons: list[str] = []

    if binary == "kubectl":
        level, reasons = _assess_kubectl(args, joined)
    elif binary == "docker":
        level, reasons = _assess_docker(args, joined)
    elif binary == "curl":
        level, reasons = _assess_curl(args)
    elif binary == "tail":
        level, reasons = ("low", ["日志读取为只读操作。"])
    else:
        level, reasons = ("critical", [f"未知二进制: {binary}"])

    min_approval = _min_approval_level(approval_mode)
    requires_approval = RISK_ORDER.get(level, 4) >= RISK_ORDER.get(min_approval, 3)
    return PolicyDecision(
        risk_level=level,
        reasons=reasons,
        requires_approval=requires_approval,
    )


def build_risk_report(command: list[str], decision: PolicyDecision) -> dict[str, object]:
    binary = command[0] if command else ""
    args = command[1:] if len(command) > 1 else []
    joined = " ".join(args).strip()

    risk_score_map = {"low": 18, "medium": 45, "high": 78, "critical": 94}
    score = risk_score_map.get(decision.risk_level, 90)

    impact_scope = "local"
    blast_radius = "single target"
    rollback = "manual recovery required"

    if binary == "kubectl":
        impact_scope = "kubernetes"
        if "delete namespace" in joined or "delete node" in joined:
            blast_radius = "cluster-wide"
            rollback = "kubectl apply -f <backup-manifest>; restore from backup snapshot"
        elif "rollout restart" in joined:
            blast_radius = "service-level"
            rollback = "kubectl rollout undo <resource>"
        elif args[:1] and args[0] in {"patch", "apply", "replace", "set", "scale"}:
            blast_radius = "namespace-level"
            rollback = "kubectl rollout undo <resource> or re-apply previous manifest"
        else:
            blast_radius = "resource-level"
            rollback = "re-apply previous kubectl spec"
    elif binary == "docker":
        impact_scope = "docker-runtime"
        if args[:1] and args[0] in {"restart", "stop", "kill", "rm", "rmi"}:
            blast_radius = "service/container-level"
            rollback = "docker start <container> or redeploy service image"
        elif "prune" in joined:
            blast_radius = "host-level"
            rollback = "recover from image/cache/volume backup"
    elif binary == "curl":
        impact_scope = "remote-api"
        methods = [x.upper() for x in args if x.startswith("-X") or x in {"POST", "PUT", "PATCH", "DELETE"}]
        if methods:
            blast_radius = "remote service state"
            rollback = "issue compensating API request based on endpoint contract"

    return {
        "risk_level": decision.risk_level,
        "risk_score": score,
        "impact_scope": impact_scope,
        "blast_radius": blast_radius,
        "requires_approval": decision.requires_approval,
        "reasons": list(decision.reasons),
        "rollback": rollback,
    }


def _min_approval_level(mode: str) -> str:
    normalized = mode.strip().lower()
    if normalized == "strict":
        return "medium"
    if normalized == "permissive":
        return "critical"
    return "high"


def _assess_kubectl(args: list[str], joined: str) -> tuple[str, list[str]]:
    read_only = {"get", "describe", "logs", "top", "version", "api-resources", "api-versions"}
    mutate = {
        "apply",
        "create",
        "replace",
        "patch",
        "edit",
        "label",
        "annotate",
        "set",
        "scale",
        "delete",
    }
    disruptive = {"drain", "uncordon", "cordon", "rollout", "taint"}

    cmd = _first_subcommand(args)
    if cmd in read_only:
        return "low", ["kubectl 只读查询命令。"]
    if cmd in mutate:
        if "delete namespace" in joined or "delete node" in joined:
            return "critical", ["涉及删除核心资源（namespace/node）。"]
        return "high", ["kubectl 变更类操作，可能影响线上状态。"]
    if cmd in disruptive:
        if "restart" in joined:
            return "critical", ["涉及 rollout restart，可能引发服务抖动。"]
        return "high", ["kubectl 干预类操作，需审批后执行。"]
    return "medium", ["kubectl 非白名单子命令，建议先审批。"]


def _assess_docker(args: list[str], joined: str) -> tuple[str, list[str]]:
    read_only = {"ps", "images", "inspect", "stats", "logs", "service", "node"}
    mutate = {"restart", "stop", "start", "kill", "rm", "rmi", "run"}

    cmd = _first_subcommand(args)
    if cmd in read_only:
        return "low", ["docker 诊断查询命令。"]
    if cmd in mutate:
        return "high", ["docker 变更类命令，可能影响容器运行。"]
    if "system prune" in joined or "volume prune" in joined:
        return "critical", ["docker prune 可能删除关键数据。"]
    return "medium", ["docker 非白名单子命令，建议先审批。"]


def _assess_curl(args: list[str]) -> tuple[str, list[str]]:
    method = "GET"
    for idx, token in enumerate(args):
        if token == "-x" and idx + 1 < len(args):
            method = args[idx + 1].upper()
        elif token.startswith("-x"):
            method = token[2:].upper()
    if method in {"GET", "HEAD"}:
        return "low", ["HTTP 只读探活请求。"]
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "high", [f"HTTP {method} 可能触发远端状态变更。"]
    return "medium", [f"未知 HTTP method={method}，建议先审批。"]


def _first_subcommand(args: list[str]) -> str:
    flags_with_value = {
        "--token",
        "--server",
        "--context",
        "--namespace",
        "--kubeconfig",
        "--cluster",
        "--user",
        "-n",
    }
    skip_next = False
    for token in args:
        if skip_next:
            skip_next = False
            continue
        if not token:
            continue
        if token in flags_with_value:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        return token
    return ""
