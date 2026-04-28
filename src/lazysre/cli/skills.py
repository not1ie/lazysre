from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from lazysre.config import settings


@dataclass(slots=True)
class SkillTemplate:
    name: str
    title: str
    description: str
    category: str
    mode: str
    risk_level: str
    required_permission: str
    instruction: str
    variables: dict[str, str] = field(default_factory=dict)
    precheck_commands: list[str] = field(default_factory=list)
    read_commands: list[str] = field(default_factory=list)
    apply_commands: list[str] = field(default_factory=list)
    verify_commands: list[str] = field(default_factory=list)
    postcheck_commands: list[str] = field(default_factory=list)
    rollback_commands: list[str] = field(default_factory=list)
    auto_rollback_on_failure: bool = True
    tags: list[str] = field(default_factory=list)
    source: str = "builtin"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SkillRunResult:
    skill: SkillTemplate
    variables: dict[str, str]
    dry_run: bool
    apply: bool
    commands: dict[str, list[str]]
    status: str
    outputs: list[dict[str, Any]] = field(default_factory=list)
    evidence_graph: dict[str, Any] = field(default_factory=dict)
    rollback_executed: bool = False
    rollback_status: str = "not_required"
    failed_phase: str = ""
    next_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill.to_dict(),
            "variables": dict(self.variables),
            "dry_run": self.dry_run,
            "apply": self.apply,
            "commands": {k: list(v) for k, v in self.commands.items()},
            "status": self.status,
            "outputs": list(self.outputs),
            "evidence_graph": dict(self.evidence_graph),
            "rollback_executed": self.rollback_executed,
            "rollback_status": self.rollback_status,
            "failed_phase": self.failed_phase,
            "next_actions": list(self.next_actions),
        }


class SkillStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(settings.skill_store_file)

    @classmethod
    def default(cls) -> "SkillStore":
        return cls(Path(settings.skill_store_file))

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"skills": {}}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except Exception:
            return {"skills": {}}
        if not isinstance(payload, dict):
            return {"skills": {}}
        skills = payload.get("skills", {})
        if not isinstance(skills, dict):
            skills = {}
        return {"skills": skills}

    def save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.path)

    def list_custom(self) -> list[SkillTemplate]:
        payload = self.load()
        raw = payload.get("skills", {})
        if not isinstance(raw, dict):
            return []
        items: list[SkillTemplate] = []
        for name, row in raw.items():
            if not isinstance(row, dict):
                continue
            item = skill_from_dict(str(name), row, source="custom")
            if item:
                items.append(item)
        return sorted(items, key=lambda x: x.name)

    def get_custom(self, name: str) -> SkillTemplate | None:
        key = normalize_skill_name(name)
        if not key:
            return None
        raw = self.load().get("skills", {})
        if not isinstance(raw, dict):
            return None
        row = raw.get(key)
        if not isinstance(row, dict):
            return None
        return skill_from_dict(key, row, source="custom")

    def upsert(self, skill: SkillTemplate) -> None:
        validate_skill(skill)
        payload = self.load()
        skills = payload.get("skills", {})
        if not isinstance(skills, dict):
            skills = {}
        row = skill.to_dict()
        row.pop("name", None)
        row.pop("source", None)
        skills[normalize_skill_name(skill.name)] = row
        payload["skills"] = skills
        self.save(payload)

    def remove(self, name: str) -> bool:
        key = normalize_skill_name(name)
        payload = self.load()
        skills = payload.get("skills", {})
        if not isinstance(skills, dict) or key not in skills:
            return False
        del skills[key]
        payload["skills"] = skills
        self.save(payload)
        return True


def builtin_skills() -> list[SkillTemplate]:
    return [
        SkillTemplate(
            name="remote-health",
            title="远程服务器全量健康巡检",
            description="通过 SSH 只读检查 Linux、Nginx、数据库、GPU/AI、CI/CD 和 Docker/Swarm 关键信号。",
            category="server",
            mode="diagnose",
            risk_level="low",
            required_permission="read",
            instruction="检查远程服务器健康，优先输出异常、证据和下一步。",
            variables={"ssh_target": "root@192.168.10.101"},
            precheck_commands=("ssh -o BatchMode=yes -o ConnectTimeout=6 {ssh_target} 'echo ok'",),
            read_commands=("lazysre remote {ssh_target} --scenario all --logs",),
            verify_commands=("lazysre remote {ssh_target} --scenario all --json",),
            tags=["remote", "linux", "swarm", "nginx", "database", "gpu", "ai"],
        ),
        SkillTemplate(
            name="swarm-health",
            title="Docker Swarm 服务健康检查",
            description="检查 Swarm service 副本、task 拒绝原因和最近日志，适合 Docker Swarm 环境。",
            category="docker",
            mode="diagnose",
            risk_level="low",
            required_permission="read",
            instruction="列出 Swarm 不健康 service，并给出只读证据。",
            variables={"service": "", "tail": "200"},
            precheck_commands=("docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}'",),
            read_commands=("lazysre swarm --logs --tail {tail}",),
            verify_commands=("lazysre swarm --logs --tail {tail}",),
            tags=["docker", "swarm", "service"],
        ),
        SkillTemplate(
            name="k8s-health",
            title="Kubernetes 集群基础巡检",
            description="检查当前 kubeconfig 可见的命名空间、异常 Pod 和事件，默认只读。",
            category="kubernetes",
            mode="diagnose",
            risk_level="low",
            required_permission="read",
            instruction="检查 K8s 集群基础健康状态。",
            variables={"namespace": "default"},
            precheck_commands=("kubectl version --short",),
            read_commands=(
                "kubectl get ns",
                "kubectl get pods -A --field-selector=status.phase!=Running",
                "kubectl get events -A --sort-by=.lastTimestamp | tail -n 40",
            ),
            postcheck_commands=("kubectl get pods -A | head -n 40",),
            tags=["k8s", "pod", "event"],
        ),
        SkillTemplate(
            name="nginx-diagnose",
            title="Nginx 配置与错误日志诊断",
            description="通过远程只读命令检查 nginx -t、服务状态和 error.log。",
            category="middleware",
            mode="diagnose",
            risk_level="low",
            required_permission="read",
            instruction="检查远程 Nginx 配置和最近错误。",
            variables={"ssh_target": "root@192.168.10.101"},
            precheck_commands=("ssh -o BatchMode=yes -o ConnectTimeout=6 {ssh_target} 'echo ok'",),
            read_commands=("lazysre remote {ssh_target} --scenario nginx --logs",),
            verify_commands=("lazysre remote {ssh_target} --scenario nginx --json",),
            tags=["nginx", "remote"],
        ),
        SkillTemplate(
            name="database-diagnose",
            title="数据库运行信号诊断",
            description="检查 MySQL/PostgreSQL/Redis/Mongo 的二进制、systemd 和容器运行信号。",
            category="database",
            mode="diagnose",
            risk_level="low",
            required_permission="read",
            instruction="检查远程数据库组件是否运行和是否异常。",
            variables={"ssh_target": "root@192.168.10.101"},
            precheck_commands=("ssh -o BatchMode=yes -o ConnectTimeout=6 {ssh_target} 'echo ok'",),
            read_commands=("lazysre remote {ssh_target} --scenario db",),
            verify_commands=("lazysre remote {ssh_target} --scenario db --json",),
            tags=["database", "mysql", "postgres", "redis", "remote"],
        ),
        SkillTemplate(
            name="gpu-ai-diagnose",
            title="GPU / AI 服务诊断",
            description="检查 GPU 利用率、显存、温度，以及 Ollama/vLLM/Triton/Xinference 等 AI 服务信号。",
            category="ai",
            mode="diagnose",
            risk_level="low",
            required_permission="read",
            instruction="检查远程 GPU 和 AI 推理服务状态。",
            variables={"ssh_target": "root@192.168.10.101"},
            precheck_commands=("ssh -o BatchMode=yes -o ConnectTimeout=6 {ssh_target} 'echo ok'",),
            read_commands=("lazysre remote {ssh_target} --scenario gpu --scenario ai",),
            verify_commands=("lazysre remote {ssh_target} --scenario gpu --scenario ai --json",),
            tags=["gpu", "ai", "llm", "remote"],
        ),
        SkillTemplate(
            name="cicd-runner-diagnose",
            title="CI/CD Runner 诊断",
            description="检查 GitLab Runner、Jenkins、Actions Runner 等构建执行节点运行状态。",
            category="cicd",
            mode="diagnose",
            risk_level="low",
            required_permission="read",
            instruction="检查远程 CI/CD Runner 是否运行和是否异常。",
            variables={"ssh_target": "root@192.168.10.101"},
            precheck_commands=("ssh -o BatchMode=yes -o ConnectTimeout=6 {ssh_target} 'echo ok'",),
            read_commands=("lazysre remote {ssh_target} --scenario cicd",),
            verify_commands=("lazysre remote {ssh_target} --scenario cicd --json",),
            tags=["cicd", "runner", "jenkins", "remote"],
        ),
    ]


def all_skills(*, store: SkillStore | None = None) -> list[SkillTemplate]:
    merged = {item.name: item for item in builtin_skills()}
    if store:
        for item in store.list_custom():
            merged[item.name] = item
    return [merged[key] for key in sorted(merged.keys())]


def find_skill(name: str, *, store: SkillStore | None = None) -> SkillTemplate | None:
    key = normalize_skill_name(name)
    if not key:
        return None
    if store:
        custom = store.get_custom(key)
        if custom:
            return custom
    for item in builtin_skills():
        if item.name == key:
            return item
    return None


def parse_skill_vars(items: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in items:
        text = str(raw or "").strip()
        if not text:
            continue
        if "=" not in text:
            raise ValueError(f"invalid --var value: {raw} (expected key=value)")
        key, value = text.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"invalid --var value: {raw} (empty key)")
        values[key] = value.strip()
    return values


def render_skill_commands(
    skill: SkillTemplate,
    *,
    overrides: dict[str, str] | None = None,
) -> tuple[dict[str, list[str]], dict[str, str]]:
    values = dict(skill.variables)
    if overrides:
        values.update({str(k): str(v) for k, v in overrides.items()})
    commands = {
        "precheck": [_safe_format(command, values) for command in skill.precheck_commands],
        "read": [_safe_format(command, values) for command in skill.read_commands],
        "apply": [_safe_format(command, values) for command in skill.apply_commands],
        "verify": [_safe_format(command, values) for command in skill.verify_commands],
        "postcheck": [_safe_format(command, values) for command in skill.postcheck_commands],
        "rollback": [_safe_format(command, values) for command in skill.rollback_commands],
    }
    return commands, values


def run_skill(
    skill: SkillTemplate,
    *,
    overrides: dict[str, str] | None = None,
    dry_run: bool = True,
    apply: bool = False,
    timeout_sec: int = 20,
    auto_rollback_on_failure: bool | None = None,
) -> SkillRunResult:
    commands, values = render_skill_commands(skill, overrides=overrides)
    selected: list[tuple[str, str]] = [("precheck", x) for x in commands["precheck"]]
    selected.extend(("read", x) for x in commands["read"])
    if apply:
        selected.extend(("apply", x) for x in commands["apply"])
        selected.extend(("verify", x) for x in commands["verify"])
        selected.extend(("postcheck", x) for x in commands["postcheck"])
    outputs: list[dict[str, Any]] = []
    status = "planned"
    failed_phase = ""
    rollback_executed = False
    rollback_status = "not_required"
    enable_auto_rollback = skill.auto_rollback_on_failure if auto_rollback_on_failure is None else bool(auto_rollback_on_failure)
    if not dry_run:
        status = "executed"
        for phase, command in selected:
            started = _now_utc_iso()
            completed = subprocess.run(
                command,
                shell=True,
                text=True,
                capture_output=True,
                timeout=max(1, timeout_sec),
                check=False,
            )
            finished = _now_utc_iso()
            outputs.append(
                {
                    "phase": phase,
                    "command": command,
                    "exit_code": completed.returncode,
                    "stdout": completed.stdout[-4000:],
                    "stderr": completed.stderr[-2000:],
                    "started_at": started,
                    "finished_at": finished,
                }
            )
            if completed.returncode != 0:
                status = "failed"
                failed_phase = phase
                break
        if status == "failed" and apply and enable_auto_rollback and commands["rollback"]:
            rollback_executed = True
            rollback_status = "executed"
            for command in commands["rollback"]:
                started = _now_utc_iso()
                completed = subprocess.run(
                    command,
                    shell=True,
                    text=True,
                    capture_output=True,
                    timeout=max(1, timeout_sec),
                    check=False,
                )
                finished = _now_utc_iso()
                outputs.append(
                    {
                        "phase": "rollback",
                        "command": command,
                        "exit_code": completed.returncode,
                        "stdout": completed.stdout[-4000:],
                        "stderr": completed.stderr[-2000:],
                        "started_at": started,
                        "finished_at": finished,
                    }
                )
                if completed.returncode != 0:
                    rollback_status = "failed"
                    break
    next_actions = []
    if dry_run:
        next_actions.append(f"确认命令无误后执行: lazysre skill run {skill.name} --execute")
    if skill.apply_commands and not apply:
        next_actions.append(f"如需修复，执行: lazysre skill run {skill.name} --apply --execute")
    if skill.rollback_commands:
        next_actions.append("执行写操作前确认 rollback_commands 已满足预期。")
    if status == "failed":
        if failed_phase:
            next_actions.append(f"故障阶段: {failed_phase}。先修复该阶段依赖，再重试 skill。")
        if rollback_executed:
            next_actions.append(f"已触发自动回滚，状态: {rollback_status}。建议执行 verify/postcheck 复核环境。")
        elif commands["rollback"]:
            next_actions.append(f"可手动回滚: lazysre skill run {skill.name} --apply --execute")
    evidence_graph = _build_evidence_graph(outputs)
    return SkillRunResult(
        skill=skill,
        variables=values,
        dry_run=dry_run,
        apply=apply,
        commands=commands,
        status=status,
        outputs=outputs,
        evidence_graph=evidence_graph,
        rollback_executed=rollback_executed,
        rollback_status=rollback_status,
        failed_phase=failed_phase,
        next_actions=next_actions,
    )


def skill_from_dict(name: str, raw: dict[str, Any], *, source: str) -> SkillTemplate | None:
    variables = raw.get("variables", {})
    item = SkillTemplate(
        name=normalize_skill_name(name),
        title=str(raw.get("title", "")).strip(),
        description=str(raw.get("description", "")).strip(),
        category=str(raw.get("category", "custom")).strip().lower() or "custom",
        mode=str(raw.get("mode", "diagnose")).strip().lower() or "diagnose",
        risk_level=str(raw.get("risk_level", "low")).strip().lower() or "low",
        required_permission=str(raw.get("required_permission", "read")).strip().lower() or "read",
        instruction=str(raw.get("instruction", "")).strip(),
        variables={str(k): str(v) for k, v in variables.items()} if isinstance(variables, dict) else {},
        precheck_commands=_string_list(raw.get("precheck_commands", [])),
        read_commands=_string_list(raw.get("read_commands", [])),
        apply_commands=_string_list(raw.get("apply_commands", [])),
        verify_commands=_string_list(raw.get("verify_commands", [])),
        postcheck_commands=_string_list(raw.get("postcheck_commands", [])),
        rollback_commands=_string_list(raw.get("rollback_commands", [])),
        auto_rollback_on_failure=_to_bool(raw.get("auto_rollback_on_failure", True), default=True),
        tags=_string_list(raw.get("tags", [])),
        source=source,
    )
    try:
        validate_skill(item)
    except ValueError:
        return None
    return item


def validate_skill(skill: SkillTemplate) -> None:
    if not normalize_skill_name(skill.name):
        raise ValueError("skill name is required")
    if not skill.title.strip():
        raise ValueError("skill title is required")
    if skill.mode not in {"diagnose", "fix", "workflow"}:
        raise ValueError("skill mode must be diagnose, fix or workflow")
    if skill.risk_level not in {"low", "medium", "high", "critical"}:
        raise ValueError("risk_level must be low, medium, high or critical")
    if skill.required_permission not in {"read", "write", "admin"}:
        raise ValueError("required_permission must be read, write or admin")
    if not skill.instruction.strip():
        raise ValueError("skill instruction is required")
    if not (skill.precheck_commands or skill.read_commands or skill.apply_commands):
        raise ValueError("skill must include at least one precheck/read/apply command")
    if skill.mode in {"fix", "workflow"} and skill.apply_commands and not skill.rollback_commands:
        raise ValueError("fix/workflow skills with apply commands must include rollback_commands")
    if skill.apply_commands and not (skill.verify_commands or skill.postcheck_commands):
        raise ValueError("skills with apply commands should include verify_commands or postcheck_commands")


def normalize_skill_name(name: str) -> str:
    text = str(name or "").strip().lower()
    out = []
    for ch in text:
        if ch.isalnum() or ch in {"-", "_"}:
            out.append(ch)
        elif ch.isspace():
            out.append("-")
    return "".join(out).strip("-_")


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _safe_format(command: str, values: dict[str, str]) -> str:
    rendered = str(command)
    for key, value in values.items():
        rendered = rendered.replace("{" + key + "}", str(value))
    return rendered


def _to_bool(value: Any, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def _build_evidence_graph(outputs: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    previous_id = ""
    for idx, row in enumerate(outputs, start=1):
        phase = str(row.get("phase", "unknown"))
        command = str(row.get("command", ""))
        node_id = f"{phase}-{idx}"
        nodes.append(
            {
                "id": node_id,
                "phase": phase,
                "command": command,
                "exit_code": int(row.get("exit_code", 1)),
                "started_at": str(row.get("started_at", "")),
                "finished_at": str(row.get("finished_at", "")),
            }
        )
        if previous_id:
            edges.append({"from": previous_id, "to": node_id, "relation": "next"})
        previous_id = node_id
    return {"nodes": nodes, "edges": edges}


def _now_utc_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
