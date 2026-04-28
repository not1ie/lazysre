from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(slots=True)
class PolicyContext:
    tenant: str = "default"
    environment: str = "prod"
    actor_role: str = "operator"
    actor_id: str = ""


@dataclass(slots=True)
class PolicyDecisionPatch:
    blocked: bool = False
    blocked_reason: str = ""
    requires_approval: bool = False
    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class PolicyCenter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._payload = self._load_or_default()

    @classmethod
    def default(cls) -> "PolicyCenter":
        return cls(Path(".data/lsre-policy.json"))

    def show(self) -> dict[str, Any]:
        return _clone_dict(self._payload)

    def init(self, *, force: bool = False) -> dict[str, Any]:
        if self.path.exists() and not force:
            return _clone_dict(self._payload)
        self._payload = _default_policy_payload()
        self._save()
        return _clone_dict(self._payload)

    def update_defaults(
        self,
        *,
        tenant: str | None = None,
        environment: str | None = None,
        actor_role: str | None = None,
        actor_id: str | None = None,
    ) -> dict[str, Any]:
        defaults = self._payload.setdefault("defaults", {})
        if tenant is not None and tenant.strip():
            defaults["tenant"] = _norm_name(tenant)
        if environment is not None and environment.strip():
            defaults["environment"] = _norm_name(environment)
        if actor_role is not None and actor_role.strip():
            defaults["actor_role"] = _norm_name(actor_role)
        if actor_id is not None:
            defaults["actor_id"] = actor_id.strip()
        self._save()
        return _clone_dict(defaults)

    def set_environment_guard(
        self,
        *,
        tenant: str,
        environment: str,
        min_approval_risk: str | None = None,
        require_ticket_for_critical: bool | None = None,
        high_risk_min_approvers: int | None = None,
        critical_risk_min_approvers: int | None = None,
    ) -> dict[str, Any]:
        env_cfg = self._ensure_environment(tenant=tenant, environment=environment)
        if min_approval_risk:
            level = _norm_risk(min_approval_risk)
            if level:
                env_cfg["min_approval_risk"] = level
        if require_ticket_for_critical is not None:
            env_cfg["require_ticket_for_critical"] = bool(require_ticket_for_critical)
        approvers_cfg = env_cfg.setdefault("min_approvers_by_risk", {})
        if high_risk_min_approvers is not None:
            approvers_cfg["high"] = max(1, min(int(high_risk_min_approvers), 5))
        if critical_risk_min_approvers is not None:
            approvers_cfg["critical"] = max(1, min(int(critical_risk_min_approvers), 5))
        self._save()
        return _clone_dict(env_cfg)

    def set_role_max_risk(
        self,
        *,
        tenant: str,
        environment: str,
        role: str,
        max_risk: str,
    ) -> dict[str, Any]:
        env_cfg = self._ensure_environment(tenant=tenant, environment=environment)
        role_cfg = env_cfg.setdefault("role_max_risk", {})
        role_cfg[_norm_name(role)] = _norm_risk(max_risk) or "critical"
        self._save()
        return _clone_dict(role_cfg)

    def add_block_pattern(self, *, tenant: str, environment: str, pattern: str) -> list[str]:
        env_cfg = self._ensure_environment(tenant=tenant, environment=environment)
        patterns = env_cfg.setdefault("blocked_command_patterns", [])
        text = pattern.strip().lower()
        if text and text not in patterns:
            patterns.append(text)
            self._save()
        return [str(x) for x in patterns if str(x).strip()]

    def add_allowed_binary(self, *, tenant: str, environment: str, binary: str) -> list[str]:
        env_cfg = self._ensure_environment(tenant=tenant, environment=environment)
        values = env_cfg.setdefault("allowed_binaries", [])
        text = binary.strip()
        if text and text not in values:
            values.append(text)
            self._save()
        return [str(x) for x in values if str(x).strip()]

    def resolve_context(
        self,
        *,
        tenant: str = "",
        environment: str = "",
        actor_role: str = "",
        actor_id: str = "",
    ) -> PolicyContext:
        defaults = self._payload.get("defaults", {})
        return PolicyContext(
            tenant=_norm_name(tenant or str(defaults.get("tenant", "default")) or "default"),
            environment=_norm_name(environment or str(defaults.get("environment", "prod")) or "prod"),
            actor_role=_norm_name(actor_role or str(defaults.get("actor_role", "operator")) or "operator"),
            actor_id=(actor_id or str(defaults.get("actor_id", ""))).strip(),
        )

    def evaluate(
        self,
        *,
        command: list[str],
        risk_level: str,
        requires_approval: bool,
        approval_mode: str,
        context: PolicyContext,
        has_approval_ticket: bool = False,
    ) -> PolicyDecisionPatch:
        patch = PolicyDecisionPatch(
            blocked=False,
            blocked_reason="",
            requires_approval=requires_approval,
            reasons=[],
            metadata={
                "policy_file": str(self.path),
                "tenant": context.tenant,
                "environment": context.environment,
                "actor_role": context.actor_role,
                "actor_id": context.actor_id,
            },
        )
        env_cfg = self._get_environment(context)
        binary = command[0] if command else ""
        joined = " ".join(command).lower().strip()

        allowed = [str(x) for x in env_cfg.get("allowed_binaries", []) if str(x).strip()]
        if allowed and binary and binary not in allowed:
            patch.blocked = True
            patch.blocked_reason = f"binary '{binary}' blocked by tenant policy"
            patch.reasons.append(f"租户策略不允许执行二进制: {binary}")

        if not patch.blocked:
            for pattern in [str(x).lower() for x in env_cfg.get("blocked_command_patterns", [])]:
                if pattern and pattern in joined:
                    patch.blocked = True
                    patch.blocked_reason = f"command contains blocked pattern: {pattern}"
                    patch.reasons.append(f"命中策略黑名单模式: {pattern}")
                    break

        role_limits = env_cfg.get("role_max_risk", {})
        if isinstance(role_limits, dict):
            max_risk = _norm_risk(str(role_limits.get(context.actor_role, role_limits.get("*", "critical"))))
            if max_risk and RISK_ORDER.get(_norm_risk(risk_level), 4) > RISK_ORDER.get(max_risk, 4):
                patch.blocked = True
                patch.blocked_reason = (
                    f"role '{context.actor_role}' max risk is {max_risk}, command risk is {_norm_risk(risk_level)}"
                )
                patch.reasons.append(
                    f"角色风险上限限制: role={context.actor_role} max={max_risk} current={_norm_risk(risk_level)}"
                )
                patch.metadata["role_max_risk"] = max_risk

        policy_min = _norm_risk(str(env_cfg.get("min_approval_risk", "")))
        mode_min = _min_approval_by_mode(approval_mode)
        threshold = _max_risk(policy_min or "low", mode_min)
        if RISK_ORDER.get(_norm_risk(risk_level), 4) >= RISK_ORDER.get(threshold, 3):
            patch.requires_approval = True
            patch.reasons.append(f"策略要求该风险级别必须审批: threshold={threshold}")

        need_ticket = bool(env_cfg.get("require_ticket_for_critical", True))
        if need_ticket and _norm_risk(risk_level) == "critical":
            patch.requires_approval = True
            if not has_approval_ticket:
                patch.blocked = True
                patch.blocked_reason = "critical action requires approval ticket"
                patch.reasons.append("critical 命令必须提供审批单号（LAZYSRE_APPROVAL_TICKET）")

        patch.metadata["policy_threshold"] = threshold
        patch.metadata["require_ticket_for_critical"] = need_ticket
        patch.metadata["min_approvers_required"] = self.min_approvers_required(
            tenant=context.tenant,
            environment=context.environment,
            risk_level=risk_level,
        )
        return patch

    def min_approvers_required(self, *, tenant: str, environment: str, risk_level: str) -> int:
        ctx = self.resolve_context(tenant=tenant, environment=environment)
        env_cfg = self._get_environment(ctx)
        risk = _norm_risk(risk_level) or "critical"
        mapping = env_cfg.get("min_approvers_by_risk", {})
        if not isinstance(mapping, dict):
            return 1
        value = mapping.get(risk, mapping.get("default", 1))
        try:
            return max(1, min(int(value), 5))
        except Exception:
            return 1

    def _ensure_environment(self, *, tenant: str, environment: str) -> dict[str, Any]:
        payload = self._payload
        tenants = payload.setdefault("tenants", {})
        ten = tenants.setdefault(_norm_name(tenant), {"environments": {}})
        envs = ten.setdefault("environments", {})
        return envs.setdefault(_norm_name(environment), _default_environment_policy())

    def _get_environment(self, context: PolicyContext) -> dict[str, Any]:
        tenants = self._payload.get("tenants", {})
        if not isinstance(tenants, dict):
            return _default_environment_policy()
        tenant = tenants.get(context.tenant)
        if not isinstance(tenant, dict):
            return _default_environment_policy()
        envs = tenant.get("environments", {})
        if not isinstance(envs, dict):
            return _default_environment_policy()
        env_cfg = envs.get(context.environment)
        if not isinstance(env_cfg, dict):
            return _default_environment_policy()
        return env_cfg

    def _load_or_default(self) -> dict[str, Any]:
        if not self.path.exists():
            payload = _default_policy_payload()
            self._payload = payload
            self._save()
            return payload
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            payload = _default_policy_payload()
        if not isinstance(payload, dict):
            payload = _default_policy_payload()
        payload.setdefault("version", 1)
        payload.setdefault("defaults", {})
        payload.setdefault("tenants", {})
        return payload

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _norm_name(text: str) -> str:
    value = str(text or "").strip().lower()
    out: list[str] = []
    for ch in value:
        if ch.isalnum() or ch in {"-", "_"}:
            out.append(ch)
        elif ch.isspace():
            out.append("-")
    return "".join(out).strip("-_") or "default"


def _norm_risk(text: str) -> str:
    lowered = str(text or "").strip().lower()
    if lowered in {"low", "medium", "high", "critical"}:
        return lowered
    return ""


def _min_approval_by_mode(mode: str) -> str:
    normalized = str(mode or "").strip().lower()
    if normalized == "strict":
        return "medium"
    if normalized == "permissive":
        return "critical"
    return "high"


def _max_risk(left: str, right: str) -> str:
    return left if RISK_ORDER.get(left, 1) >= RISK_ORDER.get(right, 1) else right


def _default_environment_policy() -> dict[str, Any]:
    return {
        "allowed_binaries": ["kubectl", "docker", "curl", "tail"],
        "blocked_command_patterns": [
            "delete namespace",
            "delete node",
            "docker system prune",
            "docker volume prune",
        ],
        "role_max_risk": {
            "viewer": "low",
            "operator": "high",
            "admin": "critical",
            "*": "high",
        },
        "min_approval_risk": "high",
        "require_ticket_for_critical": True,
        "min_approvers_by_risk": {
            "low": 1,
            "medium": 1,
            "high": 2,
            "critical": 2,
        },
    }


def _default_policy_payload() -> dict[str, Any]:
    return {
        "version": 1,
        "defaults": {
            "tenant": "default",
            "environment": "prod",
            "actor_role": "operator",
            "actor_id": "",
        },
        "tenants": {
            "default": {
                "environments": {
                    "prod": _default_environment_policy(),
                    "staging": {
                        **_default_environment_policy(),
                        "min_approval_risk": "medium",
                        "require_ticket_for_critical": False,
                        "min_approvers_by_risk": {
                            "low": 1,
                            "medium": 1,
                            "high": 1,
                            "critical": 1,
                        },
                    },
                }
            }
        },
    }


def _clone_dict(payload: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(payload, ensure_ascii=False))
