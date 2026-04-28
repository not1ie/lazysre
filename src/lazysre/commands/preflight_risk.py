from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lazysre.cli.policy import assess_command
from lazysre.cli.policy_center import PolicyCenter


@dataclass(slots=True)
class RiskFactor:
    factor: str
    weight: int
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "factor": self.factor,
            "weight": self.weight,
            "detail": self.detail,
        }


@dataclass(slots=True)
class PreflightRiskResult:
    risk_score: int
    risk_factors: list[RiskFactor]
    blast_radius: str
    recommended_time: str
    safer_alternative: str
    risk_level: str
    context: dict[str, Any]
    approval_escalation: dict[str, Any]
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": [x.to_dict() for x in self.risk_factors],
            "blast_radius": self.blast_radius,
            "recommended_time": self.recommended_time,
            "safer_alternative": self.safer_alternative,
            "context": dict(self.context),
            "approval_escalation": dict(self.approval_escalation),
            "source": self.source,
        }


def collect_preflight_risk_context(
    *,
    command_text: str,
    context_name: str,
    policy_file: Path,
    audit_log: Path,
    incidents_file: Path,
    dependency_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    center = PolicyCenter(policy_file.expanduser())
    ctx = center.resolve_context(environment=context_name.strip() or "")
    payload = center.show()
    env_cfg = _resolve_policy_env_config(payload, tenant=ctx.tenant, environment=ctx.environment)
    maintenance = _resolve_maintenance_window(env_cfg)
    now = datetime.now(UTC)
    in_window = _is_in_maintenance_window(now, maintenance)

    recent_success = _calc_recent_command_success_rate(
        audit_log=audit_log.expanduser(),
        command_text=command_text,
        days=7,
    )
    incident_stats = _calc_incident_history(incidents_file.expanduser(), command_text=command_text, days=30)
    dependency = dependency_summary or {}

    return {
        "now_utc": now.isoformat(),
        "tenant": ctx.tenant,
        "environment": ctx.environment,
        "actor_role": ctx.actor_role,
        "maintenance_window": maintenance,
        "in_maintenance_window": in_window,
        "recent_command_success_rate_7d": recent_success,
        "incident_history_30d": incident_stats,
        "dependency_health": dependency,
    }


def build_preflight_risk_result(
    *,
    command_text: str,
    context_data: dict[str, Any],
    source: str = "heuristic",
) -> PreflightRiskResult:
    argv = _split_command(command_text)
    policy = assess_command(argv, approval_mode="balanced")
    base = {"low": 20, "medium": 45, "high": 70, "critical": 85}.get(policy.risk_level, 45)
    score = int(base)
    factors: list[RiskFactor] = [
        RiskFactor("command_policy_level", int(base), f"policy risk={policy.risk_level}"),
    ]

    in_window = bool(context_data.get("in_maintenance_window", False))
    if not in_window:
        score += 12
        factors.append(RiskFactor("outside_maintenance_window", 12, "当前不在维护窗口"))

    success_rate = float(context_data.get("recent_command_success_rate_7d", 0.5) or 0.0)
    if success_rate < 0.6:
        weight = 18 if success_rate < 0.3 else 10
        score += weight
        factors.append(RiskFactor("low_recent_success_rate", weight, f"7d success rate={success_rate:.2f}"))

    incident = context_data.get("incident_history_30d", {})
    if isinstance(incident, dict):
        count = int(incident.get("count", 0) or 0)
        if count > 0:
            weight = min(12, count * 2)
            score += weight
            factors.append(RiskFactor("incident_recurrence", weight, f"30d related incidents={count}"))

    dependency = context_data.get("dependency_health", {})
    if isinstance(dependency, dict):
        unhealthy = int(dependency.get("unhealthy_services", 0) or 0) + int(dependency.get("bad_nodes", 0) or 0)
        if unhealthy > 0:
            weight = min(15, unhealthy * 3)
            score += weight
            factors.append(RiskFactor("upstream_degraded", weight, f"dependency unhealthy units={unhealthy}"))

    score = max(0, min(100, score))
    risk_level = _risk_level_by_score(score)
    blast_radius = _infer_blast_radius(command_text)
    recommended_time = _suggest_time_window(context_data)
    safer = _suggest_safer_alternative(command_text)
    escalation = {
        "triggered": score >= 70,
        "reason": "risk_score >= 70",
        "required_approval_mode": "strict" if score >= 70 else "balanced",
    }
    return PreflightRiskResult(
        risk_score=score,
        risk_factors=factors,
        blast_radius=blast_radius,
        recommended_time=recommended_time,
        safer_alternative=safer,
        risk_level=risk_level,
        context=context_data,
        approval_escalation=escalation,
        source=source,
    )


def render_preflight_risk_text(result: PreflightRiskResult) -> str:
    rows = [
        "LazySRE Preflight Risk",
        f"- risk_score: {result.risk_score}",
        f"- risk_level: {result.risk_level}",
        f"- blast_radius: {result.blast_radius}",
        f"- recommended_time: {result.recommended_time}",
        f"- safer_alternative: {result.safer_alternative}",
        f"- approval_escalation: {result.approval_escalation.get('triggered', False)}",
        "",
        "risk_factors:",
    ]
    for factor in result.risk_factors:
        rows.append(f"- {factor.factor} (+{factor.weight}): {factor.detail}")
    return "\n".join(rows)


def render_preflight_risk_payload(payload: dict[str, Any]) -> str:
    lines = [
        "LazySRE Preflight Risk",
        f"- risk_score: {payload.get('risk_score', '-')}",
        f"- risk_level: {payload.get('risk_level', '-')}",
        f"- blast_radius: {payload.get('blast_radius', '-')}",
        f"- recommended_time: {payload.get('recommended_time', '-')}",
        f"- safer_alternative: {payload.get('safer_alternative', '-')}",
        f"- approval_escalation: {payload.get('approval_escalated', payload.get('approval_escalation', {}))}",
        "",
        "risk_factors:",
    ]
    factors = payload.get("risk_factors", [])
    if isinstance(factors, list):
        for raw in factors:
            if not isinstance(raw, dict):
                continue
            lines.append(
                f"- {raw.get('factor', '-')} (+{raw.get('weight', 0)}): {raw.get('detail', '')}"
            )
    return "\n".join(lines)


def _split_command(command_text: str) -> list[str]:
    text = str(command_text or "").strip()
    if not text:
        return []
    return [x for x in text.split(" ") if x]


def _resolve_policy_env_config(payload: dict[str, Any], *, tenant: str, environment: str) -> dict[str, Any]:
    tenants = payload.get("tenants", {})
    if not isinstance(tenants, dict):
        return {}
    tenant_cfg = tenants.get(tenant, {})
    if not isinstance(tenant_cfg, dict):
        return {}
    envs = tenant_cfg.get("environments", {})
    if not isinstance(envs, dict):
        return {}
    env = envs.get(environment, {})
    return env if isinstance(env, dict) else {}


def _resolve_maintenance_window(env_cfg: dict[str, Any]) -> dict[str, str]:
    raw = env_cfg.get("maintenance_window", {})
    if not isinstance(raw, dict):
        return {"start": "", "end": "", "timezone": "UTC"}
    return {
        "start": str(raw.get("start", "")).strip(),
        "end": str(raw.get("end", "")).strip(),
        "timezone": str(raw.get("timezone", "UTC")).strip() or "UTC",
    }


def _is_in_maintenance_window(now: datetime, window: dict[str, str]) -> bool:
    start = window.get("start", "")
    end = window.get("end", "")
    if not start or not end:
        return False
    try:
        s_hour, s_min = [int(x) for x in start.split(":", 1)]
        e_hour, e_min = [int(x) for x in end.split(":", 1)]
    except Exception:
        return False
    current = now.hour * 60 + now.minute
    s = s_hour * 60 + s_min
    e = e_hour * 60 + e_min
    if s <= e:
        return s <= current <= e
    return current >= s or current <= e


def _calc_recent_command_success_rate(*, audit_log: Path, command_text: str, days: int) -> float:
    if not audit_log.exists():
        return 0.5
    limit_time = datetime.now(UTC) - timedelta(days=max(1, days))
    hits = 0
    ok = 0
    needle = command_text.strip().lower()
    try:
        lines = audit_log.read_text(encoding="utf-8").splitlines()
    except Exception:
        return 0.5
    for raw in lines:
        text = raw.strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except Exception:
            continue
        if not isinstance(row, dict):
            continue
        ts = _parse_time(str(row.get("timestamp", "")).strip())
        if not ts or ts < limit_time:
            continue
        command = row.get("command")
        if isinstance(command, list):
            cmd = " ".join(str(x) for x in command if str(x).strip()).strip()
        else:
            cmd = str(command or "").strip()
        if not cmd:
            continue
        if needle and needle not in cmd.lower():
            continue
        hits += 1
        if bool(row.get("ok")):
            ok += 1
    if hits <= 0:
        return 0.5
    return round(ok / hits, 4)


def _calc_incident_history(incidents_file: Path, *, command_text: str, days: int) -> dict[str, Any]:
    if not incidents_file.exists():
        return {"count": 0, "samples": []}
    limit_time = datetime.now(UTC) - timedelta(days=max(1, days))
    try:
        payload = json.loads(incidents_file.read_text(encoding="utf-8"))
    except Exception:
        return {"count": 0, "samples": []}
    if not isinstance(payload, dict):
        return {"count": 0, "samples": []}
    rows = payload.get("archive", [])
    if not isinstance(rows, list):
        rows = []
    needle = command_text.strip().lower()
    matched: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        updated = _parse_time(str(row.get("updated_at_utc", "")).strip())
        if not updated or updated < limit_time:
            continue
        text = " ".join(
            [
                str(row.get("title", "")),
                str(row.get("summary", "")),
                str(row.get("resolution", "")),
            ]
        ).lower()
        if needle and needle not in text:
            continue
        matched.append(
            {
                "id": str(row.get("id", "")),
                "title": str(row.get("title", ""))[:120],
                "updated_at_utc": str(row.get("updated_at_utc", "")),
            }
        )
    return {"count": len(matched), "samples": matched[:5]}


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


def _risk_level_by_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _infer_blast_radius(command_text: str) -> str:
    text = command_text.lower()
    if "namespace" in text:
        return "namespace-wide workload impact"
    if "deployment/" in text or "deploy/" in text:
        return "single deployment + upstream clients"
    if "service " in text or "service/" in text:
        return "single service + dependent callers"
    if "node" in text:
        return "node-level impact"
    return "single target"


def _suggest_time_window(context_data: dict[str, Any]) -> str:
    in_window = bool(context_data.get("in_maintenance_window", False))
    maintenance = context_data.get("maintenance_window", {})
    if not isinstance(maintenance, dict):
        maintenance = {}
    start = str(maintenance.get("start", "")).strip()
    end = str(maintenance.get("end", "")).strip()
    tz = str(maintenance.get("timezone", "UTC")).strip() or "UTC"
    if in_window:
        return f"now (inside maintenance window {start}-{end} {tz})"
    if start and end:
        return f"next maintenance window {start}-{end} {tz}"
    return "off-peak window recommended"


def _suggest_safer_alternative(command_text: str) -> str:
    text = command_text.strip()
    low = text.lower()
    if "rollout restart" in low:
        return "先执行 kubectl rollout status + 单副本灰度重启，再全量滚动"
    if "scale" in low:
        return "先 dry-run 并分级扩缩容（一次 10-20%）"
    if "delete" in low:
        return "优先 cordon/drain 或 patch 标记，避免直接 delete"
    return "先 dry-run + verify，再执行写操作"
