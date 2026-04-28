from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _ticket_id() -> str:
    ts = _now().strftime("%Y%m%d-%H%M%S")
    suffix = random.randint(100, 999)
    return f"CHG-{ts}-{suffix}"


@dataclass(slots=True)
class ApprovalTicket:
    id: str
    created_at: str
    expires_at: str
    status: str
    tenant: str
    environment: str
    actor_role: str
    risk_level: str
    reason: str
    requester: str
    required_approvers: int = 1
    approvals: list[dict[str, str]] = field(default_factory=list)
    command_prefix: str = ""
    target_hint: str = ""
    scope_note: str = ""
    approver: str = ""
    approved_at: str = ""
    comment: str = ""

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ApprovalTicket":
        return cls(
            id=str(payload.get("id", "")).strip(),
            created_at=str(payload.get("created_at", "")).strip(),
            expires_at=str(payload.get("expires_at", "")).strip(),
            status=str(payload.get("status", "pending")).strip() or "pending",
            tenant=str(payload.get("tenant", "default")).strip() or "default",
            environment=str(payload.get("environment", "prod")).strip() or "prod",
            actor_role=str(payload.get("actor_role", "operator")).strip() or "operator",
            risk_level=str(payload.get("risk_level", "critical")).strip() or "critical",
            reason=str(payload.get("reason", "")).strip(),
            requester=str(payload.get("requester", "unknown")).strip() or "unknown",
            required_approvers=max(1, int(payload.get("required_approvers", 1) or 1)),
            approvals=[
                {
                    "approver": str(item.get("approver", "")).strip(),
                    "at": str(item.get("at", "")).strip(),
                    "comment": str(item.get("comment", "")).strip(),
                }
                for item in payload.get("approvals", [])
                if isinstance(item, dict) and str(item.get("approver", "")).strip()
            ]
            if isinstance(payload.get("approvals", []), list)
            else [],
            command_prefix=str(payload.get("command_prefix", "")).strip().lower(),
            target_hint=str(payload.get("target_hint", "")).strip().lower(),
            scope_note=str(payload.get("scope_note", "")).strip(),
            approver=str(payload.get("approver", "")).strip(),
            approved_at=str(payload.get("approved_at", "")).strip(),
            comment=str(payload.get("comment", "")).strip(),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ApprovalStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(".data/lsre-approvals.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        *,
        reason: str,
        risk_level: str,
        tenant: str,
        environment: str,
        actor_role: str,
        requester: str,
        expires_hours: int = 8,
        required_approvers: int = 1,
        command_prefix: str = "",
        target_hint: str = "",
        scope_note: str = "",
    ) -> ApprovalTicket:
        rows = self._load()
        ticket = ApprovalTicket(
            id=_ticket_id(),
            created_at=_now_iso(),
            expires_at=(_now() + timedelta(hours=max(1, min(expires_hours, 168)))).isoformat(),
            status="pending",
            tenant=tenant.strip() or "default",
            environment=environment.strip() or "prod",
            actor_role=actor_role.strip() or "operator",
            risk_level=risk_level.strip().lower() or "critical",
            reason=reason.strip(),
            requester=requester.strip() or "unknown",
            required_approvers=max(1, min(required_approvers, 5)),
            command_prefix=command_prefix.strip().lower(),
            target_hint=target_hint.strip().lower(),
            scope_note=scope_note.strip(),
        )
        rows.insert(0, ticket.to_dict())
        self._save(rows[:1000])
        return ticket

    def approve(self, ticket_id: str, *, approver: str, comment: str = "") -> ApprovalTicket | None:
        rows = self._load()
        normalized_approver = approver.strip() or "unknown"
        for idx, row in enumerate(rows):
            item = ApprovalTicket.from_dict(row)
            if item.id != ticket_id:
                continue
            if item.status in {"rejected", "expired"}:
                return item
            if self._is_expired(item):
                item.status = "expired"
                rows[idx] = item.to_dict()
                self._save(rows)
                return item
            existing = {x.get("approver", "").strip().lower() for x in item.approvals}
            if normalized_approver.lower() not in existing:
                item.approvals.append(
                    {
                        "approver": normalized_approver,
                        "at": _now_iso(),
                        "comment": comment.strip(),
                    }
                )
            approved_count = len({x.get("approver", "").strip().lower() for x in item.approvals if x.get("approver")})
            if approved_count >= max(1, item.required_approvers):
                item.status = "approved"
                item.approver = normalized_approver
                item.approved_at = _now_iso()
                item.comment = comment.strip()
            else:
                item.status = "pending"
            rows[idx] = item.to_dict()
            self._save(rows)
            return item
        return None

    def list(self, *, status: str = "all", limit: int = 50) -> list[ApprovalTicket]:
        rows = [ApprovalTicket.from_dict(x) for x in self._load()]
        dirty = False
        for item in rows:
            if item.status == "pending" and self._is_expired(item):
                item.status = "expired"
                dirty = True
        if dirty:
            self._save([x.to_dict() for x in rows])
        normalized = status.strip().lower()
        if normalized in {"pending", "approved", "rejected", "expired"}:
            rows = [x for x in rows if x.status == normalized]
        rows.sort(key=lambda x: x.created_at, reverse=True)
        return rows[: max(1, min(limit, 500))]

    def get(self, ticket_id: str) -> ApprovalTicket | None:
        for row in self._load():
            item = ApprovalTicket.from_dict(row)
            if item.id == ticket_id:
                if item.status == "pending" and self._is_expired(item):
                    item.status = "expired"
                    self._update(item)
                return item
        return None

    def is_approved_and_valid(self, ticket_id: str) -> bool:
        item = self.get(ticket_id)
        if not item:
            return False
        if item.status != "approved":
            return False
        return not self._is_expired(item)

    def validate_for_execution(
        self,
        ticket_id: str,
        *,
        tenant: str,
        environment: str,
        actor_role: str,
        risk_level: str,
        command: list[str],
    ) -> tuple[bool, str, ApprovalTicket | None]:
        item = self.get(ticket_id)
        if not item:
            return False, "ticket_not_found", None
        if item.status != "approved":
            return False, f"ticket_status_{item.status}", item
        if self._is_expired(item):
            return False, "ticket_expired", item

        ticket_tenant = _norm_text(item.tenant)
        ticket_env = _norm_text(item.environment)
        ticket_role = _norm_text(item.actor_role)
        req_tenant = _norm_text(tenant)
        req_env = _norm_text(environment)
        req_role = _norm_text(actor_role)
        if req_tenant and ticket_tenant and req_tenant != ticket_tenant:
            return False, "tenant_mismatch", item
        if req_env and ticket_env and req_env != ticket_env:
            return False, "environment_mismatch", item
        if req_role and ticket_role and req_role != ticket_role:
            return False, "actor_role_mismatch", item

        req_risk = _norm_risk(risk_level)
        ticket_risk = _norm_risk(item.risk_level)
        if req_risk and ticket_risk:
            if RISK_ORDER.get(ticket_risk, 0) < RISK_ORDER.get(req_risk, 0):
                return False, "risk_scope_mismatch", item

        joined = " ".join(command).strip().lower()
        if item.command_prefix and joined and not joined.startswith(item.command_prefix):
            return False, "command_prefix_mismatch", item
        if item.target_hint and item.target_hint not in joined:
            return False, "target_mismatch", item
        return True, "ok", item

    def _load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return []
        if not isinstance(payload, list):
            return []
        out: list[dict[str, Any]] = []
        for item in payload:
            if isinstance(item, dict):
                out.append(item)
        return out

    def _save(self, rows: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    def _update(self, target: ApprovalTicket) -> None:
        rows = self._load()
        for idx, row in enumerate(rows):
            item = ApprovalTicket.from_dict(row)
            if item.id == target.id:
                rows[idx] = target.to_dict()
                self._save(rows)
                return

    def _is_expired(self, item: ApprovalTicket) -> bool:
        try:
            expires = datetime.fromisoformat(item.expires_at.replace("Z", "+00:00"))
        except Exception:
            return True
        return expires < _now()


def _norm_text(value: str) -> str:
    return str(value or "").strip().lower()


def _norm_risk(value: str) -> str:
    lowered = _norm_text(value)
    if lowered in RISK_ORDER:
        return lowered
    return ""
