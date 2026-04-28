from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from lazysre.cli.approval import ApprovalStore
from lazysre.cli.audit import AuditLogger
from lazysre.cli.policy import PolicyDecision, assess_command, build_risk_report
from lazysre.cli.policy_center import PolicyCenter, PolicyContext
from lazysre.cli.types import ExecResult


@dataclass(slots=True)
class SafeExecutor:
    dry_run: bool = True
    timeout_sec: float = 20.0
    approval_mode: str = "balanced"
    approval_granted: bool = False
    approval_callback: Callable[[list[str], PolicyDecision], bool] | None = None
    audit_logger: AuditLogger | None = None
    policy_file: str = ".data/lsre-policy.json"
    tenant: str = ""
    environment: str = ""
    actor_role: str = ""
    actor_id: str = ""
    allowed_binaries: set[str] = field(
        default_factory=lambda: {"kubectl", "docker", "curl", "tail"}
    )
    _policy_center: PolicyCenter | None = None

    def preflight(
        self, command: list[str]
    ) -> tuple[PolicyDecision | None, ExecResult | None, bool]:
        approved = self.approval_granted
        safe_command = _sanitize_command(command)
        if not command:
            result = ExecResult(
                ok=False,
                command=safe_command,
                stderr="empty command",
                exit_code=1,
                dry_run=self.dry_run,
            )
            self.record(result)
            return None, result, approved

        binary = command[0]
        if binary not in self.allowed_binaries:
            result = ExecResult(
                ok=False,
                command=safe_command,
                stderr=f"blocked command: {binary}",
                exit_code=126,
                dry_run=self.dry_run,
                blocked=True,
                risk_level="critical",
                policy_reasons=[f"binary '{binary}' is not in allowlist"],
            )
            self.record(result)
            return None, result, approved

        decision = assess_command(command, approval_mode=self.approval_mode)
        policy_center = self._get_policy_center()
        context = self._resolve_context(policy_center)
        policy_ticket = os.environ.get("LAZYSRE_APPROVAL_TICKET", "").strip()
        ticket_valid, ticket_status = self._validate_approval_ticket(
            policy_ticket,
            command=command,
            context=context,
            risk_level=decision.risk_level,
        )
        if policy_center:
            patch = policy_center.evaluate(
                command=command,
                risk_level=decision.risk_level,
                requires_approval=decision.requires_approval,
                approval_mode=self.approval_mode,
                context=context,
                has_approval_ticket=ticket_valid,
            )
            if patch.reasons:
                decision.reasons.extend([x for x in patch.reasons if x not in decision.reasons])
            decision.requires_approval = bool(decision.requires_approval or patch.requires_approval)
            if patch.blocked:
                decision.blocked = True
                decision.blocked_reason = patch.blocked_reason or decision.blocked_reason
            if patch.metadata:
                decision.policy_metadata.update(patch.metadata)
            if policy_ticket:
                decision.policy_metadata["approval_ticket"] = policy_ticket
                decision.policy_metadata["approval_ticket_valid"] = ticket_valid
                decision.policy_metadata["approval_ticket_status"] = ticket_status
                decision.policy_metadata["approval_ticket_scope"] = {
                    "tenant": context.tenant,
                    "environment": context.environment,
                    "actor_role": context.actor_role,
                }
        destructive = _contains_destructive_action(command)
        if destructive:
            decision.requires_approval = True
            if decision.risk_level in {"low", "medium"}:
                decision.risk_level = "high"
            if "destructive keyword detected, force confirm mode" not in decision.reasons:
                decision.reasons.append("destructive keyword detected, force confirm mode")
        risk_report = build_risk_report(command, decision)
        if decision.policy_metadata:
            risk_report["policy"] = dict(decision.policy_metadata)
        if decision.blocked:
            result = ExecResult(
                ok=False,
                command=safe_command,
                stderr=decision.blocked_reason or "blocked by policy",
                exit_code=126,
                dry_run=self.dry_run,
                blocked=True,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                risk_report=risk_report,
                requires_approval=decision.requires_approval,
                approved=approved,
            )
            self.record(result)
            return decision, result, approved

        if (not self.dry_run) and (not approved):
            interactive_gate = decision.risk_level in {"high", "critical"} or destructive
            if interactive_gate and self.approval_callback:
                if self.approval_callback(safe_command, decision):
                    approved = True
                else:
                    result = ExecResult(
                        ok=False,
                        command=safe_command,
                        stderr="approval rejected by user",
                        exit_code=125,
                        dry_run=False,
                        blocked=True,
                        risk_level=decision.risk_level,
                        policy_reasons=decision.reasons,
                        risk_report=risk_report,
                        requires_approval=True,
                        approved=False,
                    )
                    self.record(result)
                    return decision, result, approved
            elif decision.requires_approval:
                result = ExecResult(
                    ok=False,
                    command=safe_command,
                    stderr=(
                        "approval required by policy. "
                        "Re-run with --approve and review impact first."
                    ),
                    exit_code=125,
                    dry_run=False,
                    blocked=True,
                    risk_level=decision.risk_level,
                    policy_reasons=decision.reasons,
                    risk_report=risk_report,
                    requires_approval=True,
                    approved=False,
                )
                self.record(result)
                return decision, result, approved
        return decision, None, approved

    async def run(self, command: list[str]) -> ExecResult:
        binary = command[0] if command else ""
        safe_command = _sanitize_command(command)
        decision, blocked, approved = self.preflight(command)
        if blocked:
            return blocked
        assert decision is not None
        risk_report = build_risk_report(command, decision)
        if decision.policy_metadata:
            risk_report["policy"] = dict(decision.policy_metadata)

        if self.dry_run:
            result = ExecResult(
                ok=True,
                command=safe_command,
                stdout=f"[dry-run] {' '.join(safe_command)}",
                exit_code=0,
                dry_run=True,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                risk_report=risk_report,
                requires_approval=decision.requires_approval,
                approved=approved,
            )
            self.record(result)
            return result

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_sec)
        except TimeoutError:
            result = ExecResult(
                ok=False,
                command=safe_command,
                stderr=f"timeout after {self.timeout_sec}s",
                exit_code=124,
                dry_run=False,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                risk_report=risk_report,
                requires_approval=decision.requires_approval,
                approved=approved,
            )
            self.record(result)
            return result
        except FileNotFoundError:
            result = ExecResult(
                ok=False,
                command=safe_command,
                stderr=f"binary not found: {binary}",
                exit_code=127,
                dry_run=False,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                risk_report=risk_report,
                requires_approval=decision.requires_approval,
                approved=approved,
            )
            self.record(result)
            return result

        result = ExecResult(
            ok=(proc.returncode == 0),
            command=safe_command,
            stdout=stdout.decode("utf-8", errors="replace").strip(),
            stderr=stderr.decode("utf-8", errors="replace").strip(),
            exit_code=int(proc.returncode or 0),
            dry_run=False,
            risk_level=decision.risk_level,
            policy_reasons=decision.reasons,
            risk_report=risk_report,
            requires_approval=decision.requires_approval,
            approved=approved,
        )
        self.record(result)
        return result

    def record(self, result: ExecResult) -> None:
        if not self.audit_logger:
            return
        self.audit_logger.write(
            {
                "command": result.command,
                "ok": result.ok,
                "exit_code": result.exit_code,
                "dry_run": result.dry_run,
                "blocked": result.blocked,
                "risk_level": result.risk_level,
                "requires_approval": result.requires_approval,
                "approved": result.approved,
                "policy_reasons": result.policy_reasons,
                "risk_report": result.risk_report,
                "stderr": result.stderr[:500],
                "stdout_preview": result.stdout[:300],
            }
        )

    def _get_policy_center(self) -> PolicyCenter | None:
        if self._policy_center is not None:
            return self._policy_center
        try:
            policy_path = self.policy_file or os.environ.get("LAZYSRE_POLICY_FILE", ".data/lsre-policy.json")
            path = Path(policy_path).expanduser()
            self._policy_center = PolicyCenter(path)
        except Exception:
            self._policy_center = None
        return self._policy_center

    def _resolve_context(self, policy_center: PolicyCenter | None) -> PolicyContext:
        if policy_center:
            return policy_center.resolve_context(
                tenant=self.tenant or os.environ.get("LAZYSRE_TENANT", ""),
                environment=self.environment or os.environ.get("LAZYSRE_ENVIRONMENT", ""),
                actor_role=self.actor_role or os.environ.get("LAZYSRE_ACTOR_ROLE", ""),
                actor_id=self.actor_id or os.environ.get("LAZYSRE_ACTOR_ID", ""),
            )
        tenant = (self.tenant or os.environ.get("LAZYSRE_TENANT", "")).strip() or "default"
        environment = (self.environment or os.environ.get("LAZYSRE_ENVIRONMENT", "")).strip() or "prod"
        actor_role = (self.actor_role or os.environ.get("LAZYSRE_ACTOR_ROLE", "")).strip() or "operator"
        actor_id = (self.actor_id or os.environ.get("LAZYSRE_ACTOR_ID", "")).strip()
        return PolicyContext(
            tenant=tenant,
            environment=environment,
            actor_role=actor_role,
            actor_id=actor_id,
        )

    def _validate_approval_ticket(
        self,
        ticket_id: str,
        *,
        command: list[str],
        context: PolicyContext,
        risk_level: str,
    ) -> tuple[bool, str]:
        text = str(ticket_id or "").strip()
        if not text:
            return False, "missing"
        try:
            store_path = Path(os.environ.get("LAZYSRE_APPROVAL_STORE", ".data/lsre-approvals.json")).expanduser()
            valid, reason, _ticket = ApprovalStore(store_path).validate_for_execution(
                text,
                tenant=context.tenant,
                environment=context.environment,
                actor_role=context.actor_role,
                risk_level=risk_level,
                command=command,
            )
            return valid, reason
        except Exception:
            return False, "store_error"


def _sanitize_command(command: list[str]) -> list[str]:
    if not command:
        return []
    out: list[str] = []
    idx = 0
    while idx < len(command):
        token = command[idx]
        if token in {"--token", "--password", "--passwd"} and idx + 1 < len(command):
            out.extend([token, "***"])
            idx += 2
            continue
        if token.startswith("Bearer "):
            out.append("Bearer ***")
            idx += 1
            continue
        out.append(token)
        idx += 1
    return out


def _contains_destructive_action(command: list[str]) -> bool:
    if not command:
        return False
    text = " ".join(command).lower()
    keywords = [
        " delete ",
        " patch ",
        " restart ",
        " scale ",
        " rollout restart",
        " rm ",
        " rmi ",
        " prune",
    ]
    padded = f" {text} "
    return any(key in padded for key in keywords)
