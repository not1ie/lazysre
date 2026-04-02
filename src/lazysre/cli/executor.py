from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Callable

from lazysre.cli.audit import AuditLogger
from lazysre.cli.policy import PolicyDecision, assess_command
from lazysre.cli.types import ExecResult


@dataclass(slots=True)
class SafeExecutor:
    dry_run: bool = True
    timeout_sec: float = 20.0
    approval_mode: str = "balanced"
    approval_granted: bool = False
    approval_callback: Callable[[list[str], PolicyDecision], bool] | None = None
    audit_logger: AuditLogger | None = None
    allowed_binaries: set[str] = field(
        default_factory=lambda: {"kubectl", "docker", "curl", "tail"}
    )

    def preflight(
        self, command: list[str]
    ) -> tuple[PolicyDecision | None, ExecResult | None, bool]:
        approved = self.approval_granted
        if not command:
            result = ExecResult(
                ok=False,
                command=command,
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
                command=command,
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
        if decision.blocked:
            result = ExecResult(
                ok=False,
                command=command,
                stderr=decision.blocked_reason or "blocked by policy",
                exit_code=126,
                dry_run=self.dry_run,
                blocked=True,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                requires_approval=decision.requires_approval,
                approved=approved,
            )
            self.record(result)
            return decision, result, approved

        if (not self.dry_run) and (not approved):
            interactive_gate = decision.risk_level in {"high", "critical"}
            if interactive_gate and self.approval_callback:
                if self.approval_callback(command, decision):
                    approved = True
                else:
                    result = ExecResult(
                        ok=False,
                        command=command,
                        stderr="approval rejected by user",
                        exit_code=125,
                        dry_run=False,
                        blocked=True,
                        risk_level=decision.risk_level,
                        policy_reasons=decision.reasons,
                        requires_approval=True,
                        approved=False,
                    )
                    self.record(result)
                    return decision, result, approved
            elif decision.requires_approval:
                result = ExecResult(
                    ok=False,
                    command=command,
                    stderr=(
                        "approval required by policy. "
                        "Re-run with --approve and review impact first."
                    ),
                    exit_code=125,
                    dry_run=False,
                    blocked=True,
                    risk_level=decision.risk_level,
                    policy_reasons=decision.reasons,
                    requires_approval=True,
                    approved=False,
                )
                self.record(result)
                return decision, result, approved
        return decision, None, approved

    async def run(self, command: list[str]) -> ExecResult:
        binary = command[0] if command else ""
        decision, blocked, approved = self.preflight(command)
        if blocked:
            return blocked
        assert decision is not None

        if self.dry_run:
            result = ExecResult(
                ok=True,
                command=command,
                stdout=f"[dry-run] {' '.join(command)}",
                exit_code=0,
                dry_run=True,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
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
                command=command,
                stderr=f"timeout after {self.timeout_sec}s",
                exit_code=124,
                dry_run=False,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                requires_approval=decision.requires_approval,
                approved=approved,
            )
            self.record(result)
            return result
        except FileNotFoundError:
            result = ExecResult(
                ok=False,
                command=command,
                stderr=f"binary not found: {binary}",
                exit_code=127,
                dry_run=False,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                requires_approval=decision.requires_approval,
                approved=approved,
            )
            self.record(result)
            return result

        result = ExecResult(
            ok=(proc.returncode == 0),
            command=command,
            stdout=stdout.decode("utf-8", errors="replace").strip(),
            stderr=stderr.decode("utf-8", errors="replace").strip(),
            exit_code=int(proc.returncode or 0),
            dry_run=False,
            risk_level=decision.risk_level,
            policy_reasons=decision.reasons,
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
                "stderr": result.stderr[:500],
                "stdout_preview": result.stdout[:300],
            }
        )
