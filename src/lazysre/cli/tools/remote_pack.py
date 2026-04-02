from __future__ import annotations

import shlex
from typing import Any

import httpx

from lazysre.cli.executor import SafeExecutor
from lazysre.cli.registry import ToolDefinition
from lazysre.cli.types import ExecResult, ToolSpec


def remote_gateway_tool(name: str, base_url: str, token: str = "") -> ToolDefinition:
    tool_name = _safe_tool_name(f"remote_{name}")
    gateway_url = base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"} if token.strip() else {}

    async def _handler(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
        raw_command = str(args.get("command", "")).strip()
        if not raw_command:
            result = ExecResult(
                ok=False,
                command=[tool_name],
                stderr="missing command",
                exit_code=2,
                dry_run=executor.dry_run,
                risk_level="medium",
            )
            executor.record(result)
            return result

        command = shlex.split(raw_command)
        decision, blocked = executor.preflight(command)
        if blocked:
            return blocked
        assert decision is not None

        if executor.dry_run:
            result = ExecResult(
                ok=True,
                command=command,
                stdout=f"[dry-run] remote gateway {gateway_url} => {raw_command}",
                exit_code=0,
                dry_run=True,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                requires_approval=decision.requires_approval,
                approved=executor.approval_granted,
            )
            executor.record(result)
            return result

        timeout_sec = int(args.get("timeout_sec", executor.timeout_sec) or executor.timeout_sec)
        payload: dict[str, Any] = {
            "command": command,
            "raw_command": raw_command,
            "timeout_sec": max(1, min(timeout_sec, 120)),
        }
        if isinstance(args.get("context"), dict):
            payload["context"] = args["context"]

        try:
            async with httpx.AsyncClient(timeout=float(timeout_sec) + 3.0) as client:
                resp = await client.post(
                    f"{gateway_url}/v1/exec",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
            result = ExecResult(
                ok=bool(data.get("ok", False)),
                command=command,
                stdout=str(data.get("stdout", ""))[:5000],
                stderr=str(data.get("stderr", ""))[:3000],
                exit_code=int(data.get("exit_code", 1) or 1),
                dry_run=False,
                blocked=bool(data.get("blocked", False)),
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                requires_approval=decision.requires_approval,
                approved=executor.approval_granted,
            )
        except Exception as exc:
            result = ExecResult(
                ok=False,
                command=command,
                stderr=f"remote gateway error: {exc}",
                exit_code=1,
                dry_run=False,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                requires_approval=decision.requires_approval,
                approved=executor.approval_granted,
            )
        executor.record(result)
        return result

    return ToolDefinition(
        spec=ToolSpec(
            name=tool_name,
            description=f"Execute operational commands via remote gateway {gateway_url}.",
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout_sec": {"type": "integer", "default": 20},
                    "context": {"type": "object"},
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        ),
        handler=_handler,
    )


def _safe_tool_name(raw: str) -> str:
    lowered = raw.strip().lower()
    chars = []
    for ch in lowered:
        if ch.isalnum() or ch in {"_", "-"}:
            chars.append(ch)
        else:
            chars.append("_")
    cleaned = "".join(chars).strip("_")
    return cleaned or "remote_gateway"

