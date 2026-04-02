from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Awaitable, Callable

from lazysre.cli.executor import SafeExecutor
from lazysre.cli.types import ExecResult, ToolCall, ToolSpec

ToolHandler = Callable[[dict[str, object], SafeExecutor], Awaitable[ExecResult]]


@dataclass(slots=True)
class ToolDefinition:
    spec: ToolSpec
    handler: ToolHandler


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> None:
        self._tools[definition.spec.name] = definition

    def specs(self) -> list[ToolSpec]:
        return [x.spec for x in self._tools.values()]

    async def execute(self, call: ToolCall, executor: SafeExecutor) -> str:
        definition = self._tools.get(call.name)
        if not definition:
            return json.dumps(
                {
                    "ok": False,
                    "error": f"tool not registered: {call.name}",
                    "call_id": call.call_id,
                },
                ensure_ascii=False,
            )
        result = await definition.handler(call.arguments, executor)
        return json.dumps(
            {
                "ok": result.ok,
                "command": result.command,
                "stdout": result.stdout[:3000],
                "stderr": result.stderr[:1800],
                "exit_code": result.exit_code,
                "dry_run": result.dry_run,
                "blocked": result.blocked,
                "risk_level": result.risk_level,
                "policy_reasons": result.policy_reasons,
                "requires_approval": result.requires_approval,
                "approved": result.approved,
            },
            ensure_ascii=False,
        )
