from __future__ import annotations

from typing import Any

from lazysre.models import StepResult
from lazysre.tools.registry import ToolRegistry


class Worker:
    def __init__(self, tools: ToolRegistry) -> None:
        self._tools = tools

    async def execute(self, step: str, context: dict[str, Any]) -> StepResult:
        tool_name, instruction = _parse_tool_hint(step)
        tool = self._tools.get(tool_name) if tool_name else self._tools.choose_tool(step)
        try:
            output = await tool.run(instruction or step, context)
            return StepResult(step=step, tool=tool.name, output=output, success=True)
        except Exception as exc:
            return StepResult(step=step, tool=tool.name, output=str(exc), success=False)


def _parse_tool_hint(step: str) -> tuple[str | None, str]:
    # 允许显式指令: [tool=echo] 这里是步骤内容
    prefix = "[tool="
    if not step.startswith(prefix):
        return None, step
    right = step.find("]")
    if right == -1:
        return None, step
    name = step[len(prefix) : right].strip()
    instruction = step[right + 1 :].strip()
    if not name:
        return None, step
    return name, instruction

