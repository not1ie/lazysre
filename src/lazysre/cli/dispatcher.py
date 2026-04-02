from __future__ import annotations

from dataclasses import dataclass

from lazysre.cli.executor import SafeExecutor
from lazysre.cli.llm import FunctionCallingLLM
from lazysre.cli.registry import ToolRegistry
from lazysre.cli.types import DispatchEvent, DispatchResult, ToolOutput


@dataclass(slots=True)
class Dispatcher:
    llm: FunctionCallingLLM
    registry: ToolRegistry
    executor: SafeExecutor
    model: str
    max_steps: int = 6
    system_prompt: str = (
        "You are LazySRE CLI orchestrator with ReAct behavior. "
        "When user asks incident/root-cause questions, do not guess. "
        "First collect evidence with observer tools (metrics, cluster context, logs), "
        "then summarize likely root cause and actionable commands. "
        "Respect dry-run mode and approval policy. "
        "For any write operations (delete/patch/scale/restart), provide risk-aware guidance."
    )

    async def run(self, instruction: str) -> DispatchResult:
        events: list[DispatchEvent] = [
            DispatchEvent(kind="input", message=instruction),
            DispatchEvent(
                kind="executor_mode",
                message="dry-run" if self.executor.dry_run else "execute",
            ),
            DispatchEvent(
                kind="approval_policy",
                message=self.executor.approval_mode,
                data={"approved": self.executor.approval_granted},
            ),
        ]
        specs = self.registry.specs()
        turn = await self.llm.respond(
            model=self.model,
            tools=specs,
            system_prompt=self.system_prompt,
            user_input=instruction,
        )

        for step in range(1, self.max_steps + 1):
            if not turn.tool_calls:
                final_text = turn.text.strip() or "LLM 未返回文本结果。"
                events.append(
                    DispatchEvent(
                        kind="final",
                        message="completed",
                        data={"step": step, "text_preview": final_text[:180]},
                    )
                )
                return DispatchResult(final_text=final_text, events=events)

            outputs: list[ToolOutput] = []
            for call in turn.tool_calls:
                events.append(
                    DispatchEvent(
                        kind="tool_call",
                        message=f"{call.name}",
                        data={"call_id": call.call_id, "arguments": call.arguments},
                    )
                )
                output = await self.registry.execute(call, self.executor)
                outputs.append(ToolOutput(call_id=call.call_id, output=output))
                events.append(
                    DispatchEvent(
                        kind="tool_output",
                        message=f"{call.name} returned",
                        data={"call_id": call.call_id, "output_preview": output[:220]},
                    )
                )

            turn = await self.llm.respond(
                model=self.model,
                tools=specs,
                system_prompt=self.system_prompt,
                previous_response_id=turn.response_id,
                tool_outputs=outputs,
            )

        fallback = (
            turn.text.strip()
            if turn.text.strip()
            else f"达到最大推理步数 {self.max_steps}，请缩小问题范围后重试。"
        )
        events.append(DispatchEvent(kind="max_steps", message=f"max_steps={self.max_steps}"))
        return DispatchResult(final_text=fallback, events=events)
