from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from time import perf_counter

from lazysre.cli.context_window import ContextWindowManager
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
    text_stream: Callable[[str], None] | None = None
    context_window: ContextWindowManager = field(default_factory=ContextWindowManager)
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
        llm_start = perf_counter()
        turn = await self.llm.respond(
            model=self.model,
            tools=specs,
            system_prompt=self.system_prompt,
            user_input=instruction,
            text_stream=self.text_stream,
        )
        events.append(
            DispatchEvent(
                kind="llm_turn",
                message="initial_response",
                data={"duration_ms": round((perf_counter() - llm_start) * 1000, 2)},
            )
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
            failed_calls: list[str] = []
            for call in turn.tool_calls:
                events.append(
                    DispatchEvent(
                        kind="tool_call",
                        message=f"{call.name}",
                        data={"call_id": call.call_id, "arguments": call.arguments},
                    )
                )
                tool_start = perf_counter()
                output = await self.registry.execute(call, self.executor)
                compact = self.context_window.fit_tool_output_json(output)
                outputs.append(ToolOutput(call_id=call.call_id, output=compact))
                if _tool_output_failed(compact):
                    failed_calls.append(call.name)
                events.append(
                    DispatchEvent(
                        kind="tool_output",
                        message=f"{call.name} returned",
                        data={
                            "call_id": call.call_id,
                            "output_preview": compact[:220],
                            "duration_ms": round((perf_counter() - tool_start) * 1000, 2),
                            "step": step,
                        },
                    )
                )

            llm_step_start = perf_counter()
            turn = await self.llm.respond(
                model=self.model,
                tools=specs,
                system_prompt=self.system_prompt,
                previous_response_id=turn.response_id,
                tool_outputs=outputs,
                text_stream=self.text_stream,
            )
            events.append(
                DispatchEvent(
                    kind="llm_turn",
                    message=f"step_{step}_followup",
                data={"duration_ms": round((perf_counter() - llm_step_start) * 1000, 2)},
                )
            )
            if failed_calls and (not turn.tool_calls) and (step < self.max_steps):
                retry_hint = (
                    "Tool errors detected for calls: "
                    + ", ".join(failed_calls[:6])
                    + ". Retry with alternative tools/commands and continue OODA loop."
                )
                retry_start = perf_counter()
                turn = await self.llm.respond(
                    model=self.model,
                    tools=specs,
                    system_prompt=self.system_prompt,
                    user_input=retry_hint,
                    text_stream=self.text_stream,
                )
                events.append(
                    DispatchEvent(
                        kind="auto_retry",
                        message="tool_error_retry",
                        data={
                            "failed_calls": failed_calls[:6],
                            "duration_ms": round((perf_counter() - retry_start) * 1000, 2),
                        },
                    )
                )

        fallback = (
            turn.text.strip()
            if turn.text.strip()
            else f"达到最大推理步数 {self.max_steps}，请缩小问题范围后重试。"
        )
        events.append(DispatchEvent(kind="max_steps", message=f"max_steps={self.max_steps}"))
        return DispatchResult(final_text=fallback, events=events)


def _tool_output_failed(raw_output: str) -> bool:
    try:
        payload = json.loads(raw_output)
    except Exception:
        return False
    if not isinstance(payload, dict):
        return False
    ok = payload.get("ok")
    return bool(ok is False)
