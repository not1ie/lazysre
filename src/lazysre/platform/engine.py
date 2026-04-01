from __future__ import annotations

from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone
from time import perf_counter

from lazysre.platform.models import AgentDefinition, RunEvent, RunStatus, WorkflowDefinition, WorkflowRun
from lazysre.providers.base import LLMProvider


class WorkflowEngine:
    def __init__(self, provider: LLMProvider) -> None:
        self._provider = provider

    async def execute(
        self,
        workflow: WorkflowDefinition,
        agents: dict[str, AgentDefinition],
        run: WorkflowRun,
        should_stop: Callable[[], bool] | None = None,
    ) -> WorkflowRun:
        node_map = {n.id: n for n in workflow.nodes}
        run.status = RunStatus.running
        run.started_at = datetime.now(timezone.utc)
        run.events.append(RunEvent(kind="run_started", message="workflow 开始执行"))

        queue: deque[str] = deque([workflow.start_node])
        visited: set[str] = set()

        try:
            while queue:
                if should_stop and should_stop():
                    run.status = RunStatus.canceled
                    run.events.append(RunEvent(kind="run_canceled", message="收到取消信号"))
                    return run

                node_id = queue.popleft()
                if node_id in visited:
                    continue
                visited.add(node_id)

                node = node_map.get(node_id)
                if not node:
                    raise ValueError(f"node not found: {node_id}")

                agent = agents.get(node.agent_id)
                if not agent:
                    raise ValueError(f"agent not found: {node.agent_id}")

                run.events.append(
                    RunEvent(
                        kind="node_started",
                        message=f"节点执行开始: {node.id}",
                        data={"node_id": node.id, "agent_id": agent.id, "agent_name": agent.name},
                    )
                )

                prompt = self._build_prompt(workflow, run, node.instruction, node_id)
                started = perf_counter()
                output = await self._provider.complete(
                    system_prompt=agent.system_prompt,
                    user_prompt=prompt,
                    model=agent.model,
                )
                elapsed_ms = int((perf_counter() - started) * 1000)
                run.outputs[node.id] = output
                run.events.append(
                    RunEvent(
                        kind="node_finished",
                        message=f"节点执行完成: {node.id}",
                        data={
                            "node_id": node.id,
                            "agent_id": agent.id,
                            "duration_ms": elapsed_ms,
                            "output_preview": output[:180],
                        },
                    )
                )
                for nxt in node.next_nodes:
                    if nxt not in visited:
                        queue.append(nxt)

            run.status = RunStatus.completed
            run.summary = self._build_summary(workflow, run)
            run.events.append(RunEvent(kind="run_completed", message="workflow 执行完成"))
            return run
        except Exception as exc:
            run.status = RunStatus.failed
            run.error = str(exc)
            run.events.append(
                RunEvent(kind="run_failed", message=f"workflow 执行失败: {exc}")
            )
            return run
        finally:
            run.finished_at = datetime.now(timezone.utc)

    def _build_prompt(
        self, workflow: WorkflowDefinition, run: WorkflowRun, instruction: str, node_id: str
    ) -> str:
        context_lines = [f"workflow objective: {workflow.objective}", f"node id: {node_id}"]
        if run.input:
            context_lines.append(f"input: {run.input}")
        if run.outputs:
            context_lines.append("previous outputs:")
            for k, v in run.outputs.items():
                context_lines.append(f"- {k}: {v[:500]}")
        context_lines.append(f"node instruction: {instruction}")
        return "\n".join(context_lines)

    def _build_summary(self, workflow: WorkflowDefinition, run: WorkflowRun) -> str:
        lines = [f"workflow: {workflow.name}", f"objective: {workflow.objective}", "outputs:"]
        for node in workflow.nodes:
            if node.id in run.outputs:
                lines.append(f"- {node.id}: {run.outputs[node.id][:280]}")
        return "\n".join(lines)
