from __future__ import annotations

from collections import deque
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from lazysre.platform.models import (
    AgentDefinition,
    OpsToolDefinition,
    RunEvent,
    RunStatus,
    WorkflowDefinition,
    WorkflowNode,
    WorkflowRun,
)
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
        tools: dict[str, OpsToolDefinition] | None = None,
        tool_executor: Callable[[OpsToolDefinition, str, dict[str, Any]], Awaitable[str]]
        | None = None,
    ) -> WorkflowRun:
        node_map = {n.id: n for n in workflow.nodes}

        if run.started_at is None:
            run.started_at = datetime.now(timezone.utc)
        run.status = RunStatus.running
        if not run.events:
            run.events.append(RunEvent(kind="run_started", message="workflow 开始执行"))

        queue: deque[str] = deque(run.queue or [workflow.start_node])
        visited: set[str] = set(run.visited)

        try:
            while queue:
                if should_stop and should_stop():
                    run.status = RunStatus.canceled
                    run.events.append(RunEvent(kind="run_canceled", message="收到取消信号"))
                    return run

                node_id = queue.popleft()
                if node_id in visited:
                    continue

                node = node_map.get(node_id)
                if not node:
                    raise ValueError(f"node not found: {node_id}")
                agent = agents.get(node.agent_id)
                if not agent:
                    raise ValueError(f"agent not found: {node.agent_id}")

                required_permission = self._effective_permission(node, tools)
                actor_permission = str(run.input.get("actor_permission", "write")).lower()
                if _perm_rank(actor_permission) < _perm_rank(required_permission):
                    run.status = RunStatus.failed
                    run.error = (
                        f"permission denied for node={node.id}: need={required_permission}, "
                        f"actor={actor_permission}"
                    )
                    run.events.append(
                        RunEvent(
                            kind="permission_denied",
                            message="权限不足，执行被拒绝",
                            data={
                                "node_id": node.id,
                                "required": required_permission,
                                "actor": actor_permission,
                            },
                        )
                    )
                    return run

                if node.requires_approval and not _has_approved_node(run, node.id):
                    run.status = RunStatus.waiting_approval
                    run.pending_node_id = node.id
                    queue.appendleft(node.id)
                    run.queue = list(queue)
                    run.visited = list(visited)
                    run.events.append(
                        RunEvent(
                            kind="approval_required",
                            message=f"节点 {node.id} 等待审批",
                            data={
                                "node_id": node.id,
                                "reason": node.approval_reason or "",
                                "required_permission": required_permission,
                            },
                        )
                    )
                    return run

                run.pending_node_id = None
                visited.add(node_id)
                run.events.append(
                    RunEvent(
                        kind="node_started",
                        message=f"节点执行开始: {node.id}",
                        data={
                            "node_id": node.id,
                            "agent_id": agent.id,
                            "agent_name": agent.name,
                            "required_permission": required_permission,
                        },
                    )
                )

                tool_context = ""
                if node.tool_binding and tools and tool_executor:
                    tool = tools.get(node.tool_binding)
                    if tool:
                        tool_query = ""
                        tool_queries = run.input.get("tool_queries")
                        if isinstance(tool_queries, dict):
                            tool_query = str(tool_queries.get(node.id, ""))
                        tool_context = await tool_executor(tool, tool_query, run.input)
                        run.events.append(
                            RunEvent(
                                kind="tool_executed",
                                message=f"工具执行完成: {tool.name}",
                                data={
                                    "node_id": node.id,
                                    "tool_id": tool.id,
                                    "tool_kind": tool.kind.value,
                                    "preview": tool_context[:180],
                                },
                            )
                        )

                prompt = self._build_prompt(workflow, run, node.instruction, node_id, tool_context)
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
            run.events.append(RunEvent(kind="run_failed", message=f"workflow 执行失败: {exc}"))
            return run
        finally:
            run.queue = list(queue)
            run.visited = list(visited)
            if run.status in (RunStatus.completed, RunStatus.failed, RunStatus.canceled):
                run.finished_at = datetime.now(timezone.utc)

    def _effective_permission(
        self, node: WorkflowNode, tools: dict[str, OpsToolDefinition] | None
    ) -> str:
        node_perm = node.required_permission.strip().lower()
        if node.tool_binding and tools and node.tool_binding in tools:
            tool_perm = tools[node.tool_binding].required_permission.strip().lower()
            return tool_perm if _perm_rank(tool_perm) > _perm_rank(node_perm) else node_perm
        return node_perm

    def _build_prompt(
        self,
        workflow: WorkflowDefinition,
        run: WorkflowRun,
        instruction: str,
        node_id: str,
        tool_context: str = "",
    ) -> str:
        context_lines = [f"workflow objective: {workflow.objective}", f"node id: {node_id}"]
        if run.input:
            context_lines.append(f"input: {run.input}")
        if tool_context:
            context_lines.append(f"tool context: {tool_context[:1200]}")
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


def _perm_rank(permission: str) -> int:
    mapping = {"read": 1, "write": 2, "admin": 3}
    return mapping.get(permission.strip().lower(), 0)


def _has_approved_node(run: WorkflowRun, node_id: str) -> bool:
    for approval in run.approvals:
        if approval.node_id == node_id and approval.action == "approve":
            return True
    return False

