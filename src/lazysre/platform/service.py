from __future__ import annotations

import asyncio
from pathlib import Path

from lazysre.config import settings
from lazysre.platform.engine import WorkflowEngine
from lazysre.platform.models import (
    AgentCreateRequest,
    AgentDefinition,
    AgentRole,
    QuickstartRequest,
    RunCreateRequest,
    RunEvent,
    RunStatus,
    WorkflowCreateRequest,
    WorkflowDefinition,
    WorkflowNode,
    WorkflowRun,
)
from lazysre.platform.store import FilePlatformStore
from lazysre.providers.base import LLMProvider
from lazysre.providers.mock import MockProvider
from lazysre.providers.openai_provider import OpenAIProvider


class PlatformService:
    def __init__(self, store_path: str | None = None) -> None:
        path = store_path or str(Path(settings.data_dir) / settings.platform_store_file)
        self._store = FilePlatformStore(path)
        self._state = self._store.load()
        self._lock = asyncio.Lock()
        self._running: dict[str, asyncio.Task[None]] = {}
        self._cancel_flags: set[str] = set()
        self._provider = self._build_provider()
        self._engine = WorkflowEngine(self._provider)
        self._recover_inflight_runs()

    def _build_provider(self) -> LLMProvider:
        if settings.model_mode.lower() == "openai" and settings.openai_api_key:
            return OpenAIProvider(settings.openai_api_key)
        return MockProvider()

    async def create_agent(self, req: AgentCreateRequest) -> AgentDefinition:
        agent = AgentDefinition(
            name=req.name,
            role=req.role,
            system_prompt=req.system_prompt,
            model=req.model,
        )
        async with self._lock:
            self._state.agents[agent.id] = agent
            self._persist_unlocked()
        return agent

    async def list_agents(self) -> list[AgentDefinition]:
        return sorted(self._state.agents.values(), key=lambda x: x.created_at, reverse=True)

    async def create_workflow(self, req: WorkflowCreateRequest) -> WorkflowDefinition:
        wf = WorkflowDefinition(
            name=req.name,
            objective=req.objective,
            start_node=req.start_node,
            nodes=req.nodes,
        )
        self._validate_workflow(wf)
        async with self._lock:
            self._state.workflows[wf.id] = wf
            self._persist_unlocked()
        return wf

    async def list_workflows(self) -> list[WorkflowDefinition]:
        return sorted(self._state.workflows.values(), key=lambda x: x.created_at, reverse=True)

    async def get_workflow(self, workflow_id: str) -> WorkflowDefinition | None:
        return self._state.workflows.get(workflow_id)

    async def create_run(self, workflow_id: str, req: RunCreateRequest) -> WorkflowRun | None:
        workflow = self._state.workflows.get(workflow_id)
        if not workflow:
            return None
        run = WorkflowRun(workflow_id=workflow_id, input=req.input)
        async with self._lock:
            self._state.runs[run.id] = run
            self._persist_unlocked()
            runner = asyncio.create_task(self._run_workflow(run.id))
            self._running[run.id] = runner
        return run

    async def list_runs(self, workflow_id: str | None = None) -> list[WorkflowRun]:
        runs = list(self._state.runs.values())
        if workflow_id:
            runs = [r for r in runs if r.workflow_id == workflow_id]
        return sorted(runs, key=lambda x: x.created_at, reverse=True)

    async def get_run(self, run_id: str) -> WorkflowRun | None:
        return self._state.runs.get(run_id)

    async def cancel_run(self, run_id: str) -> WorkflowRun | None:
        async with self._lock:
            run = self._state.runs.get(run_id)
            if not run:
                return None
            self._cancel_flags.add(run_id)
            run.events.append(RunEvent(kind="cancel_requested", message="收到取消请求"))
            self._persist_unlocked()
            return run

    async def quickstart(self, req: QuickstartRequest) -> WorkflowDefinition:
        planner = await self.create_agent(
            AgentCreateRequest(
                name="Planner Agent",
                role=AgentRole.planner,
                system_prompt="你是SRE规划智能体，产出结构化排查步骤和验证计划。",
            )
        )
        worker = await self.create_agent(
            AgentCreateRequest(
                name="Worker Agent",
                role=AgentRole.worker,
                system_prompt="你是SRE执行智能体，执行排查并给出证据和操作建议。",
            )
        )
        critic = await self.create_agent(
            AgentCreateRequest(
                name="Critic Agent",
                role=AgentRole.critic,
                system_prompt="你是SRE评审智能体，审查方案风险并输出上线前检查清单。",
            )
        )
        nodes = [
            WorkflowNode(
                id="plan",
                agent_id=planner.id,
                instruction="拆解目标，给出优先级和调查路径。",
                next_nodes=["execute"],
            ),
            WorkflowNode(
                id="execute",
                agent_id=worker.id,
                instruction="根据计划执行诊断，输出根因与修复方案。",
                next_nodes=["review"],
            ),
            WorkflowNode(
                id="review",
                agent_id=critic.id,
                instruction="评审修复方案，输出风险、回滚与验证清单。",
                next_nodes=[],
            ),
        ]
        return await self.create_workflow(
            WorkflowCreateRequest(
                name=req.name,
                objective=req.objective,
                start_node="plan",
                nodes=nodes,
            )
        )

    async def _run_workflow(self, run_id: str) -> None:
        async with self._lock:
            run = self._state.runs[run_id]
            workflow = self._state.workflows[run.workflow_id]
            agents = dict(self._state.agents)

        await self._engine.execute(
            workflow=workflow,
            agents=agents,
            run=run,
            should_stop=lambda: run_id in self._cancel_flags,
        )

        async with self._lock:
            self._cancel_flags.discard(run_id)
            self._running.pop(run_id, None)
            self._persist_unlocked()

    def _validate_workflow(self, wf: WorkflowDefinition) -> None:
        node_map = {n.id: n for n in wf.nodes}
        if wf.start_node not in node_map:
            raise ValueError("start_node is not in nodes")
        for node in wf.nodes:
            if node.agent_id not in self._state.agents:
                raise ValueError(f"agent_id not found: {node.agent_id}")
            for nxt in node.next_nodes:
                if nxt not in node_map:
                    raise ValueError(f"next node not found: {nxt}")

    def _recover_inflight_runs(self) -> None:
        dirty = False
        for run in self._state.runs.values():
            if run.status == RunStatus.running:
                run.status = RunStatus.failed
                run.error = "run interrupted by process restart"
                run.events.append(
                    RunEvent(kind="run_recovered", message="检测到未完成 run，已标记为失败")
                )
                dirty = True
        if dirty:
            self._persist_unlocked()

    def _persist_unlocked(self) -> None:
        self._store.save(self._state)
