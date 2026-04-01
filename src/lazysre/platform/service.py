from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from lazysre.config import settings
from lazysre.platform.engine import WorkflowEngine
from lazysre.platform.models import (
    AgentCreateRequest,
    AgentDefinition,
    AgentRole,
    AutoDesignRequest,
    PlatformOverview,
    PlatformTemplate,
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
        self._templates = {x.slug: x for x in _default_templates()}
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

    async def list_templates(self) -> list[PlatformTemplate]:
        return list(self._templates.values())

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

    async def get_overview(self) -> PlatformOverview:
        runs = list(self._state.runs.values())
        total = len(runs)
        completed = sum(1 for x in runs if x.status == RunStatus.completed)
        failed = sum(1 for x in runs if x.status == RunStatus.failed)
        canceled = sum(1 for x in runs if x.status == RunStatus.canceled)
        active = sum(1 for x in runs if x.status == RunStatus.running)
        success_rate = round((completed / total), 3) if total else 0.0
        return PlatformOverview(
            total_agents=len(self._state.agents),
            total_workflows=len(self._state.workflows),
            total_runs=total,
            active_runs=active,
            completed_runs=completed,
            failed_runs=failed,
            canceled_runs=canceled,
            success_rate=success_rate,
        )

    async def quickstart(self, req: QuickstartRequest) -> WorkflowDefinition:
        return await self.auto_design(
            AutoDesignRequest(
                name=req.name,
                objective=req.objective,
                template_slug="incident-response",
            )
        )

    async def auto_design(self, req: AutoDesignRequest) -> WorkflowDefinition:
        objective = req.objective.strip()
        if not objective:
            raise ValueError("objective must not be empty")

        planner = await self._ensure_agent(
            name="Planner Agent",
            role=AgentRole.planner,
            prompt="你是SRE规划智能体，产出分阶段排查计划和优先级。",
        )
        worker = await self._ensure_agent(
            name="Worker Agent",
            role=AgentRole.worker,
            prompt="你是SRE执行智能体，输出证据、命令和修复动作。",
        )
        critic = await self._ensure_agent(
            name="Critic Agent",
            role=AgentRole.critic,
            prompt="你是SRE评审智能体，输出风险、回滚和验证清单。",
        )
        responder = await self._ensure_agent(
            name="Responder Agent",
            role=AgentRole.custom,
            prompt="你是值班沟通智能体，生成通报、进展播报和复盘摘要。",
        )

        agent_map = {
            "planner": planner.id,
            "worker": worker.id,
            "critic": critic.id,
            "responder": responder.id,
        }
        template = self._templates.get(req.template_slug or "")
        blueprint = await self._generate_blueprint(objective, template=template)
        nodes = self._build_nodes_from_blueprint(blueprint, agent_map)
        start_node = nodes[0].id
        name = req.name or _default_name_from_objective(objective, template=template)

        return await self.create_workflow(
            WorkflowCreateRequest(
                name=name,
                objective=objective,
                start_node=start_node,
                nodes=nodes,
            )
        )

    async def _ensure_agent(self, name: str, role: AgentRole, prompt: str) -> AgentDefinition:
        for agent in self._state.agents.values():
            if agent.name == name and agent.role == role:
                return agent
        return await self.create_agent(
            AgentCreateRequest(name=name, role=role, system_prompt=prompt)
        )

    async def _generate_blueprint(
        self, objective: str, template: PlatformTemplate | None = None
    ) -> list[dict[str, object]]:
        system_prompt = (
            "你是运维编排设计器。给定目标后，请只输出 JSON 数组。"
            "每个元素包含: id, role(planner|worker|critic|responder), instruction, next_nodes(string[])."
            "最多 6 个节点。"
        )
        user_prompt = f"objective={objective}\ntemplate={template.model_dump() if template else '{}'}"
        try:
            raw = await self._provider.complete(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                model=settings.model_name,
            )
            parsed = _extract_json_array(raw)
            if isinstance(parsed, list) and parsed:
                normalized = []
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    role = str(item.get("role", "worker")).lower()
                    normalized.append(
                        {
                            "id": str(item.get("id") or f"node-{len(normalized)+1}"),
                            "role": role,
                            "instruction": str(item.get("instruction") or "补充诊断步骤"),
                            "next_nodes": [
                                str(x) for x in item.get("next_nodes", []) if str(x).strip()
                            ],
                        }
                    )
                if normalized:
                    return normalized
        except Exception:
            pass
        return _fallback_blueprint(template=template)

    def _build_nodes_from_blueprint(
        self, blueprint: list[dict[str, object]], agent_map: dict[str, str]
    ) -> list[WorkflowNode]:
        node_ids = [str(x["id"]) for x in blueprint if x.get("id")]
        if not node_ids:
            raise ValueError("generated blueprint has no node ids")

        nodes: list[WorkflowNode] = []
        for idx, item in enumerate(blueprint):
            role = str(item.get("role", "worker")).lower()
            agent_id = agent_map.get(role) or agent_map["worker"]
            instruction = str(item.get("instruction") or "补充诊断步骤")
            next_nodes = [str(x) for x in item.get("next_nodes", []) if str(x) in node_ids]
            if not next_nodes and idx < len(node_ids) - 1:
                next_nodes = [node_ids[idx + 1]]
            nodes.append(
                WorkflowNode(
                    id=str(item["id"]),
                    agent_id=agent_id,
                    instruction=instruction,
                    next_nodes=next_nodes,
                )
            )
        return nodes

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


def _extract_json_array(raw: str) -> object:
    text = raw.strip()
    if text.startswith("[") and text.endswith("]"):
        return json.loads(text)
    match = re.search(r"\[[\s\S]*\]", text)
    if match:
        return json.loads(match.group(0))
    return []


def _default_name_from_objective(objective: str, template: PlatformTemplate | None = None) -> str:
    title = template.name if template else "AI Ops Flow"
    sliced = objective[:40].strip()
    return f"{title}: {sliced}"


def _fallback_blueprint(template: PlatformTemplate | None = None) -> list[dict[str, object]]:
    if template and template.slug == "release-guardian":
        return [
            {
                "id": "release_plan",
                "role": "planner",
                "instruction": "整理发布窗口、影响面和回滚条件。",
                "next_nodes": ["preflight_check"],
            },
            {
                "id": "preflight_check",
                "role": "worker",
                "instruction": "执行发布前检查，输出风险点和阻断项。",
                "next_nodes": ["release_review"],
            },
            {
                "id": "release_review",
                "role": "critic",
                "instruction": "审查发布策略并给出 go/no-go 建议。",
                "next_nodes": ["announce"],
            },
            {
                "id": "announce",
                "role": "responder",
                "instruction": "生成发布通知和状态播报模板。",
                "next_nodes": [],
            },
        ]

    if template and template.slug == "cost-optimizer":
        return [
            {
                "id": "collect_cost_signal",
                "role": "planner",
                "instruction": "定义成本分析维度和评估窗口。",
                "next_nodes": ["find_waste"],
            },
            {
                "id": "find_waste",
                "role": "worker",
                "instruction": "定位闲置资源和成本异常来源。",
                "next_nodes": ["optimize_review"],
            },
            {
                "id": "optimize_review",
                "role": "critic",
                "instruction": "评估优化动作风险与收益。",
                "next_nodes": ["stakeholder_report"],
            },
            {
                "id": "stakeholder_report",
                "role": "responder",
                "instruction": "输出成本优化路线图和沟通摘要。",
                "next_nodes": [],
            },
        ]

    return [
        {
            "id": "plan",
            "role": "planner",
            "instruction": "拆解目标，给出优先级和调查路径。",
            "next_nodes": ["execute"],
        },
        {
            "id": "execute",
            "role": "worker",
            "instruction": "执行诊断并给出证据、根因和修复动作。",
            "next_nodes": ["review"],
        },
        {
            "id": "review",
            "role": "critic",
            "instruction": "审查风险、回滚和验证策略。",
            "next_nodes": ["announce"],
        },
        {
            "id": "announce",
            "role": "responder",
            "instruction": "生成值班通报、进展更新和复盘摘要。",
            "next_nodes": [],
        },
    ]


def _default_templates() -> list[PlatformTemplate]:
    return [
        PlatformTemplate(
            slug="incident-response",
            name="Incident Commander",
            description="面向突发故障，快速完成定位、修复、复盘闭环。",
            recommended_objective="定位并缓解 gateway 5xx 激增，给出回滚策略和复盘结论。",
            stages=["triage", "diagnose", "mitigate", "review"],
        ),
        PlatformTemplate(
            slug="release-guardian",
            name="Release Guardian",
            description="发布前后风险守护，给出 go/no-go 和回滚策略。",
            recommended_objective="评估 v2.3.0 发布风险并输出上线判定与回滚路径。",
            stages=["planning", "preflight", "review", "announce"],
        ),
        PlatformTemplate(
            slug="cost-optimizer",
            name="Cost Optimizer",
            description="按资源利用率与业务影响分析成本优化机会。",
            recommended_objective="分析本周集群成本飙升原因并给出降本方案。",
            stages=["collect", "analyze", "review", "report"],
        ),
        PlatformTemplate(
            slug="availability-guard",
            name="Availability Guard",
            description="长期可用性治理，输出SLO改进与风险清单。",
            recommended_objective="围绕支付链路 SLO 下降给出治理计划。",
            stages=["assess", "execute", "critique", "communicate"],
        ),
    ]

