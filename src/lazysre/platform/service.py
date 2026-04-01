from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

import httpx

from lazysre.config import settings
from lazysre.platform.engine import WorkflowEngine
from lazysre.platform.models import (
    AgentCreateRequest,
    AgentDefinition,
    AgentRole,
    AutoDesignRequest,
    EnvironmentBootstrapRequest,
    EnvironmentBootstrapResult,
    OpsToolDefinition,
    OpsToolKind,
    PlatformOverview,
    PlatformTemplate,
    QuickstartRequest,
    RunApprovalRecord,
    RunApprovalRequest,
    RunCreateRequest,
    RunEvent,
    RunStatus,
    ToolCreateRequest,
    ToolProbeRequest,
    ToolProbeResult,
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

    async def create_tool(self, req: ToolCreateRequest) -> OpsToolDefinition:
        return await self._upsert_tool(req)

    async def list_tools(self) -> list[OpsToolDefinition]:
        return sorted(self._state.tools.values(), key=lambda x: x.created_at, reverse=True)

    async def probe_tool(self, tool_id: str, req: ToolProbeRequest) -> ToolProbeResult:
        tool = self._state.tools.get(tool_id)
        if not tool:
            raise ValueError("tool not found")
        preview = await self._execute_tool(
            tool=tool,
            query=req.query or tool.default_query,
            context={},
            timeout_sec=req.timeout_sec,
        )
        return ToolProbeResult(ok=True, preview=preview[:1200])

    async def list_templates(self) -> list[PlatformTemplate]:
        return list(self._templates.values())

    async def bootstrap_environment(
        self, req: EnvironmentBootstrapRequest
    ) -> EnvironmentBootstrapResult:
        monitoring_urls = _build_monitoring_url_candidates(req.monitoring_ip, req.monitoring_port)
        if not monitoring_urls:
            raise ValueError("monitoring_ip is invalid")

        created_tools: list[OpsToolDefinition] = []
        probe_results: dict[str, str] = {}
        primary_prometheus_id: str | None = None

        for idx, base_url in enumerate(monitoring_urls, start=1):
            tool = await self._upsert_tool(
                ToolCreateRequest(
                    name=(
                        "Prometheus Primary"
                        if idx == 1
                        else f"Prometheus Candidate {idx}"
                    ),
                    kind=OpsToolKind.prometheus,
                    base_url=base_url,
                    default_query="up",
                    required_permission="read",
                ),
                preserve_headers_if_empty=True,
            )
            created_tools.append(tool)
            try:
                probe = await self.probe_tool(
                    tool.id, ToolProbeRequest(query=tool.default_query, timeout_sec=5.0)
                )
                probe_results[tool.id] = f"ok: {probe.preview[:180]}"
                if primary_prometheus_id is None:
                    primary_prometheus_id = tool.id
            except Exception as exc:
                probe_results[tool.id] = f"error: {exc}"

        k8s_headers: dict[str, str] = {}
        if req.k8s_bearer_token.strip():
            k8s_headers["Authorization"] = f"Bearer {req.k8s_bearer_token.strip()}"

        k8s_tool = await self._upsert_tool(
            ToolCreateRequest(
                name="K8s API Primary",
                kind=OpsToolKind.kubernetes,
                base_url=req.k8s_api_url.rstrip("/"),
                headers=k8s_headers,
                verify_tls=req.k8s_verify_tls,
                default_query="/version",
                required_permission="read",
            ),
            preserve_headers_if_empty=True,
        )
        created_tools.append(k8s_tool)
        try:
            probe = await self.probe_tool(
                k8s_tool.id, ToolProbeRequest(query=k8s_tool.default_query, timeout_sec=5.0)
            )
            probe_results[k8s_tool.id] = f"ok: {probe.preview[:180]}"
        except Exception as exc:
            probe_results[k8s_tool.id] = f"error: {exc}"

        workflow: WorkflowDefinition | None = None
        if req.create_mission_workflow:
            workflow = await self._upsert_prod_incident_workflow(
                name=req.workflow_name.strip() or "Prod Autonomous Incident",
                prometheus_tool_id=primary_prometheus_id,
                kubernetes_tool_id=k8s_tool.id,
            )
        return EnvironmentBootstrapResult(
            tools=created_tools,
            primary_tool_id=primary_prometheus_id or (created_tools[0].id if created_tools else None),
            workflow=workflow,
            probe_results=probe_results,
        )

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
        if not run.input.get("actor_permission"):
            run.input["actor_permission"] = "write"
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

    async def approve_run(self, run_id: str, req: RunApprovalRequest) -> WorkflowRun | None:
        async with self._lock:
            run = self._state.runs.get(run_id)
            if not run:
                return None
            if run.status != RunStatus.waiting_approval or not run.pending_node_id:
                raise ValueError("run is not waiting for approval")

            run.approvals.append(
                RunApprovalRecord(
                    node_id=run.pending_node_id,
                    action=req.action,
                    approver=req.approver,
                    comment=req.comment,
                )
            )

            if req.action == "reject":
                run.status = RunStatus.failed
                run.error = f"approval rejected by {req.approver}"
                run.events.append(
                    RunEvent(
                        kind="approval_rejected",
                        message=f"{req.approver} 拒绝了节点审批",
                        data={"node_id": run.pending_node_id, "comment": req.comment},
                    )
                )
                run.pending_node_id = None
                self._persist_unlocked()
                return run

            run.events.append(
                RunEvent(
                    kind="approval_granted",
                    message=f"{req.approver} 通过了节点审批",
                    data={"node_id": run.pending_node_id, "comment": req.comment},
                )
            )
            run.status = RunStatus.running
            run.pending_node_id = None
            self._persist_unlocked()
            if run_id not in self._running:
                self._running[run_id] = asyncio.create_task(self._run_workflow(run_id))
            return run

    async def get_overview(self) -> PlatformOverview:
        runs = list(self._state.runs.values())
        total = len(runs)
        completed = sum(1 for x in runs if x.status == RunStatus.completed)
        failed = sum(1 for x in runs if x.status == RunStatus.failed)
        canceled = sum(1 for x in runs if x.status == RunStatus.canceled)
        active = sum(
            1 for x in runs if x.status in (RunStatus.running, RunStatus.waiting_approval)
        )
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
            "每个元素包含: id, role(planner|worker|critic|responder), instruction, "
            "required_permission(read|write|admin), requires_approval(bool), next_nodes(string[])。"
            "可选字段: tool_binding(string), tool_query(string)."
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
                            "tool_binding": (
                                str(item.get("tool_binding")) if item.get("tool_binding") else None
                            ),
                            "tool_query": (
                                str(item.get("tool_query")) if item.get("tool_query") else None
                            ),
                            "required_permission": _normalize_permission(
                                str(item.get("required_permission", "read"))
                            ),
                            "requires_approval": bool(item.get("requires_approval", False)),
                            "approval_reason": str(item.get("approval_reason") or "").strip(),
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

        preferred_tool_id = self._pick_default_tool_binding()
        nodes: list[WorkflowNode] = []
        for idx, item in enumerate(blueprint):
            role = str(item.get("role", "worker")).lower()
            agent_id = agent_map.get(role) or agent_map["worker"]
            instruction = str(item.get("instruction") or "补充诊断步骤")
            next_nodes = [str(x) for x in item.get("next_nodes", []) if str(x) in node_ids]
            if not next_nodes and idx < len(node_ids) - 1:
                next_nodes = [node_ids[idx + 1]]

            required_permission = _normalize_permission(
                str(item.get("required_permission", "write" if role == "worker" else "read"))
            )
            risky = _is_risky_instruction(instruction) or required_permission in ("write", "admin")
            requires_approval = bool(item.get("requires_approval", False)) or (role == "worker" and risky)
            approval_reason = (
                str(item.get("approval_reason", "")).strip() or "该步骤涉及潜在变更动作，需要人工审批"
                if requires_approval
                else None
            )
            tool_binding = (
                str(item.get("tool_binding")) if item.get("tool_binding") else None
            ) or (preferred_tool_id if role == "worker" else None)
            tool_query = str(item.get("tool_query")).strip() if item.get("tool_query") else None

            nodes.append(
                WorkflowNode(
                    id=str(item["id"]),
                    agent_id=agent_id,
                    instruction=instruction,
                    tool_binding=tool_binding,
                    tool_query=tool_query,
                    required_permission=required_permission,
                    requires_approval=requires_approval,
                    approval_reason=approval_reason,
                    next_nodes=next_nodes,
                )
            )
        return nodes

    async def _run_workflow(self, run_id: str) -> None:
        async with self._lock:
            run = self._state.runs[run_id]
            workflow = self._state.workflows[run.workflow_id]
            agents = dict(self._state.agents)
            tools = dict(self._state.tools)

        await self._engine.execute(
            workflow=workflow,
            agents=agents,
            run=run,
            should_stop=lambda: run_id in self._cancel_flags,
            tools=tools,
            tool_executor=self._execute_tool,
        )

        async with self._lock:
            self._running.pop(run_id, None)
            if run.status != RunStatus.waiting_approval:
                self._cancel_flags.discard(run_id)
            self._persist_unlocked()

    async def _execute_tool(
        self,
        tool: OpsToolDefinition,
        query: str,
        context: dict[str, Any],
        timeout_sec: float = 10.0,
    ) -> str:
        q = query or tool.default_query
        headers = dict(tool.headers or {})
        timeout = max(1.0, min(timeout_sec, 30.0))

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=tool.verify_tls,
        ) as client:
            if tool.kind == OpsToolKind.prometheus:
                url = f"{tool.base_url}/api/v1/query"
                params = {"query": q or "up"}
                resp = await client.get(url, params=params, headers=headers)
            elif tool.kind == OpsToolKind.kubernetes:
                path = q if q.startswith("/") else "/version"
                url = f"{tool.base_url}{path}"
                resp = await client.get(url, headers=headers)
            elif tool.kind == OpsToolKind.logs:
                url = f"{tool.base_url}/search"
                params = {"q": q or str(context.get("query", ""))}
                resp = await client.get(url, params=params, headers=headers)
            else:
                if q.startswith("http://") or q.startswith("https://"):
                    url = q
                elif q.startswith("/"):
                    url = f"{tool.base_url}{q}"
                else:
                    url = tool.base_url
                resp = await client.get(url, headers=headers)

            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            if "application/json" in content_type:
                body = json.dumps(resp.json(), ensure_ascii=False)
            else:
                body = " ".join(resp.text.split())
            return body[:1500]

    async def _upsert_tool(
        self, req: ToolCreateRequest, preserve_headers_if_empty: bool = False
    ) -> OpsToolDefinition:
        normalized_url = req.base_url.rstrip("/")
        req_perm = _normalize_permission(req.required_permission)
        sanitized_headers = {
            str(k).strip(): str(v).strip()
            for k, v in (req.headers or {}).items()
            if str(k).strip()
        }
        async with self._lock:
            for tool in self._state.tools.values():
                if tool.kind == req.kind and tool.base_url.rstrip("/") == normalized_url:
                    tool.name = req.name
                    if sanitized_headers or not preserve_headers_if_empty:
                        tool.headers = sanitized_headers
                    tool.verify_tls = req.verify_tls
                    tool.default_query = req.default_query
                    tool.required_permission = req_perm
                    self._persist_unlocked()
                    return tool

            tool = OpsToolDefinition(
                name=req.name,
                kind=req.kind,
                base_url=normalized_url,
                headers=sanitized_headers,
                verify_tls=req.verify_tls,
                default_query=req.default_query,
                required_permission=req_perm,
            )
            self._state.tools[tool.id] = tool
            self._persist_unlocked()
            return tool

    async def _upsert_prod_incident_workflow(
        self, name: str, prometheus_tool_id: str | None, kubernetes_tool_id: str | None
    ) -> WorkflowDefinition:
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

        nodes = [
            WorkflowNode(
                id="triage_signal",
                agent_id=planner.id,
                instruction="先读取监控信号，判断是否存在系统性可用性下降，并确定优先排查方向。",
                tool_binding=prometheus_tool_id,
                tool_query='sum(up) by (job)',
                required_permission="read",
                requires_approval=False,
                next_nodes=["correlate_k8s"],
            ),
            WorkflowNode(
                id="correlate_k8s",
                agent_id=worker.id,
                instruction="结合 K8s API 输出集群版本、组件健康与潜在异常范围。",
                tool_binding=kubernetes_tool_id,
                tool_query="/version",
                required_permission="read",
                requires_approval=False,
                next_nodes=["risk_review"],
            ),
            WorkflowNode(
                id="risk_review",
                agent_id=critic.id,
                instruction="综合证据给出根因假设、风险矩阵和可回滚修复方案。",
                required_permission="read",
                requires_approval=False,
                next_nodes=["guarded_action"],
            ),
            WorkflowNode(
                id="guarded_action",
                agent_id=worker.id,
                instruction="根据评审结论，生成可执行变更动作与验证步骤，不直接执行破坏性操作。",
                tool_binding=kubernetes_tool_id,
                tool_query="/api/v1/nodes?limit=20",
                required_permission="admin",
                requires_approval=True,
                approval_reason="该步骤会生成生产变更动作建议，需人工审批后继续",
                next_nodes=["incident_comms"],
            ),
            WorkflowNode(
                id="incident_comms",
                agent_id=responder.id,
                instruction="生成对内通报、对外说明和复盘纪要模板。",
                required_permission="read",
                requires_approval=False,
                next_nodes=[],
            ),
        ]

        wf = WorkflowDefinition(
            name=name,
            objective="围绕生产可用性故障进行信号采集、根因定位、审批变更与沟通闭环。",
            start_node="triage_signal",
            nodes=nodes,
        )
        self._validate_workflow(wf)

        async with self._lock:
            existing = next(
                (x for x in self._state.workflows.values() if x.name == name),
                None,
            )
            if existing:
                existing.objective = wf.objective
                existing.start_node = wf.start_node
                existing.nodes = wf.nodes
                self._persist_unlocked()
                return existing
            self._state.workflows[wf.id] = wf
            self._persist_unlocked()
            return wf

    def _pick_default_tool_binding(self) -> str | None:
        if not self._state.tools:
            return None
        preferred_order = [
            OpsToolKind.prometheus,
            OpsToolKind.logs,
            OpsToolKind.kubernetes,
            OpsToolKind.generic_http,
        ]
        for kind in preferred_order:
            for tool in self._state.tools.values():
                if tool.kind == kind:
                    return tool.id
        return next(iter(self._state.tools.keys()))

    def _validate_workflow(self, wf: WorkflowDefinition) -> None:
        node_map = {n.id: n for n in wf.nodes}
        if wf.start_node not in node_map:
            raise ValueError("start_node is not in nodes")
        for node in wf.nodes:
            if node.agent_id not in self._state.agents:
                raise ValueError(f"agent_id not found: {node.agent_id}")
            if node.tool_binding and node.tool_binding not in self._state.tools:
                raise ValueError(f"tool_binding not found: {node.tool_binding}")
            _normalize_permission(node.required_permission)
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


def _normalize_permission(value: str) -> str:
    norm = value.strip().lower()
    if norm not in {"read", "write", "admin"}:
        raise ValueError("required_permission must be one of read/write/admin")
    return norm


def _is_risky_instruction(instruction: str) -> bool:
    lowered = instruction.lower()
    risky_keywords = ("delete", "restart", "scale", "rollback", "drain", "kill", "升级")
    return any(word in lowered for word in risky_keywords)


def _build_monitoring_url_candidates(ip_or_url: str, port: int) -> list[str]:
    raw = ip_or_url.strip()
    if not raw:
        return []
    if raw.startswith(("http://", "https://")):
        return [raw.rstrip("/")]

    candidates = [f"http://{raw}:{port}"]
    if raw.startswith("92."):
        # 用户常见误写场景: 92.x.x.x -> 192.x.x.x
        candidates.append(f"http://192.{raw[len('92.'):]}:{port}")

    uniq: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if item in seen:
            continue
        uniq.append(item)
        seen.add(item)
    return uniq


def _fallback_blueprint(template: PlatformTemplate | None = None) -> list[dict[str, object]]:
    if template and template.slug == "release-guardian":
        return [
            {
                "id": "release_plan",
                "role": "planner",
                "instruction": "整理发布窗口、影响面和回滚条件。",
                "required_permission": "read",
                "requires_approval": False,
                "next_nodes": ["preflight_check"],
            },
            {
                "id": "preflight_check",
                "role": "worker",
                "instruction": "执行发布前检查，输出风险点和阻断项。",
                "required_permission": "write",
                "requires_approval": True,
                "approval_reason": "发布前检查会触发实际检查命令，需要人工确认",
                "next_nodes": ["release_review"],
            },
            {
                "id": "release_review",
                "role": "critic",
                "instruction": "审查发布策略并给出 go/no-go 建议。",
                "required_permission": "read",
                "requires_approval": False,
                "next_nodes": ["announce"],
            },
            {
                "id": "announce",
                "role": "responder",
                "instruction": "生成发布通知和状态播报模板。",
                "required_permission": "read",
                "requires_approval": False,
                "next_nodes": [],
            },
        ]

    if template and template.slug == "cost-optimizer":
        return [
            {
                "id": "collect_cost_signal",
                "role": "planner",
                "instruction": "定义成本分析维度和评估窗口。",
                "required_permission": "read",
                "requires_approval": False,
                "next_nodes": ["find_waste"],
            },
            {
                "id": "find_waste",
                "role": "worker",
                "instruction": "定位闲置资源和成本异常来源。",
                "required_permission": "read",
                "requires_approval": False,
                "next_nodes": ["optimize_review"],
            },
            {
                "id": "optimize_review",
                "role": "critic",
                "instruction": "评估优化动作风险与收益。",
                "required_permission": "read",
                "requires_approval": False,
                "next_nodes": ["stakeholder_report"],
            },
            {
                "id": "stakeholder_report",
                "role": "responder",
                "instruction": "输出成本优化路线图和沟通摘要。",
                "required_permission": "read",
                "requires_approval": False,
                "next_nodes": [],
            },
        ]

    return [
        {
            "id": "plan",
            "role": "planner",
            "instruction": "拆解目标，给出优先级和调查路径。",
            "required_permission": "read",
            "requires_approval": False,
            "next_nodes": ["execute"],
        },
        {
            "id": "execute",
            "role": "worker",
            "instruction": "执行诊断并给出证据、根因和修复动作。",
            "required_permission": "write",
            "requires_approval": True,
            "approval_reason": "该步骤可能执行线上变更动作，需要人工审批",
            "next_nodes": ["review"],
        },
        {
            "id": "review",
            "role": "critic",
            "instruction": "审查风险、回滚和验证策略。",
            "required_permission": "read",
            "requires_approval": False,
            "next_nodes": ["announce"],
        },
        {
            "id": "announce",
            "role": "responder",
            "instruction": "生成值班通报、进展更新和复盘摘要。",
            "required_permission": "read",
            "requires_approval": False,
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
