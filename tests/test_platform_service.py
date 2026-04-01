import asyncio
from pathlib import Path

from lazysre.platform.models import (
    AgentCreateRequest,
    AutoDesignRequest,
    EnvironmentBootstrapRequest,
    QuickstartRequest,
    RunApprovalRequest,
    RunCreateRequest,
    RunStatus,
    ToolCreateRequest,
    ToolProbeRequest,
    WorkflowCreateRequest,
    WorkflowNode,
)
from lazysre.platform.service import PlatformService


async def _wait_run(service: PlatformService, run_id: str, timeout: float = 4.0) -> RunStatus:
    start = asyncio.get_running_loop().time()
    while True:
        run = await service.get_run(run_id)
        if run and run.status in (
            RunStatus.completed,
            RunStatus.failed,
            RunStatus.canceled,
            RunStatus.waiting_approval,
        ):
            return run.status
        if asyncio.get_running_loop().time() - start > timeout:
            raise TimeoutError(f"run not finished: {run_id}")
        await asyncio.sleep(0.02)


async def test_quickstart_creates_agents_and_workflow(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))
    wf = await service.quickstart(
        QuickstartRequest(name="Incident Flow", objective="定位 gateway 5xx")
    )
    agents = await service.list_agents()
    workflows = await service.list_workflows()

    assert wf.start_node == "plan"
    assert len(agents) >= 3
    assert any(x.id == wf.id for x in workflows)


async def test_run_executes_workflow(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))
    wf = await service.quickstart(
        QuickstartRequest(name="Incident Flow", objective="定位 gateway 5xx")
    )
    run = await service.create_run(
        workflow_id=wf.id,
        req=RunCreateRequest(input={"service": "gateway", "cluster": "prod-sh"}),
    )
    assert run is not None

    # 默认 worker 节点要求审批
    status = await _wait_run(service, run.id)
    assert status in (RunStatus.waiting_approval, RunStatus.completed)
    if status == RunStatus.waiting_approval:
        approved = await service.approve_run(
            run.id,
            RunApprovalRequest(action="approve", approver="test.oncall", comment="ok"),
        )
        assert approved is not None
        status = await _wait_run(service, run.id)

    status = await _wait_run(service, run.id)
    assert status == RunStatus.completed

    loaded = await service.get_run(run.id)
    assert loaded is not None
    assert loaded.outputs
    assert loaded.summary
    assert any(evt.kind == "run_completed" for evt in loaded.events)


async def test_template_catalog_and_autodesign(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))
    templates = await service.list_templates()
    assert any(t.slug == "incident-response" for t in templates)

    wf = await service.auto_design(
        AutoDesignRequest(
            objective="评估发布风险并给出上线策略",
            template_slug="release-guardian",
            name="Release Mission",
        )
    )
    assert wf.name == "Release Mission"
    assert len(wf.nodes) >= 3
    assert wf.start_node in {n.id for n in wf.nodes}


async def test_platform_overview_metrics(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))
    wf = await service.quickstart(
        QuickstartRequest(name="Overview Flow", objective="检查可用性抖动")
    )
    run = await service.create_run(workflow_id=wf.id, req=RunCreateRequest(input={}))
    assert run is not None
    status = await _wait_run(service, run.id)
    if status == RunStatus.waiting_approval:
        await service.approve_run(
            run.id,
            RunApprovalRequest(action="approve", approver="test.oncall", comment="ok"),
        )
        status = await _wait_run(service, run.id)
    assert status in (RunStatus.completed, RunStatus.failed, RunStatus.canceled)

    overview = await service.get_overview()
    assert overview.total_workflows >= 1
    assert overview.total_runs >= 1
    assert 0.0 <= overview.success_rate <= 1.0


async def test_tool_registry_and_probe_unknown(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))
    tool = await service.create_tool(
        ToolCreateRequest(
            name="Mock Prom",
            kind="prometheus",
            base_url="http://127.0.0.1:9090",
            verify_tls=False,
            default_query="up",
            required_permission="read",
        )
    )
    assert tool.name == "Mock Prom"
    assert tool.verify_tls is False
    tools = await service.list_tools()
    assert any(t.id == tool.id for t in tools)

    try:
        await service.probe_tool("unknown", ToolProbeRequest(query="up"))
        assert False, "probe should fail for unknown tool"
    except ValueError:
        assert True


async def test_permission_denied_run(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))
    agent = await service.create_agent(
        AgentCreateRequest(
            name="Read Agent",
            role="worker",
            system_prompt="执行只读诊断。",
            model="gpt-5.4-mini",
        )
    )
    wf = await service.create_workflow(
        WorkflowCreateRequest(
            name="Permission Gate",
            objective="验证权限门禁",
            start_node="mutate",
            nodes=[
                WorkflowNode(
                    id="mutate",
                    agent_id=agent.id,
                    instruction="执行变更动作",
                    required_permission="admin",
                    requires_approval=False,
                    next_nodes=[],
                )
            ],
        )
    )
    run = await service.create_run(
        workflow_id=wf.id,
        req=RunCreateRequest(input={"actor_permission": "read"}),
    )
    assert run is not None
    status = await _wait_run(service, run.id)
    assert status == RunStatus.failed
    loaded = await service.get_run(run.id)
    assert loaded is not None
    assert loaded.error is not None
    assert "permission denied" in loaded.error


async def test_environment_bootstrap_with_monitoring_fallback(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))

    async def fake_execute_tool(tool, query, context, timeout_sec=10.0):  # type: ignore[no-untyped-def]
        if "92.168.69.176" in tool.base_url:
            raise RuntimeError("connect timeout")
        return f'{{"tool":"{tool.kind.value}","query":"{query}"}}'

    service._execute_tool = fake_execute_tool  # type: ignore[method-assign]

    boot = await service.bootstrap_environment(
        EnvironmentBootstrapRequest(
            monitoring_ip="92.168.69.176",
            monitoring_port=9090,
            k8s_api_url="https://192.168.10.1:6443",
            k8s_verify_tls=False,
            create_mission_workflow=True,
            workflow_name="Prod Autonomous Incident",
        )
    )
    assert boot.workflow is not None
    assert boot.primary_tool_id is not None
    assert any("error:" in x for x in boot.probe_results.values())
    assert any("ok:" in x for x in boot.probe_results.values())
    assert any(t.base_url == "http://192.168.69.176:9090" for t in boot.tools)

    triage = next((n for n in boot.workflow.nodes if n.id == "triage_signal"), None)
    assert triage is not None
    assert triage.tool_query == "sum(up) by (job)"

    run = await service.create_run(
        workflow_id=boot.workflow.id,
        req=RunCreateRequest(
            input={
                "actor_permission": "admin",
                "service": "gateway",
                "cluster": "prod-sh",
            }
        ),
    )
    assert run is not None
    status = await _wait_run(service, run.id)
    assert status in (RunStatus.waiting_approval, RunStatus.completed)


async def test_tool_failure_is_soft_error_and_run_continues(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))

    async def fake_execute_tool(tool, query, context, timeout_sec=10.0):  # type: ignore[no-untyped-def]
        raise RuntimeError("403 forbidden")

    service._execute_tool = fake_execute_tool  # type: ignore[method-assign]

    agent = await service.create_agent(
        AgentCreateRequest(
            name="Worker",
            role="worker",
            system_prompt="执行诊断并汇总结果",
            model="gpt-5.4-mini",
        )
    )
    tool = await service.create_tool(
        ToolCreateRequest(
            name="K8s",
            kind="kubernetes",
            base_url="https://192.168.10.1:6443",
            verify_tls=False,
            default_query="/version",
            required_permission="read",
        )
    )
    wf = await service.create_workflow(
        WorkflowCreateRequest(
            name="Soft Error Flow",
            objective="验证工具失败软降级",
            start_node="collect",
            nodes=[
                WorkflowNode(
                    id="collect",
                    agent_id=agent.id,
                    instruction="拉取集群状态并输出判断",
                    tool_binding=tool.id,
                    tool_query="/api/v1/nodes",
                    required_permission="read",
                    requires_approval=False,
                    next_nodes=[],
                )
            ],
        )
    )

    run = await service.create_run(
        workflow_id=wf.id,
        req=RunCreateRequest(input={"actor_permission": "read"}),
    )
    assert run is not None
    status = await _wait_run(service, run.id)
    assert status == RunStatus.completed
    loaded = await service.get_run(run.id)
    assert loaded is not None
    assert any(evt.kind == "tool_failed" for evt in loaded.events)
