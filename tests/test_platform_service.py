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
    SkillCreateRequest,
    SkillRunRequest,
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


async def test_skill_catalog_create_and_dry_run(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))
    service._skill_store.path = tmp_path / "skills.json"

    skills = await service.list_skills()
    assert any(item.name == "remote-health" for item in skills)

    custom = await service.create_skill(
        SkillCreateRequest(
            name="team-nginx",
            title="Team Nginx",
            description="团队 Nginx 巡检",
            category="middleware",
            mode="diagnose",
            risk_level="low",
            required_permission="read",
            instruction="检查 Nginx",
            variables={"ssh_target": "root@host"},
            precheck_commands=["echo precheck"],
            read_commands=["lazysre remote {ssh_target} --scenario nginx"],
            postcheck_commands=["echo postcheck"],
            tags=["nginx"],
        )
    )
    assert custom.source == "custom"
    assert custom.precheck_commands == ["echo precheck"]
    assert custom.postcheck_commands == ["echo postcheck"]

    result = await service.run_skill(
        "team-nginx",
        SkillRunRequest(variables={"ssh_target": "root@192.168.10.101"}, dry_run=True),
    )

    assert result.status == "planned"
    assert result.commands["precheck"] == ["echo precheck"]
    assert result.commands["read"] == ["lazysre remote root@192.168.10.101 --scenario nginx"]
    assert result.commands["postcheck"] == ["echo postcheck"]


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
        if tool.base_url.startswith("http://92.168.69.176"):
            raise RuntimeError("connect timeout")
        return f'{{"tool":"{tool.kind.value}","query":"{query}"}}'

    service._execute_tool = fake_execute_tool  # type: ignore[method-assign]

    boot = await service.bootstrap_environment(
        EnvironmentBootstrapRequest(
            monitoring_ip="92.168.69.176",
            monitoring_port=9090,
            k8s_api_url="https://192.168.10.1:6443",
            k8s_verify_tls=False,
            k8s_bearer_token="test-token-1",
            create_mission_workflow=True,
            workflow_name="Prod Autonomous Incident",
        )
    )
    assert boot.workflow is not None
    assert boot.primary_tool_id is not None
    assert any(x.startswith("error(") for x in boot.probe_results.values())
    assert any(x.startswith("ok(") for x in boot.probe_results.values())
    assert any(t.base_url == "http://192.168.69.176:9090" for t in boot.tools)
    k8s_tool = next((t for t in boot.tools if t.kind == "kubernetes"), None)
    assert k8s_tool is not None
    assert k8s_tool.headers.get("Authorization") == "Bearer test-token-1"

    triage = next((n for n in boot.workflow.nodes if n.id == "triage_signal"), None)
    assert triage is not None
    assert triage.tool_query == "sum(up) by (job)"

    # 再次引导但不带 token，应保留已有认证头，避免误清空导致 403。
    boot2 = await service.bootstrap_environment(
        EnvironmentBootstrapRequest(
            monitoring_ip="92.168.69.176",
            monitoring_port=9090,
            k8s_api_url="https://192.168.10.1:6443",
            k8s_verify_tls=False,
            k8s_bearer_token="",
            create_mission_workflow=False,
        )
    )
    k8s_tool2 = next((t for t in boot2.tools if t.kind == "kubernetes"), None)
    assert k8s_tool2 is not None
    assert k8s_tool2.headers.get("Authorization") == "Bearer test-token-1"

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


async def test_tool_health_and_bootstrap_pick_lower_latency(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))

    async def fake_execute_tool(tool, query, context, timeout_sec=10.0):  # type: ignore[no-untyped-def]
        if tool.base_url.startswith("http://92.168.69.176"):
            await asyncio.sleep(0.03)
            return '{"status":"success","candidate":"slow"}'
        if tool.base_url.startswith("http://192.168.69.176"):
            await asyncio.sleep(0.002)
            return '{"status":"success","candidate":"fast"}'
        return '{"major":"1","minor":"28"}'

    service._execute_tool = fake_execute_tool  # type: ignore[method-assign]

    boot = await service.bootstrap_environment(
        EnvironmentBootstrapRequest(
            monitoring_ip="92.168.69.176",
            monitoring_port=9090,
            k8s_api_url="https://192.168.10.1:6443",
            k8s_verify_tls=False,
            create_mission_workflow=False,
        )
    )
    assert boot.primary_tool_id is not None
    assert "ok(" in boot.probe_results[boot.primary_tool_id]

    primary = next((t for t in boot.tools if t.id == boot.primary_tool_id), None)
    assert primary is not None
    assert primary.base_url == "http://192.168.69.176:9090"

    health = await service.list_tools_health(timeout_sec=2.0)
    assert len(health) >= 3
    assert any(h.ok for h in health)
    assert any(h.kind == "kubernetes" for h in health)


async def test_incident_briefing_and_run_report_export(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))

    agent = await service.create_agent(
        AgentCreateRequest(
            name="Reporter Worker",
            role="worker",
            system_prompt="输出简洁诊断结论",
            model="gpt-5.4-mini",
        )
    )
    wf = await service.create_workflow(
        WorkflowCreateRequest(
            name="Report Flow",
            objective="验证简报与报告导出",
            start_node="collect",
            nodes=[
                WorkflowNode(
                    id="collect",
                    agent_id=agent.id,
                    instruction="收集当前状态并输出摘要",
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
    pm_evt = next((e for e in loaded.events if e.kind == "postmortem_generated"), None)
    assert pm_evt is not None
    pm_path = pm_evt.data.get("path", "")
    assert pm_path
    assert Path(pm_path).exists()

    briefing = await service.generate_incident_briefing(workflow_id=wf.id, timeout_sec=1.5)
    assert briefing.severity in {"low", "medium", "high", "critical"}
    assert briefing.headline
    assert len(briefing.recent_runs) >= 1
    assert briefing.recommendations
    assert briefing.artifact_path
    assert Path(briefing.artifact_path).exists()

    report = await service.get_run_report(run.id)
    assert report is not None
    assert report.run_id == run.id
    assert report.workflow_id == wf.id
    assert report.workflow_name == wf.name

    md = await service.export_run_report_markdown(run.id)
    assert md is not None
    assert run.id in md
    assert wf.name in md
    assert "# LazySRE Run Report" in md

    missing_md = await service.export_run_report_markdown("missing")
    assert missing_md is None

    all_items = await service.list_artifacts(kind="all", limit=50)
    assert all_items
    assert any(x.kind == "briefings" for x in all_items)
    assert any(x.kind == "postmortems" for x in all_items)

    briefing_items = await service.list_artifacts(kind="briefings", limit=20)
    assert briefing_items
    assert all(x.kind == "briefings" for x in briefing_items)

    target = briefing_items[0]
    loaded = await service.read_artifact(kind=target.kind, name=target.name)
    assert loaded is not None
    _, artifact_content = loaded
    assert "LazySRE Incident Briefing" in artifact_content or '"severity"' in artifact_content

    missing_artifact = await service.read_artifact(
        kind="briefings",
        name="missing-file.md",
    )
    assert missing_artifact is None

    try:
        await service.list_artifacts(kind="bad-kind", limit=10)
        assert False, "invalid kind should raise"
    except ValueError:
        assert True


async def test_run_compare_and_approval_advice(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))
    wf = await service.quickstart(
        QuickstartRequest(name="Compare Flow", objective="验证审批建议与 run 对比")
    )

    run1 = await service.create_run(
        workflow_id=wf.id,
        req=RunCreateRequest(input={"actor_permission": "write"}),
    )
    assert run1 is not None
    status1 = await _wait_run(service, run1.id)
    assert status1 == RunStatus.waiting_approval

    advice = await service.get_run_approval_advice(run1.id)
    assert advice is not None
    assert advice.node_id
    assert advice.recommended_action in {"approve", "approve_with_guardrails", "manual_review"}
    assert advice.reasons
    assert advice.checklist

    await service.approve_run(
        run1.id,
        RunApprovalRequest(action="approve", approver="oncall.a", comment="ok"),
    )
    status1_done = await _wait_run(service, run1.id)
    assert status1_done == RunStatus.completed

    run2 = await service.create_run(
        workflow_id=wf.id,
        req=RunCreateRequest(input={"actor_permission": "write"}),
    )
    assert run2 is not None
    status2 = await _wait_run(service, run2.id)
    assert status2 == RunStatus.waiting_approval

    await service.approve_run(
        run2.id,
        RunApprovalRequest(action="reject", approver="oncall.b", comment="high risk"),
    )
    loaded2 = await service.get_run(run2.id)
    assert loaded2 is not None
    assert loaded2.status == RunStatus.failed

    comp = await service.compare_runs(left_run_id=run1.id, right_run_id=run2.id)
    assert comp.left_run_id == run1.id
    assert comp.right_run_id == run2.id
    assert comp.left_status == RunStatus.completed.value
    assert comp.right_status == RunStatus.failed.value
    assert comp.summary

    try:
        await service.get_run_approval_advice(run1.id)
        assert False, "completed run should not have approval advice"
    except ValueError:
        assert True

    try:
        await service.compare_runs("missing-left", run2.id)
        assert False, "missing run should fail"
    except ValueError:
        assert True


async def test_approval_advice_uses_bound_tool_permission(tmp_path: Path) -> None:
    service = PlatformService(store_path=str(tmp_path / "platform.json"))
    agent = await service.create_agent(
        AgentCreateRequest(
            name="Advice Worker",
            role="worker",
            system_prompt="执行排障并给出操作建议",
            model="gpt-5.4-mini",
        )
    )
    tool = await service.create_tool(
        ToolCreateRequest(
            name="K8s Admin Tool",
            kind="kubernetes",
            base_url="https://192.168.10.1:6443",
            verify_tls=False,
            default_query="/version",
            required_permission="admin",
        )
    )
    wf = await service.create_workflow(
        WorkflowCreateRequest(
            name="Advice Tool Permission Flow",
            objective="验证审批建议按工具权限提升",
            start_node="guarded_step",
            nodes=[
                WorkflowNode(
                    id="guarded_step",
                    agent_id=agent.id,
                    instruction="重启异常工作负载并验证可用性",
                    tool_binding=tool.id,
                    required_permission="read",
                    requires_approval=True,
                    approval_reason="涉及生产操作",
                    next_nodes=[],
                )
            ],
        )
    )
    run = await service.create_run(
        workflow_id=wf.id,
        req=RunCreateRequest(input={"actor_permission": "admin"}),
    )
    assert run is not None
    status = await _wait_run(service, run.id)
    assert status == RunStatus.waiting_approval

    advice = await service.get_run_approval_advice(run.id)
    assert advice is not None
    assert advice.required_permission == "admin"
    assert advice.risk_level in {"high", "critical"}
