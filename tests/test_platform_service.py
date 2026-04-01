import asyncio
from pathlib import Path

from lazysre.platform.models import AutoDesignRequest, QuickstartRequest, RunCreateRequest, RunStatus
from lazysre.platform.service import PlatformService


async def _wait_run(service: PlatformService, run_id: str, timeout: float = 4.0) -> RunStatus:
    start = asyncio.get_running_loop().time()
    while True:
        run = await service.get_run(run_id)
        if run and run.status in (RunStatus.completed, RunStatus.failed, RunStatus.canceled):
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
    assert status in (RunStatus.completed, RunStatus.failed, RunStatus.canceled)

    overview = await service.get_overview()
    assert overview.total_workflows >= 1
    assert overview.total_runs >= 1
    assert 0.0 <= overview.success_rate <= 1.0
