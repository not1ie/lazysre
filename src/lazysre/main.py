import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from lazysre.models import MemorySearchResponse, TaskCreateRequest, TaskRecord
from lazysre.platform.models import (
    AgentCreateRequest,
    AgentDefinition,
    AutoDesignRequest,
    OpsToolDefinition,
    PlatformOverview,
    PlatformTemplate,
    QuickstartRequest,
    RunApprovalRequest,
    RunCreateRequest,
    ToolCreateRequest,
    ToolProbeRequest,
    ToolProbeResult,
    WorkflowCreateRequest,
    WorkflowDefinition,
    WorkflowRun,
)
from lazysre.platform.service import PlatformService
from lazysre.services.task_service import TaskService

app = FastAPI(title="LazySRE", version="0.1.0")
task_service = TaskService()
platform_service = PlatformService()
web_dir = Path(__file__).resolve().parent / "web"

if web_dir.exists():
    app.mount("/web", StaticFiles(directory=web_dir), name="web")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
async def web_console() -> FileResponse:
    if not web_dir.exists():
        raise HTTPException(status_code=404, detail="web console not found")
    return FileResponse(web_dir / "index.html")


@app.post("/v1/tasks", response_model=TaskRecord)
async def create_task(req: TaskCreateRequest) -> TaskRecord:
    return await task_service.create_task(req)


@app.get("/v1/tasks/{task_id}", response_model=TaskRecord)
async def get_task(task_id: str) -> TaskRecord:
    task = await task_service.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    return task


@app.get("/v1/tasks", response_model=list[TaskRecord])
async def list_tasks() -> list[TaskRecord]:
    return await task_service.list_tasks()


@app.post("/v1/tasks/{task_id}/cancel", response_model=TaskRecord)
async def cancel_task(task_id: str) -> TaskRecord:
    task = await task_service.cancel_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    return task


@app.post("/v1/tasks/{task_id}/rerun", response_model=TaskRecord)
async def rerun_task(task_id: str) -> TaskRecord:
    task = await task_service.rerun_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    return task


@app.get("/v1/memory/search", response_model=MemorySearchResponse)
async def search_memory(q: str, limit: int = 5) -> MemorySearchResponse:
    if not q.strip():
        raise HTTPException(status_code=400, detail="query must not be empty")
    if limit < 1:
        raise HTTPException(status_code=400, detail="limit must be >= 1")
    return await task_service.search_memory(query=q.strip(), limit=min(limit, 20))


@app.post("/v1/platform/agents", response_model=AgentDefinition)
async def create_agent(req: AgentCreateRequest) -> AgentDefinition:
    return await platform_service.create_agent(req)


@app.get("/v1/platform/agents", response_model=list[AgentDefinition])
async def list_agents() -> list[AgentDefinition]:
    return await platform_service.list_agents()


@app.post("/v1/platform/tools", response_model=OpsToolDefinition)
async def create_tool(req: ToolCreateRequest) -> OpsToolDefinition:
    try:
        return await platform_service.create_tool(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/platform/tools", response_model=list[OpsToolDefinition])
async def list_tools() -> list[OpsToolDefinition]:
    return await platform_service.list_tools()


@app.post("/v1/platform/tools/{tool_id}/probe", response_model=ToolProbeResult)
async def probe_tool(tool_id: str, req: ToolProbeRequest) -> ToolProbeResult:
    try:
        return await platform_service.probe_tool(tool_id, req)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"tool probe failed: {exc}") from exc


@app.get("/v1/platform/templates", response_model=list[PlatformTemplate])
async def list_templates() -> list[PlatformTemplate]:
    return await platform_service.list_templates()


@app.get("/v1/platform/overview", response_model=PlatformOverview)
async def platform_overview() -> PlatformOverview:
    return await platform_service.get_overview()


@app.post("/v1/platform/workflows", response_model=WorkflowDefinition)
async def create_workflow(req: WorkflowCreateRequest) -> WorkflowDefinition:
    try:
        return await platform_service.create_workflow(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/platform/workflows", response_model=list[WorkflowDefinition])
async def list_workflows() -> list[WorkflowDefinition]:
    return await platform_service.list_workflows()


@app.post("/v1/platform/quickstart", response_model=WorkflowDefinition)
async def quickstart(req: QuickstartRequest) -> WorkflowDefinition:
    return await platform_service.quickstart(req)


@app.post("/v1/platform/autodesign", response_model=WorkflowDefinition)
async def auto_design(req: AutoDesignRequest) -> WorkflowDefinition:
    try:
        return await platform_service.auto_design(req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/platform/workflows/{workflow_id}/runs", response_model=WorkflowRun)
async def create_run(workflow_id: str, req: RunCreateRequest) -> WorkflowRun:
    run = await platform_service.create_run(workflow_id=workflow_id, req=req)
    if not run:
        raise HTTPException(status_code=404, detail="workflow not found")
    return run


@app.get("/v1/platform/runs", response_model=list[WorkflowRun])
async def list_runs(workflow_id: str | None = None) -> list[WorkflowRun]:
    return await platform_service.list_runs(workflow_id=workflow_id)


@app.get("/v1/platform/runs/{run_id}", response_model=WorkflowRun)
async def get_run(run_id: str) -> WorkflowRun:
    run = await platform_service.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return run


@app.post("/v1/platform/runs/{run_id}/cancel", response_model=WorkflowRun)
async def cancel_run(run_id: str) -> WorkflowRun:
    run = await platform_service.cancel_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return run


@app.post("/v1/platform/runs/{run_id}/approval", response_model=WorkflowRun)
async def run_approval(run_id: str, req: RunApprovalRequest) -> WorkflowRun:
    try:
        run = await platform_service.approve_run(run_id, req)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return run


@app.get("/v1/platform/runs/{run_id}/events")
async def get_run_events(run_id: str) -> list[dict[str, object]]:
    run = await platform_service.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return [e.model_dump(mode="json") for e in run.events]


@app.get("/v1/platform/runs/{run_id}/stream")
async def stream_run(run_id: str) -> StreamingResponse:
    run = await platform_service.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")

    async def event_gen():
        index = 0
        while True:
            current = await platform_service.get_run(run_id)
            if not current:
                yield "event: end\ndata: {}\n\n"
                return
            events = current.events
            while index < len(events):
                payload = json.dumps(events[index].model_dump(mode="json"), ensure_ascii=False)
                yield f"data: {payload}\n\n"
                index += 1
            if current.status.value in ("completed", "failed", "canceled"):
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(0.5)

    return StreamingResponse(event_gen(), media_type="text/event-stream")
