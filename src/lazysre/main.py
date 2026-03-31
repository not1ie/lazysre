from fastapi import FastAPI, HTTPException

from lazysre.models import MemorySearchResponse, TaskCreateRequest, TaskRecord
from lazysre.services.task_service import TaskService

app = FastAPI(title="LazySRE", version="0.1.0")
task_service = TaskService()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


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
