from fastapi import FastAPI, HTTPException

from lazysre.models import TaskCreateRequest, TaskRecord
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

