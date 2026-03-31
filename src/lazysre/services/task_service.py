from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from lazysre.models import TaskCreateRequest, TaskRecord, TaskStatus
from lazysre.runtime.agent_runtime import AgentRuntime


class TaskService:
    def __init__(self) -> None:
        self._tasks: dict[str, TaskRecord] = {}
        self._runtime = AgentRuntime()
        self._lock = asyncio.Lock()

    async def create_task(self, req: TaskCreateRequest) -> TaskRecord:
        task = TaskRecord(objective=req.objective, context=req.context)
        async with self._lock:
            self._tasks[task.id] = task
        asyncio.create_task(self._run_task(task.id))
        return task

    async def get_task(self, task_id: str) -> TaskRecord | None:
        return self._tasks.get(task_id)

    async def list_tasks(self) -> list[TaskRecord]:
        return list(self._tasks.values())

    async def _run_task(self, task_id: str) -> None:
        task = self._tasks[task_id]
        task.status = TaskStatus.running
        task.updated_at = datetime.now(timezone.utc)
        try:
            await self._runtime.run(task)
            task.status = TaskStatus.completed
        except Exception as exc:
            task.status = TaskStatus.failed
            task.error = str(exc)
        finally:
            task.updated_at = datetime.now(timezone.utc)

