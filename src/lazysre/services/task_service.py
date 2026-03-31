from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from lazysre.config import settings
from lazysre.models import (
    MemorySearchResponse,
    TaskCreateRequest,
    TaskEvent,
    TaskRecord,
    TaskStatus,
)
from lazysre.runtime.agent_runtime import AgentRuntime, TaskCancelledError
from lazysre.storage.task_store import FileTaskStore


class TaskService:
    def __init__(self, store_path: str | None = None) -> None:
        file_path = store_path or str(Path(settings.data_dir) / settings.task_store_file)
        self._store = FileTaskStore(file_path)
        self._tasks: dict[str, TaskRecord] = self._store.load_all()
        self._runtime = AgentRuntime()
        self._lock = asyncio.Lock()
        self._running: dict[str, asyncio.Task[None]] = {}
        self._cancel_flags: set[str] = set()
        self._recover_inflight_tasks()

    async def create_task(self, req: TaskCreateRequest) -> TaskRecord:
        task = TaskRecord(objective=req.objective, context=req.context)
        async with self._lock:
            self._tasks[task.id] = task
            self._persist_unlocked()
            runner = asyncio.create_task(self._run_task(task.id))
            self._running[task.id] = runner
        return task

    async def get_task(self, task_id: str) -> TaskRecord | None:
        return self._tasks.get(task_id)

    async def list_tasks(self) -> list[TaskRecord]:
        return sorted(self._tasks.values(), key=lambda t: t.created_at, reverse=True)

    async def cancel_task(self, task_id: str) -> TaskRecord | None:
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return None
            if task.status in (TaskStatus.completed, TaskStatus.failed, TaskStatus.canceled):
                return task

            self._cancel_flags.add(task_id)
            self._add_event(task, "cancel_requested", "收到取消请求")
            self._persist_unlocked()
            return task

    async def rerun_task(self, task_id: str) -> TaskRecord | None:
        parent = self._tasks.get(task_id)
        if not parent:
            return None
        new_task = TaskRecord(
            objective=parent.objective,
            context=parent.context,
            parent_task_id=parent.id,
        )
        async with self._lock:
            self._tasks[new_task.id] = new_task
            self._persist_unlocked()
            runner = asyncio.create_task(self._run_task(new_task.id))
            self._running[new_task.id] = runner
        return new_task

    async def search_memory(self, query: str, limit: int = 5) -> MemorySearchResponse:
        hits = self._runtime.memory.search(query=query, limit=limit)
        return MemorySearchResponse(query=query, hits=hits)

    async def _run_task(self, task_id: str) -> None:
        async with self._lock:
            task = self._tasks[task_id]
            if task_id in self._cancel_flags:
                task.status = TaskStatus.canceled
                task.finished_at = datetime.now(timezone.utc)
                self._add_event(task, "canceled", "任务在启动前被取消")
                self._persist_unlocked()
                return

            task.status = TaskStatus.running
            task.started_at = datetime.now(timezone.utc)
            task.updated_at = datetime.now(timezone.utc)
            self._add_event(task, "task_started", "任务开始执行")
            self._persist_unlocked()

        def should_stop() -> bool:
            return task_id in self._cancel_flags

        def on_event(kind: str, message: str) -> None:
            self._add_event(task, kind, message)

        try:
            await self._runtime.run(task, should_stop=should_stop, on_event=on_event)
            async with self._lock:
                task.status = TaskStatus.completed
                self._add_event(task, "task_completed", "任务执行完成")
        except TaskCancelledError:
            async with self._lock:
                task.status = TaskStatus.canceled
                self._add_event(task, "task_canceled", "任务已取消")
        except Exception as exc:
            async with self._lock:
                task.status = TaskStatus.failed
                task.error = str(exc)
                self._add_event(task, "task_failed", f"任务失败: {exc}", level="error")
        finally:
            async with self._lock:
                task.finished_at = datetime.now(timezone.utc)
                task.updated_at = datetime.now(timezone.utc)
                self._cancel_flags.discard(task_id)
                self._running.pop(task_id, None)
                self._persist_unlocked()

    def _add_event(
        self, task: TaskRecord, kind: str, message: str, level: str = "info"
    ) -> None:
        task.events.append(TaskEvent(kind=kind, message=message, level=level))

    def _persist_unlocked(self) -> None:
        self._store.save_all(self._tasks)

    def _recover_inflight_tasks(self) -> None:
        dirty = False
        now = datetime.now(timezone.utc)
        for task in self._tasks.values():
            if task.status == TaskStatus.running:
                task.status = TaskStatus.failed
                task.error = "task interrupted by process restart"
                task.finished_at = now
                task.updated_at = now
                self._add_event(task, "task_recovered", "检测到未完成任务，已标记为失败", level="warning")
                dirty = True
        if dirty:
            self._store.save_all(self._tasks)
