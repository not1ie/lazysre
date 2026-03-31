import asyncio
from pathlib import Path

from lazysre.models import TaskCreateRequest, TaskRecord, TaskStatus
from lazysre.services.task_service import TaskService


async def _wait_until_terminal(service: TaskService, task_id: str, timeout: float = 3.0) -> None:
    start = asyncio.get_running_loop().time()
    while True:
        task = await service.get_task(task_id)
        if task and task.status in (
            TaskStatus.completed,
            TaskStatus.failed,
            TaskStatus.canceled,
        ):
            return
        if asyncio.get_running_loop().time() - start > timeout:
            raise TimeoutError(f"task did not finish: {task_id}")
        await asyncio.sleep(0.02)


async def test_cancel_task_marks_status_canceled(tmp_path: Path) -> None:
    service = TaskService(store_path=str(tmp_path / "tasks.json"))
    original_execute = service._runtime.worker.execute

    async def slow_execute(step: str, context: dict[str, object]):
        await asyncio.sleep(0.08)
        return await original_execute(step, context)

    service._runtime.worker.execute = slow_execute  # type: ignore[assignment]

    created = await service.create_task(
        TaskCreateRequest(objective="排查网关异常", context={"service": "gateway"})
    )
    await asyncio.sleep(0.01)
    await service.cancel_task(created.id)
    await _wait_until_terminal(service, created.id)

    task = await service.get_task(created.id)
    assert task is not None
    assert task.status == TaskStatus.canceled
    assert any(e.kind in ("task_canceled", "cancel_requested") for e in task.events)


async def test_rerun_task_creates_new_task_with_parent(tmp_path: Path) -> None:
    service = TaskService(store_path=str(tmp_path / "tasks.json"))
    created = await service.create_task(
        TaskCreateRequest(objective="定位 5xx", context={"service": "gateway"})
    )
    await _wait_until_terminal(service, created.id)

    rerun = await service.rerun_task(created.id)
    assert rerun is not None
    assert rerun.id != created.id
    assert rerun.parent_task_id == created.id
    await _wait_until_terminal(service, rerun.id)

    tasks = await service.list_tasks()
    assert len(tasks) == 2


async def test_recover_running_task_on_restart(tmp_path: Path) -> None:
    store = str(tmp_path / "tasks.json")
    service = TaskService(store_path=store)
    orphan = TaskRecord(
        objective="检查中断恢复",
        context={"service": "gateway"},
        status=TaskStatus.running,
    )
    service._tasks[orphan.id] = orphan
    service._persist_unlocked()

    recovered = TaskService(store_path=store)
    loaded = await recovered.get_task(orphan.id)
    assert loaded is not None
    assert loaded.status == TaskStatus.failed
    assert loaded.error == "task interrupted by process restart"
    assert any(e.kind == "task_recovered" for e in loaded.events)
