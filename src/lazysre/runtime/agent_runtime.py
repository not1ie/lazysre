from __future__ import annotations

from collections.abc import Callable

from lazysre.config import settings
from lazysre.models import TaskRecord
from lazysre.runtime.critic import Critic
from lazysre.runtime.memory import MemoryStore
from lazysre.runtime.planner import Planner
from lazysre.runtime.worker import Worker
from lazysre.tools.registry import ToolRegistry


class TaskCancelledError(Exception):
    pass


class AgentRuntime:
    def __init__(self) -> None:
        self.memory = MemoryStore()
        self.tools = ToolRegistry()
        self.planner = Planner()
        self.worker = Worker(self.tools)
        self.critic = Critic()

    async def run(
        self,
        task: TaskRecord,
        should_stop: Callable[[], bool] | None = None,
        on_event: Callable[[str, str], None] | None = None,
    ) -> TaskRecord:
        def emit(kind: str, message: str) -> None:
            if on_event:
                on_event(kind, message)

        if should_stop and should_stop():
            raise TaskCancelledError("task canceled before planning")

        if not task.plan:
            emit("planning_started", "开始自动规划任务")
            task.plan = await self.planner.make_plan(task.objective, task.context)
            emit("planning_finished", f"规划完成，共 {len(task.plan)} 步")

        reflections = 0
        while reflections <= settings.max_reflections:
            if should_stop and should_stop():
                raise TaskCancelledError("task canceled during execution")

            next_index = len(task.steps)
            remaining = task.plan[next_index:]
            if not remaining:
                break

            for step in remaining:
                if should_stop and should_stop():
                    raise TaskCancelledError("task canceled during step execution")
                emit("step_started", step)
                result = await self.worker.execute(step, task.context)
                task.steps.append(result)
                self.memory.append_step(task.id, result)
                emit("step_finished", f"{result.tool} success={result.success}")

            task.critic = self.critic.evaluate(task.objective, task.plan, task.steps)
            if task.critic.done:
                emit("critic_done", "质检通过，准备生成总结")
                break

            reflections += 1
            task.reflections = reflections
            task.plan.append(f"根据反馈补充诊断: {task.critic.feedback}")
            emit("reflection_added", task.critic.feedback)

        task.critic = self.critic.evaluate(task.objective, task.plan, task.steps)
        task.summary = self._summarize(task)
        self.memory.promote_summary(task.summary)
        emit("summary_ready", "任务总结已生成")
        return task

    def _summarize(self, task: TaskRecord) -> str:
        outputs = [f"{idx+1}. {step.output}" for idx, step in enumerate(task.steps)]
        lines = [
            f"目标: {task.objective}",
            f"执行步骤数: {len(task.steps)}",
            f"得分: {task.critic.score if task.critic else 0}",
            "结论:",
            *outputs[:6],
        ]
        return "\n".join(lines)
