from __future__ import annotations

from typing import Any

from lazysre.config import settings
from lazysre.models import TaskRecord
from lazysre.runtime.critic import Critic
from lazysre.runtime.memory import MemoryStore
from lazysre.runtime.planner import Planner
from lazysre.runtime.worker import Worker
from lazysre.tools.registry import ToolRegistry


class AgentRuntime:
    def __init__(self) -> None:
        self.memory = MemoryStore()
        self.tools = ToolRegistry()
        self.planner = Planner()
        self.worker = Worker(self.tools)
        self.critic = Critic()

    async def run(self, task: TaskRecord) -> TaskRecord:
        if not task.plan:
            task.plan = await self.planner.make_plan(task.objective, task.context)

        reflections = 0
        while reflections <= settings.max_reflections:
            next_index = len(task.steps)
            remaining = task.plan[next_index:]
            if not remaining:
                break

            for step in remaining:
                result = await self.worker.execute(step, task.context)
                task.steps.append(result)
                self.memory.append_step(task.id, result)

            task.critic = self.critic.evaluate(task.objective, task.plan, task.steps)
            if task.critic.done:
                break

            reflections += 1
            task.plan.append(f"根据反馈补充诊断: {task.critic.feedback}")

        task.critic = self.critic.evaluate(task.objective, task.plan, task.steps)
        task.summary = self._summarize(task)
        self.memory.promote_summary(task.summary)
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

