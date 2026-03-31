from lazysre.models import TaskRecord
from lazysre.runtime.agent_runtime import AgentRuntime


async def test_agent_runtime_completes_task() -> None:
    runtime = AgentRuntime()
    task = TaskRecord(
        objective="定位网关 5xx 升高原因并给出修复建议",
        context={"service": "gateway", "cluster": "prod-sh"},
    )

    result = await runtime.run(task)
    assert result.plan
    assert result.steps
    assert result.summary
    assert result.critic is not None
    assert result.critic.score > 0

