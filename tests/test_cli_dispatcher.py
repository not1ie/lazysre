from lazysre.cli.dispatcher import Dispatcher
from lazysre.cli.executor import SafeExecutor
from lazysre.cli.llm import MockFunctionCallingLLM
from lazysre.cli.tools import build_default_registry


async def test_dispatcher_runs_mock_tool_call_in_dry_run() -> None:
    dispatcher = Dispatcher(
        llm=MockFunctionCallingLLM(),
        registry=build_default_registry(),
        executor=SafeExecutor(dry_run=True),
        model="gpt-5.4-mini",
        max_steps=4,
    )
    result = await dispatcher.run("帮我看看 k8s pod 状态")
    tool_calls = [e for e in result.events if e.kind == "tool_call"]
    tool_outputs = [e for e in result.events if e.kind == "tool_output"]
    assert tool_calls
    assert tool_outputs
    assert "dry-run" in result.final_text


async def test_safe_executor_blocks_unknown_binary() -> None:
    executor = SafeExecutor(dry_run=False)
    result = await executor.run(["rm", "-rf", "/"])
    assert result.ok is False
    assert result.blocked is True
    assert result.exit_code == 126

