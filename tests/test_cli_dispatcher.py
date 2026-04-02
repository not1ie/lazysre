from pathlib import Path

from lazysre.cli.audit import AuditLogger
from lazysre.cli.dispatcher import Dispatcher
from lazysre.cli.executor import SafeExecutor
from lazysre.cli.llm import MockFunctionCallingLLM
from lazysre.cli.permissions import ToolPermissionContext
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


async def test_safe_executor_requires_approval_on_high_risk_execute() -> None:
    executor = SafeExecutor(dry_run=False, approval_mode="balanced", approval_granted=False)
    result = await executor.run(["kubectl", "delete", "pod", "foo"])
    assert result.ok is False
    assert result.blocked is True
    assert result.requires_approval is True
    assert result.risk_level in {"high", "critical"}
    assert result.exit_code == 125


async def test_safe_executor_interactive_gate_can_block_high_risk_even_permissive_mode() -> None:
    calls: list[list[str]] = []

    def _reject(command: list[str], _decision) -> bool:
        calls.append(command)
        return False

    executor = SafeExecutor(
        dry_run=False,
        approval_mode="permissive",
        approval_granted=False,
        approval_callback=_reject,
    )
    result = await executor.run(["kubectl", "delete", "pod", "foo"])
    assert calls
    assert result.ok is False
    assert result.blocked is True
    assert result.requires_approval is True
    assert result.exit_code == 125


async def test_safe_executor_dry_run_keeps_policy_signal(tmp_path: Path) -> None:
    audit_path = tmp_path / "cli-audit.jsonl"
    executor = SafeExecutor(
        dry_run=True,
        approval_mode="strict",
        approval_granted=False,
        audit_logger=AuditLogger(audit_path),
    )
    result = await executor.run(["docker", "restart", "api"])
    assert result.ok is True
    assert result.dry_run is True
    assert result.requires_approval is True
    assert audit_path.exists()
    content = audit_path.read_text(encoding="utf-8")
    assert '"risk_level": "high"' in content


async def test_safe_executor_masks_token_and_emits_risk_report() -> None:
    executor = SafeExecutor(dry_run=True, approval_mode="balanced")
    result = await executor.run(["kubectl", "--token", "abcd1234", "delete", "pod", "foo"])
    assert result.ok is True
    assert result.risk_report.get("risk_level") in {"high", "critical"}
    assert result.command[2] == "***"
    assert result.requires_approval is True


async def test_tool_permission_context_blocks_registry_tool() -> None:
    registry = build_default_registry(
        permission_context=ToolPermissionContext.from_iterables(
            deny_names=["docker"],
        )
    )
    dispatcher = Dispatcher(
        llm=MockFunctionCallingLLM(),
        registry=registry,
        executor=SafeExecutor(dry_run=True),
        model="gpt-5.4-mini",
        max_steps=3,
    )
    result = await dispatcher.run("重启容器")
    outputs = [e for e in result.events if e.kind == "tool_output"]
    assert outputs
    preview = str(outputs[0].data.get("output_preview", ""))
    assert "tool blocked by permission context" in preview


async def test_dispatcher_emits_timeline_durations() -> None:
    dispatcher = Dispatcher(
        llm=MockFunctionCallingLLM(),
        registry=build_default_registry(),
        executor=SafeExecutor(dry_run=True),
        model="gpt-5.4-mini",
        max_steps=3,
    )
    result = await dispatcher.run("检查 k8s")
    llm_events = [e for e in result.events if e.kind == "llm_turn"]
    assert llm_events
    assert isinstance(llm_events[0].data.get("duration_ms"), float | int)


async def test_dispatcher_stream_callback_receives_tokens() -> None:
    chunks: list[str] = []

    def _stream(delta: str) -> None:
        chunks.append(delta)

    dispatcher = Dispatcher(
        llm=MockFunctionCallingLLM(),
        registry=build_default_registry(),
        executor=SafeExecutor(dry_run=True),
        model="gpt-5.4-mini",
        max_steps=2,
        text_stream=_stream,
    )
    result = await dispatcher.run("随便问一个不会触发工具的提示")
    assert result.final_text
    assert chunks
