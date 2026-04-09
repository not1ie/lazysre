from pathlib import Path

from lazysre.cli.dispatcher import Dispatcher
from lazysre.cli.executor import SafeExecutor
from lazysre.cli.llm import MockFunctionCallingLLM
from lazysre.cli.session import SessionStore
from lazysre.cli.tools import build_default_registry
from lazysre.cli.tools.builtin import builtin_tools
from lazysre.cli.tools.redact import redact_and_compress
from lazysre.cli.types import DispatchEvent, DispatchResult


def test_builtin_tools_include_observers_with_schema() -> None:
    specs = {item.spec.name: item.spec for item in builtin_tools()}
    assert "get_cluster_context" in specs
    assert "fetch_service_logs" in specs
    assert "get_metrics" in specs
    assert "get_swarm_context" in specs
    assert "fetch_swarm_service_logs" in specs
    assert specs["get_metrics"].parameters.get("required") == ["query"]


def test_redact_and_compress_masks_sensitive_fields() -> None:
    text = "\n".join(
        [
            "token=Bearer abcdefghijklmnopqrstuvwxyz12345",
            "owner=dev@example.com",
            "node=192.168.10.101",
            "sha=9f0c607f1a2b3c4d5e6f7a8b9c0d1e2f",
        ]
        + [f"line-{i}" for i in range(0, 300)]
    )
    masked = redact_and_compress(text, max_lines=40, max_chars=600)
    assert "[redacted-token]" in masked
    assert "[redacted-email]" in masked
    assert "192.168.*.*" in masked
    assert "[redacted-hex]" in masked
    assert "...<snip>..." in masked


def test_session_store_builds_pronoun_hint(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "session.json")
    result = DispatchResult(
        final_text="done",
        events=[
            DispatchEvent(
                kind="tool_call",
                message="fetch_service_logs",
                data={"arguments": {"pod": "payment-abc-123", "namespace": "prod"}},
            )
        ],
    )
    store.append_turn("先看一下 payment pod", result)
    hint = store.build_context_hint("重启它")
    assert "last_pod=payment-abc-123" in hint
    assert "last_namespace=prod" in hint
    entities = store.entities()
    assert entities["last_pod"] == "payment-abc-123"
    assert entities["last_namespace"] == "prod"


def test_session_store_recent_clear_and_export(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "session.json")
    base = DispatchResult(final_text="处理完成", events=[])
    store.append_turn("查看 pod", base)
    store.append_turn("重启它", base)
    turns = store.recent_turns(limit=5)
    assert len(turns) == 2
    md = store.export_markdown(limit=5)
    assert "Turn 1" in md and "Turn 2" in md
    store.clear()
    assert store.recent_turns(limit=5) == []


async def test_dispatcher_react_flow_for_latency_question() -> None:
    dispatcher = Dispatcher(
        llm=MockFunctionCallingLLM(),
        registry=build_default_registry(),
        executor=SafeExecutor(dry_run=True),
        model="gpt-5.4-mini",
        max_steps=6,
    )
    result = await dispatcher.run("为什么支付服务响应变慢了？")
    tool_calls = [e for e in result.events if e.kind == "tool_call"]
    called_names = [str(e.message) for e in tool_calls]
    assert "get_metrics" in called_names
    assert "get_cluster_context" in called_names
    assert "fetch_service_logs" in called_names
    assert "rollout restart" in result.final_text
