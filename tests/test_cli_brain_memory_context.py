from pathlib import Path

from lazysre.cli.brain import BrainContext, DEFAULT_SYSTEM_PROMPT
from lazysre.cli.context_window import ContextWindowManager, compact_conversation
from lazysre.cli.memory import IncidentMemoryStore, format_memory_context


def test_brain_prompt_contains_autonomous_engine_role() -> None:
    assert "Role: LazySRE Autonomous Engine" in DEFAULT_SYSTEM_PROMPT
    rendered = BrainContext(
        target_summary="k8s_namespace=default",
        conversation_context="turn=1 user=hello",
        memory_context="case1",
    ).render()
    assert "Target Environment" in rendered
    assert "Conversation Context" in rendered
    assert "Historical Memory" in rendered


def test_context_window_compacts_tool_output() -> None:
    manager = ContextWindowManager(max_chars=300, max_tool_output_chars=260)
    raw = (
        '{"ok": true, "stdout": "' + ("line\\n" * 500) + 'error critical timeout", "stderr": ""}'
    )
    compact = manager.fit_tool_output_json(raw)
    assert len(compact) <= 260
    assert "summary" in compact or "error" in compact.lower()


def test_memory_store_add_and_search(tmp_path: Path) -> None:
    store = IncidentMemoryStore(tmp_path / "history_db")
    store.add_case(
        symptom="payment service latency spike",
        root_cause="cpu throttling in payment deployment",
        fix_commands=["kubectl -n default rollout restart deploy/payment"],
        rollback_commands=["kubectl -n default rollout undo deploy/payment"],
        metadata={"source": "test"},
    )
    rows = store.search_similar("payment latency", limit=3)
    assert rows
    context = format_memory_context(rows)
    assert "payment" in context.lower()


def test_compact_conversation_includes_trace() -> None:
    turns = [
        {
            "user": "为什么变慢",
            "assistant": "正在诊断",
            "trace": ["Thought: gather", "Action: get_metrics", "Observation: latency high"],
        }
    ]
    text = compact_conversation(turns, max_chars=500)
    assert "trace" in text
    assert "get_metrics" in text
