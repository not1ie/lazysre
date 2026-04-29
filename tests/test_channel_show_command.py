import json
from pathlib import Path

from typer.testing import CliRunner

from lazysre.cli.main import app
from lazysre.main import _create_channel_run_artifact


def _build_run_artifact(*, trace_id: str) -> dict[str, object]:
    return _create_channel_run_artifact(
        provider="telegram",
        trace_id=trace_id,
        user_id="u1",
        chat_id="c1",
        instruction="检查 swarm",
        final_text="done",
        event_count=4,
        timeline=[
            {"kind": "llm_turn", "message": "diagnosing", "duration_ms": 12},
            {"kind": "tool_call", "message": "docker service ls", "duration_ms": 30},
        ],
        actionables={
            "commands": [
                {"command": "docker service ps api", "risk_level": "low", "requires_approval": False},
            ],
            "needs_approval": False,
        },
        execution_templates={"count": 0, "items": []},
    )


def test_channel_show_by_trace_keyword_json(monkeypatch, tmp_path: Path) -> None:
    run_dir = tmp_path / "runs"
    monkeypatch.setenv("LAZYSRE_CHANNEL_RUN_DIR", str(run_dir))
    monkeypatch.delenv("LAZYSRE_CHANNEL_ARTIFACT_HMAC_KEY", raising=False)
    meta = _build_run_artifact(trace_id="trc-demo-show-1")
    assert Path(str(meta["path"])).exists()
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "channel-show",
            "demo-show",
            "--run-dir",
            str(run_dir),
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["trace_id"] == "trc-demo-show-1"
    assert payload["verify"]["ok"] is True
    assert payload["summary"]["command_count"] == 1
    assert payload["timeline"][0]["kind"] == "llm_turn"


def test_channel_show_signed_without_hmac_key_fails(monkeypatch, tmp_path: Path) -> None:
    run_dir = tmp_path / "runs"
    monkeypatch.setenv("LAZYSRE_CHANNEL_RUN_DIR", str(run_dir))
    monkeypatch.setenv("LAZYSRE_CHANNEL_ARTIFACT_HMAC_KEY", "artifact-secret")
    meta = _build_run_artifact(trace_id="trc-demo-show-2")
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "channel-show",
            str(meta["path"]),
            "--json",
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["verify"]["ok"] is False
    assert payload["verify"]["signed"] is True

    ok = runner.invoke(
        app,
        [
            "channel-show",
            str(meta["path"]),
            "--hmac-key",
            "artifact-secret",
            "--json",
        ],
    )
    assert ok.exit_code == 0
    ok_payload = json.loads(ok.stdout)
    assert ok_payload["verify"]["ok"] is True
