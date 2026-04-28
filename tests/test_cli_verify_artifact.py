import json

from typer.testing import CliRunner

from lazysre.cli.main import app
from lazysre.main import _create_channel_run_artifact


def _build_run_artifact() -> dict[str, object]:
    return _create_channel_run_artifact(
        provider="generic",
        trace_id="trc-test-verify",
        user_id="u1",
        chat_id="c1",
        instruction="检查 swarm",
        final_text="done",
        event_count=3,
        timeline=[{"kind": "final", "message": "done"}],
        actionables={"count": 0, "items": []},
        execution_templates={"count": 0, "items": []},
    )


def test_verify_artifact_cli_ok_unsigned(monkeypatch, tmp_path):
    monkeypatch.setenv("LAZYSRE_CHANNEL_RUN_DIR", str(tmp_path / "runs"))
    monkeypatch.delenv("LAZYSRE_CHANNEL_ARTIFACT_HMAC_KEY", raising=False)
    meta = _build_run_artifact()
    runner = CliRunner()
    result = runner.invoke(app, ["verify-artifact", str(meta["path"]), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["digest_match"] is True
    assert payload["signed"] is False
    assert payload["signature_valid"] is None


def test_verify_artifact_cli_signed_requires_key(monkeypatch, tmp_path):
    monkeypatch.setenv("LAZYSRE_CHANNEL_RUN_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_ARTIFACT_HMAC_KEY", "artifact-secret")
    meta = _build_run_artifact()
    runner = CliRunner()
    missing_key = runner.invoke(app, ["verify-artifact", str(meta["path"]), "--json"])
    assert missing_key.exit_code == 1
    payload = json.loads(missing_key.stdout)
    assert payload["ok"] is False
    assert payload["signed"] is True
    assert payload["signature_valid"] is False

    ok = runner.invoke(app, ["verify-artifact", str(meta["path"]), "--hmac-key", "artifact-secret", "--json"])
    assert ok.exit_code == 0
    ok_payload = json.loads(ok.stdout)
    assert ok_payload["ok"] is True
    assert ok_payload["signed"] is True
    assert ok_payload["signature_valid"] is True
