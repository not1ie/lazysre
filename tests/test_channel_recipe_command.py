import json
from pathlib import Path

from typer.testing import CliRunner

from lazysre.cli.main import app


def test_channel_recipe_json_generic() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "channel-recipe",
            "--provider",
            "generic",
            "--base-url",
            "http://127.0.0.1:8010",
            "--token",
            "abc123",
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["provider"] == "generic"
    assert payload["webhook_url"].endswith("/v1/channels/generic/webhook")
    assert payload["headers"]["X-LazySRE-Channel-Token"] == "abc123"
    assert "curl -sS -X POST" in payload["curl"]


def test_channel_recipe_text_telegram() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["channel-recipe", "--provider", "telegram"])
    assert result.exit_code == 0
    assert "/v1/channels/telegram/webhook" in result.stdout
    assert "X-LazySRE-Channel-Token" in result.stdout
    assert "X-Telegram-Bot-Api-Secret-Token" in result.stdout


def test_channel_test_local_generic_json(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LAZYSRE_CHANNEL_TOKEN", "channel-token")
    monkeypatch.setenv("LAZYSRE_CHANNEL_PROVIDER", "mock")
    monkeypatch.setenv("LAZYSRE_CHANNEL_HANDOFF_DIR", str(tmp_path / "handoff"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_DEDUP_FILE", str(tmp_path / "dedup.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_SESSION_FILE", str(tmp_path / "session.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_RUN_DIR", str(tmp_path / "runs"))
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "channel-test",
            "--provider",
            "generic",
            "--text",
            "检查 swarm",
            "--event-id",
            "evt-test-1",
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["mode"] == "local"
    assert payload["provider"] == "generic"
    assert payload["ok"] is True
    assert payload["status_code"] == 200
    assert isinstance(payload.get("response", {}).get("trace_id", ""), str)


def test_channel_test_local_telegram_includes_secret_header(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LAZYSRE_CHANNEL_TOKEN", "channel-token")
    monkeypatch.setenv("LAZYSRE_TELEGRAM_SECRET_TOKEN", "tg-secret")
    monkeypatch.setenv("LAZYSRE_CHANNEL_PROVIDER", "mock")
    monkeypatch.setenv("LAZYSRE_CHANNEL_HANDOFF_DIR", str(tmp_path / "handoff"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_DEDUP_FILE", str(tmp_path / "dedup.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_SESSION_FILE", str(tmp_path / "session.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_RUN_DIR", str(tmp_path / "runs"))
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "channel-test",
            "--provider",
            "telegram",
            "--text",
            "检查 k8s",
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    headers = payload["request"]["headers"]
    assert "X-Telegram-Bot-Api-Secret-Token" in headers
