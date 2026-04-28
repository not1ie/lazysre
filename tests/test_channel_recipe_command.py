import json

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
