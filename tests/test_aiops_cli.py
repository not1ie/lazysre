import json
from pathlib import Path

from typer.testing import CliRunner

import lazysre.cli.main as cli_main
from lazysre.cli.main import app


class _FakeBridgeClient:
    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def health(self) -> dict[str, object]:
        return {"ok": True, "status_code": 200, "url": "http://127.0.0.1:19090/health", "body": {"status": "ok"}}

    def list_skills(self, *, limit: int = 30) -> dict[str, object]:
        return {
            "ok": True,
            "status_code": 200,
            "url": "http://127.0.0.1:19090/api/v1/skills",
            "items": [
                {"name": "swarm-health", "description": "check swarm service health"},
                {"name": "k8s-latency", "description": "diagnose api latency"},
            ][:limit],
            "count": min(limit, 2),
        }


def test_aiops_cli_bind_show_ping_skills(monkeypatch, tmp_path: Path) -> None:
    cfg = tmp_path / "aiops-bridge.json"
    monkeypatch.setattr(cli_main, "_default_aiops_bridge_path", lambda: cfg)
    monkeypatch.setattr(cli_main, "_build_aiops_bridge_client", lambda *_a, **_k: _FakeBridgeClient())
    runner = CliRunner()

    bound = runner.invoke(app, ["aiops", "bind", "--base-url", "http://127.0.0.1:19090"])
    assert bound.exit_code == 0
    bind_payload = json.loads(bound.stdout)
    assert bind_payload["base_url"] == "http://127.0.0.1:19090"

    shown = runner.invoke(app, ["aiops", "show"])
    assert shown.exit_code == 0
    show_payload = json.loads(shown.stdout)
    assert show_payload["base_url"] == "http://127.0.0.1:19090"

    pinged = runner.invoke(app, ["aiops", "ping"])
    assert pinged.exit_code == 0
    ping_payload = json.loads(pinged.stdout)
    assert ping_payload["ok"] is True

    skills = runner.invoke(app, ["aiops", "skills", "--json"])
    assert skills.exit_code == 0
    skills_payload = json.loads(skills.stdout)
    assert skills_payload["ok"] is True
    assert int(skills_payload["count"]) == 2

