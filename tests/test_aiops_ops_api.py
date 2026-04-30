import json
from pathlib import Path

from fastapi.testclient import TestClient

import lazysre.cli.main as cli_main
from lazysre.main import app


class _FakeDispatchResult:
    def __init__(self, final_text: str, events: list[object]) -> None:
        self.final_text = final_text
        self.events = events


class _FakeEvent:
    def __init__(self, kind: str, message: str, data: dict | None = None) -> None:
        self.kind = kind
        self.message = message
        self.data = data or {}


async def _fake_dispatch(**_kwargs):
    text = (
        "## Status\nDiagnosing\n\n"
        "## Reasoning\n发现 swarm service 副本不足。\n\n"
        "## Commands\n"
        "```bash\n"
        "docker service ps lazysre_lazysre --no-trunc\n"
        "docker service update --force lazysre_lazysre\n"
        "```\n\n"
        "## Risk Level\nHigh\n"
    )
    return _FakeDispatchResult(
        final_text=text,
        events=[
            _FakeEvent("llm_turn", "initial_response", {"duration_ms": 12}),
            _FakeEvent("tool_call", "get_swarm_context", {"call_id": "x"}),
        ],
    )


def test_aiops_ops_diagnose_creates_ticket(monkeypatch, tmp_path: Path) -> None:
    approvals = tmp_path / "approvals.json"
    monkeypatch.setenv("LAZYSRE_APPROVAL_STORE", str(approvals))
    monkeypatch.setattr(cli_main, "_dispatch", _fake_dispatch)
    client = TestClient(app)
    resp = client.post(
        "/v1/aiops/ops/diagnose",
        json={
            "instruction": "检查 swarm 健康并给修复建议",
            "provider": "mock",
            "model": "gpt-5.4-mini",
            "approval_mode": "strict",
            "auto_create_ticket": True,
            "requester": "web-admin",
            "tenant": "default",
            "environment": "prod",
            "actor_role": "operator",
        },
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"] is True
    assert payload["approval_ticket"].startswith("CHG-")
    assert payload["ticket"] is not None
    assert payload["actionables"]["needs_approval"] is True
    assert len(payload["execution_templates"]["items"]) >= 1
    assert "final_text" in payload and payload["final_text"]

    saved = json.loads(approvals.read_text(encoding="utf-8"))
    assert isinstance(saved, list) and saved
    assert saved[0]["id"] == payload["approval_ticket"]


def test_aiops_ops_diagnose_requires_instruction() -> None:
    client = TestClient(app)
    resp = client.post("/v1/aiops/ops/diagnose", json={})
    assert resp.status_code == 400
    body = resp.json()
    assert "instruction is required" in json.dumps(body, ensure_ascii=False)
