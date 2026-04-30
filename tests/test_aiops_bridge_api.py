import json
from pathlib import Path

from fastapi.testclient import TestClient

import lazysre.main as main_mod
from lazysre.main import app


class _FakeBridgeClient:
    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def health(self) -> dict[str, object]:
        return {
            "ok": True,
            "status_code": 200,
            "url": "http://127.0.0.1:19090/health",
            "body": {"status": "ok"},
        }

    def list_skills(self, *, limit: int = 30) -> dict[str, object]:
        items = [
            {"name": "swarm-health", "description": "check swarm health"},
            {"name": "k8s-latency", "description": "diagnose k8s latency"},
            {"name": "gpu-drift", "description": "find gpu drift"},
        ][:limit]
        return {
            "ok": True,
            "status_code": 200,
            "url": "http://127.0.0.1:19090/api/v1/skills",
            "items": items,
            "count": len(items),
        }


def test_aiops_bridge_api_bind_show_ping_skills(monkeypatch, tmp_path: Path) -> None:
    cfg = tmp_path / "bridge.json"
    monkeypatch.setattr(main_mod, "_aiops_bridge_config_path", lambda: cfg)
    monkeypatch.setattr(main_mod, "_build_aiops_bridge_client", lambda *_a, **_k: _FakeBridgeClient())

    client = TestClient(app)
    bind = client.post(
        "/v1/aiops/bridge/bind",
        json={
            "base_url": "http://127.0.0.1:19090",
            "api_key_env": "LAZY_AIOPS_API_KEY",
            "timeout_sec": 15,
            "verify_tls": False,
        },
    )
    assert bind.status_code == 200
    bind_payload = bind.json()
    assert bind_payload["base_url"] == "http://127.0.0.1:19090"
    assert bind_payload["timeout_sec"] == 15
    assert bind_payload["verify_tls"] is False

    shown = client.get("/v1/aiops/bridge")
    assert shown.status_code == 200
    show_payload = shown.json()
    assert show_payload["base_url"] == "http://127.0.0.1:19090"
    assert show_payload["api_key_env"] == "LAZY_AIOPS_API_KEY"

    ping = client.get("/v1/aiops/bridge/ping")
    assert ping.status_code == 200
    ping_payload = ping.json()
    assert ping_payload["ok"] is True
    assert ping_payload["status_code"] == 200

    skills = client.get("/v1/aiops/bridge/skills", params={"limit": 2, "min_score": 0.3, "source_contains": "swarm"})
    assert skills.status_code == 200
    skills_payload = skills.json()
    assert skills_payload["ok"] is True
    assert int(skills_payload["count"]) == 2
    assert skills_payload["query_options"]["limit"] == 2
    assert abs(float(skills_payload["query_options"]["min_score"]) - 0.3) < 1e-6
    assert skills_payload["query_options"]["source_contains"] == "swarm"


def test_aiops_bridge_bind_requires_base_url(monkeypatch, tmp_path: Path) -> None:
    cfg = tmp_path / "bridge.json"
    monkeypatch.setattr(main_mod, "_aiops_bridge_config_path", lambda: cfg)
    client = TestClient(app)
    resp = client.post("/v1/aiops/bridge/bind", json={"base_url": ""})
    assert resp.status_code == 400
    payload = resp.json()
    assert "base_url is required" in json.dumps(payload, ensure_ascii=False)

