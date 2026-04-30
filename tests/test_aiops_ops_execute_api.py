import json
from pathlib import Path

from fastapi.testclient import TestClient

from lazysre.cli.approval import ApprovalStore
from lazysre.main import app


def test_aiops_ops_execute_low_risk_probe_and_execute() -> None:
    client = TestClient(app)
    dry = client.post(
        "/v1/aiops/ops/execute",
        json={"command": "echo hello-lazysre", "execute": False, "approval_mode": "strict", "dry_run_probe": True},
    )
    assert dry.status_code == 200
    dry_payload = dry.json()
    assert dry_payload["ok"] is True
    assert dry_payload["dry_run"] is True
    probe = dry_payload.get("probe") or {}
    assert probe.get("ok") is True

    run = client.post(
        "/v1/aiops/ops/execute",
        json={"command": "echo hello-lazysre", "execute": True, "approval_mode": "strict"},
    )
    assert run.status_code == 200
    run_payload = run.json()
    assert run_payload["ok"] is True
    assert run_payload["result"]["exit_code"] == 0


def test_aiops_ops_execute_high_risk_requires_ticket(monkeypatch, tmp_path: Path) -> None:
    store_file = tmp_path / "approvals.json"
    monkeypatch.setenv("LAZYSRE_APPROVAL_STORE", str(store_file))
    client = TestClient(app)
    blocked = client.post(
        "/v1/aiops/ops/execute",
        json={
            "command": "docker service update --force lazysre_lazysre",
            "execute": True,
            "approval_mode": "strict",
            "tenant": "default",
            "environment": "prod",
            "actor_role": "operator",
        },
    )
    assert blocked.status_code == 200
    body = blocked.json()
    assert body["ok"] is False
    assert body["blocked"] is True
    assert "approval_ticket required" in body["reason"]

    store = ApprovalStore(store_file)
    ticket = store.create(
        reason="test high-risk docker update",
        risk_level="critical",
        tenant="default",
        environment="prod",
        actor_role="operator",
        requester="tester",
        command_prefix="docker service",
    )
    store.approve(ticket.id, approver="admin1", comment="ok")

    allowed = client.post(
        "/v1/aiops/ops/execute",
        json={
            "command": "docker service update --force lazysre_lazysre",
            "execute": False,
            "approval_mode": "strict",
            "approval_ticket": ticket.id,
            "tenant": "default",
            "environment": "prod",
            "actor_role": "operator",
            "dry_run_probe": False,
        },
    )
    assert allowed.status_code == 200
    payload = allowed.json()
    assert payload["ok"] is True
    assert payload["approval_ticket"] == ticket.id
    assert payload["ticket"]["id"] == ticket.id


def test_aiops_ops_approve_endpoint(monkeypatch, tmp_path: Path) -> None:
    store_file = tmp_path / "approvals.json"
    monkeypatch.setenv("LAZYSRE_APPROVAL_STORE", str(store_file))
    store = ApprovalStore(store_file)
    ticket = store.create(
        reason="approve endpoint",
        risk_level="high",
        tenant="default",
        environment="prod",
        actor_role="operator",
        requester="tester",
    )
    client = TestClient(app)
    resp = client.post(
        "/v1/aiops/ops/approve",
        json={"ticket_id": ticket.id, "approver": "ops-lead", "comment": "approved"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"] is True
    assert payload["ticket"]["id"] == ticket.id
    assert payload["is_ready"] is True


def test_aiops_ops_execute_disallow_unknown_binary() -> None:
    client = TestClient(app)
    resp = client.post("/v1/aiops/ops/execute", json={"command": "python -V", "execute": False})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"] is False
    assert payload["blocked"] is True
    assert "not allowed" in json.dumps(payload, ensure_ascii=False)
