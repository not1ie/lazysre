import json
from pathlib import Path

from fastapi.testclient import TestClient

from lazysre.cli.approval import ApprovalStore
from lazysre.main import app


def test_channel_webhook_requires_token(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("LAZYSRE_CHANNEL_TOKEN", "channel-token")
    monkeypatch.setenv("LAZYSRE_CHANNEL_HANDOFF_DIR", str(tmp_path / "handoff"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_DEDUP_FILE", str(tmp_path / "dedup.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_SESSION_FILE", str(tmp_path / "session.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_RUN_DIR", str(tmp_path / "runs"))
    client = TestClient(app)

    blocked = client.post("/v1/channels/generic/webhook", json={"text": "检查 swarm"})
    assert blocked.status_code == 401

    allowed = client.post(
        "/v1/channels/generic/webhook",
        headers={"X-LazySRE-Channel-Token": "channel-token"},
        json={"event_id": "ev-1", "text": "检查 swarm"},
    )
    assert allowed.status_code == 200
    body = allowed.json()
    assert body["ok"] is True
    assert body["dry_run"] is True
    assert body["trace_id"].startswith("trc-")
    assert body["ack"]["duplicate"] is False
    assert body["ack"]["trace_id"] == body["trace_id"]
    assert isinstance(body.get("receipt", {}), dict)
    assert body["receipt"]["status"] == "succeeded"
    assert body["receipt"]["trace_id"] == body["trace_id"]
    assert isinstance(body.get("progress", []), list)
    assert isinstance(body.get("lifecycle", []), list)
    assert body["lifecycle"][-1]["state"] == "succeeded"
    assert isinstance(body.get("timeline", []), list)
    assert isinstance(body.get("actionables", {}), dict)
    assert isinstance(body.get("execution_templates", {}), dict)
    assert "items" in body["execution_templates"]
    assert "count" in body["execution_templates"]
    if body["execution_templates"]["items"]:
        first_item = body["execution_templates"]["items"][0]
        assert "environment" in first_item
        assert "prerequisites" in first_item
        assert "rollback_template" in first_item
        assert "task_sheet" in first_item
    assert "final" in body
    assert "timeline" in body["final"]
    assert "actionables" in body["final"]
    assert "execution_templates" in body["final"]
    assert body["session"]["turns"] >= 1
    assert body["final"]["trace_id"] == body["trace_id"]
    assert "reply" in body
    assert "handoff" in body
    assert "artifacts" in body and "run" in body["artifacts"]
    run_meta = body["artifacts"]["run"]
    run_path = Path(str(run_meta["path"]))
    assert run_path.exists()
    run_payload = json.loads(run_path.read_text(encoding="utf-8"))
    assert run_payload["trace_id"] == body["trace_id"]
    assert run_payload["instruction"] == "检查 swarm"
    assert "execution_templates" in run_payload
    assert run_payload["integrity"]["algorithm"] == "sha256"
    assert isinstance(run_payload["integrity"]["digest"], str)
    assert run_payload["integrity"]["signed"] is False
    assert run_payload["approval_snapshot"]["present"] is False
    handoff = body["handoff"]
    handoff_path = Path(str(handoff["path"]))
    assert handoff_path.exists()
    payload = json.loads(handoff_path.read_text(encoding="utf-8"))
    assert payload["provider"] == "generic"
    assert payload["trace_id"] == body["trace_id"]
    assert payload["instruction"] == "检查 swarm"
    assert payload["handoff_command"].startswith('lazysre fix "')
    assert isinstance(payload.get("similar_cases", []), list)
    assert isinstance(payload.get("run_artifact", {}), dict)
    assert payload["run_artifact"]["trace_id"] == body["trace_id"]
    assert payload["run_artifact"]["digest"] == run_payload["integrity"]["digest"]


def test_channel_webhook_run_artifact_signature_and_approval_snapshot(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("LAZYSRE_CHANNEL_TOKEN", "channel-token")
    monkeypatch.setenv("LAZYSRE_CHANNEL_HANDOFF_DIR", str(tmp_path / "handoff"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_DEDUP_FILE", str(tmp_path / "dedup.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_SESSION_FILE", str(tmp_path / "session.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_RUN_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_ARTIFACT_HMAC_KEY", "artifact-secret")
    approval_file = tmp_path / "approvals.json"
    monkeypatch.setenv("LAZYSRE_APPROVAL_STORE", str(approval_file))
    store = ApprovalStore(approval_file)
    ticket = store.create(
        reason="restart service",
        risk_level="critical",
        tenant="default",
        environment="prod",
        actor_role="operator",
        requester="alice",
        expires_hours=2,
        required_approvers=1,
    )
    store.approve(ticket.id, approver="bob", comment="ok")
    monkeypatch.setenv("LAZYSRE_APPROVAL_TICKET", ticket.id)

    client = TestClient(app)
    allowed = client.post(
        "/v1/channels/generic/webhook",
        headers={"X-LazySRE-Channel-Token": "channel-token"},
        json={"event_id": "ev-sign", "text": "检查 swarm"},
    )
    assert allowed.status_code == 200
    body = allowed.json()
    run_meta = body["artifacts"]["run"]
    run_path = Path(str(run_meta["path"]))
    run_payload = json.loads(run_path.read_text(encoding="utf-8"))
    assert run_payload["integrity"]["signed"] is True
    assert run_payload["integrity"]["signature_algorithm"] == "hmac-sha256"
    assert run_payload["approval_snapshot"]["present"] is True
    assert run_payload["approval_snapshot"]["ticket_id"] == ticket.id
    assert run_meta["signed"] is True

    duplicated = client.post(
        "/v1/channels/generic/webhook",
        headers={"X-LazySRE-Channel-Token": "channel-token"},
        json={"event_id": "ev-sign", "text": "检查 swarm"},
    )
    assert duplicated.status_code == 200
    duplicate_body = duplicated.json()
    assert duplicate_body["ok"] is True
    assert duplicate_body["duplicate"] is True
    assert duplicate_body["ack"]["duplicate"] is True
    assert duplicate_body["receipt"]["status"] == "ignored"
    assert duplicate_body["lifecycle"][-1]["state"] == "ignored"
    assert duplicate_body["event_count"] == 0
    assert isinstance(duplicate_body.get("progress", []), list)


def test_channel_artifact_verify_endpoint(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("LAZYSRE_CHANNEL_TOKEN", "channel-token")
    monkeypatch.setenv("LAZYSRE_CHANNEL_HANDOFF_DIR", str(tmp_path / "handoff"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_DEDUP_FILE", str(tmp_path / "dedup.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_SESSION_FILE", str(tmp_path / "session.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_RUN_DIR", str(tmp_path / "runs"))
    client = TestClient(app)
    resp = client.post(
        "/v1/channels/generic/webhook",
        headers={"X-LazySRE-Channel-Token": "channel-token"},
        json={"event_id": "ev-verify", "text": "检查 swarm"},
    )
    assert resp.status_code == 200
    run_path = resp.json()["artifacts"]["run"]["path"]
    verified = client.get("/v1/channels/artifacts/verify", params={"path": run_path})
    assert verified.status_code == 200
    payload = verified.json()
    assert payload["ok"] is True
    assert payload["digest_match"] is True
    assert payload["signed"] is False
    assert payload["signature_valid"] is None


def test_channel_artifact_verify_endpoint_fails_on_tamper(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("LAZYSRE_CHANNEL_TOKEN", "channel-token")
    monkeypatch.setenv("LAZYSRE_CHANNEL_HANDOFF_DIR", str(tmp_path / "handoff"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_DEDUP_FILE", str(tmp_path / "dedup.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_SESSION_FILE", str(tmp_path / "session.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_RUN_DIR", str(tmp_path / "runs"))
    client = TestClient(app)
    resp = client.post(
        "/v1/channels/generic/webhook",
        headers={"X-LazySRE-Channel-Token": "channel-token"},
        json={"event_id": "ev-verify-bad", "text": "检查 swarm"},
    )
    assert resp.status_code == 200
    run_path = Path(resp.json()["artifacts"]["run"]["path"])
    payload = json.loads(run_path.read_text(encoding="utf-8"))
    payload["final_text"] = "tampered"
    run_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    verified = client.get("/v1/channels/artifacts/verify", params={"path": str(run_path)})
    assert verified.status_code == 400
    detail = verified.json()["detail"]
    assert detail["ok"] is False
    assert detail["digest_match"] is False


def test_channel_webhook_reset_control(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("LAZYSRE_CHANNEL_SESSION_FILE", str(tmp_path / "session.json"))
    client = TestClient(app)
    first = client.post(
        "/v1/channels/generic/webhook",
        json={"event_id": "ev-a", "chat_id": "c1", "user_id": "u1", "text": "检查 swarm"},
    )
    assert first.status_code == 200
    reset = client.post(
        "/v1/channels/generic/webhook",
        json={"event_id": "ev-b", "chat_id": "c1", "user_id": "u1", "text": "/reset"},
    )
    assert reset.status_code == 200
    body = reset.json()
    assert body["ok"] is True
    assert body["control"] == "reset"
    assert body["session"]["turns"] == 0
    assert body["receipt"]["status"] == "succeeded"
    assert body["lifecycle"][-1]["state"] == "succeeded"


def test_channel_webhook_session_control(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("LAZYSRE_CHANNEL_SESSION_FILE", str(tmp_path / "session.json"))
    monkeypatch.setenv("LAZYSRE_CHANNEL_DEDUP_FILE", str(tmp_path / "dedup.json"))
    client = TestClient(app)
    first = client.post(
        "/v1/channels/generic/webhook",
        json={"event_id": "ev-s1", "chat_id": "c1", "user_id": "u1", "text": "检查 swarm"},
    )
    assert first.status_code == 200
    second = client.post(
        "/v1/channels/generic/webhook",
        json={"event_id": "ev-s2", "chat_id": "c1", "user_id": "u1", "text": "检查 k8s"},
    )
    assert second.status_code == 200
    session = client.post(
        "/v1/channels/generic/webhook",
        json={"event_id": "ev-s3", "chat_id": "c1", "user_id": "u1", "text": "/session"},
    )
    assert session.status_code == 200
    body = session.json()
    assert body["ok"] is True
    assert body["control"] == "session"
    assert body["session"]["turns"] >= 2
    assert "session turns=" in body["final"]["text"]
    assert body["receipt"]["status"] == "succeeded"


def test_channel_webhook_approve_control(monkeypatch, tmp_path: Path):
    approval_file = tmp_path / "approvals.json"
    monkeypatch.setenv("LAZYSRE_APPROVAL_STORE", str(approval_file))
    store = ApprovalStore(approval_file)
    ticket = store.create(
        reason="restart service",
        risk_level="critical",
        tenant="default",
        environment="prod",
        actor_role="operator",
        requester="alice",
        expires_hours=2,
        required_approvers=1,
    )
    client = TestClient(app)
    _ = client.post(
        "/v1/channels/generic/webhook",
        json={"event_id": "ev-c0", "chat_id": "room-1", "user_id": "u-approver", "text": "先检查一下"},
    )
    approved = client.post(
        "/v1/channels/generic/webhook",
        json={"event_id": "ev-c", "chat_id": "room-1", "user_id": "u-approver", "text": f"/approve {ticket.id} 同意"},
    )
    assert approved.status_code == 200
    body = approved.json()
    assert body["ok"] is True
    assert body["control"] == "approve"
    assert "status=approved" in body["final"]["text"]
    assert body["approval"]["status"] == "approved"
    assert body["approval"]["ticket_id"] == ticket.id
    assert body["approval"]["current_approvals"] >= 1
    assert isinstance(body["approval"].get("execution_templates", {}), dict)
    assert body["receipt"]["status"] == "succeeded"


def test_channel_webhook_approvals_control(monkeypatch, tmp_path: Path):
    approval_file = tmp_path / "approvals.json"
    monkeypatch.setenv("LAZYSRE_APPROVAL_STORE", str(approval_file))
    store = ApprovalStore(approval_file)
    _ = store.create(
        reason="scale deployment",
        risk_level="high",
        tenant="default",
        environment="prod",
        actor_role="operator",
        requester="alice",
        expires_hours=2,
        required_approvers=2,
    )
    client = TestClient(app)
    resp = client.post(
        "/v1/channels/generic/webhook",
        json={"event_id": "ev-appr", "user_id": "u1", "text": "/approvals"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["control"] == "approvals"
    assert "pending approvals" in body["final"]["text"]
    assert body["receipt"]["status"] == "succeeded"


def test_telegram_webhook_secret_header(monkeypatch):
    monkeypatch.setenv("LAZYSRE_TELEGRAM_SECRET_TOKEN", "tg-secret")
    client = TestClient(app)
    blocked = client.post(
        "/v1/channels/telegram/webhook",
        json={"update_id": 1, "message": {"text": "检查 k8s", "chat": {"id": 1}, "from": {"id": 2}}},
    )
    assert blocked.status_code == 401
    allowed = client.post(
        "/v1/channels/telegram/webhook",
        headers={"X-Telegram-Bot-Api-Secret-Token": "tg-secret"},
        json={"update_id": 1, "message": {"text": "检查 k8s", "chat": {"id": 1}, "from": {"id": 2}}},
    )
    assert allowed.status_code == 200
    assert allowed.json()["ok"] is True


def test_feishu_challenge_is_public(monkeypatch):
    monkeypatch.setenv("LAZYSRE_CHANNEL_TOKEN", "channel-token")
    client = TestClient(app)

    resp = client.post("/v1/channels/feishu/webhook", json={"challenge": "abc"})
    assert resp.status_code == 200
    assert resp.json() == {"challenge": "abc"}


def test_feishu_verification_token(monkeypatch):
    monkeypatch.setenv("LAZYSRE_FEISHU_VERIFICATION_TOKEN", "verify-token")
    client = TestClient(app)
    blocked = client.post(
        "/v1/channels/feishu/webhook",
        json={
            "token": "bad",
            "header": {"event_id": "evt-1"},
            "event": {
                "sender": {"sender_id": {"open_id": "ou_1"}},
                "message": {"chat_id": "oc_1", "content": '{"text":"检查远程服务器"}'},
            },
        },
    )
    assert blocked.status_code == 401
    allowed = client.post(
        "/v1/channels/feishu/webhook",
        json={
            "token": "verify-token",
            "header": {"event_id": "evt-1-2"},
            "event": {
                "sender": {"sender_id": {"open_id": "ou_1"}},
                "message": {"chat_id": "oc_1", "content": '{"text":"检查远程服务器"}'},
            },
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["ok"] is True
