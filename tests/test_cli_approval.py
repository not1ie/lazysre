from pathlib import Path

from lazysre.cli.approval import ApprovalStore


def test_approval_store_create_approve_and_validate(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals.json")
    ticket = store.create(
        reason="prod restart",
        risk_level="critical",
        tenant="acme",
        environment="prod",
        actor_role="admin",
        requester="alice",
        expires_hours=2,
    )
    assert ticket.status == "pending"
    assert store.is_approved_and_valid(ticket.id) is False

    approved = store.approve(ticket.id, approver="bob", comment="approved")
    assert approved is not None
    assert approved.status == "approved"
    assert store.is_approved_and_valid(ticket.id) is True


def test_approval_store_multi_approver_threshold(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals.json")
    ticket = store.create(
        reason="critical restart",
        risk_level="critical",
        tenant="acme",
        environment="prod",
        actor_role="operator",
        requester="alice",
        expires_hours=2,
        required_approvers=2,
    )
    first = store.approve(ticket.id, approver="oncall-a", comment="ok")
    assert first is not None
    assert first.status == "pending"
    assert len(first.approvals) == 1
    assert store.is_approved_and_valid(ticket.id) is False

    second = store.approve(ticket.id, approver="oncall-b", comment="agree")
    assert second is not None
    assert second.status == "approved"
    assert len(second.approvals) == 2
    assert store.is_approved_and_valid(ticket.id) is True


def test_approval_store_validate_scope_for_execution(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals.json")
    ticket = store.create(
        reason="restart payment",
        risk_level="critical",
        tenant="acme",
        environment="prod",
        actor_role="operator",
        requester="alice",
        expires_hours=2,
        required_approvers=2,
        command_prefix="kubectl rollout restart",
        target_hint="deploy/payment",
    )
    store.approve(ticket.id, approver="oncall-a", comment="ok")
    store.approve(ticket.id, approver="oncall-b", comment="ok")

    ok, reason, _item = store.validate_for_execution(
        ticket.id,
        tenant="acme",
        environment="prod",
        actor_role="operator",
        risk_level="high",
        command=["kubectl", "rollout", "restart", "deploy/payment"],
    )
    assert ok is True
    assert reason == "ok"

    not_ok, reason2, _ = store.validate_for_execution(
        ticket.id,
        tenant="acme",
        environment="prod",
        actor_role="operator",
        risk_level="critical",
        command=["kubectl", "rollout", "restart", "deploy/order"],
    )
    assert not_ok is False
    assert reason2 == "target_mismatch"
