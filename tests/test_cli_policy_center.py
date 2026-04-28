from pathlib import Path

from lazysre.cli.policy_center import PolicyCenter


def test_policy_center_defaults_and_context_update(tmp_path: Path) -> None:
    center = PolicyCenter(tmp_path / "policy.json")
    payload = center.show()
    assert payload["defaults"]["tenant"] == "default"
    assert "prod" in payload["tenants"]["default"]["environments"]

    updated = center.update_defaults(
        tenant="acme",
        environment="staging",
        actor_role="viewer",
        actor_id="u-1",
    )
    assert updated["tenant"] == "acme"
    assert updated["environment"] == "staging"
    assert updated["actor_role"] == "viewer"
    assert updated["actor_id"] == "u-1"

    ctx = center.resolve_context()
    assert ctx.tenant == "acme"
    assert ctx.environment == "staging"
    assert ctx.actor_role == "viewer"
    assert ctx.actor_id == "u-1"


def test_policy_center_evaluate_blocks_by_role_and_pattern(tmp_path: Path) -> None:
    center = PolicyCenter(tmp_path / "policy.json")
    center.set_role_max_risk(
        tenant="default",
        environment="prod",
        role="operator",
        max_risk="medium",
    )
    center.add_block_pattern(
        tenant="default",
        environment="prod",
        pattern="rollout restart",
    )
    ctx = center.resolve_context(
        tenant="default",
        environment="prod",
        actor_role="operator",
    )

    high_risk = center.evaluate(
        command=["kubectl", "delete", "pod", "x"],
        risk_level="high",
        requires_approval=True,
        approval_mode="balanced",
        context=ctx,
        has_approval_ticket=True,
    )
    assert high_risk.blocked is True
    assert "max risk" in high_risk.blocked_reason
    assert high_risk.metadata.get("min_approvers_required") == 2

    blocked_pattern = center.evaluate(
        command=["kubectl", "rollout", "restart", "deploy/api"],
        risk_level="critical",
        requires_approval=True,
        approval_mode="strict",
        context=center.resolve_context(
            tenant="default",
            environment="prod",
            actor_role="admin",
        ),
        has_approval_ticket=True,
    )
    assert blocked_pattern.blocked is True
    assert "blocked pattern" in blocked_pattern.blocked_reason
