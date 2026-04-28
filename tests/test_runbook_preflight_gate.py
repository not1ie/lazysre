import pytest
import typer

import lazysre.cli.main as main
from lazysre.cli.runbook import find_runbook
from lazysre.commands.preflight_risk import PreflightRiskResult, RiskFactor


def _default_options(*, execute: bool) -> dict[str, object]:
    return {
        "execute": execute,
        "approve": False,
        "interactive_approval": True,
        "stream_output": False,
        "verbose_reasoning": False,
        "approval_mode": "balanced",
        "audit_log": ".data/lsre-audit.jsonl",
        "lock_file": ".data/lsre-tool-lock.json",
        "session_file": ".data/lsre-session.json",
        "deny_tool": [],
        "deny_prefix": [],
        "tool_pack": ["builtin"],
        "remote_gateway": [],
        "model": "gpt-5.4-mini",
        "provider": "mock",
        "max_steps": 3,
    }


def test_execute_runbook_blocks_high_risk_preflight(monkeypatch) -> None:
    template = find_runbook("payment-latency-fix")
    assert template is not None
    monkeypatch.setattr(main, "collect_preflight_risk_context", lambda **kwargs: {})
    monkeypatch.setattr(
        main,
        "build_preflight_risk_result",
        lambda **kwargs: PreflightRiskResult(
            risk_score=88,
            risk_factors=[RiskFactor("x", 10, "x")],
            blast_radius="service",
            recommended_time="window",
            safer_alternative="dry-run",
            risk_level="high",
            context={},
            approval_escalation={"triggered": True},
            source="test",
        ),
    )
    with pytest.raises(typer.BadParameter):
        main._execute_runbook(  # noqa: SLF001
            template=template,
            instruction="kubectl rollout restart deploy/payment",
            apply=True,
            skip_preflight=False,
            options=_default_options(execute=True),
        )


def test_execute_runbook_skip_preflight_allows_fix(monkeypatch) -> None:
    template = find_runbook("payment-latency-fix")
    assert template is not None
    called = {"ok": False}

    def _fake_run_fix(**kwargs):
        called["ok"] = True

    monkeypatch.setattr(main, "_run_fix", _fake_run_fix)
    monkeypatch.setattr(main, "collect_preflight_risk_context", lambda **kwargs: {})
    monkeypatch.setattr(
        main,
        "build_preflight_risk_result",
        lambda **kwargs: PreflightRiskResult(
            risk_score=95,
            risk_factors=[RiskFactor("x", 10, "x")],
            blast_radius="service",
            recommended_time="window",
            safer_alternative="dry-run",
            risk_level="critical",
            context={},
            approval_escalation={"triggered": True},
            source="test",
        ),
    )
    main._execute_runbook(  # noqa: SLF001
        template=template,
        instruction="kubectl rollout restart deploy/payment",
        apply=True,
        skip_preflight=True,
        options=_default_options(execute=True),
    )
    assert called["ok"] is True
