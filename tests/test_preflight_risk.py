import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import lazysre.cli.main as cli_main
from lazysre.cli.main import app, _resolve_preflight_command_text
from lazysre.commands.preflight_risk import (
    build_preflight_risk_result,
    collect_preflight_risk_context,
)


def test_resolve_preflight_command_text_from_plan_file(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "apply_commands": ["kubectl rollout restart deploy/payment"],
                "verify_commands": ["kubectl rollout status deploy/payment"],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    text = _resolve_preflight_command_text(command="", plan_file=str(plan))
    assert "rollout restart" in text


def test_collect_preflight_risk_context_and_score(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "version": 1,
                "defaults": {"tenant": "default", "environment": "prod", "actor_role": "operator", "actor_id": ""},
                "tenants": {
                    "default": {
                        "environments": {
                            "prod": {
                                "maintenance_window": {"start": "01:00", "end": "05:00", "timezone": "UTC"}
                            }
                        }
                    }
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        "\n".join(
            [
                json.dumps({"timestamp": "2026-04-27T10:00:00+00:00", "command": ["kubectl", "rollout", "restart", "deploy/payment"], "ok": False}),
                json.dumps({"timestamp": "2026-04-27T11:00:00+00:00", "command": ["kubectl", "rollout", "restart", "deploy/payment"], "ok": True}),
            ]
        ),
        encoding="utf-8",
    )
    incidents = tmp_path / "incident.json"
    incidents.write_text(
        json.dumps(
            {
                "active": None,
                "archive": [
                    {
                        "id": "INC-1",
                        "title": "payment restart caused spike",
                        "summary": "kubectl rollout restart deploy/payment",
                        "resolution": "rollback",
                        "updated_at_utc": "2026-04-27T12:00:00+00:00",
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    context = collect_preflight_risk_context(
        command_text="kubectl rollout restart deploy/payment",
        context_name="prod",
        policy_file=policy_file,
        audit_log=audit,
        incidents_file=incidents,
        dependency_summary={"ok": False, "unhealthy_services": 2, "bad_nodes": 0},
    )
    result = build_preflight_risk_result(
        command_text="kubectl rollout restart deploy/payment",
        context_data=context,
    )
    assert result.risk_score >= 70
    assert result.approval_escalation["triggered"] is True


def test_preflight_command_risk_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_collect_preflight_report(**_: object) -> dict[str, object]:
        return {
            "kind": "preflight",
            "scope": {},
            "checks": [],
            "summary": {"total": 0, "pass": 0, "warn": 0, "error": 0, "healthy": True},
            "sections": {},
            "gate": {"healthy": True, "blocking_count": 0},
        }

    monkeypatch.setattr(cli_main, "_collect_preflight_report", fake_collect_preflight_report)
    monkeypatch.setattr(
        cli_main,
        "_collect_preflight_dependency_summary",
        lambda **_: {"ok": False, "unhealthy_services": 3, "bad_nodes": 0, "warn": 1, "error": 0},
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "--audit-log",
            str(tmp_path / "audit.jsonl"),
            "preflight",
            "--command",
            "kubectl rollout restart deploy/payment",
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["kind"] == "preflight"
    assert "risk" in payload
    assert "risk_score" in payload["risk"]
    if int(payload["risk"]["risk_score"]) >= 70:
        assert payload["risk"]["approval_escalated"] is True
