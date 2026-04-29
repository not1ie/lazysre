import json
from pathlib import Path

from typer.testing import CliRunner

from lazysre.cli.main import app


def _write_run(path: Path, *, trace_id: str, provider: str, needs_approval: bool, command_count: int = 1) -> None:
    commands = [{"command": "docker service ls", "risk_level": "low", "requires_approval": False} for _ in range(command_count)]
    payload = {
        "trace_id": trace_id,
        "created_at": "2026-04-29T08:00:00+00:00",
        "provider": provider,
        "instruction": "检查 swarm",
        "event_count": 3,
        "actionables": {
            "commands": commands,
            "needs_approval": needs_approval,
        },
        "integrity": {"digest": f"digest-{trace_id}"},
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_channel_tail_json_filters(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_run(run_dir / "a.json", trace_id="trc-a", provider="generic", needs_approval=False)
    _write_run(run_dir / "b.json", trace_id="trc-b", provider="telegram", needs_approval=True, command_count=2)

    runner = CliRunner()
    all_rows = runner.invoke(app, ["channel-tail", "--run-dir", str(run_dir), "--json"])
    assert all_rows.exit_code == 0
    all_payload = json.loads(all_rows.stdout)
    assert all_payload["count"] == 2

    provider_rows = runner.invoke(
        app,
        ["channel-tail", "--run-dir", str(run_dir), "--provider", "telegram", "--json"],
    )
    assert provider_rows.exit_code == 0
    provider_payload = json.loads(provider_rows.stdout)
    assert provider_payload["count"] == 1
    assert provider_payload["records"][0]["trace_id"] == "trc-b"

    approval_rows = runner.invoke(
        app,
        ["channel-tail", "--run-dir", str(run_dir), "--needs-approval", "yes", "--json"],
    )
    assert approval_rows.exit_code == 0
    approval_payload = json.loads(approval_rows.stdout)
    assert approval_payload["count"] == 1
    assert approval_payload["records"][0]["needs_approval"] is True


def test_channel_tail_invalid_option(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    runner = CliRunner()
    result = runner.invoke(app, ["channel-tail", "--run-dir", str(run_dir), "--needs-approval", "maybe"])
    assert result.exit_code != 0
