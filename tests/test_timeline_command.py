import json
from pathlib import Path

from typer.testing import CliRunner

from lazysre.cli.main import app
from lazysre.commands.timeline import collect_timeline_datasets, render_timeline_mermaid


def test_timeline_collect_from_skill_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "skill-evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "outputs": [
                    {
                        "phase": "precheck",
                        "command": "kubectl get ns",
                        "exit_code": 0,
                        "started_at": "2026-04-28T10:00:00+00:00",
                        "finished_at": "2026-04-28T10:00:01+00:00",
                    },
                    {
                        "phase": "apply",
                        "command": "kubectl rollout restart deploy/payment",
                        "exit_code": 0,
                        "started_at": "2026-04-28T10:00:02+00:00",
                        "finished_at": "2026-04-28T10:00:05+00:00",
                    },
                    {
                        "phase": "verify",
                        "command": "kubectl rollout status deploy/payment",
                        "exit_code": 0,
                        "started_at": "2026-04-28T10:00:06+00:00",
                        "finished_at": "2026-04-28T10:00:09+00:00",
                    },
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    datasets = collect_timeline_datasets(evidence_file=str(evidence), compare=[])
    assert len(datasets) == 1
    ds = datasets[0]
    assert len(ds.events) == 3
    assert ds.events[0].phase == "precheck"
    assert ds.events[1].phase == "apply"
    assert ds.first_fix_at is not None
    assert ds.mttd_sec is None


def test_timeline_collect_from_channel_artifact_with_execution_templates(tmp_path: Path) -> None:
    artifact = tmp_path / "trc-x.json"
    artifact.write_text(
        json.dumps(
            {
                "created_at": "2026-04-28T10:00:00+00:00",
                "timeline": [
                    {"kind": "llm_turn", "message": "diagnosing root cause", "duration_ms": 10},
                    {"kind": "tool_call", "message": "get_swarm_context", "duration_ms": 20},
                ],
                "execution_templates": {
                    "items": [
                        {
                            "task_sheet": {
                                "execute": ["docker service update --force api"],
                                "verify_commands": ["docker service ps api --no-trunc"],
                                "rollback": ["docker service rollback api"],
                            }
                        }
                    ]
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    datasets = collect_timeline_datasets(evidence_file=str(artifact), compare=[])
    assert len(datasets) == 1
    ds = datasets[0]
    phases = [x.phase for x in ds.events]
    assert "llm_response" in phases
    assert "apply" in phases
    assert "verify" in phases
    assert "rollback" in phases
    assert ds.first_fix_at is not None
    assert "gantt" in render_timeline_mermaid(datasets)


def test_timeline_cli_json_and_compare(tmp_path: Path) -> None:
    file1 = tmp_path / "a.json"
    file2 = tmp_path / "b.json"
    base_payload = {
        "outputs": [
            {
                "phase": "apply",
                "command": "docker service update --force api",
                "exit_code": 0,
                "started_at": "2026-04-28T10:00:00+00:00",
                "finished_at": "2026-04-28T10:00:02+00:00",
            }
        ]
    }
    file1.write_text(json.dumps(base_payload, ensure_ascii=False), encoding="utf-8")
    bad_payload = {
        "outputs": [
            {
                "phase": "apply",
                "command": "docker service update --force api",
                "exit_code": 1,
                "started_at": "2026-04-28T10:00:00+00:00",
                "finished_at": "2026-04-28T10:00:03+00:00",
            }
        ]
    }
    file2.write_text(json.dumps(bad_payload, ensure_ascii=False), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "timeline",
            "--evidence-file",
            str(file1),
            "--compare",
            str(file2),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["count"] == 2
    assert payload["comparison"]["delta_failed_events"] == 1
    assert payload["comparison"]["candidates"][0]["delta_failed_events"] == 1


def test_timeline_cli_json_multi_compare(tmp_path: Path) -> None:
    file1 = tmp_path / "base.json"
    file2 = tmp_path / "cand-a.json"
    file3 = tmp_path / "cand-b.json"
    file1.write_text(
        json.dumps(
            {
                "outputs": [
                    {
                        "phase": "precheck",
                        "command": "docker service ps api",
                        "exit_code": 0,
                        "started_at": "2026-04-28T10:00:00+00:00",
                        "finished_at": "2026-04-28T10:00:02+00:00",
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    file2.write_text(
        json.dumps(
            {
                "outputs": [
                    {
                        "phase": "precheck",
                        "command": "docker service ps api",
                        "exit_code": 1,
                        "started_at": "2026-04-28T10:00:00+00:00",
                        "finished_at": "2026-04-28T10:00:03+00:00",
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    file3.write_text(
        json.dumps(
            {
                "outputs": [
                    {
                        "phase": "precheck",
                        "command": "docker service ps api",
                        "exit_code": 0,
                        "started_at": "2026-04-28T10:00:00+00:00",
                        "finished_at": "2026-04-28T10:00:01+00:00",
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "timeline",
            "--evidence-file",
            str(file1),
            "--compare",
            str(file2),
            "--compare",
            str(file3),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["count"] == 3
    assert payload["comparison"]["baseline"] == "base"
    assert len(payload["comparison"]["candidates"]) == 2
    assert payload["comparison"]["candidates"][0]["candidate"] == "cand-a"
    assert payload["comparison"]["candidates"][1]["candidate"] == "cand-b"
