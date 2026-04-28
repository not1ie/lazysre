import json
from pathlib import Path

from typer.testing import CliRunner

from lazysre.cli.main import app
from lazysre.cli.incident import IncidentStore
from lazysre.runbook import GeneratedRunbookStore, find_best_matching_runbook, normalize_runbook_name


def _write_incident(path: Path, incident_id: str, title: str, summary: str) -> None:
    store = IncidentStore(path)
    payload = {
        "active": {
            "id": incident_id,
            "title": title,
            "severity": "high",
            "status": "open",
            "assignee": "-",
            "summary": summary,
            "source": "manual",
            "tags": [],
            "opened_at_utc": "2026-04-28T10:00:00+00:00",
            "updated_at_utc": "2026-04-28T10:00:00+00:00",
            "closed_at_utc": "",
            "resolution": "",
            "timeline": [
                {
                    "at_utc": "2026-04-28T10:00:00+00:00",
                    "kind": "opened",
                    "message": "opened by manual; severity=high; assignee=-",
                },
                {
                    "at_utc": "2026-04-28T10:01:00+00:00",
                    "kind": "summary",
                    "message": summary,
                },
            ],
        },
        "archive": [],
    }
    store._save_raw(payload)  # noqa: SLF001 - test fixture helper


def test_runbook_generate_show_and_diff(tmp_path: Path) -> None:
    incident_file = tmp_path / "incident.json"
    _write_incident(
        incident_file,
        incident_id="CHG-20260428-001",
        title="Swarm API timeout spike",
        summary="payment p95 > 800ms and service replicas unstable",
    )
    evidence_v1 = tmp_path / "evidence-v1.json"
    evidence_v1.write_text(
        json.dumps(
            {
                "outputs": [
                    {"phase": "precheck", "command": "docker service ls", "exit_code": 0},
                    {"phase": "apply", "command": "docker service update --force payment_api", "exit_code": 0},
                    {"phase": "verify", "command": "docker service ps payment_api --no-trunc", "exit_code": 0},
                    {"phase": "rollback", "command": "docker service rollback payment_api", "exit_code": 0},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    evidence_v2 = tmp_path / "evidence-v2.json"
    evidence_v2.write_text(
        json.dumps(
            {
                "outputs": [
                    {"phase": "precheck", "command": "docker service ls", "exit_code": 0},
                    {"phase": "apply", "command": "docker service update --image api:v2 payment_api", "exit_code": 0},
                    {"phase": "verify", "command": "docker service ps payment_api --no-trunc", "exit_code": 0},
                    {"phase": "rollback", "command": "docker service rollback payment_api", "exit_code": 0},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    out_dir = tmp_path / "runbooks"
    runner = CliRunner()
    first = runner.invoke(
        app,
        [
            "runbook",
            "generate",
            "--from-incident",
            "CHG-20260428-001",
            "--incident-file",
            str(incident_file),
            "--evidence-file",
            str(evidence_v1),
            "--output",
            str(out_dir),
        ],
    )
    assert first.exit_code == 0
    second = runner.invoke(
        app,
        [
            "runbook",
            "generate",
            "--from-incident",
            "CHG-20260428-001",
            "--incident-file",
            str(incident_file),
            "--evidence-file",
            str(evidence_v2),
            "--output",
            str(out_dir),
        ],
    )
    assert second.exit_code == 0

    name = normalize_runbook_name("Swarm API timeout spike")
    assert (out_dir / name / "v1.yaml").exists()
    assert (out_dir / name / "v2.yaml").exists()

    show = runner.invoke(
        app,
        [
            "runbook",
            "show",
            name,
            "--generated",
            "--generated-dir",
            str(out_dir),
            "--version",
            "v2",
        ],
    )
    assert show.exit_code == 0
    payload = json.loads(show.stdout)
    assert payload["version"] == "v2"
    assert payload["source_incident_id"] == "CHG-20260428-001"
    assert isinstance(payload["remediation_steps"], list)
    assert payload["remediation_steps"]

    diff = runner.invoke(
        app,
        [
            "runbook",
            "diff",
            name,
            "--generated-dir",
            str(out_dir),
            "--version",
            "v1",
            "--version",
            "v2",
        ],
    )
    assert diff.exit_code == 0
    assert ("docker service update --force" in diff.stdout) or ("docker service update --image" in diff.stdout)


def test_generated_runbook_similarity_match(tmp_path: Path) -> None:
    store = GeneratedRunbookStore(tmp_path / "generated")
    store.save_new_version(
        "swarm-timeout",
        {
            "schema_version": 1,
            "source_incident_id": "CHG-1",
            "created_at": "2026-04-28T10:00:00+00:00",
            "trigger_patterns": ["swarm timeout", "payment p95 800ms"],
            "diagnosis_steps": [],
            "remediation_steps": [],
            "verify_steps": [],
            "rollback_steps": [],
            "incident_title": "Swarm API timeout spike",
            "incident_summary": "payment timeout and replica issues",
        },
    )
    match = find_best_matching_runbook(
        store,
        query="payment api timeout and swarm replica unstable",
    )
    assert match is not None
    assert match[0].name == "swarm-timeout"
    assert match[1] > 0.0
