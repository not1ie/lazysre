from lazysre.cli.main import (
    _render_incident_postmortem_markdown,
    _render_skill_graph_markdown,
)
from lazysre.cli.memory import MemoryCase
from lazysre.cli.incident import IncidentRecord


def test_render_skill_graph_markdown_contains_mermaid() -> None:
    payload = {
        "skill": {"name": "swarm-health"},
        "status": "planned",
        "commands": {
            "precheck": ["docker info"],
            "read": ["lazysre swarm --logs --tail 200"],
            "apply": [],
            "verify": [],
            "postcheck": [],
            "rollback": [],
        },
    }
    text = _render_skill_graph_markdown(payload)
    assert "```mermaid" in text
    assert "graph TD" in text
    assert "swarm-health" in text
    assert "docker info" in text


def test_render_incident_postmortem_markdown_sections() -> None:
    rec = IncidentRecord(
        id="INC-20260428-TEST",
        title="payment latency spike",
        severity="high",
        status="closed",
        assignee="oncall",
        summary="p99 latency increased",
        source="manual",
        tags=["payment", "latency"],
        opened_at_utc="2026-04-28T00:00:00+00:00",
        updated_at_utc="2026-04-28T00:10:00+00:00",
        closed_at_utc="2026-04-28T00:12:00+00:00",
        resolution="rolled restart",
        timeline=[
            {"at_utc": "2026-04-28T00:02:00+00:00", "kind": "diagnose", "message": "pod restart loop"},
            {"at_utc": "2026-04-28T00:09:00+00:00", "kind": "fix", "message": "rollout restart deployment"},
        ],
    )
    memory_rows = [
        MemoryCase(
            id=1,
            created_at="2026-04-01T00:00:00+00:00",
            symptom="payment timeout",
            root_cause="insufficient replicas",
            fix_commands=["kubectl -n prod scale deploy/payment --replicas=4"],
            rollback_commands=["kubectl -n prod scale deploy/payment --replicas=2"],
            metadata={},
            score=0.68,
        )
    ]
    markdown = _render_incident_postmortem_markdown(
        incident=rec,
        evidence_payload={"evidence_graph": {"nodes": [{"phase": "apply", "exit_code": 0, "command": "kubectl ..."}]}},
        similar_cases=memory_rows,
    )
    assert "## Incident Summary" in markdown
    assert "## Evidence" in markdown
    assert "## Similar Historical Cases" in markdown
    assert "payment latency spike" in markdown
