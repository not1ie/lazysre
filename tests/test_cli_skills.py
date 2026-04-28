from pathlib import Path

import pytest

from lazysre.cli.skills import (
    SkillStore,
    SkillTemplate,
    all_skills,
    find_skill,
    parse_skill_vars,
    render_skill_commands,
    run_skill,
)


def test_builtin_skills_include_remote_health() -> None:
    items = all_skills()
    remote = next((item for item in items if item.name == "remote-health"), None)

    assert remote is not None
    assert remote.risk_level == "low"
    assert remote.precheck_commands
    assert "lazysre remote {ssh_target} --scenario all --logs" in remote.read_commands


def test_skill_store_custom_override_and_render(tmp_path: Path) -> None:
    store = SkillStore(tmp_path / "skills.json")
    store.upsert(
        SkillTemplate(
            name="team-nginx",
            title="Team Nginx",
            description="diagnose nginx",
            category="middleware",
            mode="diagnose",
            risk_level="low",
            required_permission="read",
            instruction="check nginx",
            variables={"ssh_target": "root@host"},
            read_commands=["lazysre remote {ssh_target} --scenario nginx"],
            tags=["nginx"],
            source="custom",
        )
    )

    item = find_skill("team-nginx", store=store)
    assert item is not None
    commands, variables = render_skill_commands(item, overrides={"ssh_target": "root@192.168.10.101"})
    assert variables["ssh_target"] == "root@192.168.10.101"
    assert commands["read"] == ["lazysre remote root@192.168.10.101 --scenario nginx"]


def test_run_skill_dry_run_outputs_next_actions() -> None:
    item = find_skill("swarm-health")
    assert item is not None

    result = run_skill(item, overrides=parse_skill_vars(["tail=50"]), dry_run=True)

    assert result.status == "planned"
    assert result.dry_run is True
    assert result.commands["read"] == ["lazysre swarm --logs --tail 50"]
    assert result.commands["precheck"]
    assert result.evidence_graph == {"nodes": [], "edges": []}
    assert any("lazysre skill run swarm-health --execute" in item for item in result.next_actions)


def test_run_skill_execute_failure_triggers_auto_rollback(monkeypatch: pytest.MonkeyPatch) -> None:
    executed: list[str] = []

    class _Completed:
        def __init__(self, rc: int) -> None:
            self.returncode = rc
            self.stdout = "ok"
            self.stderr = "boom" if rc else ""

    def _fake_run(command: str, **_: object) -> _Completed:
        executed.append(command)
        if command == "apply-fail":
            return _Completed(1)
        return _Completed(0)

    monkeypatch.setattr("lazysre.cli.skills.subprocess.run", _fake_run)
    skill = SkillTemplate(
        name="rollback-demo",
        title="Rollback Demo",
        description="",
        category="custom",
        mode="fix",
        risk_level="high",
        required_permission="write",
        instruction="test",
        precheck_commands=["precheck-ok"],
        read_commands=["read-ok"],
        apply_commands=["apply-fail"],
        verify_commands=["verify-ok"],
        rollback_commands=["rollback-ok"],
        source="custom",
    )

    result = run_skill(
        skill,
        dry_run=False,
        apply=True,
        timeout_sec=2,
        auto_rollback_on_failure=True,
    )

    assert result.status == "failed"
    assert result.failed_phase == "apply"
    assert result.rollback_executed is True
    assert result.rollback_status == "executed"
    assert executed == ["precheck-ok", "read-ok", "apply-fail", "rollback-ok"]
    assert any(node["phase"] == "rollback" for node in result.evidence_graph["nodes"])
