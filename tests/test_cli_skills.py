from pathlib import Path

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
    assert any("lazysre skill run swarm-health --execute" in item for item in result.next_actions)
