from lazysre.main import _build_execution_templates


def test_build_execution_templates_contains_task_sheet_and_rollback() -> None:
    payload = _build_execution_templates(
        [
            "kubectl rollout restart deploy/payment",
            "docker service update --force lazysre_lazysre",
            "curl -sS http://127.0.0.1:32080/health",
        ],
        source="unit-test",
        approval_ticket="CHG-TEST-1",
        target_context={
            "active_profile": "prod-sh",
            "target": {
                "ssh_target": "root@192.168.10.101",
                "k8s_context": "prod-context",
                "k8s_namespace": "ops",
                "prometheus_url": "http://92.168.69.176:9090",
            },
        },
    )
    assert payload["count"] == 3
    items = payload["items"]
    assert isinstance(items, list)
    first = items[0]
    assert first["target"]["platform"] == "kubernetes"
    assert isinstance(first["prerequisites"], list)
    assert first["environment"]["active_profile"] == "prod-sh"
    assert first["environment"]["k8s_namespace"] == "ops"
    assert isinstance(first["preflight_commands"], list)
    assert isinstance(first["verify_commands"], list)
    assert "ops" in first["rollback_template"]["command"]
    assert first["rollback_template"]["strategy"] == "k8s-rollout-undo"
    assert "kubectl rollout undo" in first["rollback_template"]["command"]
    assert "task_sheet" in first
    assert first["task_sheet"]["execute_command"].startswith("LAZYSRE_APPROVAL_TICKET=CHG-TEST-1 ")

    second = items[1]
    assert second["target"]["platform"] == "docker"
    assert "root@192.168.10.101" in " ".join(second["prerequisites"])
    assert second["rollback_template"]["strategy"] == "swarm-rollback"
    assert "docker service rollback" in second["rollback_template"]["command"]

    third = items[2]
    assert third["target"]["platform"] == "http"
    assert third["target"]["resource"].startswith("http://")
    assert third["environment"]["prometheus_url"].startswith("http://")
