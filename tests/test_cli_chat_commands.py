from lazysre.cli.main import _parse_chat_slo_command, _parse_chat_topology_command


def test_parse_chat_slo_command_basic() -> None:
    parsed = _parse_chat_slo_command("burn-rate --window 6h --config-file /tmp/s.yaml --json")
    assert parsed["action"] == "burn-rate"
    assert parsed["window"] == "6h"
    assert parsed["config_file"] == "/tmp/s.yaml"
    assert parsed["json"] is True


def test_parse_chat_topology_command_basic() -> None:
    parsed = _parse_chat_topology_command("impact payment --env prod --depth 3")
    assert parsed["action"] == "impact"
    assert parsed["service_name"] == "payment"
    assert parsed["env"] == "prod"
    assert parsed["depth"] == "3"
