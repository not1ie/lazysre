import pytest

from lazysre.cli.runbook import (
    builtin_runbooks,
    find_runbook,
    parse_runbook_vars,
    render_runbook_instruction,
)


def test_builtin_runbooks_and_lookup() -> None:
    items = builtin_runbooks()
    assert items
    assert any(x.name == "k8s-latency-diagnose" for x in items)
    assert find_runbook("payment-latency-fix") is not None
    assert find_runbook("not-exist") is None


def test_parse_vars_and_render_instruction() -> None:
    template = find_runbook("payment-latency-fix")
    assert template is not None
    values = parse_runbook_vars(["service=order", "namespace=prod", "p95_ms=450"])
    instruction, resolved = render_runbook_instruction(template, overrides=values)
    assert "order" in instruction
    assert "prod" in instruction
    assert resolved["service"] == "order"
    assert resolved["namespace"] == "prod"


def test_parse_vars_reject_invalid_input() -> None:
    with pytest.raises(ValueError):
        parse_runbook_vars(["namespace"])


def test_render_instruction_requires_missing_keys() -> None:
    template = find_runbook("payment-latency-fix")
    assert template is not None
    template.variables = {}
    with pytest.raises(ValueError):
        render_runbook_instruction(template, overrides={"service": "payment"})
