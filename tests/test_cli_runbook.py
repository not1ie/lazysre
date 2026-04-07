import pytest

from lazysre.cli.runbook import (
    RunbookStore,
    RunbookTemplate,
    all_runbooks,
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


def test_runbook_store_custom_override(tmp_path) -> None:
    store = RunbookStore(tmp_path / "runbooks.json")
    custom = RunbookTemplate(
        name="payment-latency-fix",
        title="Custom Payment Fix",
        mode="fix",
        instruction="请修复 {service}",
        description="custom",
        variables={"service": "pay"},
        source="custom",
    )
    store.upsert(custom)

    selected = find_runbook("payment-latency-fix", store=store)
    assert selected is not None
    assert selected.source == "custom"
    assert selected.title == "Custom Payment Fix"

    names = [x.name for x in all_runbooks(store=store)]
    assert "payment-latency-fix" in names


def test_runbook_store_remove(tmp_path) -> None:
    store = RunbookStore(tmp_path / "runbooks.json")
    custom = RunbookTemplate(
        name="my-fix",
        title="My Fix",
        mode="diagnose",
        instruction="check {svc}",
        description="x",
        variables={"svc": "api"},
        source="custom",
    )
    store.upsert(custom)
    assert store.get_custom("my-fix") is not None
    assert store.remove("my-fix") is True
    assert store.get_custom("my-fix") is None


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
