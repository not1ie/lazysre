from lazysre.cli.runbook import builtin_runbooks, find_runbook


def test_builtin_runbooks_and_lookup() -> None:
    items = builtin_runbooks()
    assert items
    assert any(x.name == "k8s-latency-diagnose" for x in items)
    assert find_runbook("payment-latency-fix") is not None
    assert find_runbook("not-exist") is None
