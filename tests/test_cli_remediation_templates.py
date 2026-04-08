from lazysre.cli.remediation_templates import (
    get_template,
    list_templates,
    match_template_for_text,
    maybe_detect_quick_fix_intent,
    parse_var_items,
    render_template,
)


def test_list_templates_and_lookup_by_alias() -> None:
    templates = list_templates()
    names = {item.name for item in templates}
    assert "k8s-crashloopbackoff" in names
    assert "k8s-high-cpu" in names
    assert get_template("crashloop") is not None


def test_match_template_for_text() -> None:
    matched = match_template_for_text("线上支付 pod 出现 CrashLoopBackOff，帮我修复")
    assert matched is not None
    assert matched.name == "k8s-crashloopbackoff"


def test_parse_var_items_and_render_template() -> None:
    template = get_template("k8s-high-cpu")
    assert template is not None
    vars_map = parse_var_items(["namespace=prod", "workload=deploy/pay", "replicas=5"])
    rendered = render_template(template, overrides=vars_map)
    apply_cmds = rendered["apply_commands"]
    assert "kubectl -n prod scale deploy/pay --replicas=5" in apply_cmds


def test_detect_quick_fix_intent_with_apply_flag() -> None:
    template, apply_requested = maybe_detect_quick_fix_intent("帮我一键修复 CrashLoopBackOff")
    assert template is not None
    assert template.name == "k8s-crashloopbackoff"
    assert apply_requested is True
