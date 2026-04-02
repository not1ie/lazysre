from lazysre.cli.fix_mode import (
    FixPlan,
    build_plan_record,
    compose_fix_instruction,
    evaluate_apply_guardrail,
    extract_fix_plan,
)


def test_compose_fix_instruction_contains_required_sections() -> None:
    prompt = compose_fix_instruction("支付服务慢")
    assert "## Root Cause" in prompt
    assert "## Fix Plan" in prompt
    assert "## Apply Commands" in prompt
    assert "## Rollback Commands" in prompt


def test_extract_fix_plan_with_explicit_sections() -> None:
    text = """
## Root Cause
cpu throttle

## Fix Plan
1. restart

## Apply Commands
```bash
kubectl -n default rollout restart deploy/payment
kubectl -n default get pods -l app=payment -w
```

## Rollback Commands
```bash
kubectl -n default rollout undo deploy/payment
```
"""
    plan = extract_fix_plan(text)
    assert plan.apply_commands[0].startswith("kubectl -n default rollout restart")
    assert plan.rollback_commands == ["kubectl -n default rollout undo deploy/payment"]


def test_extract_fix_plan_with_fallback_blocks() -> None:
    text = """
建议按顺序执行：
```bash
kubectl -n default scale deploy/payment --replicas=4
```

回滚：
```bash
kubectl -n default scale deploy/payment --replicas=2
```
"""
    plan = extract_fix_plan(text)
    assert plan.apply_commands == ["kubectl -n default scale deploy/payment --replicas=4"]
    assert plan.rollback_commands == ["kubectl -n default scale deploy/payment --replicas=2"]


def test_evaluate_apply_guardrail() -> None:
    allowed, confirm = evaluate_apply_guardrail(
        risk_level="high", allow_high_risk=False, auto_approve_low_risk=False
    )
    assert allowed is False
    assert confirm is False

    allowed2, confirm2 = evaluate_apply_guardrail(
        risk_level="low", allow_high_risk=False, auto_approve_low_risk=True
    )
    assert allowed2 is True
    assert confirm2 is False

    allowed3, confirm3 = evaluate_apply_guardrail(
        risk_level="medium", allow_high_risk=False, auto_approve_low_risk=True
    )
    assert allowed3 is True
    assert confirm3 is True


def test_build_plan_record_shape() -> None:
    plan = FixPlan(
        apply_commands=["kubectl get pods"],
        rollback_commands=["kubectl rollout undo deploy/api"],
    )
    record = build_plan_record(
        instruction="修复 api",
        plan=plan,
        final_text="## Root Cause",
        selected_apply_commands=["kubectl get pods"],
        approval_mode="balanced",
    )
    assert record["instruction"] == "修复 api"
    assert "generated_at" in record
    assert record["plan"]["apply_commands"] == ["kubectl get pods"]
