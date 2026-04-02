from lazysre.cli.fix_mode import compose_fix_instruction, extract_fix_plan


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
