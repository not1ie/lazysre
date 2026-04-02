from lazysre.cli.main import (
    _looks_like_apply_request,
    _looks_like_fix_request,
    _rewrite_argv_for_default_run,
    _should_launch_assistant,
)


def test_rewrite_argv_default_run_simple_instruction() -> None:
    argv = ["lsre", "检查", "k8s"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "run", "检查", "k8s"]


def test_rewrite_argv_preserves_subcommand() -> None:
    argv = ["lsre", "pack", "list", "--index", "idx.json"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "pack", "list", "--index", "idx.json"]


def test_rewrite_argv_with_global_option_then_instruction() -> None:
    argv = ["lsre", "--provider", "mock", "检查k8s"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "--provider", "mock", "run", "检查k8s"]


def test_rewrite_argv_with_session_file_option_then_instruction() -> None:
    argv = ["lsre", "--session-file", ".data/custom-session.json", "重启它"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "--session-file", ".data/custom-session.json", "run", "重启它"]


def test_rewrite_argv_preserves_target_subcommand() -> None:
    argv = ["lsre", "target", "show"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "target", "show"]


def test_rewrite_argv_preserves_history_subcommand() -> None:
    argv = ["lsre", "history", "show", "--limit", "5"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "history", "show", "--limit", "5"]


def test_rewrite_argv_preserves_fix_subcommand() -> None:
    argv = ["lsre", "fix", "支付服务变慢", "--apply"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "fix", "支付服务变慢", "--apply"]


def test_detect_fix_and_apply_intent() -> None:
    assert _looks_like_fix_request("请帮我修复支付服务")
    assert _looks_like_fix_request("fix payment service latency")
    assert _looks_like_apply_request("执行修复计划")
    assert _looks_like_apply_request("apply fix")
    assert _looks_like_fix_request("执行修复计划") is False


def test_should_launch_assistant_with_only_options() -> None:
    assert _should_launch_assistant(["--provider", "mock"]) is True
    assert _should_launch_assistant([]) is True
    assert _should_launch_assistant(["chat"]) is False
    assert _should_launch_assistant(["检查k8s"]) is False
