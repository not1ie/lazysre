from lazysre.cli.main import _rewrite_argv_for_default_run


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
