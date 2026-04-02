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

