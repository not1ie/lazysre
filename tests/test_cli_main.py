import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from lazysre.cli.main import (
    _archive_report_for_git,
    _backup_target_profile,
    _build_doctor_gate,
    _build_incident_report_payload,
    _compute_doctor_autofix,
    _collect_runtime_status,
    _default_report_output_path,
    _doctor_is_healthy,
    _extract_command_candidates,
    _extract_named_field,
    _looks_like_apply_request,
    _looks_like_fix_request,
    _parse_step_selection,
    _read_last_fix_plan_summary,
    _render_incident_report_markdown,
    _rewrite_argv_for_default_run,
    _summarize_doctor_checks,
    _push_report_to_git,
    _resolve_runbook_vars,
    _target_runbook_context_vars,
    _prepare_runbook_instruction,
    _parse_chat_runbook_command,
    _parse_chat_runbook_var_extra,
    _parse_chat_report_command,
    _collect_install_doctor_report,
    _safe_run_command,
    _should_launch_assistant,
)
from lazysre.cli.runbook import find_runbook
from lazysre.cli.target import TargetEnvironment


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


def test_rewrite_argv_preserves_status_subcommand() -> None:
    argv = ["lsre", "status", "--json"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "status", "--json"]


def test_rewrite_argv_preserves_approve_subcommand() -> None:
    argv = ["lsre", "approve", "--steps", "1,3-4", "--execute"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "approve", "--steps", "1,3-4", "--execute"]


def test_rewrite_argv_preserves_memory_subcommand() -> None:
    argv = ["lsre", "memory", "show", "--limit", "5"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "memory", "show", "--limit", "5"]


def test_rewrite_argv_preserves_doctor_subcommand() -> None:
    argv = ["lsre", "doctor", "--json"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "doctor", "--json"]


def test_rewrite_argv_preserves_report_and_runbook_subcommands() -> None:
    argv1 = ["lsre", "report", "--format", "json"]
    _rewrite_argv_for_default_run(argv1)
    assert argv1 == ["lsre", "report", "--format", "json"]
    argv2 = ["lsre", "runbook", "list"]
    _rewrite_argv_for_default_run(argv2)
    assert argv2 == ["lsre", "runbook", "list"]
    argv3 = ["lsre", "install-doctor", "--json"]
    _rewrite_argv_for_default_run(argv3)
    assert argv3 == ["lsre", "install-doctor", "--json"]


def test_detect_fix_and_apply_intent() -> None:
    assert _looks_like_fix_request("请帮我修复支付服务")
    assert _looks_like_fix_request("fix payment service latency")
    assert _looks_like_apply_request("执行修复计划")
    assert _looks_like_apply_request("apply fix")
    assert _looks_like_fix_request("执行修复计划") is False


def test_should_launch_assistant_with_only_options() -> None:
    assert _should_launch_assistant(["--provider", "mock"]) is True
    assert _should_launch_assistant(["--verbose-reasoning"]) is True
    assert _should_launch_assistant([]) is True
    assert _should_launch_assistant(["chat"]) is False
    assert _should_launch_assistant(["status"]) is False
    assert _should_launch_assistant(["doctor"]) is False
    assert _should_launch_assistant(["install-doctor"]) is False
    assert _should_launch_assistant(["report"]) is False
    assert _should_launch_assistant(["runbook"]) is False
    assert _should_launch_assistant(["approve"]) is False
    assert _should_launch_assistant(["memory"]) is False
    assert _should_launch_assistant(["检查k8s"]) is False


def test_extract_named_field_handles_markdown_and_plain_prefix() -> None:
    text = """
**Status**: Diagnosing
Risk Level: Medium
"""
    assert _extract_named_field(text, ["status"]) == "Diagnosing"
    assert _extract_named_field(text, ["risk level"]) == "Medium"


def test_extract_command_candidates_prefers_apply_commands() -> None:
    text = """
## Apply Commands
```bash
kubectl -n default rollout restart deploy/payment
kubectl -n default get pods -l app=payment -w
```
"""
    commands = _extract_command_candidates(text, max_items=5)
    assert commands[0] == "kubectl -n default rollout restart deploy/payment"
    assert "kubectl -n default get pods -l app=payment -w" in commands


def test_read_last_fix_plan_summary(tmp_path: Path) -> None:
    plan_path = tmp_path / "last.json"
    plan_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-04-07T00:00:00Z",
                "instruction": "修复 payment",
                "plan": {"apply_commands": ["kubectl get pods"]},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    summary = _read_last_fix_plan_summary(plan_path)
    assert summary["exists"] is True
    assert summary["apply_commands"] == 1


def test_collect_runtime_status_without_probe(tmp_path: Path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "turns": [{"user": "检查集群", "assistant": "ok"}],
                "entities": {},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    profile_file = tmp_path / "target.json"
    profile_file.write_text(
        json.dumps(
            {
                "prometheus_url": "http://127.0.0.1:9090",
                "k8s_api_url": "https://127.0.0.1:6443",
                "k8s_namespace": "default",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    status = _collect_runtime_status(
        session_file=session_file,
        profile_file=profile_file,
        include_probe=False,
        execute_probe=False,
        timeout_sec=4,
        audit_log=tmp_path / "audit.jsonl",
    )
    assert "target" in status
    assert "session" in status
    assert "probe" not in status


def test_parse_step_selection_supports_ranges() -> None:
    selected = _parse_step_selection("1, 3-5, 9, 7-6, x", max_step=8)
    assert selected == {1, 3, 4, 5, 6, 7}


def test_summarize_doctor_checks() -> None:
    summary = _summarize_doctor_checks(
        [
            {"severity": "pass"},
            {"severity": "warn"},
            {"severity": "error"},
            {"severity": "unknown"},
        ]
    )
    assert summary["total"] == 4
    assert summary["pass"] == 1
    assert summary["warn"] == 1
    assert summary["error"] == 2
    assert summary["healthy"] is False


def test_doctor_is_healthy_strict_and_non_strict() -> None:
    summary = {"error": 0, "warn": 1}
    assert _doctor_is_healthy(summary, strict=False) is True
    assert _doctor_is_healthy(summary, strict=True) is False


def test_compute_doctor_autofix_sets_safe_defaults(monkeypatch) -> None:
    monkeypatch.setattr(
        "lazysre.cli.main._detect_kubectl_current_context",
        lambda: "autofix-context",
    )
    target = TargetEnvironment(
        prometheus_url="",
        k8s_api_url="",
        k8s_context="",
        k8s_namespace="",
        k8s_bearer_token="",
        k8s_verify_tls=False,
    )
    updates, actions = _compute_doctor_autofix(target)
    assert updates.get("k8s_namespace") == "default"
    assert "prometheus_url" in updates
    assert "k8s_api_url" in updates
    assert updates.get("k8s_context") == "autofix-context"
    assert actions


def test_backup_target_profile(tmp_path: Path) -> None:
    profile = tmp_path / "target.json"
    profile.write_text('{"k8s_namespace":"default"}', encoding="utf-8")
    backup_path = _backup_target_profile(profile)
    assert backup_path
    backup = Path(backup_path)
    assert backup.exists()
    assert backup.read_text(encoding="utf-8") == profile.read_text(encoding="utf-8")


def test_build_doctor_gate_strict_and_non_strict() -> None:
    report = {
        "checks": [
            {"name": "a", "severity": "pass", "hint": ""},
            {"name": "b", "severity": "warn", "hint": "fix warn"},
            {"name": "c", "severity": "error", "hint": "fix error"},
        ]
    }
    gate_non_strict = _build_doctor_gate(report, strict=False)
    assert gate_non_strict["blocking_count"] == 1
    assert gate_non_strict["exit_code_advice"] == 1

    gate_strict = _build_doctor_gate(report, strict=True)
    assert gate_strict["blocking_count"] == 2
    assert gate_strict["exit_code_advice"] == 2


def test_build_report_payload_and_markdown(tmp_path: Path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "turns": [
                    {"user": "排查支付延迟", "assistant": "先看 metrics"},
                    {"user": "执行修复", "assistant": "建议 rollout restart"},
                ],
                "entities": {},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    profile_file = tmp_path / "target.json"
    profile_file.write_text(
        json.dumps(
            {
                "prometheus_url": "http://127.0.0.1:9090",
                "k8s_api_url": "https://127.0.0.1:6443",
                "k8s_context": "dev",
                "k8s_namespace": "default",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    payload = _build_incident_report_payload(
        session_file=session_file,
        target_profile_file=profile_file,
        include_doctor=False,
        include_memory=False,
        memory_limit=3,
        turn_limit=5,
        audit_log=tmp_path / "audit.jsonl",
    )
    assert payload["session"]
    md = _render_incident_report_markdown(payload)
    assert "LazySRE Incident Report" in md
    assert "Recent Session Turns" in md


def test_default_report_output_path_switches_for_push() -> None:
    normal = _default_report_output_path(fmt="markdown", stamp="20260407-010203", push_to_git=False)
    pushed = _default_report_output_path(fmt="json", stamp="20260407-010203", push_to_git=True)
    assert normal == ".data/lsre-report-20260407-010203.md"
    assert pushed == "reports/lsre-report-20260407-010203.json"


def test_archive_report_for_git_copies_into_reports(tmp_path: Path) -> None:
    source = tmp_path / "out.md"
    source.write_text("# report\n", encoding="utf-8")
    old = Path.cwd()
    try:
        # archive path uses cwd/reports, so switch into tmp workspace for this test
        os.chdir(tmp_path)
        archived = _archive_report_for_git(source, stamp="20260407-010203")
        assert archived.as_posix().startswith("reports/")
        assert archived.exists()
        assert archived.read_text(encoding="utf-8") == "# report\n"
    finally:
        os.chdir(old)


def test_push_report_to_git_success(monkeypatch, tmp_path: Path) -> None:
    archived = tmp_path / "reports" / "r.md"
    archived.parent.mkdir(parents=True, exist_ok=True)
    archived.write_text("ok\n", encoding="utf-8")

    monkeypatch.setattr("lazysre.cli.main.shutil.which", lambda _: "/usr/bin/git")

    calls: list[list[str]] = []

    def _fake_git(args: list[str]):
        calls.append(args)
        if args[:2] == ["rev-parse", "--is-inside-work-tree"]:
            return subprocess.CompletedProcess(["git", *args], 0, "true\n", "")
        if args[0] == "add":
            return subprocess.CompletedProcess(["git", *args], 0, "", "")
        if args[0] == "commit":
            return subprocess.CompletedProcess(["git", *args], 0, "[main] ok\n", "")
        if args[0] == "push":
            return subprocess.CompletedProcess(["git", *args], 0, "", "")
        return subprocess.CompletedProcess(["git", *args], 1, "", "unexpected")

    monkeypatch.setattr("lazysre.cli.main._run_git_command", _fake_git)
    ok = _push_report_to_git(
        archived_path=archived,
        remote="origin",
        commit_message="chore(report): test",
    )
    assert ok is True
    assert any(cmd and cmd[0] == "push" for cmd in calls)


def test_push_report_to_git_no_changes(monkeypatch, tmp_path: Path) -> None:
    archived = tmp_path / "reports" / "r.md"
    archived.parent.mkdir(parents=True, exist_ok=True)
    archived.write_text("ok\n", encoding="utf-8")

    monkeypatch.setattr("lazysre.cli.main.shutil.which", lambda _: "/usr/bin/git")

    def _fake_git(args: list[str]):
        if args[:2] == ["rev-parse", "--is-inside-work-tree"]:
            return subprocess.CompletedProcess(["git", *args], 0, "true\n", "")
        if args[0] == "add":
            return subprocess.CompletedProcess(["git", *args], 0, "", "")
        if args[0] == "commit":
            return subprocess.CompletedProcess(
                ["git", *args],
                1,
                "nothing to commit, working tree clean\n",
                "",
            )
        return subprocess.CompletedProcess(["git", *args], 0, "", "")

    monkeypatch.setattr("lazysre.cli.main._run_git_command", _fake_git)
    ok = _push_report_to_git(
        archived_path=archived,
        remote="origin",
        commit_message="chore(report): test",
    )
    assert ok is False


def test_target_runbook_context_vars(tmp_path: Path, monkeypatch) -> None:
    target_file = tmp_path / "target.json"
    target_file.write_text(
        json.dumps(
            {
                "prometheus_url": "http://127.0.0.1:9090",
                "k8s_api_url": "https://127.0.0.1:6443",
                "k8s_context": "dev",
                "k8s_namespace": "payments",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("lazysre.cli.main.ClusterProfileStore.default", lambda: type("X", (), {"get_active": lambda self: "prod"})())
    values = _target_runbook_context_vars(profile_file=target_file)
    assert values["namespace"] == "payments"
    assert values["k8s_context"] == "dev"
    assert values["target_profile"] == "prod"


def test_resolve_runbook_vars_prefers_cli_over_target(tmp_path: Path, monkeypatch) -> None:
    target_file = tmp_path / "target.json"
    target_file.write_text(
        json.dumps(
            {
                "prometheus_url": "http://127.0.0.1:9090",
                "k8s_api_url": "https://127.0.0.1:6443",
                "k8s_context": "dev",
                "k8s_namespace": "payments",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("lazysre.cli.main.ClusterProfileStore.default", lambda: type("X", (), {"get_active": lambda self: "prod"})())
    template = find_runbook("payment-latency-fix")
    assert template is not None
    values = _resolve_runbook_vars(
        template=template,
        var_items=["namespace=checkout", "service=order"],
        profile_file=target_file,
    )
    assert values["namespace"] == "checkout"
    assert values["service"] == "order"
    assert values["target_profile"] == "prod"


def test_prepare_runbook_instruction_includes_vars_and_extra(tmp_path: Path, monkeypatch) -> None:
    target_file = tmp_path / "target.json"
    target_file.write_text(
        json.dumps(
            {
                "prometheus_url": "http://127.0.0.1:9090",
                "k8s_api_url": "https://127.0.0.1:6443",
                "k8s_context": "dev",
                "k8s_namespace": "payments",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("lazysre.cli.main.ClusterProfileStore.default", lambda: type("X", (), {"get_active": lambda self: "prod"})())
    template = find_runbook("payment-latency-fix")
    assert template is not None
    rendered = _prepare_runbook_instruction(
        template=template,
        var_items=["service=order"],
        extra="仅观察，不做变更",
        profile_file=target_file,
    )
    assert "payments" in rendered
    assert "service=order" in rendered
    assert "[runbook-extra]" in rendered


def test_parse_chat_runbook_var_extra() -> None:
    vars_payload, extra = _parse_chat_runbook_var_extra(
        ["service=pay", "--var", "namespace=prod", "只读检查", "--var=p95_ms=350"]
    )
    assert "service=pay" in vars_payload
    assert "namespace=prod" in vars_payload
    assert "p95_ms=350" in vars_payload
    assert extra == "只读检查"


def test_parse_chat_runbook_command_run_and_render() -> None:
    parsed_run = _parse_chat_runbook_command("payment-latency-fix service=order namespace=prod")
    assert parsed_run["action"] == "run"
    assert parsed_run["name"] == "payment-latency-fix"
    assert parsed_run["apply"] is False

    parsed_render = _parse_chat_runbook_command("render payment-latency-fix --var service=order")
    assert parsed_render["action"] == "render"
    assert parsed_render["name"] == "payment-latency-fix"
    assert "service=order" in parsed_render["var_items"]

    parsed_run_apply = _parse_chat_runbook_command(
        "run payment-latency-fix --apply --runbook-file /tmp/rb.json service=order"
    )
    assert parsed_run_apply["action"] == "run"
    assert parsed_run_apply["name"] == "payment-latency-fix"
    assert parsed_run_apply["apply"] is True
    assert parsed_run_apply["runbook_file"] == "/tmp/rb.json"


def test_parse_chat_runbook_command_add_and_export_import_remove() -> None:
    parsed_add = _parse_chat_runbook_command(
        'add my-fix --title "My Fix" --instruction "check {service}" --mode fix service=pay --force'
    )
    assert parsed_add["action"] == "add"
    assert parsed_add["name"] == "my-fix"
    assert parsed_add["mode"] == "fix"
    assert parsed_add["force"] is True
    assert "service=pay" in parsed_add["var_items"]

    parsed_export = _parse_chat_runbook_command("export --scope effective --name a --name b --output /tmp/x.json")
    assert parsed_export["action"] == "export"
    assert parsed_export["scope"] == "effective"
    assert parsed_export["names"] == ["a", "b"]

    parsed_import = _parse_chat_runbook_command("import --input /tmp/x.json --replace")
    assert parsed_import["action"] == "import"
    assert parsed_import["merge"] is False

    parsed_remove = _parse_chat_runbook_command("remove my-fix --yes")
    assert parsed_remove["action"] == "remove"
    assert parsed_remove["yes"] is True


def test_parse_chat_report_command_defaults_and_options() -> None:
    defaults = _parse_chat_report_command("")
    assert defaults["fmt"] == "markdown"
    assert defaults["include_doctor"] is True
    assert defaults["push_to_git"] is False

    parsed = _parse_chat_report_command(
        "json --output /tmp/r.json --limit 8 --no-doctor --no-memory --push-to-git "
        '--git-remote origin --git-message "archive report"'
    )
    assert parsed["fmt"] == "json"
    assert parsed["output"] == "/tmp/r.json"
    assert parsed["limit"] == 8
    assert parsed["include_doctor"] is False
    assert parsed["include_memory"] is False
    assert parsed["push_to_git"] is True
    assert parsed["git_remote"] == "origin"
    assert parsed["git_message"] == "archive report"


def test_parse_chat_report_command_errors() -> None:
    with pytest.raises(ValueError):
        _parse_chat_report_command("--limit abc")
    with pytest.raises(ValueError):
        _parse_chat_report_command("--unknown")


def test_safe_run_command_success_and_failure() -> None:
    ok = _safe_run_command([sys.executable, "-c", "print('ok')"], timeout_sec=3)
    assert ok["ok"] is True
    assert "ok" in str(ok["stdout"])

    bad = _safe_run_command([sys.executable, "-c", "import sys; sys.exit(7)"], timeout_sec=3)
    assert bad["ok"] is False
    assert bad["exit_code"] == 7


def test_collect_install_doctor_report_shape() -> None:
    report = _collect_install_doctor_report()
    assert "checks" in report
    assert "summary" in report
    checks = report["checks"]
    assert isinstance(checks, list)
    names = {str(x.get("name", "")) for x in checks if isinstance(x, dict)}
    assert "runtime.python_version" in names
    assert "runtime.lazysre_import" in names
