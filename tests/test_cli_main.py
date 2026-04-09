import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import lazysre.cli.main as cli_main
from lazysre.cli.main import (
    _archive_report_for_git,
    _backup_target_profile,
    _build_cli_llm,
    _build_provider_setup_checks,
    _build_doctor_gate,
    _build_incident_report_payload,
    _compute_doctor_autofix,
    _collect_runtime_status,
    _collect_environment_discovery,
    _collect_swarm_health_report,
    _default_report_output_path,
    _doctor_is_healthy,
    _extract_template_var_items_from_text,
    _extract_apply_step_selection,
    _extract_step_selection_from_text,
    _extract_target_updates_from_text,
    _extract_profile_save_request,
    _extract_profile_switch_name,
    _extract_profile_remove_request,
    _extract_profile_export_request,
    _extract_profile_import_request,
    _extract_runbook_var_items_from_text,
    _extract_command_candidates,
    _extract_named_field,
    _compose_template_var_items,
    _compose_runbook_var_items,
    _build_quick_k8s_action_plan,
    _extract_requested_replicas,
    _normalize_chat_input_text,
    _normalize_natural_language_text,
    _normalize_slash_command_text,
    _looks_like_auto_fix_request,
    _looks_like_apply_request,
    _looks_like_approval_queue_request,
    _looks_like_context_request,
    _looks_like_doctor_request,
    _looks_like_explain_step_request,
    _looks_like_fix_request,
    _looks_like_force_high_risk_apply_request,
    _looks_like_help_request,
    _looks_like_init_request,
    _looks_like_install_doctor_request,
    _looks_like_low_risk_apply_request,
    _looks_like_quickstart_request,
    _looks_like_reset_request,
    _looks_like_scan_request,
    _looks_like_swarm_diagnose_request,
    _looks_like_report_request,
    _looks_like_target_show_request,
    _looks_like_target_update_request,
    _looks_like_target_profile_current_request,
    _looks_like_target_profile_list_request,
    _looks_like_target_profile_remove_request,
    _looks_like_target_profile_export_request,
    _looks_like_target_profile_import_request,
    _looks_like_read_then_write_strategy_request,
    _looks_like_switch_dry_run_request,
    _looks_like_switch_execute_request,
    _looks_like_undo_request,
    _looks_like_logs_action_request,
    _looks_like_restart_action_request,
    _looks_like_scale_action_request,
    _looks_like_status_request,
    _extract_swarm_service_name,
    _looks_like_template_library_request,
    _looks_like_with_impact_request,
    _split_fix_plan_read_write_commands,
    _parse_step_selection,
    _read_last_fix_plan_summary,
    _render_incident_report_markdown,
    _rewrite_argv_for_default_run,
    _summarize_doctor_checks,
    _push_report_to_git,
    _resolve_default_provider,
    _resolve_provider_api_key,
    _resolve_runbook_vars,
    _target_runbook_context_vars,
    _prepare_runbook_instruction,
    _parse_chat_runbook_command,
    _parse_chat_runbook_var_extra,
    _parse_chat_report_command,
    _parse_chat_template_command,
    _collect_install_doctor_report,
    _safe_run_command,
    _should_launch_assistant,
)
from lazysre.cli.llm import (
    AnthropicMessagesLLM,
    GeminiFunctionCallingLLM,
    OpenAICompatibleFunctionCallingLLM,
)
from lazysre.cli.fix_mode import FixPlan
from lazysre.cli.runbook import find_runbook
from lazysre.cli.secrets import SecretStore
from lazysre.cli.target import TargetEnvironment
from lazysre.config import settings


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
    argv4 = ["lsre", "scan", "--json"]
    _rewrite_argv_for_default_run(argv4)
    assert argv4 == ["lsre", "scan", "--json"]
    argv5 = ["lsre", "swarm", "--json"]
    _rewrite_argv_for_default_run(argv5)
    assert argv5 == ["lsre", "swarm", "--json"]
    argv6 = ["lsre", "setup", "--json"]
    _rewrite_argv_for_default_run(argv6)
    assert argv6 == ["lsre", "setup", "--json"]
    argv7 = ["lsre", "template", "list"]
    _rewrite_argv_for_default_run(argv7)
    assert argv7 == ["lsre", "template", "list"]
    argv8 = ["lsre", "init"]
    _rewrite_argv_for_default_run(argv8)
    assert argv8 == ["lsre", "init"]
    argv9 = ["lsre", "login", "--api-key", "sk-xxx"]
    _rewrite_argv_for_default_run(argv9)
    assert argv9 == ["lsre", "login", "--api-key", "sk-xxx"]
    argv10 = ["lsre", "quickstart", "--json"]
    _rewrite_argv_for_default_run(argv10)
    assert argv10 == ["lsre", "quickstart", "--json"]
    argv11 = ["lsre", "reset"]
    _rewrite_argv_for_default_run(argv11)
    assert argv11 == ["lsre", "reset"]
    argv12 = ["lsre", "undo"]
    _rewrite_argv_for_default_run(argv12)
    assert argv12 == ["lsre", "undo"]


def test_secret_store_supports_multiple_provider_keys(tmp_path: Path) -> None:
    store = SecretStore(tmp_path / "secrets.json")
    store.set_api_key("anthropic", "sk-ant-1234567890")
    store.set_api_key("gemini", "gem-key-1234567890")

    assert store.get_api_key("anthropic") == "sk-ant-1234567890"
    assert store.get_api_key("gemini") == "gem-key-1234567890"
    assert store.masked_api_key("anthropic").startswith("sk-a")
    assert store.clear_api_key("gemini") is True
    assert store.get_api_key("gemini") == ""


def test_resolve_default_provider_prefers_available_real_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_path = tmp_path / "secrets.json"
    store = SecretStore(secrets_path)
    store.set_api_key("gemini", "gem-key-123")

    monkeypatch.setattr(settings, "openai_api_key", "", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "", raising=False)
    monkeypatch.setattr(settings, "gemini_api_key", "", raising=False)
    monkeypatch.setattr(settings, "deepseek_api_key", "", raising=False)
    monkeypatch.setattr(settings, "qwen_api_key", "", raising=False)
    monkeypatch.setattr(settings, "kimi_api_key", "", raising=False)
    assert _resolve_default_provider(secrets_file=secrets_path) == "gemini"

    monkeypatch.setattr(settings, "anthropic_api_key", "ant-key-123", raising=False)
    assert _resolve_default_provider(secrets_file=secrets_path) == "anthropic"


def test_build_cli_llm_supports_anthropic_and_gemini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_path = tmp_path / "secrets.json"
    store = SecretStore(secrets_path)
    store.set_api_key("anthropic", "ant-key-123")
    store.set_api_key("gemini", "gem-key-123")
    store.set_api_key("deepseek", "ds-key-123")

    monkeypatch.setattr(settings, "openai_api_key", "", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "", raising=False)
    monkeypatch.setattr(settings, "gemini_api_key", "", raising=False)
    monkeypatch.setattr(settings, "deepseek_api_key", "", raising=False)
    monkeypatch.setattr(settings, "qwen_api_key", "", raising=False)
    monkeypatch.setattr(settings, "kimi_api_key", "", raising=False)

    provider1, model1, llm1 = _build_cli_llm(
        provider="anthropic",
        model="gpt-5.4-mini",
        secrets_file=secrets_path,
    )
    provider2, model2, llm2 = _build_cli_llm(
        provider="gemini",
        model="gpt-5.4-mini",
        secrets_file=secrets_path,
    )

    assert provider1 == "anthropic"
    assert model1.startswith("claude-")
    assert isinstance(llm1, AnthropicMessagesLLM)
    assert provider2 == "gemini"
    assert model2.startswith("gemini-")
    assert isinstance(llm2, GeminiFunctionCallingLLM)

    provider3, model3, llm3 = _build_cli_llm(
        provider="deepseek",
        model="gpt-5.4-mini",
        secrets_file=secrets_path,
    )
    assert provider3 == "deepseek"
    assert model3 == "deepseek-chat"
    assert isinstance(llm3, OpenAICompatibleFunctionCallingLLM)


def test_build_provider_setup_checks_reports_multiple_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_path = tmp_path / "secrets.json"
    store = SecretStore(secrets_path)
    store.set_api_key("gemini", "gem-key-123")
    store.set_api_key("kimi", "kimi-key-123")

    monkeypatch.setattr(settings, "openai_api_key", "", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "ant-key-456", raising=False)
    monkeypatch.setattr(settings, "gemini_api_key", "", raising=False)
    monkeypatch.setattr(settings, "deepseek_api_key", "", raising=False)
    monkeypatch.setattr(settings, "qwen_api_key", "", raising=False)
    monkeypatch.setattr(settings, "kimi_api_key", "", raising=False)

    checks = _build_provider_setup_checks(secrets_file=secrets_path)
    assert checks["anthropic"]["ok"] is True
    assert "env" in str(checks["anthropic"]["detail"])
    assert checks["gemini"]["ok"] is True
    assert "secrets" in str(checks["gemini"]["detail"])
    assert checks["kimi"]["ok"] is True
    assert checks["openai"]["ok"] is False


def test_detect_fix_and_apply_intent() -> None:
    assert _looks_like_fix_request("请帮我修复支付服务")
    assert _looks_like_fix_request("fix payment service latency")
    assert _looks_like_apply_request("执行修复计划")
    assert _looks_like_apply_request("apply fix")
    assert _looks_like_fix_request("执行修复计划") is False
    assert _looks_like_init_request("请帮我初始化 lazysre")
    assert _looks_like_init_request("我要配置 OpenAI Key")
    assert _looks_like_status_request("帮我看下当前状态")
    assert _looks_like_scan_request("自动检测当前环境并列出问题")
    assert _looks_like_swarm_diagnose_request("看看服务器上的服务有没有异常")
    assert _extract_swarm_service_name("为什么 lazysre_lazysre 服务副本不足") == "lazysre_lazysre"
    assert _looks_like_doctor_request("做一次环境体检")
    assert _looks_like_install_doctor_request("做一下安装检查")
    assert _looks_like_report_request("导出复盘报告")
    assert _looks_like_template_library_request("有哪些修复模板")
    assert _looks_like_quickstart_request("帮我修复环境")
    assert _looks_like_help_request("你会什么")
    assert _looks_like_switch_execute_request("切换到执行模式")
    assert _looks_like_switch_dry_run_request("切回dry-run")
    assert _looks_like_reset_request("我要重置一下")
    assert _looks_like_context_request("你记住了什么")
    assert _looks_like_auto_fix_request("请自动修复 payment 延迟")
    assert _looks_like_undo_request("回滚刚才修复")
    assert _looks_like_logs_action_request("看它日志")
    assert _looks_like_restart_action_request("重启它")
    assert _looks_like_scale_action_request("扩容到3")
    assert _looks_like_approval_queue_request("看审批队列")
    assert _looks_like_with_impact_request("看审批队列并给影响评估")
    assert _looks_like_low_risk_apply_request("只执行低风险步骤")
    assert _looks_like_force_high_risk_apply_request("允许高风险也执行")
    assert _looks_like_read_then_write_strategy_request("先只跑只读步骤再执行写操作")
    assert _looks_like_explain_step_request("解释第2步为什么执行")
    assert _looks_like_target_update_request("把 namespace 设成 prod")
    assert _looks_like_target_show_request("查看目标配置")
    assert _looks_like_target_profile_current_request("看看当前profile")
    assert _looks_like_target_profile_list_request("列出所有profile")
    assert _looks_like_target_profile_remove_request("删除profile prod")
    assert _looks_like_target_profile_export_request("导出profile到 .data/p.json")
    assert _looks_like_target_profile_import_request("从 .data/p.json 导入profile")


def test_normalize_chat_input_text() -> None:
    assert _normalize_slash_command_text("/quikstart") == "/quickstart"
    assert _normalize_slash_command_text("/stauts probe") == "/status probe"
    assert _normalize_natural_language_text("请看模版库") == "请看模板库"
    assert _normalize_chat_input_text("/templete list") == "/template list"
    assert _normalize_chat_input_text("quikstart 一下") == "quickstart 一下"


def test_extract_apply_step_selection() -> None:
    assert _extract_apply_step_selection("执行第1步和第3步") == "1,3"
    assert _extract_apply_step_selection("执行步骤: 1, 3-4, 7 到 8") == "1,3-4,7-8"
    assert _extract_apply_step_selection("apply fix") == ""


def test_extract_step_selection_from_text() -> None:
    assert _extract_step_selection_from_text("解释第2步和第4步") == "2,4"
    assert _extract_step_selection_from_text("讲解步骤: 1, 3-5") == "1,3-5"
    assert _extract_step_selection_from_text("只想知道原因") == ""


def test_extract_target_updates_from_text() -> None:
    payload = _extract_target_updates_from_text(
        "把 prometheus 设成 http://92.168.69.176:9090 ，k8s api 改成 https://192.168.10.1:6443 ，namespace 改成 prod，开启tls校验"
    )
    assert payload["prometheus_url"] == "http://92.168.69.176:9090"
    assert payload["k8s_api_url"] == "https://192.168.10.1:6443"
    assert payload["k8s_namespace"] == "prod"
    assert payload["k8s_verify_tls"] is True


def test_extract_profile_switch_name() -> None:
    assert _extract_profile_switch_name("切到 prod 集群") == "prod"
    assert _extract_profile_switch_name("switch to staging profile") == "staging"
    assert _extract_profile_switch_name("随便聊聊") == ""


def test_extract_profile_save_request() -> None:
    name1, activate1 = _extract_profile_save_request("保存当前为 prod")
    assert name1 == "prod"
    assert activate1 is False
    name2, activate2 = _extract_profile_save_request("保存当前profile为 staging 并切换")
    assert name2 == "staging"
    assert activate2 is True
    name3, activate3 = _extract_profile_save_request("save current profile as qa and activate")
    assert name3 == "qa"
    assert activate3 is True


def test_extract_profile_remove_request() -> None:
    name1, confirmed1 = _extract_profile_remove_request("删除profile prod")
    assert name1 == "prod"
    assert confirmed1 is False
    name2, confirmed2 = _extract_profile_remove_request("确认删除 staging")
    assert name2 == "staging"
    assert confirmed2 is True


def test_extract_profile_export_request() -> None:
    req = _extract_profile_export_request("导出prod profile到 .data/profiles.json")
    assert req["output"] == ".data/profiles.json"
    assert req["names"] == ["prod"]
    req_all = _extract_profile_export_request("导出全部profile")
    assert req_all["names"] == []


def test_extract_profile_import_request() -> None:
    req = _extract_profile_import_request("从 .data/profiles.json 导入profile 并激活@active")
    assert req["input_file"] == ".data/profiles.json"
    assert req["merge"] is True
    assert req["activate"] == "@active"
    req_replace = _extract_profile_import_request("import profiles from /tmp/a.json replace")
    assert req_replace["input_file"] == "/tmp/a.json"
    assert req_replace["merge"] is False


def test_split_fix_plan_read_write_commands() -> None:
    plan = FixPlan(
        apply_commands=[
            "kubectl -n default get pods",
            "kubectl -n default scale deploy/payment --replicas=3",
            "docker ps",
            "docker restart payment-api",
        ],
        rollback_commands=[],
    )
    read_only, writes = _split_fix_plan_read_write_commands(plan, approval_mode="balanced")
    assert "kubectl -n default get pods" in read_only
    assert "docker ps" in read_only
    assert "kubectl -n default scale deploy/payment --replicas=3" in writes
    assert "docker restart payment-api" in writes


def test_extract_template_vars_and_compose_with_session(tmp_path: Path) -> None:
    extracted = _extract_template_var_items_from_text(
        "请一键修复 CrashLoopBackOff namespace=prod pod=pay-7 deploy/payment 副本 4"
    )
    assert "namespace=prod" in extracted
    assert "pod=pay-7" in extracted
    assert "workload=deploy/payment" in extracted
    assert "replicas=4" in extracted

    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "turns": [],
                "entities": {
                    "last_namespace": "ops",
                    "last_service": "payment",
                    "last_pod": "payment-abc-1",
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    merged = _compose_template_var_items(
        "帮我修复 CrashLoopBackOff",
        {"session_file": str(session_file)},
    )
    assert "namespace=ops" in merged
    assert "service=payment" in merged
    assert "pod=payment-abc-1" in merged
    assert "workload=deploy/payment" in merged


def test_extract_requested_replicas() -> None:
    assert _extract_requested_replicas("扩容到3") == 3
    assert _extract_requested_replicas("replicas=5") == 5
    assert _extract_requested_replicas("scale to 7") == 7


def test_build_quick_k8s_action_plan_from_memory(tmp_path: Path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "turns": [],
                "entities": {
                    "last_namespace": "ops",
                    "last_service": "payment",
                    "last_pod": "payment-abc-1",
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    options = {
        "session_file": str(session_file),
        "approval_mode": "balanced",
        "audit_log": str(tmp_path / "audit.jsonl"),
        "model": "gpt-5.4-mini",
        "provider": "mock",
    }
    logs_plan = _build_quick_k8s_action_plan("看它日志", options)
    assert logs_plan is not None
    assert "kubectl -n ops logs payment-abc-1 --tail=200" in logs_plan["commands"]

    restart_plan = _build_quick_k8s_action_plan("重启它", options)
    assert restart_plan is not None
    assert "kubectl -n ops rollout restart deploy/payment" in restart_plan["commands"]

    scale_plan = _build_quick_k8s_action_plan("扩容到4", options)
    assert scale_plan is not None
    assert "kubectl -n ops scale deploy/payment --replicas=4" in scale_plan["commands"]


def test_should_launch_assistant_with_only_options() -> None:
    assert _should_launch_assistant(["--provider", "mock"]) is True
    assert _should_launch_assistant(["--verbose-reasoning"]) is True
    assert _should_launch_assistant([]) is True
    assert _should_launch_assistant(["chat"]) is False
    assert _should_launch_assistant(["init"]) is False
    assert _should_launch_assistant(["quickstart"]) is False
    assert _should_launch_assistant(["reset"]) is False
    assert _should_launch_assistant(["undo"]) is False
    assert _should_launch_assistant(["login"]) is False
    assert _should_launch_assistant(["logout"]) is False
    assert _should_launch_assistant(["status"]) is False
    assert _should_launch_assistant(["scan"]) is False
    assert _should_launch_assistant(["swarm"]) is False
    assert _should_launch_assistant(["doctor"]) is False
    assert _should_launch_assistant(["install-doctor"]) is False
    assert _should_launch_assistant(["setup"]) is False
    assert _should_launch_assistant(["template"]) is False
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


def test_extract_runbook_var_items_from_text() -> None:
    items = _extract_runbook_var_items_from_text(
        "payment 服务 p95 450ms namespace prod",
        allowed_keys={"service", "p95_ms", "namespace", "target_profile"},
    )
    assert "service=payment" in items
    assert "p95_ms=450" in items
    assert "namespace=prod" in items


def test_compose_runbook_var_items_auto_fill(tmp_path: Path, monkeypatch) -> None:
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
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "turns": [],
                "entities": {"last_service": "checkout", "last_namespace": "ops"},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("lazysre.cli.main.ClusterProfileStore.default", lambda: type("X", (), {"get_active": lambda self: "prod"})())
    template = find_runbook("payment-latency-fix")
    assert template is not None
    items = _compose_runbook_var_items(
        template=template,
        text="请排查服务 payment，目标 p95 420ms",
        options={"session_file": str(session_file)},
        base_items=[],
        profile_file=target_file,
    )
    assert "service=payment" in items
    assert "p95_ms=420" in items
    assert "namespace=payments" in items


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


def test_parse_chat_template_command_variants() -> None:
    parsed_list = _parse_chat_template_command("")
    assert parsed_list["action"] == "list"

    parsed_show = _parse_chat_template_command("show k8s-high-cpu")
    assert parsed_show["action"] == "show"
    assert parsed_show["name"] == "k8s-high-cpu"

    parsed_run = _parse_chat_template_command(
        "run k8s-crashloopbackoff --apply --var namespace=prod pod=pay-123 --max-apply-steps 3"
    )
    assert parsed_run["action"] == "run"
    assert parsed_run["name"] == "k8s-crashloopbackoff"
    assert parsed_run["apply"] is True
    assert parsed_run["max_apply_steps"] == 3
    assert "namespace=prod" in parsed_run["var_items"]
    assert "pod=pay-123" in parsed_run["var_items"]


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


def test_collect_environment_discovery_scans_without_k8s_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_which(name: str) -> str:
        if name in {"docker", "kubectl", "curl"}:
            return f"/usr/bin/{name}"
        return ""

    def fake_safe_run(command: list[str], *, timeout_sec: int) -> dict[str, object]:
        tool = Path(command[0]).name
        args = command[1:]
        if tool == "docker" and args[:2] == ["version", "--format"]:
            return {"ok": True, "stdout": "25.0.0", "stderr": "", "exit_code": 0}
        if tool == "docker" and args[:1] == ["info"]:
            return {"ok": True, "stdout": "active", "stderr": "", "exit_code": 0}
        if tool == "docker" and args[:2] == ["ps", "-a"]:
            return {"ok": True, "stdout": "old-api\tExited (1) 2 hours ago", "stderr": "", "exit_code": 0}
        if tool == "docker" and args[:2] == ["service", "ls"]:
            return {"ok": True, "stdout": "lazysre\t1/1\timage:latest", "stderr": "", "exit_code": 0}
        if tool == "kubectl" and args[:2] == ["config", "current-context"]:
            return {"ok": True, "stdout": "prod", "stderr": "", "exit_code": 0}
        if tool == "kubectl" and args[:2] == ["get", "nodes"]:
            return {"ok": True, "stdout": "node/node-1", "stderr": "", "exit_code": 0}
        if tool == "kubectl" and args[:2] == ["get", "pods"]:
            return {
                "ok": True,
                "stdout": "default web 1/1 Running 0 1d\nprod bad 0/1 CrashLoopBackOff 7 5m",
                "stderr": "",
                "exit_code": 0,
            }
        if tool == "kubectl" and args[:2] == ["get", "events"]:
            return {"ok": True, "stdout": "prod 1m Warning BackOff pod/bad", "stderr": "", "exit_code": 0}
        if tool == "curl":
            return {"ok": True, "stdout": "Prometheus Server is Ready.", "stderr": "", "exit_code": 0}
        return {"ok": False, "stdout": "", "stderr": "unexpected", "exit_code": 1}

    monkeypatch.setattr(cli_main.shutil, "which", fake_which)
    monkeypatch.setattr(cli_main, "_safe_run_command", fake_safe_run)
    monkeypatch.setattr(settings, "openai_api_key", "", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "", raising=False)
    monkeypatch.setattr(settings, "gemini_api_key", "", raising=False)
    monkeypatch.setattr(settings, "deepseek_api_key", "", raising=False)
    monkeypatch.setattr(settings, "qwen_api_key", "", raising=False)
    monkeypatch.setattr(settings, "kimi_api_key", "", raising=False)
    monkeypatch.setenv("TARGET_PROMETHEUS_URL", "http://prometheus:9090")

    report = _collect_environment_discovery(timeout_sec=3, secrets_file=tmp_path / "secrets.json")

    assert report["mode"] == "read-only/no-secret"
    assert "docker-swarm" in report["usable_targets"]
    assert "kubernetes" in report["usable_targets"]
    assert "prometheus" in report["usable_targets"]
    names = {str(x.get("name", "")) for x in report["checks"] if isinstance(x, dict)}
    assert "docker.exited_containers" in names
    assert "k8s.problem_pods" in names
    assert "llm.provider_key" in names
    assert any(str(x.get("name")) == "k8s.problem_pods" for x in report["issues"] if isinstance(x, dict))


def test_collect_swarm_health_report_detects_unhealthy_service(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_which(name: str) -> str:
        return "/usr/bin/docker" if name == "docker" else ""

    def fake_safe_run(command: list[str], *, timeout_sec: int) -> dict[str, object]:
        args = command[1:]
        if args[:1] == ["info"]:
            return {"ok": True, "stdout": "active", "stderr": "", "exit_code": 0}
        if args[:2] == ["node", "ls"]:
            return {"ok": True, "stdout": "node-1\tReady\tActive\tLeader", "stderr": "", "exit_code": 0}
        if args[:2] == ["service", "ls"]:
            return {
                "ok": True,
                "stdout": "api\treplicated\t0/1\tapi:latest\nweb\treplicated\t2/2\tweb:latest",
                "stderr": "",
                "exit_code": 0,
            }
        if args[:2] == ["service", "ps"]:
            return {
                "ok": True,
                "stdout": "api.1\tRejected 10 seconds ago\tNo such image: api:latest\tnode-1",
                "stderr": "",
                "exit_code": 0,
            }
        if args[:2] == ["service", "logs"]:
            return {"ok": True, "stdout": "pull failed", "stderr": "", "exit_code": 0}
        return {"ok": False, "stdout": "", "stderr": "unexpected", "exit_code": 1}

    monkeypatch.setattr(cli_main.shutil, "which", fake_which)
    monkeypatch.setattr(cli_main, "_safe_run_command", fake_safe_run)

    report = _collect_swarm_health_report(include_logs=True, timeout_sec=3)

    assert report["ok"] is False
    assert len(report["unhealthy_services"]) == 1
    assert report["unhealthy_services"][0]["name"] == "api"
    assert "No such image" in report["tasks"][0]["tasks"][0]["error"]
    assert report["logs"][0]["service"] == "api"
