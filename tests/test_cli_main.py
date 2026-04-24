import json
import os
import subprocess
import sys
import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

import lazysre.cli.main as cli_main
from lazysre.cli.main import (
    _archive_report_for_git,
    _backup_target_profile,
    _build_cli_llm,
    _build_provider_setup_checks,
    _build_doctor_gate,
    _build_discovery_target_updates,
    _build_environment_drift,
    _build_environment_landscape,
    _build_incident_report_payload,
    _compute_doctor_autofix,
    _collect_runtime_status,
    _collect_environment_discovery,
    _build_environment_scan_briefing,
    _build_overview_briefing,
    _build_overview_recommended_commands,
    _collect_swarm_health_report,
    _collect_remote_docker_report,
    _remote_shell_command,
    _normalize_ssh_target,
    _resolve_ssh_target_arg,
    _remote_report_check_ok,
    _build_remote_briefing,
    _run_remote_connect_flow,
    _collect_watch_snapshot,
    _run_autopilot_cycle,
    _run_remote_autopilot_cycle,
    _build_autopilot_report,
    _build_remote_autopilot_report,
    _render_autopilot_report_markdown,
    _build_action_inbox_from_watch,
    _find_action_inbox_item,
    _run_action_command,
    _render_watch_report_markdown,
    _render_action_inbox_markdown,
    _build_latest_watch_context,
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
    _looks_like_shell_command,
    _extract_named_field,
    _compose_template_var_items,
    _compose_runbook_var_items,
    _build_quick_k8s_action_plan,
    _extract_requested_replicas,
    _normalize_chat_input_text,
    _normalize_natural_language_text,
    _normalize_slash_command_text,
    _rewrite_simple_quick_phrase_to_command,
    _render_unknown_slash_command_message,
    _suggest_unknown_slash_command,
    _bootstrap_chat_input_history,
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
    _looks_like_preflight_request,
    _looks_like_low_risk_apply_request,
    _looks_like_quickstart_request,
    _looks_like_reset_request,
    _looks_like_scan_request,
    _looks_like_swarm_diagnose_request,
    _looks_like_remote_diagnose_request,
    _looks_like_remote_connect_request,
    _looks_like_watch_request,
    _looks_like_actions_request,
    _looks_like_action_run_request,
    _looks_like_autopilot_request,
    _looks_like_report_request,
    _looks_like_brief_request,
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
    _extract_ssh_target_from_text,
    _looks_like_latest_watch_reference,
    _looks_like_template_library_request,
    _looks_like_with_impact_request,
    _extract_action_id_from_text,
    _split_fix_plan_read_write_commands,
    _parse_step_selection,
    _read_last_fix_plan_summary,
    _read_last_incident_session_summary,
    _render_incident_report_markdown,
    _rewrite_argv_for_default_run,
    _summarize_doctor_checks,
    _should_launch_default_tui,
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
    _write_first_scan_marker,
    _render_cached_startup_brief,
    _load_tui_runtime_state,
    _save_tui_runtime_state,
    _apply_saved_tui_runtime_state,
    _version_info,
    _version_text,
    _build_tui_dashboard_snapshot,
    _render_tui_demo_text,
    _render_recent_activity_text,
    _render_focus_text,
    _render_environment_drift_text,
    _render_quick_actions_text,
    _render_trace_text,
    _render_timeline_text,
    _build_tui_footer_line,
    _truncate_tui_status_text,
    _build_tui_action_bar,
    _build_tui_help_overlay_lines,
    _build_tui_idle_content_rows,
    _build_tui_panel_hint,
    _build_tui_status_hint_line,
    _build_tui_panel_counts,
    _render_tui_quick_help_text,
    _build_tui_focus_card,
    _build_tui_prompt_line_and_cursor,
    _build_tui_compact_action_bar,
    _build_tui_compact_sidebar_lines,
    _build_tui_start_coach,
    _build_tui_boot_actions,
    _format_tui_output_for_display,
    _normalize_tui_ui_mode,
    _toggle_tui_ui_mode,
    _pick_tui_next_command,
    _maybe_apply_runtime_provider_fallback,
    _maybe_apply_tui_provider_fallback,
    _parse_tui_escape_sequence,
    _normalize_tui_key_alias,
    _render_tui_completion_card,
    _render_tui_simple_result_card,
    _render_tui_success_card,
    _resolve_tui_boot_action_command,
    _looks_like_ordinal_shortcut,
    _resolve_tui_numeric_shortcut_command,
    _sanitize_tui_secret_tokens,
    _should_auto_fallback_to_mock,
    _build_tui_starter_prompts,
    _build_recent_trace_summary,
    _infer_trace_stage,
    _build_tui_panel_tabs,
    _build_tui_sidebar_lines,
    _tui_welcome_message,
    _collect_snapshot_recent_commands,
    _render_history_text,
    _resolve_tui_empty_submit_command,
    _maybe_auto_bootstrap_for_tui,
    _normalize_runtime_exception_message,
    _normalize_tui_panel_name,
    _switch_tui_panel,
    _cycle_tui_completion,
    _cycle_tui_input_history,
    _merge_tui_input_history,
    _load_tui_input_history,
    _save_tui_input_history,
    _delete_tui_word_left,
    _apply_tui_ctrl_edit_key,
    _build_tui_bootstrap_input_history,
    _build_provider_runtime_report,
    _switch_runtime_provider,
    _tui_completion_candidates,
    _tui_text_display_width,
    _handle_incident_inline_command,
    _handle_tui_input,
    _classify_quick_action_confidence,
    _derive_closed_loop_plan,
    _infer_verification_commands,
    _looks_like_remediate_request,
    _render_closed_loop_report_markdown,
    _run_closed_loop_execution,
    _safe_run_ssh_command,
    _safe_run_command,
    _safe_int,
    _should_launch_assistant,
)
from lazysre.cli.llm import (
    AnthropicMessagesLLM,
    GeminiFunctionCallingLLM,
    OpenAICompatibleFunctionCallingLLM,
)
from lazysre.cli.fix_mode import FixPlan
from lazysre.cli.policy import assess_command
from lazysre.cli.runbook import find_runbook
from lazysre.cli.secrets import SecretStore
from lazysre.cli.target import TargetEnvironment, TargetEnvStore
from lazysre.cli.types import DispatchResult
from lazysre.config import settings


def test_rewrite_argv_default_run_simple_instruction() -> None:
    argv = ["lsre", "检查", "k8s"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "run", "检查", "k8s"]


def test_rewrite_argv_preserves_subcommand() -> None:
    argv = ["lsre", "pack", "list", "--index", "idx.json"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "pack", "list", "--index", "idx.json"]


def test_rewrite_argv_preserves_incident_subcommand() -> None:
    argv = ["lsre", "incident", "status"]
    _rewrite_argv_for_default_run(argv)
    assert argv == ["lsre", "incident", "status"]


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
    argv6 = ["lsre", "watch", "--count", "1"]
    _rewrite_argv_for_default_run(argv6)
    assert argv6 == ["lsre", "watch", "--count", "1"]
    argv7 = ["lsre", "setup", "--json"]
    _rewrite_argv_for_default_run(argv7)
    assert argv7 == ["lsre", "setup", "--json"]
    argv8 = ["lsre", "template", "list"]
    _rewrite_argv_for_default_run(argv8)
    assert argv8 == ["lsre", "template", "list"]
    argv9 = ["lsre", "init"]
    _rewrite_argv_for_default_run(argv9)
    assert argv9 == ["lsre", "init"]
    argv10 = ["lsre", "login", "--api-key", "sk-xxx"]
    _rewrite_argv_for_default_run(argv10)
    assert argv10 == ["lsre", "login", "--api-key", "sk-xxx"]
    argv11 = ["lsre", "quickstart", "--json"]
    _rewrite_argv_for_default_run(argv11)
    assert argv11 == ["lsre", "quickstart", "--json"]
    argv12 = ["lsre", "reset"]
    _rewrite_argv_for_default_run(argv12)
    assert argv12 == ["lsre", "reset"]
    argv13 = ["lsre", "undo"]
    _rewrite_argv_for_default_run(argv13)
    assert argv13 == ["lsre", "undo"]
    argv14 = ["lsre", "actions", "--json"]
    _rewrite_argv_for_default_run(argv14)
    assert argv14 == ["lsre", "actions", "--json"]
    argv15 = ["lsre", "autopilot", "--json"]
    _rewrite_argv_for_default_run(argv15)
    assert argv15 == ["lsre", "autopilot", "--json"]
    argv16 = ["lsre", "remote", "root@192.168.10.101", "--json"]
    _rewrite_argv_for_default_run(argv16)
    assert argv16 == ["lsre", "remote", "root@192.168.10.101", "--json"]
    argv17 = ["lsre", "connect", "root@192.168.10.101"]
    _rewrite_argv_for_default_run(argv17)
    assert argv17 == ["lsre", "connect", "root@192.168.10.101"]
    argv18 = ["lsre", "brief", "--json"]
    _rewrite_argv_for_default_run(argv18)
    assert argv18 == ["lsre", "brief", "--json"]
    argv19 = ["lsre", "version"]
    _rewrite_argv_for_default_run(argv19)
    assert argv19 == ["lsre", "version"]
    argv20 = ["lsre", "--version"]
    _rewrite_argv_for_default_run(argv20)
    assert argv20 == ["lsre", "--version"]
    argv21 = ["lsre", "tui", "--demo"]
    _rewrite_argv_for_default_run(argv21)
    assert argv21 == ["lsre", "tui", "--demo"]
    argv22 = ["lsre", "remediate", "swarm 副本不足", "--json"]
    _rewrite_argv_for_default_run(argv22)
    assert argv22 == ["lsre", "remediate", "swarm 副本不足", "--json"]
    argv23 = ["lsre", "secret-scan", "--staged", "--json"]
    _rewrite_argv_for_default_run(argv23)
    assert argv23 == ["lsre", "secret-scan", "--staged", "--json"]
    argv24 = ["lsre", "preflight", "--strict", "--json"]
    _rewrite_argv_for_default_run(argv24)
    assert argv24 == ["lsre", "preflight", "--strict", "--json"]


def test_secret_store_supports_multiple_provider_keys(tmp_path: Path) -> None:
    store = SecretStore(tmp_path / "secrets.json")
    store.set_api_key("anthropic", "sk-ant-1234567890")
    store.set_api_key("gemini", "gem-key-1234567890")
    store.set_provider_base_url("compatible", "https://oneapi.example.com/v1")
    store.set_provider_model("compatible", "gpt-4o-mini")

    assert store.get_api_key("anthropic") == "sk-ant-1234567890"
    assert store.get_api_key("gemini") == "gem-key-1234567890"
    assert store.masked_api_key("anthropic").startswith("sk-a")
    assert store.get_provider_base_url("compatible") == "https://oneapi.example.com/v1"
    assert store.get_provider_model("compatible") == "gpt-4o-mini"
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
    store.set_api_key("compatible", "compat-key-123")
    store.set_provider_base_url("compatible", "https://oneapi.example.com/v1")
    store.set_provider_model("compatible", "gpt-4o-mini")

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

    provider4, model4, llm4 = _build_cli_llm(
        provider="compatible",
        model="gpt-5.4-mini",
        secrets_file=secrets_path,
    )
    assert provider4 == "compatible"
    assert model4 == "gpt-4o-mini"
    assert isinstance(llm4, OpenAICompatibleFunctionCallingLLM)


def test_build_provider_setup_checks_reports_multiple_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_path = tmp_path / "secrets.json"
    store = SecretStore(secrets_path)
    store.set_api_key("gemini", "gem-key-123")
    store.set_api_key("kimi", "kimi-key-123")
    store.set_api_key("compatible", "compat-key-123")
    store.set_provider_base_url("compatible", "https://oneapi.example.com/v1")
    store.set_provider_model("compatible", "gpt-4o-mini")

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
    assert checks["compatible"]["ok"] is True
    assert "base_url=https://oneapi.example.com/v1" in str(checks["compatible"]["detail"])
    assert "model=gpt-4o-mini" in str(checks["compatible"]["detail"])
    assert checks["openai"]["ok"] is False


def test_build_provider_setup_checks_marks_compatible_missing_base_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_path = tmp_path / "secrets.json"
    store = SecretStore(secrets_path)
    store.set_api_key("compatible", "compat-key-123")

    monkeypatch.setattr(settings, "openai_api_key", "", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "", raising=False)
    monkeypatch.setattr(settings, "gemini_api_key", "", raising=False)
    monkeypatch.setattr(settings, "deepseek_api_key", "", raising=False)
    monkeypatch.setattr(settings, "qwen_api_key", "", raising=False)
    monkeypatch.setattr(settings, "kimi_api_key", "", raising=False)

    checks = _build_provider_setup_checks(secrets_file=secrets_path)

    assert checks["compatible"]["ok"] is False
    assert "缺少 base_url" in str(checks["compatible"]["hint"])


def test_build_provider_runtime_report_and_switch_provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_path = tmp_path / "secrets.json"
    store = SecretStore(secrets_path)
    store.set_api_key("compatible", "compat-key-123")
    store.set_provider_base_url("compatible", "https://oneapi.example.com/v1")
    store.set_provider_model("compatible", "gpt-4o-mini")

    monkeypatch.setattr(settings, "openai_api_key", "", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "", raising=False)
    monkeypatch.setattr(settings, "gemini_api_key", "", raising=False)
    monkeypatch.setattr(settings, "deepseek_api_key", "", raising=False)
    monkeypatch.setattr(settings, "qwen_api_key", "", raising=False)
    monkeypatch.setattr(settings, "kimi_api_key", "", raising=False)

    report = _build_provider_runtime_report(
        {"provider": "auto", "model": "gpt-5.4-mini"},
        secrets_file=secrets_path,
    )

    assert report["active_provider"] == "compatible"
    assert report["resolved_model"] == "gpt-4o-mini"
    assert report["active_ready"] is True

    options = {"provider": "auto", "model": "gpt-5.4-mini"}
    message = _switch_runtime_provider(options, "compatible", secrets_file=secrets_path)
    assert "已切换 Provider" in message
    assert options["provider"] == "compatible"
    assert options["model"] == "gpt-4o-mini"


def test_switch_runtime_provider_rejects_unready_provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets_path = tmp_path / "secrets.json"
    store = SecretStore(secrets_path)
    store.set_api_key("compatible", "compat-key-123")

    monkeypatch.setattr(settings, "openai_api_key", "", raising=False)
    monkeypatch.setattr(settings, "anthropic_api_key", "", raising=False)
    monkeypatch.setattr(settings, "gemini_api_key", "", raising=False)
    monkeypatch.setattr(settings, "deepseek_api_key", "", raising=False)
    monkeypatch.setattr(settings, "qwen_api_key", "", raising=False)
    monkeypatch.setattr(settings, "kimi_api_key", "", raising=False)

    options = {"provider": "auto", "model": "gpt-5.4-mini"}
    message = _switch_runtime_provider(options, "compatible", secrets_file=secrets_path)

    assert "尚未就绪" in message
    assert options["provider"] == "auto"


def test_build_provider_runtime_report_marks_mock_ready() -> None:
    report = _build_provider_runtime_report({"provider": "mock", "model": "gpt-5.4-mini"})
    assert report["active_provider"] == "mock"
    assert report["active_ready"] is True
    assert "无需 API Key" in str(report["active_detail"])


def test_detect_fix_and_apply_intent() -> None:
    assert _looks_like_fix_request("请帮我修复支付服务")
    assert _looks_like_fix_request("fix payment service latency")
    assert _looks_like_apply_request("执行修复计划")
    assert _looks_like_apply_request("apply fix")
    assert _looks_like_fix_request("执行修复计划") is False
    assert _looks_like_init_request("请帮我初始化 lazysre")
    assert _looks_like_init_request("我要配置 OpenAI Key")
    assert _looks_like_status_request("帮我看下当前状态")
    assert _looks_like_brief_request("给我一个总览简报")
    assert _looks_like_scan_request("自动检测当前环境并列出问题")
    assert _looks_like_swarm_diagnose_request("看看服务器上的服务有没有异常")
    assert _looks_like_remote_diagnose_request("远程诊断 root@192.168.10.101 的 docker swarm")
    assert _looks_like_remote_connect_request("连接服务器 root@192.168.10.101")
    assert _looks_like_remote_connect_request("connect root@192.168.10.101")
    assert _looks_like_remote_connect_request("connect prometheus") is False
    assert _extract_ssh_target_from_text("请 ssh root@192.168.10.101 看看") == "root@192.168.10.101"
    assert _looks_like_target_update_request("把远程服务器设成 root@192.168.10.101")
    assert _looks_like_watch_request("开始巡检一下")
    assert _looks_like_actions_request("巡检之后下一步做什么")
    assert _looks_like_actions_request("给我推荐动作")
    assert _looks_like_action_run_request("执行第1个建议")
    assert _extract_action_id_from_text("执行第12个动作") == 12
    assert _extract_action_id_from_text("执行第一步建议") == 1
    assert _extract_action_id_from_text("运行③号动作") == 3
    assert _extract_action_id_from_text("apply action #2") == 2
    assert _looks_like_autopilot_request("帮我自动驾驶排查一下")
    assert _looks_like_autopilot_request("一键巡检并诊断")
    assert _looks_like_latest_watch_reference("修复巡检发现的问题")
    assert _extract_swarm_service_name("为什么 lazysre_lazysre 服务副本不足") == "lazysre_lazysre"
    assert _looks_like_doctor_request("做一次环境体检")
    assert _looks_like_install_doctor_request("做一下安装检查")
    assert _looks_like_preflight_request("上线前检查一下")
    assert _looks_like_preflight_request("run preflight check")
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
    assert _normalize_slash_command_text("/conect root@192.168.10.101") == "/connect root@192.168.10.101"
    assert _normalize_slash_command_text("/brif") == "/brief"
    assert _normalize_slash_command_text("/hist") == "/history"
    assert _normalize_slash_command_text("/rt") == "/retry"
    assert _normalize_natural_language_text("请看模版库") == "请看模板库"
    assert _normalize_natural_language_text("conect root@192.168.10.101") == "connect root@192.168.10.101"
    assert _normalize_natural_language_text("brif") == "brief"
    assert _normalize_chat_input_text("/templete list") == "/template list"
    assert _normalize_chat_input_text("quikstart 一下") == "/quickstart 一下"
    assert _normalize_chat_input_text("do 1") == "/do 1"
    assert _normalize_chat_input_text("go 2") == "/go 2"
    assert _normalize_chat_input_text("history 第二条") == "/history 第二条"
    assert _normalize_chat_input_text("provider mock") == "/provider mock"
    assert _normalize_chat_input_text("ui expert") == "/ui expert"
    assert _normalize_chat_input_text("help full") == "/help full"
    assert _normalize_chat_input_text("provders") == "/providers"
    assert _normalize_chat_input_text("pannel next") == "/panel next"
    assert _normalize_chat_input_text("secretcheck") == "/secret-scan"
    assert _normalize_chat_input_text("secret scan") == "/secret-scan"
    assert _normalize_chat_input_text("/secret scan") == "/secret-scan"
    assert _normalize_chat_input_text("preflight") == "/preflight"
    assert _normalize_chat_input_text("/preflght --strict") == "/preflight --strict"
    assert _normalize_chat_input_text("help me check this") == "help me check this"


def test_safe_int_accepts_flexible_ordinal_tokens() -> None:
    assert _safe_int("1") == 1
    assert _safe_int("#2") == 2
    assert _safe_int("no.3") == 3
    assert _safe_int("第4步") == 4
    assert _safe_int("第一步") == 1
    assert _safe_int("第十二条") == 12
    assert _safe_int("③") == 3
    assert _safe_int("❿") == 10
    assert _safe_int("检查一下") == 0


def test_rewrite_simple_quick_phrase_to_command() -> None:
    assert _rewrite_simple_quick_phrase_to_command("继续") == "/next"
    assert _rewrite_simple_quick_phrase_to_command("继续完善") == "/next"
    assert _rewrite_simple_quick_phrase_to_command("继续排查一下") == "/next"
    assert _rewrite_simple_quick_phrase_to_command("历史") == "/history"
    assert _rewrite_simple_quick_phrase_to_command("看历史") == "/history"
    assert _rewrite_simple_quick_phrase_to_command("重试") == "/retry"
    assert _rewrite_simple_quick_phrase_to_command("再试一下") == "/retry"
    assert _rewrite_simple_quick_phrase_to_command("帮助") == "/help"
    assert _rewrite_simple_quick_phrase_to_command("命令怎么用") == "/help"
    assert _rewrite_simple_quick_phrase_to_command("环境扫描") == "/scan"
    assert _rewrite_simple_quick_phrase_to_command("先扫描一下") == "/scan"
    assert _rewrite_simple_quick_phrase_to_command("简报") == "/brief"
    assert _rewrite_simple_quick_phrase_to_command("总览一下") == "/brief"
    assert _rewrite_simple_quick_phrase_to_command("执行轨迹看看") == "/trace"
    assert _rewrite_simple_quick_phrase_to_command("时间线") == "/timeline"
    assert _rewrite_simple_quick_phrase_to_command("provider状态") == "/providers"
    assert _rewrite_simple_quick_phrase_to_command("体检一下") == "/doctor"
    assert _rewrite_simple_quick_phrase_to_command("安装检查") == "/doctor install"
    assert _rewrite_simple_quick_phrase_to_command("发布前检查") == "/preflight"
    assert _rewrite_simple_quick_phrase_to_command("上线前检查一下") == "/preflight"
    assert _rewrite_simple_quick_phrase_to_command("密钥检查") == "/secret-scan"
    assert _rewrite_simple_quick_phrase_to_command("暂存区泄漏检查") == "/secret-scan --staged"
    assert _rewrite_simple_quick_phrase_to_command("/history") == ""


def test_suggest_unknown_slash_command() -> None:
    suggestion = _suggest_unknown_slash_command("/provders")
    assert suggestion in {"/providers", "/provider"}


def test_render_unknown_slash_command_message_contains_help() -> None:
    msg = _render_unknown_slash_command_message("/foobar")
    assert "未知命令" in msg
    assert "/help" in msg


def test_bootstrap_chat_input_history_reads_session_file(tmp_path: Path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "turns": [
                    {"user": "检查 swarm", "assistant": "ok"},
                    {"user": "ALL_PROXY=socks5://u:p@example.com:1080", "assistant": "ok"},
                    {"user": "检查 swarm", "assistant": "dup"},
                ],
                "entities": {},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    rows = _bootstrap_chat_input_history({"session_file": str(session_file)}, limit=10)
    assert "检查 swarm" in rows
    assert any("://***:***@" in item for item in rows)
    assert rows.count("检查 swarm") == 1


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
        "把 prometheus 设成 http://92.168.69.176:9090 ，k8s api 改成 https://192.168.10.1:6443 ，namespace 改成 prod，把远程服务器设成 root@192.168.10.101，开启tls校验"
    )
    assert payload["prometheus_url"] == "http://92.168.69.176:9090"
    assert payload["k8s_api_url"] == "https://192.168.10.1:6443"
    assert payload["k8s_namespace"] == "prod"
    assert payload["ssh_target"] == "root@192.168.10.101"
    assert payload["k8s_verify_tls"] is True
    assert "ssh_target" not in _extract_target_updates_from_text("远程诊断 root@192.168.10.101 的 docker swarm")


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


def test_should_launch_default_tui_with_only_options() -> None:
    assert _should_launch_default_tui(["--provider", "mock"]) is True
    assert _should_launch_default_tui(["--verbose-reasoning"]) is True
    assert _should_launch_default_tui([]) is True
    assert _should_launch_default_tui(["chat"]) is False
    assert _should_launch_default_tui(["init"]) is False
    assert _should_launch_default_tui(["quickstart"]) is False
    assert _should_launch_default_tui(["reset"]) is False
    assert _should_launch_default_tui(["undo"]) is False
    assert _should_launch_default_tui(["login"]) is False
    assert _should_launch_default_tui(["logout"]) is False
    assert _should_launch_default_tui(["status"]) is False
    assert _should_launch_default_tui(["brief"]) is False
    assert _should_launch_default_tui(["scan"]) is False
    assert _should_launch_default_tui(["swarm"]) is False
    assert _should_launch_default_tui(["watch"]) is False
    assert _should_launch_default_tui(["actions"]) is False
    assert _should_launch_default_tui(["autopilot"]) is False
    assert _should_launch_default_tui(["remediate"]) is False
    assert _should_launch_default_tui(["tui"]) is False
    assert _should_launch_default_tui(["connect"]) is False
    assert _should_launch_default_tui(["remote"]) is False
    assert _should_launch_default_tui(["doctor"]) is False
    assert _should_launch_default_tui(["install-doctor"]) is False
    assert _should_launch_default_tui(["preflight"]) is False
    assert _should_launch_default_tui(["secret-scan"]) is False
    assert _should_launch_default_tui(["setup"]) is False
    assert _should_launch_default_tui(["template"]) is False
    assert _should_launch_default_tui(["report"]) is False
    assert _should_launch_default_tui(["incident"]) is False
    assert _should_launch_default_tui(["runbook"]) is False
    assert _should_launch_default_tui(["approve"]) is False
    assert _should_launch_default_tui(["memory"]) is False
    assert _should_launch_default_tui(["version"]) is False
    assert _should_launch_default_tui(["--version"]) is False
    assert _should_launch_default_tui(["检查k8s"]) is False


def test_should_launch_assistant_is_no_longer_default_surface() -> None:
    assert _should_launch_assistant(["--provider", "mock"]) is False
    assert _should_launch_assistant(["--verbose-reasoning"]) is False
    assert _should_launch_assistant([]) is False
    assert _should_launch_assistant(["chat"]) is False
    assert _should_launch_assistant(["init"]) is False
    assert _should_launch_assistant(["quickstart"]) is False
    assert _should_launch_assistant(["reset"]) is False
    assert _should_launch_assistant(["undo"]) is False
    assert _should_launch_assistant(["login"]) is False
    assert _should_launch_assistant(["logout"]) is False
    assert _should_launch_assistant(["status"]) is False
    assert _should_launch_assistant(["brief"]) is False
    assert _should_launch_assistant(["scan"]) is False
    assert _should_launch_assistant(["swarm"]) is False
    assert _should_launch_assistant(["watch"]) is False
    assert _should_launch_assistant(["actions"]) is False
    assert _should_launch_assistant(["autopilot"]) is False
    assert _should_launch_assistant(["remediate"]) is False
    assert _should_launch_assistant(["tui"]) is False
    assert _should_launch_assistant(["connect"]) is False
    assert _should_launch_assistant(["remote"]) is False
    assert _should_launch_assistant(["doctor"]) is False
    assert _should_launch_assistant(["install-doctor"]) is False
    assert _should_launch_assistant(["preflight"]) is False
    assert _should_launch_assistant(["secret-scan"]) is False
    assert _should_launch_assistant(["setup"]) is False
    assert _should_launch_assistant(["template"]) is False
    assert _should_launch_assistant(["report"]) is False
    assert _should_launch_assistant(["incident"]) is False
    assert _should_launch_assistant(["runbook"]) is False
    assert _should_launch_assistant(["approve"]) is False
    assert _should_launch_assistant(["memory"]) is False
    assert _should_launch_assistant(["version"]) is False
    assert _should_launch_assistant(["--version"]) is False
    assert _should_launch_assistant(["检查k8s"]) is False


def test_version_info_and_cli_version_output() -> None:
    info = _version_info()
    assert info["name"] == "lazysre"
    assert isinstance(info["version"], str)
    assert _version_text(info).startswith(f"lazysre {info['version']}")

    env = {**os.environ, "PYTHONPATH": str(Path.cwd() / "src")}
    result = subprocess.run(
        [sys.executable, "-m", "lazysre", "--version"],
        cwd=Path.cwd(),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "lazysre" in result.stdout
    assert str(info["version"]) in result.stdout


def test_tui_demo_snapshot_contains_operational_shortcuts() -> None:
    snapshot = _build_tui_dashboard_snapshot(
        {"execute": False, "provider": "mock", "model": "test-model", "audit_log": "missing.jsonl"}
    )
    rendered = _render_tui_demo_text(snapshot)

    assert "LazySRE Console" in rendered
    assert "Overview" in rendered
    assert "◉ LazySRE" in rendered
    assert "AI Operations Console" in rendered
    assert "Provider  mock" in rendered
    assert "/connect <user>@<host>" in rendered
    assert "/remote --logs" in rendered
    assert "/scan" in rendered
    assert "/trace" in rendered
    assert "/timeline" in rendered
    assert "Signals" in rendered
    assert "Next Actions" in rendered
    assert "Shortcuts" in rendered
    assert "Ask" in rendered
    assert "默认只读" in rendered


def test_tui_demo_snapshot_renders_incident_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)
    (tmp_path / "lsre-remediation-last.json").write_text(
        json.dumps(
            {
                "generated_at_utc": "2026-04-10T08:05:00+00:00",
                "objective": "恢复 payment 副本",
                "mode": "execute",
                "ok": True,
                "next_step": "继续观察一个 watch 周期。",
                "execution": {
                    "diagnose": {"executed": 1, "succeeded": 1, "failed": 0},
                    "apply": {"executed": 1, "succeeded": 1, "failed": 0},
                    "verify": {"executed": 1, "succeeded": 1, "failed": 0},
                    "rollback": {"executed": 0, "succeeded": 0, "failed": 0},
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    rendered = _render_tui_demo_text(
        _build_tui_dashboard_snapshot(
            {"execute": False, "provider": "mock", "model": "test-model", "audit_log": str(tmp_path / "audit.jsonl")}
        )
    )

    assert "Incident Session" in rendered
    assert "恢复 payment 副本" in rendered
    assert "diagnose:1/1 ok -> apply:1/1 ok -> verify:1/1 ok" in rendered


def test_natural_language_remediate_detection() -> None:
    assert _looks_like_remediate_request("闭环修复 swarm 副本不足")
    assert _looks_like_remediate_request("修复并验证 payment")
    assert _looks_like_remediate_request("失败自动回滚")
    assert not _looks_like_remediate_request("普通查看状态")


def test_closed_loop_template_plan_infers_verify_commands() -> None:
    plan = _derive_closed_loop_plan(
        objective="swarm 副本不足",
        observation={
            "action_inbox": {
                "actions": [
                    {
                        "template": "swarm-replicas-unhealthy",
                        "variables": {"service": "api", "tail": "50"},
                    }
                ]
            }
        },
        from_last_plan=False,
    )

    assert plan["source"] == "template"
    assert plan["template"] == "swarm-replicas-unhealthy"
    assert "docker service update --force api" in plan["apply_commands"]
    assert "docker service rollback api" in plan["rollback_commands"]
    assert any("docker service ps api" in cmd for cmd in plan["verify_commands"])


def test_closed_loop_report_markdown_includes_commands() -> None:
    markdown = _render_closed_loop_report_markdown(
        {
            "generated_at_utc": "2026-04-09T00:00:00Z",
            "objective": "repair api",
            "mode": "dry-run",
            "ok": False,
            "next_step": "review",
            "observation": {"source": "autopilot", "status": "needs_attention", "summary": {"actions": 1}},
            "plan": {
                "source": "template",
                "template": "swarm-replicas-unhealthy",
                "diagnose_commands": ["docker service ps api --no-trunc"],
                "apply_commands": ["docker service update --force api"],
                "verify_commands": ["docker service ps api --no-trunc"],
                "rollback_commands": ["docker service rollback api"],
            },
            "execution": {
                "diagnose": {"executed": 1, "succeeded": 1, "failed": 0},
                "apply": {"executed": 0, "succeeded": 0, "failed": 0},
                "verify": {"executed": 1, "succeeded": 1, "failed": 0},
                "rollback": {"executed": 0, "succeeded": 0, "failed": 0},
            },
        }
    )

    assert "Closed-loop Remediation Report" in markdown
    assert "docker service update --force api" in markdown
    assert "docker service rollback api" in markdown


def test_closed_loop_report_markdown_includes_remote_target() -> None:
    markdown = _render_closed_loop_report_markdown(
        {
            "generated_at_utc": "2026-04-09T00:00:00Z",
            "objective": "repair remote api",
            "mode": "execute",
            "remote_target": "root@192.168.10.101",
            "ok": True,
            "next_step": "watch",
            "observation": {},
            "plan": {},
            "execution": {},
        }
    )

    assert "Remote Target: `root@192.168.10.101`" in markdown


def test_remote_closed_loop_execution_uses_ssh_for_all_stages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str]] = []

    def fake_ssh(target: str, remote_command: str, *, timeout_sec: int) -> dict[str, object]:
        calls.append((target, remote_command))
        return {"ok": True, "stdout": "ok", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(cli_main, "_safe_run_ssh_command", fake_ssh)
    monkeypatch.setattr(cli_main, "_generate_impact_statement", lambda **_: "impact")
    monkeypatch.setattr(cli_main.typer, "confirm", lambda *_, **__: True)

    result = _run_closed_loop_execution(
        diagnose_commands=["docker service ps api --no-trunc"],
        plan=FixPlan(
            apply_commands=["docker service update --force api"],
            rollback_commands=["docker service rollback api"],
        ),
        verify_commands=["docker service ps api --no-trunc"],
        apply=True,
        verify=True,
        rollback_on_failure=False,
        max_apply_steps=3,
        execute=True,
        approval_mode="balanced",
        audit_log=str(tmp_path / "audit.jsonl"),
        allow_high_risk=True,
        auto_approve_low_risk=True,
        model="mock",
        provider="mock",
        remote_target="root@192.168.10.101",
    )

    assert result["ok"] is True
    assert result["diagnose"]["executed"] == 1
    assert result["apply"]["executed"] == 1
    assert result["verify"]["executed"] == 1
    assert calls == [
        ("root@192.168.10.101", "docker service ps api --no-trunc"),
        ("root@192.168.10.101", "docker service update --force api"),
        ("root@192.168.10.101", "docker service ps api --no-trunc"),
    ]


def test_safe_run_ssh_command_ignores_user_config_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_run(command: list[str], *, timeout_sec: int) -> dict[str, object]:
        seen.append(command)
        return {"ok": True, "stdout": "ok", "stderr": "", "exit_code": 0}

    monkeypatch.delenv("LAZYSRE_SSH_CONFIG", raising=False)
    monkeypatch.setattr(cli_main, "_safe_run_command", fake_run)

    result = _safe_run_ssh_command("root@192.168.10.101", "docker version", timeout_sec=3)

    assert result["ok"] is True
    assert seen
    assert seen[0][0:3] == ["ssh", "-F", "/dev/null"]


def test_safe_run_ssh_command_can_use_default_user_config(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_run(command: list[str], *, timeout_sec: int) -> dict[str, object]:
        seen.append(command)
        return {"ok": True, "stdout": "ok", "stderr": "", "exit_code": 0}

    monkeypatch.setenv("LAZYSRE_SSH_CONFIG", "default")
    monkeypatch.setattr(cli_main, "_safe_run_command", fake_run)

    _safe_run_ssh_command("root@192.168.10.101", "docker version", timeout_sec=3)

    assert seen
    assert "-F" not in seen[0]


def test_infer_verification_commands_for_k8s_and_swarm() -> None:
    plan = FixPlan(
        apply_commands=[
            "kubectl -n prod rollout restart deploy/payment",
            "docker service update --force api",
        ],
        rollback_commands=[],
    )

    commands = _infer_verification_commands(plan)
    assert "kubectl get pods -A --field-selector=status.phase!=Running" in commands
    assert "docker service ps api --no-trunc" in commands


def test_docker_service_mutations_are_not_read_only() -> None:
    assert assess_command(["docker", "service", "ps", "api"]).risk_level == "low"
    assert assess_command(["docker", "service", "logs", "api"]).risk_level == "low"
    assert assess_command(["docker", "service", "update", "--force", "api"]).risk_level == "high"
    assert assess_command(["docker", "service", "rollback", "api"]).risk_level == "high"


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


def test_looks_like_shell_command_supports_sudo_prefix() -> None:
    assert _looks_like_shell_command("sudo docker service ls")
    assert _looks_like_shell_command("sudo kubectl get pods -A")
    assert not _looks_like_shell_command("sudo 删除服务")


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
    monkeypatch.setattr(settings, "target_prometheus_url", "", raising=False)
    monkeypatch.setattr(settings, "target_k8s_api_url", "", raising=False)
    monkeypatch.setattr(
        "lazysre.cli.main._detect_kubectl_current_context",
        lambda: "autofix-context",
    )
    monkeypatch.setattr(
        "lazysre.cli.main._detect_kubectl_server",
        lambda: "https://10.0.0.1:6443",
    )
    monkeypatch.setattr(
        "lazysre.cli.main._detect_kubectl_default_namespace",
        lambda: "prod",
    )
    monkeypatch.setattr(
        "lazysre.cli.main._detect_prometheus_ready_url",
        lambda: "http://prometheus:9090",
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
    assert updates.get("k8s_namespace") == "prod"
    assert updates.get("prometheus_url") == "http://prometheus:9090"
    assert updates.get("k8s_api_url") == "https://10.0.0.1:6443"
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
                "ssh_target": "root@192.168.10.101",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("lazysre.cli.main.ClusterProfileStore.default", lambda: type("X", (), {"get_active": lambda self: "prod"})())
    values = _target_runbook_context_vars(profile_file=target_file)
    assert values["namespace"] == "payments"
    assert values["k8s_context"] == "dev"
    assert values["ssh_target"] == "root@192.168.10.101"
    assert values["target_profile"] == "prod"


def test_resolve_ssh_target_arg_uses_target_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target_file = tmp_path / "target.json"
    old_profile = settings.target_profile_file
    try:
        settings.target_profile_file = str(target_file)
        target_file.write_text(
            json.dumps({"ssh_target": "root@192.168.10.101"}, ensure_ascii=False),
            encoding="utf-8",
        )
        assert _resolve_ssh_target_arg("") == "root@192.168.10.101"
        assert _resolve_ssh_target_arg("@target") == "root@192.168.10.101"
        assert _resolve_ssh_target_arg("root@192.168.10.102") == "root@192.168.10.102"
        assert _resolve_ssh_target_arg("not-a-host") == ""
    finally:
        settings.target_profile_file = old_profile


def test_remote_intent_and_action_use_saved_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target_file = tmp_path / "target.json"
    old_profile = settings.target_profile_file
    calls: list[dict[str, object]] = []

    def fake_remote(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            "target": kwargs.get("target", ""),
            "ok": True,
            "summary": {"pass": 1, "warn": 0, "error": 0},
            "checks": [],
            "unhealthy_services": [],
            "bad_nodes": [],
            "root_causes": [],
            "recommendations": [],
        }

    try:
        settings.target_profile_file = str(target_file)
        target_file.write_text(
            json.dumps({"ssh_target": "root@192.168.10.101"}, ensure_ascii=False),
            encoding="utf-8",
        )
        monkeypatch.setattr(cli_main, "_collect_remote_docker_report", fake_remote)

        assert _looks_like_remote_diagnose_request("远程诊断一下 docker swarm")
        assert _run_action_command("lazysre remote --logs", options={}, execute_mode=False) is True
        assert calls[0]["target"] == "root@192.168.10.101"
        assert calls[0]["include_logs"] is True
    finally:
        settings.target_profile_file = old_profile


def test_connect_action_saves_verified_remote_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target_file = tmp_path / "target.json"
    old_profile = settings.target_profile_file
    calls: list[dict[str, object]] = []

    def fake_remote(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            "target": kwargs.get("target", ""),
            "ok": True,
            "summary": {"pass": 2, "warn": 0, "error": 0},
            "checks": [
                {"name": "ssh.connect", "ok": True, "severity": "pass"},
                {"name": "remote.docker.version", "ok": True, "severity": "pass"},
            ],
            "services": [],
            "unhealthy_services": [],
            "bad_nodes": [],
            "root_causes": [],
            "recommendations": [],
        }

    try:
        settings.target_profile_file = str(target_file)
        target_file.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(cli_main, "_collect_remote_docker_report", fake_remote)

        assert _run_action_command("lazysre connect root@192.168.10.101 --logs", options={}, execute_mode=False) is True
        assert calls[0]["target"] == "root@192.168.10.101"
        assert calls[0]["include_logs"] is True
        saved = json.loads(target_file.read_text(encoding="utf-8"))
        assert saved["ssh_target"] == "root@192.168.10.101"
    finally:
        settings.target_profile_file = old_profile


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


def test_collect_proxy_runtime_checks_without_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ["ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]:
        monkeypatch.delenv(key, raising=False)

    checks = cli_main._collect_proxy_runtime_checks()
    by_name = {str(item.get("name", "")): item for item in checks if isinstance(item, dict)}

    row = by_name["runtime.proxy_env"]
    assert row["ok"] is True
    assert row["severity"] == "pass"
    assert row["detail"] == "(unset)"
    assert "runtime.proxy_socksio" not in by_name


def test_collect_proxy_runtime_checks_requires_socksio_when_socks_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALL_PROXY", "socks5://myuser:mypass@example.com:1080")
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.setattr(cli_main, "_is_socksio_available", lambda: False)

    checks = cli_main._collect_proxy_runtime_checks()
    by_name = {str(item.get("name", "")): item for item in checks if isinstance(item, dict)}

    env_row = by_name["runtime.proxy_env"]
    assert "myuser:mypass@" not in str(env_row["detail"])
    assert "://***:***@" in str(env_row["detail"])

    socks_row = by_name["runtime.proxy_socksio"]
    assert socks_row["ok"] is False
    assert socks_row["severity"] == "error"
    assert "httpx[socks]" in str(socks_row["hint"])


def test_collect_proxy_runtime_checks_socksio_not_required_for_http_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:8080")
    for key in ["ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "https_proxy"]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:8080")
    monkeypatch.setattr(cli_main, "_is_socksio_available", lambda: False)

    checks = cli_main._collect_proxy_runtime_checks()
    by_name = {str(item.get("name", "")): item for item in checks if isinstance(item, dict)}
    row = by_name["runtime.proxy_socksio"]
    assert row["ok"] is True
    assert row["severity"] == "pass"
    assert "not required" in str(row["detail"])


def test_collect_workspace_secret_checks_detects_google_key(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    sample_key = "A" + "I" + "z" + "a" + "UNITTESTTOKENVALUE1234567890ABCDEF"
    (project / "app.py").write_text(f'KEY = "{sample_key}"\n', encoding="utf-8")

    checks = cli_main._collect_workspace_secret_checks(root=project)
    assert isinstance(checks, list)
    row = checks[0]
    assert row["name"] == "runtime.workspace_secret_scan"
    assert row["ok"] is False
    assert row["severity"] == "error"
    findings = row.get("findings", [])
    assert isinstance(findings, list) and findings
    first = findings[0]
    assert first["file"] == "app.py"
    assert first["line"] == 1
    assert "AIza***REDACTED***" in str(first["token"])


def test_collect_workspace_secret_checks_ignores_demo_markers(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    sample_key = ("A" + "I" + "z" + "a" + "UNITTESTTOKENVALUE1234567890ABCDEF") + "-demo"
    (project / "tests.py").write_text(f'KEY = "{sample_key}"\n', encoding="utf-8")

    checks = cli_main._collect_workspace_secret_checks(root=project)
    row = checks[0]
    assert row["name"] == "runtime.workspace_secret_scan"
    assert row["ok"] is True
    assert row["severity"] == "pass"


def test_collect_secret_scan_report_staged_scope(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    monkeypatch.setattr(cli_main, "_resolve_staged_secret_scan_paths", lambda workspace: [])

    report = cli_main._collect_secret_scan_report(root=project, staged=True, max_findings=5)
    checks = report["checks"]
    assert isinstance(checks, list)
    first = checks[0]
    assert first["name"] == "runtime.workspace_secret_scan_scope"
    assert "scope=staged files (0)" in str(first["detail"])


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
    assert report["briefing"]["status"] == "attention"
    assert "docker-swarm" in report["briefing"]["headline"]
    assert report["briefing"]["next"] == "lazysre swarm --logs"
    assert report["landscape"]["profile"] == "hybrid-swarm-k8s"
    assert report["briefing"]["profile_label"] == "Hybrid Swarm + K8s"
    assert any("signal:" in item for item in report["briefing"]["evidence"])


def test_build_discovery_target_updates_prefers_discovered_values() -> None:
    target = TargetEnvironment(
        prometheus_url="",
        k8s_api_url="",
        k8s_context="",
        k8s_namespace="default",
        k8s_bearer_token="",
        k8s_verify_tls=False,
        ssh_target="",
    )

    updates = _build_discovery_target_updates(
        target,
        {
            "discoveries": {
                "prometheus": {"url": "http://prometheus:9090"},
                "kubernetes": {
                    "context": "prod-cluster",
                    "server": "https://10.0.0.1:6443",
                    "namespace": "prod",
                },
            }
        },
    )

    assert updates == {
        "prometheus_url": "http://prometheus:9090",
        "k8s_context": "prod-cluster",
        "k8s_api_url": "https://10.0.0.1:6443",
        "k8s_namespace": "prod",
    }


def test_build_environment_scan_briefing_when_no_targets() -> None:
    report = {
        "summary": {"pass": 1, "warn": 2, "error": 0},
        "usable_targets": [],
        "issues": [
            {"name": "binary.docker", "severity": "warn", "detail": "(not found)", "hint": "install docker"}
        ],
        "suggestions": ["帮我解释为什么当前机器还不能被 LazySRE 纳管"],
        "next_actions": ["未发现可直接访问的运维目标；建议先确认 docker daemon 或 kubectl kubeconfig 是否可用"],
    }

    briefing = _build_environment_scan_briefing(report)

    assert briefing["status"] == "attention"
    assert "暂未发现" in briefing["headline"]
    assert briefing["next"] == 'lazysre "帮我解释为什么当前机器还不能被 LazySRE 纳管"'


def test_build_environment_landscape_detects_hybrid_runtime() -> None:
    landscape = _build_environment_landscape(
        {
            "usable_targets": ["docker", "docker-swarm", "kubernetes", "prometheus"],
            "discoveries": {
                "docker": {
                    "reachable": True,
                    "swarm_active": True,
                    "swarm_services": 6,
                    "exited_containers": 2,
                },
                "kubernetes": {
                    "reachable": True,
                    "nodes": 3,
                    "namespace": "prod",
                    "problem_pods": 2,
                    "warning_events": 4,
                },
                "prometheus": {"reachable": True, "url": "http://prom:9090"},
                "providers": {"configured": ["openai"]},
            },
        }
    )

    assert landscape["profile"] == "hybrid-swarm-k8s"
    assert landscape["label"] == "Hybrid Swarm + K8s"
    assert "swarm=6 services" in landscape["summary"]
    assert any("Swarm active" in item for item in landscape["signals"])
    assert any("K8s problem pods=2" in item for item in landscape["signals"])
    assert any("Prometheus ready" in item for item in landscape["signals"])


def test_build_environment_drift_detects_target_changes() -> None:
    drift = _build_environment_drift(
        {
            "generated_at_utc": "2026-04-10T00:00:00+00:00",
            "usable_targets": ["docker-swarm", "kubernetes"],
        },
        ["docker", "prometheus"],
    )

    assert drift["exists"] is True
    assert drift["status"] == "changed"
    assert "新增 prometheus" in drift["headline"]
    assert "缺失 kubernetes" in drift["headline"]
    assert "kubernetes" in drift["removed_targets"]
    assert "prometheus" in drift["added_targets"]


def test_build_environment_drift_stable_when_targets_match() -> None:
    drift = _build_environment_drift(
        {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "usable_targets": ["docker", "kubernetes", "prometheus"],
        },
        ["docker", "kubernetes", "prometheus"],
    )

    assert drift["status"] == "stable"
    assert "稳定" in drift["headline"]


def test_build_environment_scan_briefing_includes_profile_and_signals() -> None:
    report = {
        "summary": {"pass": 6, "warn": 2, "error": 0},
        "usable_targets": ["docker", "docker-swarm", "kubernetes", "prometheus"],
        "discoveries": {
            "docker": {"reachable": True, "swarm_active": True, "swarm_services": 4, "exited_containers": 1},
            "kubernetes": {"reachable": True, "nodes": 2, "namespace": "prod", "problem_pods": 1, "warning_events": 2},
            "prometheus": {"reachable": True, "url": "http://prometheus:9090"},
            "providers": {"configured": []},
        },
        "issues": [{"name": "k8s.problem_pods", "severity": "warn", "detail": "1 problem pod", "hint": "check pod"}],
        "suggestions": ["检查 K8s 异常 Pod 和 Warning Events"],
        "next_actions": ["lazysre swarm --logs"],
    }

    briefing = _build_environment_scan_briefing(report)

    assert briefing["profile"] == "hybrid-swarm-k8s"
    assert briefing["profile_label"] == "Hybrid Swarm + K8s"
    assert "现场画像" in briefing["headline"]
    assert any("profile:" in item for item in briefing["evidence"])
    assert any("signal:" in item for item in briefing["evidence"])
    assert any("K8s problem pods=1" in item for item in briefing["signals"])


def test_build_overview_briefing_prefers_remote_attention() -> None:
    scan_report = {
        "summary": {"pass": 5, "warn": 0, "error": 0},
        "usable_targets": ["docker-swarm"],
        "issues": [],
        "suggestions": [],
        "next_actions": ["lazysre swarm --logs"],
        "briefing": {
            "status": "healthy",
            "headline": "已发现可纳管目标：docker-swarm，可以直接开始自然语言诊断。",
            "evidence": ["checks: pass=5 warn=0 error=0"],
            "next": "lazysre swarm --logs",
        },
    }
    remote_report = {
        "target": "root@192.168.10.101",
        "ok": False,
        "summary": {"pass": 3, "warn": 1, "error": 0},
        "checks": [],
        "unhealthy_services": [{"name": "api", "replicas": "0/1"}],
        "bad_nodes": [],
        "root_causes": [],
        "recommendations": ["lazysre remote root@192.168.10.101 --service api --logs"],
        "briefing": {
            "status": "attention",
            "headline": "发现 1 个远程 Swarm 服务副本异常：api(0/1)。",
            "evidence": ["checks: pass=3 warn=1 error=0"],
            "next": "lazysre remote root@192.168.10.101 --service api --logs",
        },
    }

    briefing = _build_overview_briefing(scan_report=scan_report, remote_report=remote_report)
    commands = _build_overview_recommended_commands(
        {"briefing": briefing, "scan": scan_report, "remote": remote_report}
    )

    assert briefing["status"] == "attention"
    assert "远程" in briefing["headline"]
    assert briefing["next"] == "lazysre remote root@192.168.10.101 --service api --logs"
    assert commands[0] == "lazysre remote root@192.168.10.101 --service api --logs"


def test_first_run_marker_accepts_overview_brief_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)
    report = {
        "source": "overview-brief",
        "briefing": {
            "status": "attention",
            "headline": "本机：已发现可纳管目标。",
            "evidence": ["scan: checks pass=3 warn=1 error=0"],
            "next": "lazysre swarm --logs",
        },
        "scan": {
            "summary": {"pass": 3, "warn": 1, "error": 0},
            "usable_targets": ["docker-swarm"],
            "issues": [{"name": "docker.exited_containers", "severity": "warn"}],
            "suggestions": ["分析 Docker Swarm 服务健康"],
            "next_actions": ["lazysre swarm --logs"],
        },
    }

    marker = _write_first_scan_marker(report)
    payload = json.loads(marker.read_text(encoding="utf-8"))

    assert payload["source"] == "overview-brief"
    assert payload["briefing"]["next"] == "lazysre swarm --logs"
    assert payload["usable_targets"] == ["docker-swarm"]


def test_render_cached_startup_brief_prints_next_step(capsys: pytest.CaptureFixture[str]) -> None:
    old_console = cli_main._console
    try:
        cli_main._console = None
        _render_cached_startup_brief(
            {
                "generated_at_utc": "2026-04-09T00:00:00+00:00",
                "briefing": {
                    "status": "attention",
                    "headline": "本机：发现 Docker Swarm。",
                    "next": "lazysre swarm --logs",
                },
            }
        )
    finally:
        cli_main._console = old_console

    out = capsys.readouterr().out
    assert "上次总览: attention" in out
    assert "lazysre swarm --logs" in out


def test_maybe_auto_bootstrap_for_tui_writes_marker_on_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)

    def fake_collect(*, timeout_sec: int, secrets_file: Path | None) -> dict[str, object]:
        assert timeout_sec == 3
        assert secrets_file is None
        return {
            "source": "environment-scan",
            "briefing": {
                "status": "attention",
                "headline": "本机发现 Docker Swarm。",
                "next": "lazysre swarm --logs",
            },
            "usable_targets": ["docker-swarm"],
            "summary": {"warn": 1, "error": 0},
            "next_actions": ["lazysre swarm --logs"],
        }

    monkeypatch.setattr(cli_main, "_collect_environment_discovery", fake_collect)

    result = _maybe_auto_bootstrap_for_tui({"startup_scan_timeout_sec": 3})
    marker = tmp_path / "lsre-onboarding.json"
    payload = json.loads(marker.read_text(encoding="utf-8"))

    assert result["triggered"] is True
    assert result["written"] is True
    assert payload["first_scan_done"] is True
    assert payload["briefing"]["next"] == "lazysre swarm --logs"


def test_maybe_auto_bootstrap_for_tui_skips_when_marker_exists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)
    (tmp_path / "lsre-onboarding.json").write_text("{}", encoding="utf-8")

    def fake_collect(*, timeout_sec: int, secrets_file: Path | None) -> dict[str, object]:
        raise AssertionError("should not run collect when marker already exists")

    monkeypatch.setattr(cli_main, "_collect_environment_discovery", fake_collect)

    result = _maybe_auto_bootstrap_for_tui({})

    assert result["triggered"] is False
    assert result["reason"] == "marker-exists"


def test_maybe_auto_bootstrap_for_tui_respects_disable_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)

    def fake_collect(*, timeout_sec: int, secrets_file: Path | None) -> dict[str, object]:
        raise AssertionError("should not run collect when disabled")

    monkeypatch.setattr(cli_main, "_collect_environment_discovery", fake_collect)

    result = _maybe_auto_bootstrap_for_tui({"tui_auto_bootstrap": False})

    assert result["triggered"] is False
    assert result["reason"] == "disabled"


def test_build_tui_dashboard_snapshot_reads_marker_and_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)
    session_file = tmp_path / "session.json"
    audit_log = tmp_path / "audit.jsonl"
    session_file.write_text(
        json.dumps(
            {
                "turns": [
                    {"user": "检查 swarm 服务", "assistant": "好的"},
                    {"user": "重启它", "assistant": "已生成计划"},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (tmp_path / "lsre-onboarding.json").write_text(
        json.dumps(
            {
                "generated_at_utc": "2026-04-10T00:00:00+00:00",
                "usable_targets": ["docker-swarm", "kubernetes"],
                "landscape": {
                    "profile": "hybrid-swarm-k8s",
                    "label": "Hybrid Swarm + K8s",
                    "summary": "Hybrid Swarm + K8s; swarm=3 services, k8s nodes=2/problem_pods=1",
                    "signals": [
                        "Swarm active，services=3",
                        "K8s reachable，nodes=2，namespace=prod",
                        "K8s problem pods=1",
                    ],
                },
                "next_actions": ["lazysre swarm --logs"],
                "briefing": {
                        "status": "attention",
                        "headline": "本机已发现 Swarm 和 K8s，可直接开始诊断。",
                        "profile": "hybrid-swarm-k8s",
                        "profile_label": "Hybrid Swarm + K8s",
                        "summary": "Hybrid Swarm + K8s; swarm=3 services, k8s nodes=2/problem_pods=1",
                        "signals": [
                            "Swarm active，services=3",
                            "K8s reachable，nodes=2，namespace=prod",
                            "K8s problem pods=1",
                        ],
                        "next": "lazysre swarm --logs",
                    },
                },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (tmp_path / "lsre-watch-last.json").write_text(
        json.dumps(
            {
                "cycle": 3,
                "alerts": [{"source": "swarm", "name": "api", "detail": "replicas=0/1"}],
                "swarm": {
                    "posture": {
                        "headline": "Swarm 主要阻塞点是 api，根因倾向 swarm_image_pull_failed。",
                        "summary": "services=3 unhealthy=1 bad_nodes=0 root_causes=1",
                        "focus_service": "api",
                        "signals": [
                            "services=3",
                            "unhealthy=1",
                            "top_root_cause=swarm_image_pull_failed",
                        ],
                        "top_actions": [
                            "lazysre template run swarm-image-pull-failed --var service=api --apply",
                            "lazysre swarm --service api --logs",
                        ],
                    }
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (tmp_path / "lsre-fix-last.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-04-10T00:10:00+00:00",
                "instruction": "重启 api 服务以恢复副本",
                "plan": {"apply_commands": ["docker service update --force api"]},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (tmp_path / "lsre-remediation-last.json").write_text(
        json.dumps(
            {
                "generated_at_utc": "2026-04-10T00:12:00+00:00",
                "objective": "恢复 api 服务副本",
                "mode": "dry-run",
                "ok": False,
                "next_step": "先查看 verify 输出，再决定是否真正执行。",
                "execution": {
                    "diagnose": {"executed": 1, "succeeded": 1, "failed": 0},
                    "apply": {"executed": 1, "succeeded": 0, "failed": 1},
                    "verify": {"executed": 1, "succeeded": 0, "failed": 1},
                    "rollback": {"executed": 0, "succeeded": 0, "failed": 0},
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (tmp_path / "lsre-quick-action-last.json").write_text(
        json.dumps(
            {
                "executed_at_utc": "2026-04-10T08:35:00+00:00",
                "action_id": "1",
                "title": "Active Alert",
                "source": "focus",
                "command": "/activity",
                "status": "ok",
                "output_preview": "Recent Activity | watch attention alerts=1 cycle=3",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    audit_log.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-04-10T08:30:00+00:00",
                        "status": "ok",
                        "command": ["docker", "service", "ls"],
                    },
                    ensure_ascii=False,
                ),
                json.dumps(
                    {
                        "timestamp": "2026-04-10T08:31:00+00:00",
                        "status": "ok",
                        "action": "scan",
                    },
                    ensure_ascii=False,
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    snapshot = _build_tui_dashboard_snapshot(
        {
            "execute": False,
            "provider": "mock",
            "model": "test-model",
            "session_file": str(session_file),
            "audit_log": str(audit_log),
        }
    )

    assert snapshot["status"] == "attention"
    assert "docker-swarm" in snapshot["usable_targets"]
    assert snapshot["environment_profile"] == "Hybrid Swarm + K8s"
    assert "swarm=3 services" in snapshot["environment_summary"]
    assert any("Swarm active" in item for item in snapshot["environment_signals"])
    assert snapshot["swarm_posture"]["focus_service"] == "api"
    assert snapshot["incident_session"]["source"] == "closed-loop-remediation"
    assert snapshot["incident_session"]["status"] == "attention"
    assert snapshot["session_turns"] == 2
    assert snapshot["last_user"] == "重启它"
    assert snapshot["recent_commands"] == ["检查 swarm 服务", "重启它"]
    assert snapshot["recommended_commands"][0] == "lazysre swarm --logs"
    assert any("watch attention alerts=1 cycle=3" in item for item in snapshot["recent_activity"])
    assert any("fix plan | cmds=1" in item for item in snapshot["recent_activity"])
    assert any("docker service ls" in item for item in snapshot["recent_activity"])
    assert "/activity" in snapshot["recent_activity_commands"]
    assert "/swarm --service api --logs" in snapshot["recent_activity_commands"]
    assert any("08:30 [observe/ok/exec] docker service ls" in item for item in snapshot["timeline_entries"])
    assert snapshot["focus_title"] == "Swarm Posture"
    assert snapshot["focus_actions"][0] == "lazysre template run swarm-image-pull-failed --var service=api --apply"
    assert isinstance(snapshot["quick_action_items"], list)
    assert snapshot["quick_action_items"]
    assert snapshot["quick_action_items"][0]["id"] == "1"
    assert snapshot["latest_quick_action"]["command"] == "/activity"
    assert any(item.get("command") == "/activity" and item.get("last_status") == "ok" for item in snapshot["quick_action_items"])


def test_build_tui_dashboard_snapshot_masks_secrets_in_session_preview(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "turns": [
                    {"user": "我有一个k8s集群，root密码是demo-password", "assistant": "ok"},
                    {"user": "api key=google-api-key-demo-value", "assistant": "ok"},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (tmp_path / "lsre-onboarding.json").write_text(
        json.dumps({"generated_at_utc": "2026-04-10T00:00:00+00:00", "briefing": {}}, ensure_ascii=False),
        encoding="utf-8",
    )

    snapshot = _build_tui_dashboard_snapshot(
        {
            "execute": False,
            "provider": "mock",
            "model": "test-model",
            "session_file": str(session_file),
            "audit_log": str(tmp_path / "audit.jsonl"),
        }
    )
    assert "demo-password" not in snapshot["last_user"]
    assert "google-api-key-demo-value" not in snapshot["last_user"]
    assert any("***REDACTED***" in item for item in snapshot["recent_commands"])


def test_render_recent_activity_text_includes_next_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)
    (tmp_path / "lsre-watch-last.json").write_text(
        json.dumps(
            {
                "cycle": 2,
                "alerts": [{"source": "swarm", "name": "payment", "detail": "replicas=0/1"}],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (tmp_path / "lsre-fix-last.json").write_text(
        json.dumps(
            {
                "instruction": "重启 payment 服务",
                "plan": {"apply_commands": ["docker service update --force payment"]},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    rendered = _render_recent_activity_text({"audit_log": str(tmp_path / "missing.jsonl")})

    assert "Recent Activity" in rendered
    assert "watch attention alerts=1 cycle=2" in rendered
    assert "Suggested Next Commands" in rendered
    assert "/activity" in rendered


def test_render_focus_text_prefers_recent_failure(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-04-10T08:30:00+00:00",
                        "status": "ok",
                        "command": ["docker", "service", "ls"],
                    },
                    ensure_ascii=False,
                ),
                json.dumps(
                    {
                        "timestamp": "2026-04-10T08:31:00+00:00",
                        "status": "fail",
                        "command": ["docker", "service", "update", "--force", "api"],
                    },
                    ensure_ascii=False,
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    rendered = _render_focus_text({"audit_log": str(audit_log), "provider": "mock"})

    assert "Recent Failure" in rendered
    assert "/trace" in rendered
    assert "/timeline" in rendered


def test_render_environment_drift_text_uses_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {
            "environment_drift": {
                "exists": True,
                "status": "changed",
                "headline": "环境基线发生漂移：新增 prometheus 缺失 kubernetes",
                "signals": ["baseline=docker,kubernetes", "current=docker,prometheus"],
                "top_actions": ["lazysre scan", "kubectl config current-context"],
            }
        },
    )

    rendered = _render_environment_drift_text({})

    assert "Environment Drift" in rendered
    assert "changed" in rendered
    assert "新增 prometheus" in rendered
    assert "lazysre scan" in rendered


def test_render_quick_actions_text_lists_numbered_items(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {
            "quick_action_items": [
                {"id": "1", "title": "Focus", "source": "focus", "command": "/trace", "last_status": "ok", "last_output_preview": "Trace Summary ready"},
                {"id": "2", "title": "Recommended", "source": "recommended", "command": "lazysre scan"},
            ],
            "latest_quick_action": {"status": "ok", "command": "/trace"},
        },
    )

    rendered = _render_quick_actions_text({})

    assert "Quick Actions" in rendered
    assert "1. [inspect][low][focus] Focus [last=ok]" in rendered
    assert "cmd: /trace" in rendered
    assert "last-output: Trace Summary ready" in rendered
    assert "2. [inspect][low][recommended] Recommended" in rendered
    assert "cmd: lazysre scan" in rendered
    assert "Last Run" in rendered
    assert "/do 1" in rendered


def test_classify_quick_action_confidence_levels() -> None:
    assert _classify_quick_action_confidence({"source": "focus", "kind": "inspect", "risk": "low"}) == "high"
    assert _classify_quick_action_confidence({"source": "recommended", "kind": "write", "risk": "high"}) == "low"
    assert _classify_quick_action_confidence({"source": "recommended", "kind": "inspect", "risk": "medium"}) == "medium"


def test_render_timeline_text_includes_audit_entries(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-04-10T08:30:00+00:00",
                        "ok": True,
                        "dry_run": False,
                        "command": ["docker", "service", "ls"],
                    },
                    ensure_ascii=False,
                ),
                json.dumps(
                    {
                        "timestamp": "2026-04-10T08:31:00+00:00",
                        "ok": False,
                        "dry_run": True,
                        "remote_target": "root@10.0.0.8",
                        "command": ["kubectl", "get", "pods"],
                    },
                    ensure_ascii=False,
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    rendered = _render_timeline_text({"audit_log": str(audit_log)})

    assert "Execution Timeline" in rendered
    assert "Trace Summary" in rendered
    assert "08:30 [observe/ok/exec] docker service ls" in rendered
    assert "08:31 [observe/fail/dry-run] root@10.0.0.8 :: kubectl get pods" in rendered


def test_render_trace_text_summarizes_recent_operations(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text(
        "\n".join(
            [
                json.dumps(
                    {"timestamp": "2026-04-10T08:30:00+00:00", "ok": True, "dry_run": False, "command": ["docker", "service", "ls"]},
                    ensure_ascii=False,
                ),
                json.dumps(
                    {"timestamp": "2026-04-10T08:31:00+00:00", "ok": False, "dry_run": True, "command": ["kubectl", "get", "pods"]},
                    ensure_ascii=False,
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    rendered = _render_trace_text({"audit_log": str(audit_log)})

    assert rendered.startswith("Operation Trace")
    assert "steps=2 ok=1 fail=1 dry-run=1 exec=1" in rendered
    assert "top-tools=" in rendered
    assert "stage-flow=observex2" in rendered


def test_build_tui_footer_line_includes_last_user_command() -> None:
    footer = _build_tui_footer_line(
        snapshot={
            "mode": "dry-run",
            "active_provider": "auto->mock",
            "usable_targets": ["docker", "kubernetes"],
            "recent_activity": ["watch attention alerts=1 cycle=2", "fix plan | cmds=1 | 重启 payment"],
            "timeline_entries": ["08:30 [ok/exec] docker service ls"],
        },
        status="running",
        history=[
            ("LazySRE", "welcome"),
            ("You", "/activity"),
            ("LazySRE", "Recent Activity"),
        ],
    )

    assert "Status running" in footer
    assert "Provider auto->mock" in footer
    assert "Targets 2" in footer
    assert "Activity 2" in footer
    assert "Timeline 1" in footer
    assert "Last /activity" in footer


def test_build_tui_footer_line_truncates_and_sanitizes_last_user() -> None:
    footer = _build_tui_footer_line(
        snapshot={
            "mode": "dry-run",
            "active_provider": "gemini",
            "usable_targets": ["kubernetes"],
            "recent_activity": [],
            "timeline_entries": [],
        },
        status="ready",
        history=[
            ("You", "检查 key=google-api-key-demo-value 和最近 k8s pod 崩溃原因"),
        ],
    )
    assert "google-api-key-demo-value" not in footer
    assert "key=***REDACTED***" in footer
    assert "Last 检查 key=***REDACTED***" in footer
    assert "…" in footer


def test_truncate_tui_status_text_collapses_spaces_and_adds_ellipsis() -> None:
    out = _truncate_tui_status_text("  alpha   beta   gamma   delta  ", max_chars=11)
    assert out == "alpha beta…"


def test_normalize_tui_panel_name_aliases() -> None:
    assert _normalize_tui_panel_name("summary") == "overview"
    assert _normalize_tui_panel_name("actions") == "activity"
    assert _normalize_tui_panel_name("provider") == "providers"
    assert _normalize_tui_panel_name("weird") == "overview"


def test_switch_tui_panel_updates_options() -> None:
    options = {"tui_panel": "overview"}

    msg = _switch_tui_panel(options, "timeline")
    assert options["tui_panel"] == "timeline"
    assert "timeline" in msg

    msg2 = _switch_tui_panel(options, "next")
    assert options["tui_panel"] == "providers"
    assert "providers" in msg2

    msg3 = _switch_tui_panel(options, "2")
    assert options["tui_panel"] == "activity"
    assert "activity" in msg3


def test_build_tui_panel_counts_summarizes_snapshot() -> None:
    counts = _build_tui_panel_counts(
        {
            "recent_activity": ["a1", "a2"],
            "timeline_entries": ["t1"],
            "recommended_commands": ["r1", "r2", "r3"],
            "configured_providers": ["openai", "compatible"],
            "provider_report": {"providers": {"openai": {}, "compatible": {}, "gemini": {}}},
        }
    )

    assert counts["overview"] == "3"
    assert counts["activity"] == "2"
    assert counts["timeline"] == "1"
    assert counts["providers"] == "2/3"


def test_build_recent_trace_summary_handles_empty_and_counts() -> None:
    assert "暂无 trace" in _build_recent_trace_summary([])[0]

    summary = _build_recent_trace_summary(
        [
            {"status": "ok", "mode": "exec", "stage": "observe", "summary": "docker service ls"},
            {"status": "fail", "mode": "dry-run", "stage": "apply", "summary": "kubectl apply -f x.yaml"},
        ]
    )

    assert "steps=2 ok=1 fail=1 dry-run=1 exec=1" in summary[0]
    assert "stage-flow=observex1 -> applyx1" in summary[-1]


def test_read_last_incident_session_summary_prefers_newer_closed_loop(tmp_path: Path) -> None:
    (tmp_path / "lsre-fix-last.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-04-10T08:00:00+00:00",
                "instruction": "重启 api 服务",
                "plan": {
                    "apply_commands": ["docker service update --force api"],
                    "rollback_commands": ["docker service rollback api"],
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (tmp_path / "lsre-remediation-last.json").write_text(
        json.dumps(
            {
                "generated_at_utc": "2026-04-10T08:05:00+00:00",
                "objective": "恢复 api 副本",
                "mode": "execute",
                "ok": False,
                "next_step": "先查看 verify 阶段输出，再考虑回滚。",
                "execution": {
                    "diagnose": {"executed": 1, "succeeded": 1, "failed": 0},
                    "apply": {"executed": 1, "succeeded": 0, "failed": 1},
                    "verify": {"executed": 1, "succeeded": 0, "failed": 1},
                    "rollback": {"executed": 0, "succeeded": 0, "failed": 0},
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    summary = _read_last_incident_session_summary(tmp_path)

    assert summary["exists"] is True
    assert summary["source"] == "closed-loop-remediation"
    assert summary["status"] == "attention"
    assert "恢复 api 副本" in summary["headline"]
    assert "diagnose:1/1 ok" in summary["stage_flow"]
    assert "apply:0/1 fail=1" in summary["stage_flow"]
    assert summary["commands"][0] == "/trace"


def test_read_last_incident_session_summary_falls_back_to_fix_plan(tmp_path: Path) -> None:
    (tmp_path / "lsre-fix-last.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-04-10T08:00:00+00:00",
                "instruction": "扩容 payment 到 3 个副本",
                "plan": {
                    "apply_commands": ["docker service scale payment=3"],
                    "rollback_commands": ["docker service scale payment=1"],
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    summary = _read_last_incident_session_summary(tmp_path)

    assert summary["exists"] is True
    assert summary["source"] == "fix-plan"
    assert summary["status"] == "plan-ready"
    assert "payment" in summary["headline"]
    assert summary["stage_flow"] == "plan apply=1 rollback=1"
    assert summary["commands"][0] == "/approve"


def test_infer_trace_stage_recognizes_common_phases() -> None:
    assert _infer_trace_stage("docker service ls") == "observe"
    assert _infer_trace_stage("kubectl apply -f k.yaml") == "apply"
    assert _infer_trace_stage("kubectl rollout status deploy/api") == "verify"
    assert _infer_trace_stage("fix plan for payment") == "plan"


def test_build_tui_panel_tabs_marks_active_panel() -> None:
    lines = _build_tui_panel_tabs(
        "timeline",
        width=80,
        snapshot={
            "recent_activity": ["a1", "a2"],
            "timeline_entries": ["t1"],
            "recommended_commands": ["r1"],
            "configured_providers": ["openai"],
            "provider_report": {"providers": {"openai": {}, "compatible": {}}},
        },
    )
    joined = "\n".join(lines)

    assert "[3:timeline(1)]" in joined
    assert "1:overview(1)" in joined
    assert "4:providers(1/2)" in joined


def test_build_tui_panel_hint_changes_by_panel() -> None:
    assert "总览环境" in _build_tui_panel_hint("overview")
    assert "建议动作" in _build_tui_panel_hint("activity")
    assert "执行轨迹" in _build_tui_panel_hint("timeline")
    assert "模型与网关" in _build_tui_panel_hint("providers")


def test_build_tui_help_overlay_lines_reflects_panel_and_next_action() -> None:
    lines = _build_tui_help_overlay_lines(
        {
            "sidebar_panel": "activity",
            "provider": "mock",
            "active_provider": "mock",
            "focus_title": "Swarm Failure",
            "quick_action_items": [
                {"id": "1", "command": "/activity", "title": "Active Alert"},
                {"id": "2", "command": "/scan", "title": "Rescan"},
            ],
            "latest_quick_action": {"status": "ok", "command": "/activity"},
        },
        width=40,
    )

    joined = "\n".join(lines)

    assert "LazySRE Help" in joined
    assert "当前面板: activity" in joined
    assert "建议下一步: /do 2 -> /scan" in joined
    assert "F1 或 ? 打开/关闭帮助" in joined
    assert "列出最近失败的 Swarm service" in joined
    assert "Try Asking" in joined


def test_build_tui_starter_prompts_include_target_specific_items() -> None:
    prompts = _build_tui_starter_prompts(
        {
            "sidebar_panel": "providers",
            "provider": "mock",
            "active_provider": "openai",
            "usable_targets": ["docker", "swarm", "k8s"],
        }
    )

    joined = "\n".join(prompts)

    assert "检查当前环境有什么异常" in joined
    assert "列出 Swarm 当前不健康的 service" in joined
    assert "看看 Docker 容器里有没有异常重启" in joined
    assert "找出当前集群里异常 Pod 和最近 Events" in joined
    assert "检查 openai provider 当前是否可用" in joined


def test_build_tui_idle_content_rows_show_starter_prompts() -> None:
    rows = _build_tui_idle_content_rows(
        {
            "sidebar_panel": "overview",
            "panel_hint": "总览环境与下一步",
            "quick_action_items": [{"id": "1", "command": "/focus", "title": "Focus"}],
            "latest_quick_action": {"status": "ok", "command": "/focus"},
            "usable_targets": ["swarm"],
        },
        width=48,
    )

    joined = "\n".join(rows)

    assert "Start Here" in joined
    assert "Try Asking" in joined
    assert "列出 Swarm 当前不健康的 service" in joined
    assert "Direct Commands" in joined
    assert "/do 1" in joined


def test_tui_text_display_width_handles_mixed_cn_en() -> None:
    assert _tui_text_display_width("abc中文") == 7


def test_parse_tui_escape_sequence_for_arrows_and_delete() -> None:
    assert _parse_tui_escape_sequence("[A") == "<UP>"
    assert _parse_tui_escape_sequence("[B") == "<DOWN>"
    assert _parse_tui_escape_sequence("[3~") == "<DELETE>"


def test_parse_tui_escape_sequence_for_function_style_prefix() -> None:
    assert _parse_tui_escape_sequence("\x1b[A".replace("\x1b", "")) == "<UP>"
    assert _parse_tui_escape_sequence("foo[1~") == "<HOME>"


def test_parse_tui_escape_sequence_with_modifier_arrow() -> None:
    assert _parse_tui_escape_sequence("[1;5A") == "<UP>"
    assert _parse_tui_escape_sequence("[1;3B") == "<DOWN>"


def test_normalize_tui_key_alias_for_unicode_arrows() -> None:
    assert _normalize_tui_key_alias("↑") == "<UP>"
    assert _normalize_tui_key_alias("↓") == "<DOWN>"
    assert _normalize_tui_key_alias("←") == "<LEFT>"
    assert _normalize_tui_key_alias("→") == "<RIGHT>"
    assert _normalize_tui_key_alias("⬆") == "<UP>"
    assert _normalize_tui_key_alias("⬇") == "<DOWN>"
    assert _normalize_tui_key_alias("x") == "x"


def test_normalize_tui_key_alias_ignores_ime_modifier_glyphs() -> None:
    assert _normalize_tui_key_alias("⇧") == ""
    assert _normalize_tui_key_alias("⌥") == ""
    assert _normalize_tui_key_alias("⌘") == ""
    assert _normalize_tui_key_alias("⌃") == ""


def test_normalize_tui_key_alias_for_full_escape_sequence() -> None:
    assert _normalize_tui_key_alias("\x1b[A") == "<UP>"
    assert _normalize_tui_key_alias("\x1b[1;5A") == "<UP>"
    assert _normalize_tui_key_alias("[A") == "<UP>"
    assert _normalize_tui_key_alias("OA") == "<UP>"


def test_normalize_tui_key_alias_for_named_curses_keys() -> None:
    assert _normalize_tui_key_alias("KEY_UP") == "<UP>"
    assert _normalize_tui_key_alias("KEY_DOWN") == "<DOWN>"
    assert _normalize_tui_key_alias("KEY_LEFT") == "<LEFT>"
    assert _normalize_tui_key_alias("KEY_RIGHT") == "<RIGHT>"
    assert _normalize_tui_key_alias("KEY_HOME") == "<HOME>"
    assert _normalize_tui_key_alias("KEY_END") == "<END>"
    assert _normalize_tui_key_alias("KEY_DC") == "<DELETE>"


def test_format_tui_output_for_display_removes_internal_trace_lines() -> None:
    raw = "\n".join(
        [
            "[llm_turn] initial_response {...}",
            "[lm_turn] step_1_followup {...}",
            "[tool_call] get_context",
            "## Status",
            "Diagnosing",
            "",
            "```bash",
            "kubectl get pods",
            "```",
        ]
    )
    cleaned = _format_tui_output_for_display(raw)
    assert "[llm_turn]" not in cleaned
    assert "[lm_turn]" not in cleaned
    assert "[tool_call]" not in cleaned
    assert "Status:" in cleaned
    assert "kubectl get pods" in cleaned


def test_build_tui_compact_sidebar_lines_contains_guided_blocks() -> None:
    lines = _build_tui_compact_sidebar_lines(
        {
            "focus_title": "Environment Drift",
            "focus_body": "targets changed",
            "recommended_commands": ["/scan"],
            "provider": "gemini",
            "active_provider": "gemini",
            "usable_targets": ["docker", "kubernetes", "prometheus"],
            "mode": "dry-run",
        },
        width=40,
    )
    joined = "\n".join(lines)
    assert "Status" in joined
    assert "Next" in joined
    assert "Target" in joined
    assert "Provider gemini" in joined


def test_build_tui_compact_action_bar_mentions_shift_shortcuts() -> None:
    line = _build_tui_compact_action_bar({"focus_title": "x", "focus_body": "y"})
    assert "Enter" in line
    assert "1-4 actions" in line
    assert "/ui expert" in line


def test_tui_welcome_message_contains_one_minute_setup_and_go4() -> None:
    text = _tui_welcome_message(
        {
            "provider_ready": False,
            "provider": "auto",
            "active_provider": "auto->mock",
            "usable_targets": [],
            "status": "cold-start",
            "latest_quick_action": {},
        }
    )
    assert "One Minute Start" in text
    assert "/go 1|2|3|4" in text
    assert "/quickstart" in text


def test_build_tui_start_coach_prioritizes_provider_setup() -> None:
    coach = _build_tui_start_coach(
        {
            "provider_ready": False,
            "provider": "auto",
            "active_provider": "auto->mock",
            "usable_targets": [],
            "status": "cold-start",
            "latest_quick_action": {},
        }
    )
    assert coach["phase"] == "connect_llm"
    assert "/go 1" in str(coach["primary"])


def test_build_tui_start_coach_prioritizes_remote_target_on_mac() -> None:
    coach = _build_tui_start_coach(
        {
            "provider_ready": True,
            "provider": "gemini",
            "active_provider": "gemini",
            "target_strategy": "remote-first",
            "ssh_target": "",
            "usable_targets": ["docker", "kubernetes"],
            "status": "ready",
            "latest_quick_action": {},
        }
    )
    assert coach["phase"] == "connect_target"
    assert "Mac 作为控制台" in str(coach["headline"])
    assert _resolve_tui_boot_action_command({"target_strategy": "remote-first", "provider_ready": True}, 1) == "/connect"


def test_build_tui_start_coach_uses_saved_remote_target_first() -> None:
    snapshot = {
        "provider_ready": True,
        "provider": "gemini",
        "active_provider": "gemini",
        "target_strategy": "remote-first",
        "ssh_target": "root@10.0.0.8",
        "usable_targets": ["remote-ssh"],
        "status": "cold-start",
        "latest_quick_action": {},
    }
    coach = _build_tui_start_coach(snapshot)
    assert coach["phase"] == "remote_observe"
    assert _resolve_tui_boot_action_command(snapshot, 1) == "/remote --logs"


def test_resolve_tui_boot_action_command_by_stage() -> None:
    snapshot_connect = {
        "provider_ready": False,
        "provider": "auto",
        "active_provider": "auto->mock",
        "usable_targets": [],
        "status": "cold-start",
        "latest_quick_action": {},
    }
    assert _resolve_tui_boot_action_command(snapshot_connect, 1) == "/quickstart"
    assert _resolve_tui_boot_action_command(snapshot_connect, 2) == "/provider mock"
    assert _resolve_tui_boot_action_command(snapshot_connect, 3) == "/providers"
    assert _resolve_tui_boot_action_command(snapshot_connect, 4) == "/provider gemini"

    snapshot_ready = {
        "provider_ready": True,
        "provider": "gemini",
        "active_provider": "gemini",
        "usable_targets": ["docker"],
        "status": "ready",
        "latest_quick_action": {"status": "ok"},
        "focus_title": "ok",
        "focus_body": "ok",
        "quick_action_items": [],
    }
    assert _resolve_tui_boot_action_command(snapshot_ready, 1) == "/scan"
    assert _resolve_tui_boot_action_command(snapshot_ready, 2) == "/brief"
    assert _resolve_tui_boot_action_command(snapshot_ready, 3) == "/next"
    assert _resolve_tui_boot_action_command(snapshot_ready, 4) == "/doctor strict"


def test_handle_tui_input_go_show_mentions_four_actions() -> None:
    output = _handle_tui_input("/go show", {"provider": "auto", "model": "gpt-5.4-mini"})
    assert "用法：/go 1|2|3|4" in output


def test_render_tui_success_card_has_three_sections() -> None:
    out = _render_tui_success_card("操作已完成\n- pod_count=12\n- warn=0", request="检查 k8s")
    assert "Done" in out
    assert "Conclusion" in out
    assert "Evidence" in out
    assert "Next" in out


def test_pick_tui_next_command_prefers_trace_after_failure() -> None:
    command = _pick_tui_next_command(
        {
            "provider_ready": True,
            "usable_targets": ["docker"],
            "status": "ready",
            "latest_quick_action": {"status": "fail", "command": "/do 1"},
            "focus_title": "x",
            "focus_body": "y",
            "quick_action_items": [{"id": "1", "command": "/trace"}],
        }
    )
    assert command == "/trace"


def test_pick_tui_next_command_resolves_go_primary_command() -> None:
    command = _pick_tui_next_command(
        {
            "provider_ready": False,
            "provider": "auto",
            "active_provider": "auto->mock",
            "usable_targets": [],
            "status": "cold-start",
            "latest_quick_action": {},
        }
    )
    assert command == "/quickstart"


def test_pick_tui_next_command_prefers_brief_for_cold_start() -> None:
    command = _pick_tui_next_command(
        {
            "provider_ready": True,
            "provider": "gemini",
            "active_provider": "gemini",
            "usable_targets": ["docker"],
            "status": "cold-start",
            "latest_quick_action": {"status": "ok"},
        }
    )
    assert command == "/brief"


def test_normalize_tui_ui_mode_defaults_to_simple() -> None:
    assert _normalize_tui_ui_mode("simple") == "simple"
    assert _normalize_tui_ui_mode("expert") == "expert"
    assert _normalize_tui_ui_mode("advanced") == "expert"
    assert _normalize_tui_ui_mode("weird") == "simple"


def test_toggle_tui_ui_mode_roundtrip() -> None:
    assert _toggle_tui_ui_mode("simple") == "expert"
    assert _toggle_tui_ui_mode("expert") == "simple"
    assert _toggle_tui_ui_mode("advanced") == "simple"


def test_sanitize_tui_secret_tokens_masks_google_key() -> None:
    raw = "error: key=google-api-key-demo-value"
    masked = _sanitize_tui_secret_tokens(raw)
    assert "google-api-key-demo-value" not in masked
    assert "key=***REDACTED***" in masked


def test_sanitize_tui_secret_tokens_masks_password_phrase() -> None:
    raw = "我有一个k8s集群，ip是10.0.0.1，root密码是demo-password"
    masked = _sanitize_tui_secret_tokens(raw)
    assert "demo-password" not in masked
    assert "密码=***REDACTED***" in masked


def test_sanitize_tui_secret_tokens_masks_proxy_userinfo() -> None:
    raw = "ALL_PROXY=socks5://myuser:mypass@example.com:1080"
    masked = _sanitize_tui_secret_tokens(raw)
    assert "myuser:mypass@" not in masked
    assert "://***:***@" in masked


def test_format_tui_output_for_display_renders_error_card() -> None:
    out = _format_tui_output_for_display("error: Client error '400 Bad Request' for url 'https://x?key=abc'")
    assert "Needs Attention" in out
    assert "Reason" in out
    assert "Do Now" in out
    assert "Fallback" in out


def test_format_tui_output_for_display_renders_degraded_card_for_auto_fallback() -> None:
    out = _format_tui_output_for_display(
        "[auto-fallback]\nProvider `gemini` 调用失败，已自动降级到 mock（仅建议/低风险模式）。 原因: Gemini API HTTP 400: bad request"
    )
    assert "Result: Degraded" in out
    assert "Do Now:" in out
    assert "Provider `gemini` 调用失败" in out or "Gemini API HTTP 400" in out


def test_maybe_apply_tui_provider_fallback_switches_to_mock() -> None:
    options = {"provider": "gemini", "model": "gemini-2.5-flash"}
    note = _maybe_apply_tui_provider_fallback(
        options,
        "[auto-fallback]\nProvider `gemini` 调用失败，已自动降级到 mock（仅建议/低风险模式）。",
    )
    assert options["provider"] == "mock"
    assert "gpt" in str(options["model"]).lower()
    assert "自动切换为 mock" in note


def test_maybe_apply_tui_provider_fallback_noop_for_normal_output() -> None:
    options = {"provider": "gemini", "model": "gemini-2.5-flash"}
    note = _maybe_apply_tui_provider_fallback(options, "Result: Success\nAll good")
    assert note == ""
    assert options["provider"] == "gemini"


def test_render_tui_completion_card_keeps_failed_card() -> None:
    out = _render_tui_completion_card("Result: Failed\nReason: bad key", request="check", duration_ms=8)
    assert "Result: Success" not in out
    assert "Result: Failed" in out


def test_render_tui_simple_result_card_summarizes_markdown_style_output() -> None:
    raw = "\n".join(
        [
            "Status: Diagnosing",
            "Reasoning: 已定位到 swarm 副本不足与镜像拉取失败。",
            "Risk Level: High - service update 可能抖动",
            "Commands:",
            "docker service ps lazysre_lazysre --no-trunc",
            "docker service logs --tail 200 lazysre_lazysre",
            "docker service update --force lazysre_lazysre",
        ]
    )
    out = _render_tui_simple_result_card(raw, request="检查 swarm")
    assert "Done" in out
    assert "Status  Diagnosing" in out
    assert "Summary" in out
    assert "Risk" in out
    assert "Commands" in out
    assert "docker service update --force lazysre_lazysre" in out
    assert "Next" in out


def test_render_tui_completion_card_uses_simple_summary_mode() -> None:
    raw = "\n".join(
        [
            "## Status",
            "Diagnosing",
            "## Reasoning",
            "已完成首轮定位",
            "## Commands",
            "kubectl get pods -A",
        ]
    )
    out = _render_tui_completion_card(raw, request="检查 k8s", duration_ms=12, ui_mode="simple")
    assert "Result" in out
    assert "Status" in out
    assert "Summary" in out
    assert "Commands" in out
    assert "## Reasoning" not in out


def test_render_tui_completion_card_expert_keeps_detailed_mode() -> None:
    raw = "操作已完成\n- pod_count=12\n- warn=0"
    out = _render_tui_completion_card(raw, request="检查 k8s", duration_ms=9, ui_mode="expert")
    assert "Done" in out
    assert "Evidence" in out
    assert "Next" in out


def test_handle_tui_input_ui_switches_mode() -> None:
    options = {"tui_ui_mode": "simple"}
    res = cli_main._handle_tui_input("/ui expert", options)
    assert "expert" in res
    assert options["tui_ui_mode"] == "expert"


def test_render_tui_quick_help_text_contains_core_guidance() -> None:
    text = _render_tui_quick_help_text(
        {
            "mode": "dry-run",
            "provider": "auto",
            "active_provider": "auto->mock",
            "status": "ready",
            "latest_quick_action": {"status": "ok", "command": "/scan"},
        }
    )
    assert "Quick Help" in text
    assert "/next" in text
    assert "/scan" in text
    assert "/brief" in text
    assert "/providers" in text
    assert "/doctor" in text
    assert "/secret-scan" in text
    assert "Shift+N/T/U/R" in text


def test_handle_tui_input_help_returns_quick_help(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {"mode": "dry-run", "provider": "mock", "active_provider": "mock", "status": "ready"},
    )
    out = _handle_tui_input("/help", {"execute": False})
    assert "Quick Help" in out
    assert "/next" in out
    assert "Brand" not in out


def test_handle_tui_input_help_full_returns_demo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {"mode": "dry-run", "provider": "mock", "active_provider": "mock", "status": "ready"},
    )
    out = _handle_tui_input("/help full", {"execute": False})
    assert "LazySRE Console" in out
    assert "Overview" in out


def test_tui_runtime_state_roundtrip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state_file = tmp_path / "lsre-tui-state.json"
    monkeypatch.setattr(cli_main, "_tui_state_file", lambda: state_file)

    _save_tui_runtime_state(panel="providers", ui_mode="expert")
    state = _load_tui_runtime_state()
    assert state["panel"] == "providers"
    assert state["ui_mode"] == "expert"


def test_apply_saved_tui_runtime_state_keeps_simple_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state_file = tmp_path / "lsre-tui-state.json"
    monkeypatch.setattr(cli_main, "_tui_state_file", lambda: state_file)
    _save_tui_runtime_state(panel="timeline", ui_mode="expert")

    options: dict[str, object] = {"tui_panel": "overview", "tui_ui_mode": "simple"}
    _apply_saved_tui_runtime_state(options)
    assert options["tui_panel"] == "timeline"
    assert options["tui_ui_mode"] == "simple"


def test_apply_saved_tui_runtime_state_can_restore_expert(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state_file = tmp_path / "lsre-tui-state.json"
    monkeypatch.setattr(cli_main, "_tui_state_file", lambda: state_file)
    monkeypatch.setenv("LAZYSRE_TUI_RESTORE_UI", "1")
    _save_tui_runtime_state(panel="timeline", ui_mode="expert")

    options: dict[str, object] = {"tui_panel": "overview", "tui_ui_mode": "simple"}
    _apply_saved_tui_runtime_state(options)
    assert options["tui_panel"] == "timeline"
    assert options["tui_ui_mode"] == "expert"


def test_switch_tui_panel_persists_state(monkeypatch: pytest.MonkeyPatch) -> None:
    persisted: dict[str, object] = {}
    monkeypatch.setattr(cli_main, "_persist_tui_runtime_state", lambda opts: persisted.update(opts))

    options: dict[str, object] = {"tui_panel": "overview", "tui_ui_mode": "simple"}
    output = _switch_tui_panel(options, "providers")
    assert "已切换左侧面板" in output
    assert options["tui_panel"] == "providers"
    assert persisted.get("tui_panel") == "providers"


def test_handle_tui_input_retry_uses_last_input() -> None:
    options = {"execute": False, "tui_last_input": "/mode show"}
    output = _handle_tui_input("/retry", options)
    assert "重试上一条: /mode show" in output
    assert "当前模式: dry-run" in output


def test_handle_tui_input_retry_falls_back_to_recent_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {"recent_commands": ["/mode show"]},
    )
    output = _handle_tui_input("/retry", {"execute": False})
    assert "重试上一条: /mode show" in output
    assert "当前模式: dry-run" in output


def test_handle_tui_input_history_show(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {"recent_commands": ["/mode show"], "recent_commands_full": ["/scan", "/mode show", "检查 swarm"]},
    )
    output = _handle_tui_input("/history", {"execute": False})
    assert "History (latest first)" in output
    assert "- 1. 检查 swarm" in output
    assert "- 3. /scan" in output


def test_handle_tui_input_history_search(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {
            "recent_commands": ["/mode show"],
            "recent_commands_full": ["/scan", "/mode show", "检查 swarm", "检查 k8s pod"],
        },
    )
    output = _handle_tui_input("/history k8s", {"execute": False})
    assert "History Search: k8s" in output
    assert "检查 k8s pod" in output
    assert "/scan" not in output


def test_render_history_text_no_match() -> None:
    output = _render_history_text(["/scan", "检查 swarm"], query="k8s")
    assert "没有匹配结果" in output
    assert "/history 查看全部历史" in output


def test_handle_tui_input_history_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {"recent_commands": ["/mode show"], "recent_commands_full": ["/scan", "/mode show", "检查 swarm"]},
    )
    output = _handle_tui_input("/history 2", {"execute": False})
    assert "重放历史[2]: /mode show" in output
    assert "当前模式: dry-run" in output


def test_handle_tui_input_history_replay_accepts_ordinal_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {"recent_commands": ["/mode show"], "recent_commands_full": ["/scan", "/mode show", "检查 swarm"]},
    )
    output = _handle_tui_input("/history 第二条", {"execute": False})
    assert "重放历史[2]: /mode show" in output
    assert "当前模式: dry-run" in output


def test_collect_snapshot_recent_commands_prefers_full() -> None:
    rows = _collect_snapshot_recent_commands(
        {"recent_commands": ["/mode show"], "recent_commands_full": ["/scan", "/mode show", "检查 swarm"]},
        limit=12,
    )
    assert rows == ["/scan", "/mode show", "检查 swarm"]


def test_handle_tui_input_unknown_slash_command_returns_hint() -> None:
    output = _handle_tui_input("/foobar", {"execute": False})
    assert "未知命令" in output
    assert "/help" in output


def test_handle_tui_input_quick_phrase_history(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {"recent_commands": ["/scan", "/mode show"]},
    )
    output = _handle_tui_input("历史", {"execute": False})
    assert "History (latest first)" in output
    assert "/mode show" in output


def test_handle_tui_input_quick_phrase_next(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_build_tui_dashboard_snapshot", lambda options: {"status": "ready"})
    monkeypatch.setattr(cli_main, "_pick_tui_next_command", lambda snapshot: "/mode show")
    output = _handle_tui_input("继续", {"execute": False})
    assert "自动执行下一步: /mode show" in output
    assert "当前模式: dry-run" in output


def test_handle_tui_input_do_accepts_ordinal_token(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[int] = []

    def _fake_run_quick_action_item(*, options: dict[str, object], action_id: int, execute_mode: bool):
        called.append(action_id)
        return True, "Quick Action Result\n- ok"

    monkeypatch.setattr(cli_main, "_run_quick_action_item", _fake_run_quick_action_item)

    output = _handle_tui_input("/do 第一步", {"execute": False})
    assert "Quick Action Result" in output
    assert called == [1]


def test_handle_tui_input_bare_do_command(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[int] = []

    def _fake_run_quick_action_item(*, options: dict[str, object], action_id: int, execute_mode: bool):
        called.append(action_id)
        return True, "Quick Action Result\n- ok"

    monkeypatch.setattr(cli_main, "_run_quick_action_item", _fake_run_quick_action_item)

    output = _handle_tui_input("do 1", {"execute": False})
    assert "Quick Action Result" in output
    assert called == [1]


def test_handle_tui_input_go_accepts_circled_number(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_build_tui_dashboard_snapshot", lambda options: {"status": "ready"})
    monkeypatch.setattr(
        cli_main,
        "_resolve_tui_boot_action_command",
        lambda snapshot, action_id: "/mode show" if action_id == 3 else "",
    )
    output = _handle_tui_input("/go ③", {"execute": False})
    assert "执行引导动作: /mode show" in output
    assert "当前模式: dry-run" in output


def test_handle_tui_input_bare_provider_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_switch_runtime_provider", lambda options, provider_name: f"switch:{provider_name}")
    out = _handle_tui_input("provider mock", {"execute": False, "provider": "auto"})
    assert out == "switch:mock"


def test_handle_tui_input_secret_scan_renders_doctor_report(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_collect_secret_scan_report",
        lambda root=None, max_findings=8, staged=False: {
            "checks": [
                {
                    "name": "runtime.workspace_secret_scan",
                    "ok": False,
                    "severity": "error",
                    "detail": "detected 1 suspicious token(s): src/app.py:7",
                    "hint": "rotate now",
                }
            ],
            "summary": {"pass": 0, "warn": 0, "error": 1, "healthy": False},
        },
    )
    output = _handle_tui_input("/secret-scan", {"execute": False})
    assert "workspace_secret_scan" in output
    assert "detected 1 suspicious token" in output


def test_handle_tui_input_secret_scan_with_tail_still_runs_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_collect_secret_scan_report",
        lambda root=None, max_findings=8, staged=False: {
            "checks": [{"name": "runtime.workspace_secret_scan", "ok": True, "severity": "pass", "detail": "ok", "hint": ""}],
            "summary": {"pass": 1, "warn": 0, "error": 0, "healthy": True},
        },
    )
    output = _handle_tui_input("/secret-scan --json", {"execute": False})
    assert "workspace_secret_scan" in output


def test_handle_tui_input_doctor_install_renders_report(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_collect_install_doctor_report",
        lambda: {
            "checks": [{"name": "runtime.python_version", "ok": True, "severity": "pass", "detail": "3.11", "hint": ""}],
            "summary": {"pass": 1, "warn": 0, "error": 0, "healthy": True},
        },
    )
    output = _handle_tui_input("/doctor install", {"execute": False})
    assert "runtime.python_version" in output


def test_handle_tui_input_quick_phrase_secret_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_collect_secret_scan_report",
        lambda root=None, max_findings=8, staged=False: {
            "checks": [{"name": "runtime.workspace_secret_scan", "ok": True, "severity": "pass", "detail": "ok", "hint": ""}],
            "summary": {"pass": 1, "warn": 0, "error": 0, "healthy": True},
        },
    )
    output = _handle_tui_input("密钥检查", {"execute": False})
    assert "workspace_secret_scan" in output


def test_handle_tui_input_secret_scan_parses_staged_and_max_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _fake_report(*, root=None, max_findings=8, staged=False):
        captured["max_findings"] = max_findings
        captured["staged"] = staged
        return {
            "checks": [{"name": "runtime.workspace_secret_scan", "ok": True, "severity": "pass", "detail": "ok", "hint": ""}],
            "summary": {"pass": 1, "warn": 0, "error": 0, "healthy": True},
        }

    monkeypatch.setattr(cli_main, "_collect_secret_scan_report", _fake_report)
    output = _handle_tui_input("/secret-scan --staged --max-findings 3", {"execute": False})
    assert "workspace_secret_scan" in output
    assert captured["staged"] is True
    assert captured["max_findings"] == 3


def test_handle_tui_input_preflight_parses_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _fake_preflight(
        *,
        profile_file: Path,
        timeout_sec: int,
        dry_run_probe: bool,
        strict: bool,
        staged: bool,
        max_findings: int,
        audit_log: Path,
    ) -> dict[str, object]:
        captured["profile_file"] = str(profile_file)
        captured["timeout_sec"] = timeout_sec
        captured["dry_run_probe"] = dry_run_probe
        captured["strict"] = strict
        captured["staged"] = staged
        captured["max_findings"] = max_findings
        captured["audit_log"] = str(audit_log)
        return {
            "checks": [{"name": "runtime.preflight", "ok": True, "severity": "pass", "detail": "ok", "hint": ""}],
            "summary": {"pass": 1, "warn": 0, "error": 0, "healthy": True},
            "gate": {"healthy": True},
        }

    monkeypatch.setattr(cli_main, "_collect_preflight_report", _fake_preflight)
    output = _handle_tui_input("/preflight --strict --all-files --max-findings 5 --timeout-sec 9", {"execute": False})
    assert "runtime.preflight" in output
    assert captured["strict"] is True
    assert captured["staged"] is False
    assert captured["max_findings"] == 5
    assert captured["timeout_sec"] == 9
    assert captured["dry_run_probe"] is True


def test_resolve_tui_numeric_shortcut_prefers_do_when_action_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {"quick_action_items": [{"id": "1", "command": "/trace"}]},
    )
    assert _resolve_tui_numeric_shortcut_command("1", options={"execute": False}) == "/do 1"


def test_resolve_tui_numeric_shortcut_falls_back_to_go(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_build_tui_dashboard_snapshot", lambda options: {"quick_action_items": []})
    assert _resolve_tui_numeric_shortcut_command("2", options={"execute": False}) == "/go 2"
    assert _resolve_tui_numeric_shortcut_command("9", options={"execute": False}) == ""


def test_resolve_tui_numeric_shortcut_accepts_ordinal_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {"quick_action_items": [{"id": "1", "command": "/trace"}]},
    )
    assert _resolve_tui_numeric_shortcut_command("①", options={"execute": False}) == "/do 1"
    assert _resolve_tui_numeric_shortcut_command("#1", options={"execute": False}) == "/do 1"
    assert _resolve_tui_numeric_shortcut_command("第1步", options={"execute": False}) == "/do 1"
    assert _resolve_tui_numeric_shortcut_command("no.1", options={"execute": False}) == "/do 1"


def test_resolve_tui_numeric_shortcut_rejects_non_ordinal_phrase(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_build_tui_dashboard_snapshot", lambda options: {"quick_action_items": []})
    assert _resolve_tui_numeric_shortcut_command("我有一个k8s集群", options={"execute": False}) == ""


def test_looks_like_ordinal_shortcut_detection() -> None:
    assert _looks_like_ordinal_shortcut("③")
    assert _looks_like_ordinal_shortcut("第1步")
    assert _looks_like_ordinal_shortcut("#2")
    assert _looks_like_ordinal_shortcut("no.3")
    assert not _looks_like_ordinal_shortcut("继续排查")
    assert not _looks_like_ordinal_shortcut("我有一个k8s集群")


def test_resolve_tui_empty_submit_command_for_new_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_pick_tui_next_command", lambda snapshot: "/next")
    command = _resolve_tui_empty_submit_command(
        snapshot={"status": "cold-start"},
        history=[("LazySRE", "welcome")],
    )
    assert command == "/next"


def test_resolve_tui_empty_submit_command_ignores_after_user_input(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_pick_tui_next_command", lambda snapshot: "/next")
    command = _resolve_tui_empty_submit_command(
        snapshot={"status": "ready"},
        history=[("LazySRE", "welcome"), ("You", "检查环境")],
    )
    assert command == ""


def test_handle_incident_inline_command_open_note_close(tmp_path: Path) -> None:
    path = tmp_path / "incident.json"
    opened = _handle_incident_inline_command("/incident open 支付服务延迟", path=path)
    assert "Incident" in opened
    assert "status: open" in opened
    noted = _handle_incident_inline_command("/incident note 已执行scan", path=path)
    assert "Incident" in noted
    closed = _handle_incident_inline_command("/incident close 已恢复", path=path)
    assert "status: closed" in closed


def test_handle_incident_inline_command_uses_default_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)
    opened = _handle_incident_inline_command("/incident open 默认路径")
    assert "status: open" in opened
    assert (tmp_path / "lsre-incident.json").exists()


def test_handle_tui_input_incident_respects_incident_file_option(tmp_path: Path) -> None:
    path = tmp_path / "custom-incident.json"
    options = {"incident_file": str(path)}
    output = _handle_tui_input("/incident open tui incident", options)
    assert "status: open" in output
    assert path.exists()


def test_build_tui_prompt_line_and_cursor_handles_mixed_cn_en() -> None:
    prompt, cursor_x = _build_tui_prompt_line_and_cursor(input_text="我又一k8s", cursor_index=4, width=40)

    assert prompt.startswith("lsre> 我又一k8s")
    assert cursor_x == 13


def test_normalize_runtime_exception_message_for_socks_proxy_error() -> None:
    msg = _normalize_runtime_exception_message(
        RuntimeError(
            "Using SOCKS proxy, but the 'socksio' package is not installed. "
            "Make sure to install httpx using `pip install httpx[socks]`."
        )
    )
    assert "fix:" in msg
    assert "httpx[socks]" in msg
    assert "ALL_PROXY" in msg


def test_normalize_runtime_exception_message_redacts_google_api_key() -> None:
    raw = (
        "Client error '400 Bad Request' for url "
        "'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        "?key=google-api-key-demo-value'"
    )
    msg = _normalize_runtime_exception_message(RuntimeError(raw))
    assert "google-api-key-demo-value" not in msg
    assert "key=***REDACTED***" in msg


def test_should_auto_fallback_to_mock_detects_provider_runtime_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LAZYSRE_DISABLE_MOCK_FALLBACK", raising=False)
    assert _should_auto_fallback_to_mock(
        provider_mode="gemini",
        error=RuntimeError("Gemini API HTTP 400: API key not valid"),
    )
    assert not _should_auto_fallback_to_mock(
        provider_mode="mock",
        error=RuntimeError("Gemini API HTTP 400: API key not valid"),
    )


def test_should_auto_fallback_to_mock_respects_disable_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LAZYSRE_DISABLE_MOCK_FALLBACK", "1")
    assert not _should_auto_fallback_to_mock(
        provider_mode="gemini",
        error=RuntimeError("Gemini API HTTP 400: API key not valid"),
    )


def test_maybe_apply_runtime_provider_fallback_switches_session_to_mock() -> None:
    options = {"provider": "gemini", "model": "gemini-2.5-flash"}
    result = DispatchResult(
        final_text="[auto-fallback]\nProvider `gemini` 调用失败",
        events=[
            cli_main.DispatchEvent(
                kind="system",
                message="provider_fallback",
                data={
                    "from": "gemini",
                    "to": "mock",
                    "reason": "Gemini API HTTP 400: API key not valid. key=google-api-key-demo-value",
                },
            )
        ],
    )

    note = _maybe_apply_runtime_provider_fallback(options, result)
    assert options["provider"] == "mock"
    assert options["model"] == cli_main.resolve_model_name("openai", settings.model_name)
    assert "google-api-key-demo-value" not in note
    assert "切换到 `mock`" in note


def test_maybe_apply_runtime_provider_fallback_no_event_is_noop() -> None:
    options = {"provider": "gemini", "model": "gemini-2.5-flash"}
    result = DispatchResult(final_text="ok", events=[])
    note = _maybe_apply_runtime_provider_fallback(options, result)
    assert note == ""
    assert options["provider"] == "gemini"


def test_dispatch_auto_fallback_to_mock(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class _PrimaryLLM:
        pass

    class _FakeDispatcher:
        def __init__(self, *, llm, **kwargs):  # noqa: ANN003
            self._llm = llm

        async def run(self, instruction: str) -> DispatchResult:
            if isinstance(self._llm, cli_main.MockFunctionCallingLLM):
                return DispatchResult(final_text="mock response", events=[])
            raise RuntimeError("Gemini API HTTP 400: API key not valid. key=google-api-key-demo-value")

    def _fake_build_cli_llm(provider: str, model: str):
        if provider == "mock":
            return "mock", "gpt-5.4-mini", cli_main.MockFunctionCallingLLM()
        return "gemini", "gemini-2.5-flash", _PrimaryLLM()

    monkeypatch.setattr(cli_main, "Dispatcher", _FakeDispatcher)
    monkeypatch.setattr(cli_main, "_build_cli_llm", _fake_build_cli_llm)
    monkeypatch.delenv("LAZYSRE_DISABLE_MOCK_FALLBACK", raising=False)

    result = asyncio.run(
        cli_main._dispatch(
            instruction="检查环境",
            execute=False,
            approve=False,
            interactive_approval=False,
            approval_mode="balanced",
            audit_log=str(tmp_path / "audit.jsonl"),
            lock_file=str(tmp_path / "lock.json"),
            deny_tool=[],
            deny_prefix=[],
            tool_pack=["builtin"],
            remote_gateway=[],
            model="gpt-5.4-mini",
            provider="gemini",
            max_steps=3,
            text_stream=None,
            conversation_context="",
            memory_context="",
        )
    )
    assert "[auto-fallback]" in result.final_text
    assert "mock response" in result.final_text
    assert "google-api-key-demo-value" not in result.final_text
    assert result.events
    assert result.events[0].message == "provider_fallback"


def test_render_tui_demo_text_shows_swarm_posture_block() -> None:
    rendered = _render_tui_demo_text(
        {
            "version": "0.1.1",
            "mode": "dry-run",
            "provider": "mock",
            "model": "gpt-5.4-mini",
            "sidebar_panel": "overview",
            "panel_hint": "hint",
            "status": "attention",
            "headline": "headline",
            "focus_title": "Swarm Posture",
            "focus_body": "api needs repair",
            "swarm_posture": {
                "headline": "Swarm 主要阻塞点是 api，根因倾向 swarm_image_pull_failed。",
                "signals": ["top_root_cause=swarm_image_pull_failed", "focus_service=api"],
            },
            "active_provider": "mock",
            "usable_targets": ["docker-swarm"],
            "configured_providers": ["mock"],
            "namespace": "default",
            "ssh_target": "",
            "prometheus_url": "",
            "session_turns": 1,
            "last_user": "",
            "recent_activity": [],
            "recent_activity_commands": [],
            "focus_actions": ["lazysre swarm --service api --logs"],
            "quick_action_items": [],
            "latest_quick_action": {},
            "recommended_commands": ["/swarm --logs"],
            "recent_commands": [],
            "trace_summary": [],
            "timeline_entries": [],
            "shortcuts": ["/swarm --logs"],
            "environment_profile": "Observed Swarm",
            "environment_summary": "Observed Swarm; swarm=3 services",
            "environment_signals": ["Swarm active，services=3"],
        }
    )

    assert "Swarm Posture" in rendered
    assert "swarm_image_pull_failed" in rendered


def test_build_tui_status_hint_line_uses_panel() -> None:
    line = _build_tui_status_hint_line({"sidebar_panel": "timeline"})
    assert line.startswith("hint>")
    assert "执行轨迹" in line


def test_build_tui_status_hint_line_prioritizes_failed_quick_action() -> None:
    line = _build_tui_status_hint_line(
        {"sidebar_panel": "overview", "latest_quick_action": {"status": "fail", "command": "/swarm --logs"}}
    )
    assert "/trace" in line
    assert "/timeline" in line


def test_quick_action_kind_classifies_common_commands() -> None:
    assert cli_main._classify_quick_action_kind("/trace") == "inspect"
    assert cli_main._classify_quick_action_kind("lazysre template run swarm-image-pull-failed --var service=api --apply") == "template"
    assert cli_main._classify_quick_action_kind("lazysre remote root@192.168.10.101 --logs") == "remote"
    assert cli_main._classify_quick_action_kind("docker service update --force api") == "write"
    assert cli_main._classify_quick_action_risk("/trace") == "low"
    assert cli_main._classify_quick_action_risk("lazysre template run swarm-image-pull-failed --var service=api --apply") == "high"
    assert cli_main._classify_quick_action_risk("lazysre remote root@192.168.10.101 --logs") == "low"
    assert cli_main._classify_quick_action_risk("docker service update --force api") == "high"


def test_sort_quick_action_catalog_prefers_low_risk_inspect_in_normal_state() -> None:
    items = [
        {"id": "1", "title": "Apply", "source": "recommended", "command": "docker service update --force api", "kind": "write", "risk": "high"},
        {"id": "2", "title": "Trace", "source": "focus", "command": "/trace", "kind": "inspect", "risk": "low"},
        {"id": "3", "title": "Scan", "source": "recommended", "command": "lazysre scan", "kind": "inspect", "risk": "low"},
    ]

    sorted_items = cli_main._sort_quick_action_catalog(items, latest_result={})

    assert sorted_items[0]["command"] == "/trace"
    assert sorted_items[1]["command"] == "lazysre scan"
    assert sorted_items[-1]["command"] == "docker service update --force api"


def test_sort_quick_action_catalog_demotes_latest_successful_command() -> None:
    items = [
        {"id": "1", "title": "Trace", "source": "focus", "command": "/trace", "kind": "inspect", "risk": "low"},
        {"id": "2", "title": "Scan", "source": "recommended", "command": "lazysre scan", "kind": "inspect", "risk": "low"},
    ]

    sorted_items = cli_main._sort_quick_action_catalog(items, latest_result={"status": "ok", "command": "/trace"})

    assert sorted_items[0]["command"] == "lazysre scan"
    assert sorted_items[1]["command"] == "/trace"


def test_sort_quick_action_catalog_prioritizes_trace_after_failure() -> None:
    items = [
        {"id": "1", "title": "Apply", "source": "recommended", "command": "docker service update --force api", "kind": "write", "risk": "high"},
        {"id": "2", "title": "Timeline", "source": "focus", "command": "/timeline", "kind": "inspect", "risk": "low"},
        {"id": "3", "title": "Trace", "source": "focus", "command": "/trace", "kind": "inspect", "risk": "low"},
    ]

    sorted_items = cli_main._sort_quick_action_catalog(items, latest_result={"status": "fail"})

    assert sorted_items[0]["command"] == "/trace"
    assert sorted_items[1]["command"] == "/timeline"
    assert sorted_items[-1]["command"] == "docker service update --force api"


def test_build_tui_state_card_skips_latest_successful_command() -> None:
    card = cli_main._build_tui_state_card(
        {
            "focus_title": "Ready",
            "focus_body": "no blocker",
            "latest_quick_action": {"status": "ok", "command": "/trace"},
            "quick_action_items": [
                {"id": "1", "command": "/trace"},
                {"id": "2", "command": "lazysre scan"},
            ],
            "focus_actions": ["/activity"],
        }
    )
    assert card["next"] == "/do 2 -> lazysre scan"


def test_build_tui_action_bar_changes_by_panel() -> None:
    overview_bar = _build_tui_action_bar({"sidebar_panel": "overview"})
    activity_bar = _build_tui_action_bar({"sidebar_panel": "activity"})
    timeline_bar = _build_tui_action_bar({"sidebar_panel": "timeline"})
    provider_bar = _build_tui_action_bar({"sidebar_panel": "providers"})

    assert "/focus" in overview_bar
    assert "/do 1" in overview_bar
    assert "/do 1" in activity_bar
    assert "/trace" in timeline_bar
    assert "/providers" in provider_bar
    assert "/preflight" in provider_bar
    assert "Overview" in timeline_bar


def test_build_tui_action_bar_prioritizes_trace_after_failed_quick_action() -> None:
    bar = _build_tui_action_bar({"sidebar_panel": "overview", "latest_quick_action": {"status": "fail", "command": "/do 1"}})
    assert "/trace" in bar
    assert "/timeline" in bar
    assert "/do 1" in bar


def test_build_tui_sidebar_lines_honors_selected_panel() -> None:
    snapshot = {
        "sidebar_panel": "timeline",
        "status": "attention",
        "mode": "dry-run",
        "provider": "auto",
        "model": "gpt-5.4-mini",
        "focus_title": "Recent Failure",
        "focus_body": "08:31 [apply/exec] docker service update --force api",
        "focus_actions": ["/trace", "/timeline"],
        "usable_targets": ["docker", "kubernetes"],
        "configured_providers": ["openai", "compatible"],
        "namespace": "ops",
        "ssh_target": "root@10.0.0.8",
        "prometheus_url": "http://127.0.0.1:9090",
        "session_turns": 3,
        "timeline_entries": ["08:30 [ok/exec] docker service ls"],
        "recent_commands": ["/scan", "/timeline"],
        "recent_activity": ["watch attention alerts=1 cycle=2"],
        "recent_activity_commands": ["/activity"],
        "recommended_commands": ["lazysre brief"],
        "shortcuts": ["/brief", "/timeline", "/panel next"],
    }

    lines = _build_tui_sidebar_lines(snapshot, width=32)
    joined = "\n".join(lines)

    assert "Panels:" in joined
    assert "◉ LazySRE" in joined
    assert "AI Operations Console" in joined
    assert "[3:timeline(1)]" in joined
    assert "hint:" in joined
    assert "panel: timeline" in joined
    assert "Execution Timeline:" in joined
    assert "Command Trail:" in joined
    assert "Recent Activity:" not in joined


def test_build_tui_sidebar_lines_overview_shows_focus_section() -> None:
    snapshot = {
        "sidebar_panel": "overview",
        "panel_hint": _build_tui_panel_hint("overview"),
        "status": "attention",
        "mode": "dry-run",
        "provider": "auto",
        "model": "gpt-5.4-mini",
        "focus_title": "Active Alert",
        "focus_body": "watch attention alerts=1 cycle=2",
        "focus_actions": ["/activity", "/scan"],
        "quick_action_items": [
            {"id": "1", "title": "Active Alert", "source": "focus", "command": "/activity", "last_status": "ok"},
            {"id": "2", "title": "Recommended", "source": "recommended", "command": "/scan"},
        ],
        "latest_quick_action": {"status": "ok", "command": "/activity", "output_preview": "Recent Activity ready"},
        "usable_targets": ["docker"],
        "configured_providers": ["mock"],
        "namespace": "default",
        "ssh_target": "",
        "prometheus_url": "",
        "session_turns": 1,
        "timeline_entries": [],
        "trace_summary": [],
        "recent_commands": [],
        "recent_activity": [],
        "recent_activity_commands": [],
        "recommended_commands": ["/scan"],
        "shortcuts": ["/focus", "/brief", "/scan"],
        "headline": "当前环境可直接巡检",
        "last_user": "检查当前环境",
    }

    joined = "\n".join(_build_tui_sidebar_lines(snapshot, width=36))

    assert "focus: Active Alert" in joined
    assert "quick: ok:/activity" in joined
    assert "next: /do 2 -> /scan" in joined
    assert "Focus:" in joined
    assert "Focus Actions:" in joined
    assert "Quick Actions:" in joined
    assert "Last Quick Action:" in joined
    assert "[inspect][low][focus] Active" in joined
    assert "Alert [last=ok]" in joined
    assert "[last=ok]" in joined
    assert "cmd: /activity" in joined
    assert "/activity" in joined


def test_tui_demo_state_card_prioritizes_debug_after_failure() -> None:
    rendered = _render_tui_demo_text(
        {
            "version": "0.1.1",
            "mode": "dry-run",
            "provider": "mock",
            "model": "gpt-5.4-mini",
            "sidebar_panel": "overview",
            "panel_hint": "hint",
            "status": "attention",
            "headline": "headline",
            "focus_title": "Recent Failure",
            "focus_body": "payment remediation failed",
            "active_provider": "mock",
            "usable_targets": ["docker"],
            "configured_providers": ["mock"],
            "namespace": "default",
            "ssh_target": "",
            "prometheus_url": "",
            "session_turns": 1,
            "last_user": "修复 payment",
            "recent_activity": [],
            "recent_activity_commands": [],
            "focus_actions": ["/trace", "/timeline"],
            "quick_action_items": [{"id": "1", "command": "/swarm --logs", "last_status": "fail"}],
            "latest_quick_action": {"status": "fail", "command": "/swarm --logs"},
            "recommended_commands": ["/trace"],
            "recent_commands": [],
            "trace_summary": [],
            "timeline_entries": [],
            "shortcuts": ["/do 1", "/trace"],
        }
    )
    assert "Next  /trace -> /timeline -> /do 1" in rendered


def test_build_tui_sidebar_lines_shows_empty_state_for_provider_panel() -> None:
    snapshot = {
        "sidebar_panel": "providers",
        "panel_hint": _build_tui_panel_hint("providers"),
        "status": "cold-start",
        "mode": "dry-run",
        "provider": "auto",
        "model": "gpt-5.4-mini",
        "usable_targets": [],
        "configured_providers": [],
        "namespace": "default",
        "ssh_target": "",
        "prometheus_url": "",
        "session_turns": 0,
        "timeline_entries": [],
        "trace_summary": [],
        "recent_commands": [],
        "recent_activity": [],
        "recent_activity_commands": [],
        "recommended_commands": [],
        "provider_report": {"providers": {}, "active_ready": False, "active_detail": ""},
        "shortcuts": ["/providers", "/panel next"],
    }

    joined = "\n".join(_build_tui_sidebar_lines(snapshot, width=32))

    assert "暂无可用 provider" in joined


def test_build_tui_sidebar_lines_shows_empty_state_for_activity_panel() -> None:
    snapshot = {
        "sidebar_panel": "activity",
        "panel_hint": _build_tui_panel_hint("activity"),
        "status": "cold-start",
        "mode": "dry-run",
        "provider": "auto",
        "model": "gpt-5.4-mini",
        "usable_targets": [],
        "configured_providers": [],
        "namespace": "default",
        "ssh_target": "",
        "prometheus_url": "",
        "session_turns": 0,
        "timeline_entries": [],
        "recent_commands": [],
        "recent_activity": [],
        "recent_activity_commands": [],
        "recommended_commands": [],
        "shortcuts": ["/activity", "/panel next"],
    }

    joined = "\n".join(_build_tui_sidebar_lines(snapshot, width=32))

    assert "暂无活动" in joined


def test_tui_completion_candidates_include_shortcuts_and_recommended() -> None:
    snapshot = {
        "shortcuts": ["/brief", "/scan", "/refresh", "/providers", "/do 1"],
        "recommended_commands": ["lazysre swarm --logs", "lazysre autopilot"],
    }

    candidates = _tui_completion_candidates("/r", snapshot)

    assert "/refresh" in candidates
    assert "/scan" not in candidates
    assert "/preflight" not in candidates

    preflight_candidates = _tui_completion_candidates("/pre", snapshot)
    assert "/preflight" in preflight_candidates


def test_handle_tui_input_drift_renders_drift_report(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {
            "environment_drift": {
                "exists": True,
                "status": "changed",
                "headline": "环境基线发生漂移：新增 prometheus 缺失 kubernetes",
                "signals": ["baseline=docker,kubernetes", "current=docker,prometheus"],
                "top_actions": ["lazysre scan"],
            }
        },
    )

    out = _handle_tui_input("/drift", {"execute": False})

    assert "Environment Drift" in out
    assert "新增 prometheus" in out
    assert "lazysre scan" in out


def test_handle_tui_input_do_runs_quick_action(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []
    snapshots = [
        {
            "quick_action_items": [
                {"id": "1", "title": "Focus", "source": "focus", "command": "/trace"}
            ]
        },
        {
            "focus_title": "Recent Failure",
            "focus_body": "08:31 [apply/exec] docker service update --force api",
            "quick_action_items": [
                {"id": "1", "title": "Trace", "source": "focus", "command": "/trace"}
            ],
        },
    ]

    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: snapshots.pop(0),
    )

    def fake_run(command_text: str, *, options: dict[str, object], execute_mode: bool) -> tuple[bool, str]:
        calls.append({"command_text": command_text, "options": options, "execute_mode": execute_mode})
        return True, "Trace Summary\n- steps=3 ok=3 fail=0"

    monkeypatch.setattr(cli_main, "_run_suggested_command", fake_run)

    out = _handle_tui_input("/do 1", {"execute": False})

    assert "Quick Action Result" in out
    assert "Trace Summary" in out
    assert "Focus Now" in out
    assert calls[0]["command_text"] == "/trace"
    assert calls[0]["execute_mode"] is False


def test_handle_tui_input_numeric_shortcut_runs_do(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "_build_tui_dashboard_snapshot",
        lambda options: {"focus_title": "Trace", "focus_body": "ok", "quick_action_items": [{"id": "1", "command": "/trace"}]},
    )
    monkeypatch.setattr(cli_main, "_run_suggested_command", lambda command_text, *, options, execute_mode: (True, "Trace OK"))
    output = _handle_tui_input("1", {"execute": False})
    assert "Quick Action Result" in output
    assert "Trace OK" in output


def test_handle_tui_input_numeric_shortcut_runs_go(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_build_tui_dashboard_snapshot", lambda options: {"quick_action_items": []})
    monkeypatch.setattr(cli_main, "_resolve_tui_boot_action_command", lambda snapshot, action_id: "/mode show")
    output = _handle_tui_input("1", {"execute": False})
    assert "执行引导动作: /mode show" in output
    assert "当前模式: dry-run" in output


def test_handle_tui_input_do_failed_action_prioritizes_trace(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshots = [
        {
            "quick_action_items": [
                {"id": "1", "title": "Focus", "source": "focus", "command": "/swarm --logs"}
            ]
        },
        {
            "focus_title": "Recent Failure",
            "focus_body": "swarm check failed",
            "quick_action_items": [
                {"id": "1", "title": "Focus", "source": "focus", "command": "/swarm --logs"}
            ],
            "latest_quick_action": {"status": "fail", "command": "/swarm --logs"},
        },
    ]

    monkeypatch.setattr(cli_main, "_build_tui_dashboard_snapshot", lambda options: snapshots.pop(0))
    monkeypatch.setattr(
        cli_main,
        "_run_suggested_command",
        lambda command_text, *, options, execute_mode: (False, "error: swarm service unhealthy"),
    )

    out = _handle_tui_input("/do 1", {"execute": False})

    assert "Status: failed" in out
    assert "/trace: 查看最近执行链路" in out
    assert "/timeline: 查看完整时间线" in out


def test_cycle_tui_input_history_roundtrip() -> None:
    history = ["/scan", "/providers", "检查 swarm"]
    text1, idx1, seed1 = _cycle_tui_input_history("", input_history=history, history_index=-1, history_seed="", direction="up")
    text2, idx2, seed2 = _cycle_tui_input_history(text1, input_history=history, history_index=idx1, history_seed=seed1, direction="up")
    text3, idx3, seed3 = _cycle_tui_input_history(text2, input_history=history, history_index=idx2, history_seed=seed2, direction="down")

    assert text1 == "检查 swarm"
    assert text2 == "/providers"
    assert text3 == "检查 swarm"
    assert idx3 == 2
    assert seed3 == ""


def test_cycle_tui_input_history_prefix_filter_roundtrip() -> None:
    history = ["/scan", "检查 swarm", "检查 k8s", "/brief"]
    text1, idx1, seed1 = _cycle_tui_input_history("检", input_history=history, history_index=-1, history_seed="", direction="up")
    text2, idx2, seed2 = _cycle_tui_input_history(text1, input_history=history, history_index=idx1, history_seed=seed1, direction="up")
    text3, idx3, seed3 = _cycle_tui_input_history(text2, input_history=history, history_index=idx2, history_seed=seed2, direction="down")
    text4, idx4, seed4 = _cycle_tui_input_history(text3, input_history=history, history_index=idx3, history_seed=seed3, direction="down")

    assert text1 == "检查 k8s"
    assert text2 == "检查 swarm"
    assert text3 == "检查 k8s"
    assert text4 == "检"
    assert idx4 == -1
    assert seed4 == "检"


def test_cycle_tui_input_history_prefix_filter_case_insensitive() -> None:
    history = ["/scan", "/Status", "/brief"]
    text1, idx1, seed1 = _cycle_tui_input_history("/s", input_history=history, history_index=-1, history_seed="", direction="up")
    text2, idx2, seed2 = _cycle_tui_input_history(text1, input_history=history, history_index=idx1, history_seed=seed1, direction="up")

    assert text1 == "/Status"
    assert text2 == "/scan"
    assert seed2 == "/s"


def test_cycle_tui_input_history_prefix_filter_no_match_keeps_seed() -> None:
    history = ["/scan", "/status", "/brief"]
    text, idx, seed = _cycle_tui_input_history("/xyz", input_history=history, history_index=-1, history_seed="", direction="up")

    assert text == "/xyz"
    assert idx == -1
    assert seed == "/xyz"


def test_merge_tui_input_history_dedupes_and_keeps_latest_order() -> None:
    merged = _merge_tui_input_history(
        ["/scan", "/brief", "/scan"],
        ["/providers", "/brief", "检查 swarm"],
        max_entries=20,
    )
    assert merged[-4:] == ["/scan", "/providers", "/brief", "检查 swarm"]


def test_tui_input_history_roundtrip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "lsre-tui-input-history.txt"
    monkeypatch.setattr(cli_main, "_tui_input_history_file", lambda: path)

    _save_tui_input_history(["/scan", "key=google-api-key-demo-value", "/brief"])
    rows = _load_tui_input_history()

    assert "/scan" in rows
    assert "/brief" in rows
    assert all("google-api-key-demo-value" not in item for item in rows)
    assert any("key=***REDACTED***" in item for item in rows)


def test_delete_tui_word_left_handles_spaces_and_mixed_text() -> None:
    text, cursor = _delete_tui_word_left("检查 k8s pod", len("检查 k8s pod"))
    assert text == "检查 k8s "
    assert cursor == len("检查 k8s ")


def test_apply_tui_ctrl_edit_key_basic_ops() -> None:
    t1, c1, ok1 = _apply_tui_ctrl_edit_key(key="\x01", input_text="abcd", cursor_index=3)  # Ctrl+A
    assert ok1 is True and t1 == "abcd" and c1 == 0

    t2, c2, ok2 = _apply_tui_ctrl_edit_key(key="\x05", input_text="abcd", cursor_index=1)  # Ctrl+E
    assert ok2 is True and t2 == "abcd" and c2 == 4

    t3, c3, ok3 = _apply_tui_ctrl_edit_key(key="\x15", input_text="abcde", cursor_index=2)  # Ctrl+U
    assert ok3 is True and t3 == "cde" and c3 == 0

    t4, c4, ok4 = _apply_tui_ctrl_edit_key(key="\x0b", input_text="abcde", cursor_index=2)  # Ctrl+K
    assert ok4 is True and t4 == "ab" and c4 == 2

    t5, c5, ok5 = _apply_tui_ctrl_edit_key(key="\x17", input_text="检查 k8s pod", cursor_index=len("检查 k8s pod"))  # Ctrl+W
    assert ok5 is True and t5 == "检查 k8s " and c5 == len("检查 k8s ")

    t6, c6, ok6 = _apply_tui_ctrl_edit_key(key="x", input_text="abc", cursor_index=2)
    assert ok6 is False and t6 == "abc" and c6 == 2


def test_build_tui_bootstrap_input_history_includes_recent_and_defaults() -> None:
    history = _build_tui_bootstrap_input_history(
        {
            "recent_commands": ["检查k8s", "/scan", "ALL_PROXY=socks5://u:p@x:1080"],
            "recommended_commands": ["/brief", "/providers", "/scan"],
        }
    )

    assert "检查k8s" in history
    assert "/scan" in history
    assert "/brief" in history
    assert "/next" in history
    assert "/history" in history
    assert "/retry" in history
    assert any("://***:***@" in item for item in history)


def test_cycle_tui_completion_keeps_original_prefix_across_tabs() -> None:
    snapshot = {
        "shortcuts": ["/refresh", "/remote <user>@<host> --logs"],
        "recommended_commands": [],
    }

    first, idx, seed = _cycle_tui_completion("/r", snapshot=snapshot, completion_index=-1, completion_seed="")
    second, idx2, seed2 = _cycle_tui_completion(first, snapshot=snapshot, completion_index=idx, completion_seed=seed)

    assert first == "/refresh"
    assert second == "/remote <user>@<host> --logs"
    assert seed2 == "/r"


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
    assert report["root_causes"][0]["category"] == "swarm_image_pull_failed"
    assert report["posture"]["status"] == "attention"
    assert report["posture"]["focus_service"] == "api"
    assert report["posture"]["focus_category"] == "swarm_image_pull_failed"
    assert report["posture"]["top_actions"][0] == "lazysre template run swarm-image-pull-failed --var service=api --apply"


def test_collect_remote_docker_report_detects_swarm_issue(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_safe_run(command: list[str], *, timeout_sec: int) -> dict[str, object]:
        assert command[0] == "ssh"
        remote_command = str(command[-1])
        calls.append(remote_command)
        if remote_command == "printf lazysre-ok":
            return {"ok": True, "stdout": "lazysre-ok", "stderr": "", "exit_code": 0}
        if "docker version" in remote_command:
            return {"ok": True, "stdout": "25.0.0", "stderr": "", "exit_code": 0}
        if "docker info" in remote_command:
            return {"ok": True, "stdout": "active", "stderr": "", "exit_code": 0}
        if "docker ps -a" in remote_command:
            return {"ok": True, "stdout": "", "stderr": "", "exit_code": 0}
        if "docker node ls" in remote_command:
            return {"ok": True, "stdout": "node-1\tReady\tActive\tLeader", "stderr": "", "exit_code": 0}
        if "docker service ls" in remote_command:
            return {"ok": True, "stdout": "api\treplicated\t0/1\tapi:latest", "stderr": "", "exit_code": 0}
        if "docker service ps" in remote_command:
            return {"ok": True, "stdout": "api.1\tRejected 1 second ago\tNo such image: api:latest\tnode-1", "stderr": "", "exit_code": 0}
        if "docker service logs" in remote_command:
            return {"ok": True, "stdout": "pull failed", "stderr": "", "exit_code": 0}
        return {"ok": False, "stdout": "", "stderr": "unexpected", "exit_code": 1}

    monkeypatch.setattr(cli_main, "_safe_run_command", fake_safe_run)

    report = _collect_remote_docker_report(
        target="root@192.168.10.101",
        include_logs=True,
        timeout_sec=3,
    )

    assert report["source"] == "remote-ssh"
    assert report["target"] == "root@192.168.10.101"
    assert report["ok"] is False
    assert report["unhealthy_services"][0]["name"] == "api"
    assert report["root_causes"][0]["category"] == "swarm_image_pull_failed"
    assert report["briefing"]["status"] == "attention"
    assert "api" in report["briefing"]["headline"]
    assert "lazysre remote root@192.168.10.101 --service api --logs" in report["recommendations"]
    assert report["posture"]["status"] == "attention"
    assert report["posture"]["focus_service"] == "api"
    assert report["posture"]["top_actions"][0] == "lazysre remote root@192.168.10.101 --service api --logs"
    assert any("docker service logs" in item for item in calls)


def test_remote_scenario_packs_collect_linux_nginx_gpu(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_safe_run(command: list[str], *, timeout_sec: int) -> dict[str, object]:
        remote_command = str(command[-1])
        calls.append(remote_command)
        if remote_command == "printf lazysre-ok":
            return {"ok": True, "stdout": "lazysre-ok", "stderr": "", "exit_code": 0}
        if "## linux" in remote_command:
            return {"ok": True, "stdout": "## linux\nup 1 day\n/dev/sda1 90% /", "stderr": "", "exit_code": 0}
        if "command -v nginx" in remote_command:
            return {"ok": True, "stdout": "## nginx\nnginx version: nginx/1.24\nsyntax is ok", "stderr": "", "exit_code": 0}
        if "nvidia-smi" in remote_command:
            return {"ok": True, "stdout": "NVIDIA A10,535,1024,24576,5,42", "stderr": "", "exit_code": 0}
        if "docker version" in remote_command:
            return {"ok": False, "stdout": "", "stderr": "docker missing", "exit_code": 1}
        return {"ok": True, "stdout": "", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(cli_main, "_safe_run_command", fake_safe_run)

    report = _collect_remote_docker_report(
        target="root@192.168.10.101",
        scenarios=["linux", "nginx", "gpu"],
        timeout_sec=3,
    )

    scenario_reports = report["scenario_reports"]
    assert [item["name"] for item in scenario_reports] == ["linux", "nginx", "gpu"]
    assert scenario_reports[0]["severity"] == "warn"
    assert scenario_reports[0]["status"] == "disk_pressure"
    assert scenario_reports[1]["severity"] == "pass"
    assert scenario_reports[2]["severity"] == "pass"
    assert any("scenario=nginx" in item for item in report["briefing"]["evidence"])
    assert "lazysre remote root@192.168.10.101 --scenario linux --json" in report["recommendations"]
    assert any("nvidia-smi" in item for item in calls)


def test_remote_report_markdown_includes_scenario_findings() -> None:
    markdown = cli_main._render_remote_docker_report_markdown(
        {
            "generated_at_utc": "2026-04-24T00:00:00Z",
            "target": "root@192.168.10.101",
            "ok": False,
            "summary": {"pass": 1, "warn": 1, "error": 0},
            "briefing": {},
            "checks": [],
            "scenario_reports": [
                {
                    "name": "linux",
                    "severity": "warn",
                    "status": "disk_pressure",
                    "headline": "Linux 主机磁盘使用率最高 90%，需要优先确认容量。",
                    "signals": ["max_disk=90%"],
                    "recommendations": ["lazysre remote root@192.168.10.101 --scenario linux --json"],
                }
            ],
            "root_causes": [],
            "recommendations": [],
        }
    )

    assert "status=`disk_pressure`" in markdown
    assert "Linux 主机磁盘使用率最高 90%" in markdown
    assert "Signals: max_disk=90%" in markdown
    assert "Next: `lazysre remote root@192.168.10.101 --scenario linux --json`" in markdown


def test_remote_scenario_classifier_detects_runtime_and_unhealthy_services() -> None:
    db_running = cli_main._classify_remote_scenario_report(
        name="database",
        stdout="## database\nbin:mysql\ndocker:mysql mysql:8 Up 2 hours",
        stderr="",
        severity="pass",
    )
    ai_unhealthy = cli_main._classify_remote_scenario_report(
        name="ai",
        stdout="## ai\ndocker:vllm vllm:latest Restarting (1) 10 seconds ago",
        stderr="",
        severity="pass",
    )
    cicd_installed = cli_main._classify_remote_scenario_report(
        name="cicd",
        stdout="## cicd\nbin:gitlab-runner",
        stderr="",
        severity="pass",
    )

    assert db_running["severity"] == "pass"
    assert db_running["status"] == "running"
    assert ai_unhealthy["severity"] == "warn"
    assert ai_unhealthy["status"] == "service_unhealthy"
    assert cicd_installed["severity"] == "info"
    assert cicd_installed["status"] == "installed_not_running"


def test_extract_remote_scenarios_from_text_and_all_alias() -> None:
    assert cli_main._extract_remote_scenarios_from_text("远程检查 nginx gpu root@1.1.1.1") == ["nginx", "gpu"]
    assert cli_main._normalize_remote_scenarios(["all"]) == ["linux", "nginx", "database", "gpu", "ai", "cicd"]


def test_remote_scenario_intent_uses_saved_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target_file = tmp_path / "target.json"
    old_profile = settings.target_profile_file
    try:
        settings.target_profile_file = str(target_file)
        target_file.write_text(json.dumps({"ssh_target": "root@192.168.10.101"}, ensure_ascii=False), encoding="utf-8")
        assert _looks_like_remote_diagnose_request("检查 nginx 配置")
        assert _looks_like_remote_diagnose_request("看看 gpu 和 ai 服务")
    finally:
        settings.target_profile_file = old_profile


def test_build_remote_briefing_classifies_ssh_blocker() -> None:
    report = {
        "target": "root@192.168.10.101",
        "ok": False,
        "summary": {"pass": 0, "warn": 0, "error": 1},
        "checks": [
            {
                "name": "ssh.connect",
                "ok": False,
                "severity": "error",
                "detail": "connection timed out",
            }
        ],
        "unhealthy_services": [],
        "bad_nodes": [],
        "root_causes": [],
        "recommendations": ["先确认本机可执行：ssh root@192.168.10.101 'docker version'"],
    }

    briefing = _build_remote_briefing(report)

    assert briefing["status"] == "blocked"
    assert "无法连接" in briefing["headline"]
    assert briefing["next"].startswith("先确认本机可执行")


def test_run_remote_connect_flow_saves_target_after_ssh_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target_file = tmp_path / "target.json"
    old_profile = settings.target_profile_file

    def fake_remote(**kwargs: object) -> dict[str, object]:
        return {
            "target": kwargs.get("target", ""),
            "ok": True,
            "summary": {"pass": 2, "warn": 0, "error": 0},
            "checks": [
                {"name": "ssh.connect", "ok": True, "severity": "pass"},
                {"name": "remote.docker.version", "ok": True, "severity": "pass"},
            ],
            "nodes": [],
            "bad_nodes": [],
            "services": [],
            "unhealthy_services": [],
            "tasks": [],
            "logs": [],
            "root_causes": [],
            "recommendations": [],
        }

    try:
        settings.target_profile_file = str(target_file)
        monkeypatch.setattr(cli_main, "_collect_remote_docker_report", fake_remote)
        report = _run_remote_connect_flow(
            target="root@192.168.10.101",
            save_target=True,
            include_logs=False,
            tail=40,
            timeout_sec=3,
        )
        assert _remote_report_check_ok(report, "ssh.connect") is True
        assert report["target_save"]["saved"] is True
        assert TargetEnvStore(target_file).load().ssh_target == "root@192.168.10.101"
    finally:
        settings.target_profile_file = old_profile


def test_remote_helpers_validate_target_and_quote_command() -> None:
    assert _normalize_ssh_target("root@192.168.10.101") == "root@192.168.10.101"
    assert _normalize_ssh_target("root;rm@host") == ""
    command = _remote_shell_command(["docker", "service", "ps", "api service"])
    assert command == "docker service ps 'api service'"


def test_collect_watch_snapshot_rolls_up_scan_and_swarm_alerts(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_scan(*, timeout_sec: int, secrets_file: Path | None) -> dict[str, object]:
        return {
            "summary": {"warn": 1, "error": 0},
            "usable_targets": ["docker-swarm"],
            "issues": [
                {"name": "docker.exited_containers", "severity": "warn", "detail": "old-api", "hint": "check logs"}
            ],
            "suggestions": ["分析 Docker Swarm 服务健康"],
        }

    def fake_swarm(**kwargs: object) -> dict[str, object]:
        return {
            "ok": False,
            "summary": {"warn": 1, "error": 0},
            "unhealthy_services": [{"name": "api", "replicas": "0/1"}],
            "bad_nodes": [],
            "root_causes": [
                {
                    "category": "swarm_image_pull_failed",
                    "severity": "high",
                    "service": "api",
                    "evidence": "No such image",
                    "advice": "check registry",
                }
            ],
            "recommendations": ["lazysre swarm --service api --logs"],
            "posture": {
                "status": "attention",
                "headline": "Swarm 主要阻塞点是 api，根因倾向 swarm_image_pull_failed。",
                "focus_service": "api",
                "focus_category": "swarm_image_pull_failed",
                "signals": ["top_root_cause=swarm_image_pull_failed"],
                "top_actions": ["lazysre template run swarm-image-pull-failed --var service=api --apply"],
            },
        }

    monkeypatch.setattr(cli_main, "_collect_environment_discovery", fake_scan)
    monkeypatch.setattr(cli_main, "_collect_swarm_health_report", fake_swarm)

    snapshot = _collect_watch_snapshot(cycle=1, include_swarm=True, include_logs=False, timeout_sec=3)

    assert snapshot["ok"] is False
    assert snapshot["usable_targets"] == ["docker-swarm"]
    assert any(alert["source"] == "swarm" and alert["name"] == "api" for alert in snapshot["alerts"])
    assert any(alert["source"] == "swarm-root-cause" for alert in snapshot["alerts"])
    assert snapshot["swarm"]["posture"]["focus_service"] == "api"


def test_build_tui_focus_card_prefers_swarm_posture_after_watch_alerts() -> None:
    card = _build_tui_focus_card(
        recent_activity=["watch attention alerts=1 cycle=3"],
        recent_activity_commands=["/activity", "/swarm --service api --logs"],
        provider_report={"active_ready": True},
        timeline=[],
        watch_snapshot={
            "swarm": {
                "posture": {
                    "headline": "Swarm 主要阻塞点是 api，根因倾向 swarm_image_pull_failed。",
                    "summary": "services=2 unhealthy=1 bad_nodes=0 root_causes=1",
                    "focus_service": "api",
                    "top_actions": [
                        "lazysre template run swarm-image-pull-failed --var service=api --apply",
                        "lazysre swarm --service api --logs",
                    ],
                }
            }
        },
    )

    assert card["title"] == "Swarm Posture"
    assert "api" in card["body"]
    assert card["actions"][0] == "lazysre template run swarm-image-pull-failed --var service=api --apply"


def test_build_tui_focus_card_uses_environment_drift_when_changed() -> None:
    card = _build_tui_focus_card(
        recent_activity=["env drift | 环境基线发生漂移"],
        recent_activity_commands=["lazysre scan"],
        provider_report={"active_ready": True},
        timeline=[],
        environment_drift={
            "status": "changed",
            "headline": "环境基线发生漂移：新增 prometheus 缺失 kubernetes",
            "top_actions": ["lazysre scan", "kubectl config current-context"],
        },
        incident_session={},
        watch_snapshot={},
    )

    assert card["title"] == "Environment Drift"
    assert "漂移" in card["body"]
    assert card["actions"][0] == "lazysre scan"


def test_build_tui_focus_card_uses_incident_session_when_present() -> None:
    card = _build_tui_focus_card(
        recent_activity=["incident attention | 恢复 payment 副本"],
        recent_activity_commands=["/trace", "/timeline"],
        provider_report={"active_ready": True},
        timeline=[],
        incident_session={
            "exists": True,
            "status": "attention",
            "headline": "恢复 payment 副本",
            "stage_flow": "diagnose:1/1 ok -> apply:0/1 fail=1",
            "commands": ["/trace", "/timeline", "lazysre undo"],
        },
        watch_snapshot={},
    )

    assert card["title"] == "Incident Session"
    assert "payment" in card["body"]
    assert card["actions"][:2] == ["/trace", "/timeline"]


def test_run_watch_snapshots_persists_alert_memory_once(monkeypatch: pytest.MonkeyPatch) -> None:
    saved: list[dict[str, object]] = []

    class FakeStore:
        path = Path("/tmp/fake-memory.db")

        def add_case(self, **kwargs: object) -> None:
            saved.append(dict(kwargs))

    def fake_snapshot(**kwargs: object) -> dict[str, object]:
        return {
            "generated_at_utc": "2026-04-09T00:00:00+00:00",
            "cycle": kwargs.get("cycle", 1),
            "ok": False,
            "alerts": [
                {
                    "source": "swarm-root-cause",
                    "severity": "high",
                    "name": "swarm_image_pull_failed",
                    "detail": "service=api evidence=No such image",
                    "hint": "check registry",
                }
            ],
            "swarm": {
                "root_causes": [
                    {
                        "category": "swarm_image_pull_failed",
                        "service": "api",
                        "advice": "check registry",
                    }
                ]
            },
            "usable_targets": ["docker-swarm"],
            "suggestions": [],
        }

    monkeypatch.setattr(cli_main, "_collect_watch_snapshot", fake_snapshot)
    monkeypatch.setattr(cli_main, "_open_incident_memory_store", lambda: FakeStore())
    monkeypatch.setattr(cli_main.time, "sleep", lambda _: None)

    snapshots = cli_main._run_watch_snapshots(
        interval_sec=1,
        count=2,
        include_swarm=True,
        include_logs=False,
        timeout_sec=1,
        remember=True,
        output=None,
    )

    assert len(snapshots) == 2
    assert len(saved) == 1
    assert "watch alerts" in str(saved[0]["symptom"])
    assert "swarm_image_pull_failed" in str(saved[0]["root_cause"])


def test_watch_report_markdown_and_latest_context(tmp_path: Path) -> None:
    snapshot = {
        "generated_at_utc": "2026-04-09T00:00:00+00:00",
        "cycle": 1,
        "ok": False,
        "alerts": [
            {
                "source": "swarm-root-cause",
                "severity": "high",
                "name": "swarm_image_pull_failed",
                "detail": "service=api evidence=No such image",
                "hint": "lazysre swarm --service api --logs",
            }
        ],
        "swarm": {
            "root_causes": [
                {
                    "category": "swarm_image_pull_failed",
                    "service": "api",
                    "severity": "high",
                    "advice": "check registry",
                }
            ],
            "recommendations": ["lazysre swarm --service api --logs"],
        },
    }
    markdown = _render_watch_report_markdown([snapshot])
    assert "# LazySRE Watch Report" in markdown
    assert "swarm_image_pull_failed" in markdown
    assert "lazysre swarm --service api --logs" in markdown

    watch_file = tmp_path / "watch-last.json"
    watch_file.write_text(json.dumps(snapshot), encoding="utf-8")
    context = _build_latest_watch_context("修复巡检发现的问题", path=watch_file)
    assert "Latest watch snapshot" in context
    assert "swarm_image_pull_failed" in context
    assert _build_latest_watch_context("普通问题", path=watch_file) == ""


def test_action_inbox_maps_watch_to_swarm_template() -> None:
    snapshot = {
        "generated_at_utc": "2026-04-09T00:00:00+00:00",
        "alerts": [
            {
                "source": "swarm-root-cause",
                "severity": "high",
                "name": "swarm_image_pull_failed",
                "detail": "service=api evidence=No such image",
                "hint": "lazysre swarm --service api --logs",
            }
        ],
        "swarm": {
            "root_causes": [
                {
                    "category": "swarm_image_pull_failed",
                    "service": "api",
                    "severity": "high",
                    "advice": "registry auth failed",
                }
            ],
            "unhealthy_services": [{"name": "api", "replicas": "0/1"}],
        },
    }

    inbox = _build_action_inbox_from_watch(snapshot)

    assert inbox["summary"]["total"] >= 2
    first = inbox["actions"][0]
    assert first["template"] == "swarm-image-pull-failed"
    assert first["command"] == "lazysre template run swarm-image-pull-failed --var service=api --apply"
    markdown = _render_action_inbox_markdown(inbox)
    assert "# LazySRE Action Inbox" in markdown
    assert "swarm-image-pull-failed" in markdown
    assert "lazysre template run swarm-image-pull-failed --var service=api --apply" in markdown
    assert _find_action_inbox_item(inbox, 1) == first
    assert _find_action_inbox_item(inbox, 999) is None


def test_run_action_command_dispatches_template(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    def fake_template(**kwargs: object) -> None:
        calls.append(dict(kwargs))

    monkeypatch.setattr(cli_main, "_run_remediation_template", fake_template)
    options = {
        "execute": False,
        "approve": False,
        "interactive_approval": True,
        "stream_output": False,
        "verbose_reasoning": False,
        "approval_mode": "balanced",
        "audit_log": str(tmp_path / "audit.jsonl"),
        "lock_file": str(tmp_path / "lock.json"),
        "session_file": str(tmp_path / "session.json"),
        "deny_tool": [],
        "deny_prefix": [],
        "tool_pack": ["builtin"],
        "remote_gateway": [],
        "model": "gpt-5.4-mini",
        "provider": "mock",
        "max_steps": 6,
    }

    ok = _run_action_command(
        "lazysre template run swarm-image-pull-failed --var service=api --apply",
        options=options,
        execute_mode=False,
    )

    assert ok is True
    assert calls[0]["template_name"] == "swarm-image-pull-failed"
    assert calls[0]["var_items"] == ["service=api"]
    assert calls[0]["apply"] is True
    assert calls[0]["execute"] is False


def test_build_autopilot_report_promotes_first_action() -> None:
    scan_report = {
        "summary": {"warn": 1, "error": 0},
        "usable_targets": ["docker-swarm"],
        "issues": [{"name": "docker.swarm", "severity": "warn", "detail": "service unhealthy"}],
        "suggestions": ["检查 Swarm 服务"],
    }
    watch_snapshot = {
        "generated_at_utc": "2026-04-09T00:00:00+00:00",
        "ok": False,
        "alerts": [{"source": "swarm", "severity": "high", "name": "api", "detail": "0/1"}],
    }
    action_inbox = {
        "summary": {"total": 1, "high": 1, "medium": 0, "low": 0},
        "actions": [
            {
                "id": 1,
                "title": "修复 Swarm 镜像拉取失败: api",
                "command": "lazysre template run swarm-image-pull-failed --var service=api --apply",
            }
        ],
    }

    report = _build_autopilot_report(
        goal="自动排查",
        scan_report=scan_report,
        watch_snapshot=watch_snapshot,
        action_inbox=action_inbox,
    )

    assert report["status"] == "needs_attention"
    assert report["recommended_commands"][0] == "lazysre template run swarm-image-pull-failed --var service=api --apply"
    assert "优先处理" in str(report["next_step"])
    markdown = _render_autopilot_report_markdown(report)
    assert "# LazySRE Autopilot Report" in markdown
    assert "lazysre template run swarm-image-pull-failed --var service=api --apply" in markdown


def test_build_remote_autopilot_report_promotes_remote_recommendations() -> None:
    remote_report = {
        "generated_at_utc": "2026-04-09T00:00:00+00:00",
        "target": "root@192.168.10.101",
        "ok": False,
        "summary": {"warn": 1, "error": 0},
        "unhealthy_services": [{"name": "api", "replicas": "0/1"}],
        "root_causes": [
            {
                "category": "swarm_image_pull_failed",
                "service": "api",
                "severity": "high",
                "advice": "registry auth failed",
            }
        ],
        "recommendations": ["lazysre remote root@192.168.10.101 --service api --logs"],
    }

    report = _build_remote_autopilot_report(goal="远程自动驾驶", remote_report=remote_report)

    assert report["source"] == "remote-autopilot"
    assert report["status"] == "needs_attention"
    assert report["recommended_commands"][0] == "lazysre remote root@192.168.10.101 --service api --logs"
    assert report["action_inbox"]["actions"][0]["source"] == "remote-root-cause"


def test_run_remote_autopilot_cycle_writes_latest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_remote(**kwargs: object) -> dict[str, object]:
        return {
            "generated_at_utc": "2026-04-09T00:00:00+00:00",
            "target": kwargs.get("target", ""),
            "ok": True,
            "summary": {"warn": 0, "error": 0},
            "unhealthy_services": [],
            "root_causes": [],
            "recommendations": ["lazysre remote root@192.168.10.101 --json"],
        }

    monkeypatch.setattr(cli_main, "_collect_remote_docker_report", fake_remote)
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)

    report = _run_remote_autopilot_cycle(
        goal="远程巡检",
        target="root@192.168.10.101",
        service_filter="",
        include_logs=False,
        timeout_sec=1,
    )

    assert report["source"] == "remote-autopilot"
    assert report["status"] == "clear"
    assert (tmp_path / "lsre-autopilot-last.json").exists()


def test_run_autopilot_cycle_builds_watch_actions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_scan(*, timeout_sec: int, secrets_file: Path | None) -> dict[str, object]:
        return {
            "summary": {"warn": 1, "error": 0},
            "usable_targets": ["docker-swarm"],
            "issues": [],
            "suggestions": [],
        }

    def fake_watch(**kwargs: object) -> list[dict[str, object]]:
        return [
            {
                "generated_at_utc": "2026-04-09T00:00:00+00:00",
                "ok": False,
                "alerts": [],
                "swarm": {
                    "root_causes": [
                        {
                            "category": "swarm_image_pull_failed",
                            "service": "api",
                            "severity": "high",
                            "advice": "registry auth failed",
                        }
                    ],
                    "unhealthy_services": [],
                },
            }
        ]

    monkeypatch.setattr(cli_main, "_collect_environment_discovery", fake_scan)
    monkeypatch.setattr(cli_main, "_run_watch_snapshots", fake_watch)
    monkeypatch.setattr(settings, "data_dir", str(tmp_path), raising=False)

    report = _run_autopilot_cycle(
        goal="自动驾驶排查",
        include_swarm=True,
        include_logs=False,
        remember=False,
        timeout_sec=1,
    )

    assert report["status"] == "needs_attention"
    assert report["summary"]["actions"] == 1
    assert report["recommended_commands"][0] == "lazysre template run swarm-image-pull-failed --var service=api --apply"
    assert (tmp_path / "lsre-autopilot-last.json").exists()
