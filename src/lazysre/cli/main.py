from __future__ import annotations

import asyncio
from difflib import get_close_matches
import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from string import Formatter
from typing import Annotated

import typer

from lazysre.cli.audit import AuditLogger
from lazysre.cli.brain import BrainContext
from lazysre.cli.context_window import ContextWindowManager
from lazysre.cli.dispatcher import Dispatcher
from lazysre.cli.executor import SafeExecutor
from lazysre.cli.fix_mode import (
    FixPlan,
    build_plan_record,
    compose_fix_instruction,
    evaluate_apply_guardrail,
    extract_fix_plan,
)
from lazysre.cli.llm import (
    AnthropicMessagesLLM,
    GeminiFunctionCallingLLM,
    MockFunctionCallingLLM,
    OpenAICompatibleFunctionCallingLLM,
    OpenAIResponsesLLM,
)
from lazysre.cli.permissions import ToolPermissionContext
from lazysre.cli.policy import PolicyDecision, assess_command, build_risk_report
from lazysre.cli.session import SessionStore
from lazysre.cli.memory import IncidentMemoryStore, MemoryCase, format_memory_context
from lazysre.cli.secrets import SecretStore
from lazysre.cli.runbook import (
    RunbookStore,
    RunbookTemplate,
    all_runbooks,
    find_runbook,
    parse_runbook_vars,
    render_runbook_instruction,
)
from lazysre.cli.remediation_templates import (
    get_template as get_remediation_template,
    list_templates as list_remediation_templates,
    match_template_for_text,
    maybe_detect_quick_fix_intent,
    parse_var_items as parse_remediation_var_items,
    render_template as render_remediation_template,
)
from lazysre.cli.target import TargetEnvStore, probe_target_environment
from lazysre.cli.target_profiles import ClusterProfileStore
from lazysre.cli.tools import build_default_registry
from lazysre.cli.tools.marketplace import (
    LockedPack,
    ToolPackLockStore,
    compute_module_digest,
    find_marketplace_pack,
    load_marketplace_index,
    verify_pack_signature,
)
from lazysre.config import settings
from lazysre.providers.registry import (
    PROVIDER_SPECS,
    get_provider_spec,
    provider_mode_error_text,
    provider_mode_help_text,
    resolve_model_name,
)

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
except Exception:  # pragma: no cover
    Console = None  # type: ignore[assignment]
    Markdown = None  # type: ignore[assignment]
    Panel = None  # type: ignore[assignment]
    Table = None  # type: ignore[assignment]

_console = Console() if Console else None

app = typer.Typer(
    name="lsre",
    help="LazySRE AI-native CLI for operations workflows.",
    add_completion=False,
    no_args_is_help=False,
)
pack_app = typer.Typer(help="Tool pack marketplace and lock management.")
target_app = typer.Typer(help="Target environment profile management.")
target_profile_app = typer.Typer(help="Multi-cluster target profile management.")
history_app = typer.Typer(help="Session history management.")
memory_app = typer.Typer(help="Long-term incident memory management.")
runbook_app = typer.Typer(help="Workflow runbook templates.")
template_app = typer.Typer(help="One-click remediation templates.")


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    execute: Annotated[bool, typer.Option("--execute", help="Run commands for real. Default is dry-run.")] = False,
    approve: Annotated[bool, typer.Option("--approve", help="Acknowledge policy gate for high-risk commands.")] = False,
    interactive_approval: Annotated[bool, typer.Option("--interactive-approval/--no-interactive-approval", help="Prompt y/n confirmation for risky write actions in execute mode.")] = True,
    stream_output: Annotated[bool, typer.Option("--stream-output/--no-stream-output", help="Stream model tokens in terminal output.")] = True,
    verbose_reasoning: Annotated[bool, typer.Option("--verbose-reasoning/--no-verbose-reasoning", help="Show full AI reasoning content instead of collapsed summary.")] = False,
    approval_mode: Annotated[str, typer.Option(help="Policy level: strict|balanced|permissive")] = "balanced",
    audit_log: Annotated[str, typer.Option(help="Audit jsonl path for command execution records.")] = ".data/lsre-audit.jsonl",
    lock_file: Annotated[str, typer.Option(help="Tool pack lock file path.")] = ".data/lsre-tool-lock.json",
    session_file: Annotated[str, typer.Option(help="Session memory file path.")] = ".data/lsre-session.json",
    deny_tool: Annotated[list[str], typer.Option("--deny-tool", help="Block specific tools by name, can be repeated.")] = [],
    deny_prefix: Annotated[list[str], typer.Option("--deny-prefix", help="Block tools by prefix, can be repeated.")] = [],
    tool_pack: Annotated[list[str], typer.Option("--tool-pack", help="Tool pack spec. e.g. builtin or module:pkg.mod[:factory].")] = ["builtin"],
    remote_gateway: Annotated[list[str], typer.Option("--remote-gateway", help="Remote gateway <name>=<url>[#token]. can be repeated.")] = [],
    model: Annotated[str, typer.Option(help="Model name for LLM dispatcher.")] = settings.model_name,
    provider: Annotated[str, typer.Option(help=f"LLM provider: {provider_mode_help_text()}")] = "auto",
    max_steps: Annotated[int, typer.Option(help="Max function-calling iterations.")] = 6,
) -> None:
    ctx.obj = {
        "execute": execute,
        "approve": approve,
        "interactive_approval": interactive_approval,
        "stream_output": stream_output,
        "verbose_reasoning": verbose_reasoning,
        "approval_mode": approval_mode,
        "audit_log": audit_log,
        "lock_file": lock_file,
        "session_file": session_file,
        "deny_tool": list(deny_tool),
        "deny_prefix": list(deny_prefix),
        "tool_pack": list(tool_pack),
        "remote_gateway": list(remote_gateway),
        "model": model,
        "provider": provider,
        "max_steps": max(1, min(max_steps, 12)),
    }
    if ctx.invoked_subcommand is None and _should_launch_assistant(sys.argv[1:]):
        options = _merged_options(
            ctx,
            execute=None,
            approve=None,
            interactive_approval=None,
            stream_output=None,
            verbose_reasoning=None,
            approval_mode=None,
            audit_log=None,
            lock_file=None,
            session_file=None,
            deny_tool=None,
            deny_prefix=None,
            tool_pack=None,
            remote_gateway=None,
            model=None,
            provider=None,
            max_steps=None,
        )
        _assistant_chat_loop(options)
        raise typer.Exit()


@app.command("run")
def run_instruction(
    ctx: typer.Context,
    instruction: Annotated[str, typer.Argument(help='Natural-language instruction, e.g. lsre "check k8s pods"')],
) -> None:
    options = _merged_options(
        ctx,
        execute=None,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=None,
        audit_log=None,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=None,
        provider=None,
        max_steps=None,
    )
    _run_once(
        instruction=instruction,
        execute=bool(options["execute"]),
        approve=bool(options["approve"]),
        interactive_approval=bool(options["interactive_approval"]),
        stream_output=bool(options["stream_output"]),
        verbose_reasoning=bool(options["verbose_reasoning"]),
        approval_mode=str(options["approval_mode"]),
        audit_log=str(options["audit_log"]),
        lock_file=str(options["lock_file"]),
        session_file=str(options["session_file"]),
        deny_tool=list(options["deny_tool"]),
        deny_prefix=list(options["deny_prefix"]),
        tool_pack=list(options["tool_pack"]),
        remote_gateway=list(options["remote_gateway"]),
        model=str(options["model"]),
        provider=str(options["provider"]),
        max_steps=int(options["max_steps"]),
    )


@app.command("status")
def status(
    ctx: typer.Context,
    session_file: Annotated[str | None, typer.Option("--session-file", help="Override session memory file path.")] = None,
    profile_file: Annotated[str, typer.Option("--profile-file", help="Target profile JSON path.")] = settings.target_profile_file,
    probe: Annotated[bool, typer.Option("--probe", help="Run target environment probe summary.")] = False,
    execute_probe: Annotated[bool, typer.Option("--execute-probe", help="Execute probe commands for real. Default is dry-run probe.")] = False,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Probe timeout seconds.")] = 6,
    as_json: Annotated[bool, typer.Option("--json", help="Print status as JSON.")] = False,
) -> None:
    options = _merged_options(
        ctx,
        execute=None,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=None,
        audit_log=None,
        lock_file=None,
        session_file=session_file,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=None,
        provider=None,
        max_steps=None,
    )
    snapshot = _collect_runtime_status(
        session_file=Path(str(options["session_file"])),
        profile_file=Path(profile_file),
        include_probe=probe,
        execute_probe=execute_probe,
        timeout_sec=timeout_sec,
        audit_log=Path(str(options["audit_log"])),
    )
    if as_json or (not _console):
        typer.echo(json.dumps(snapshot, ensure_ascii=False, indent=2))
        return
    _render_status_snapshot(snapshot)


@app.command("scan")
def scan(
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Per-check timeout seconds.")] = 5,
    as_json: Annotated[bool, typer.Option("--json", help="Print environment scan as JSON.")] = False,
) -> None:
    report = _collect_environment_discovery(timeout_sec=timeout_sec, secrets_file=None)
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _render_environment_discovery(report)


@app.command("swarm")
def swarm(
    service: Annotated[str, typer.Option("--service", help="Optional service name filter.")] = "",
    logs: Annotated[bool, typer.Option("--logs", help="Include recent logs for unhealthy/selected services.")] = False,
    tail: Annotated[int, typer.Option("--tail", help="Log/task tail lines.")] = 80,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Per-check timeout seconds.")] = 6,
    as_json: Annotated[bool, typer.Option("--json", help="Print Swarm health as JSON.")] = False,
) -> None:
    report = _collect_swarm_health_report(
        service_filter=service,
        include_logs=logs,
        tail=tail,
        timeout_sec=timeout_sec,
    )
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _render_swarm_health_report(report)


@app.command("watch")
def watch(
    interval_sec: Annotated[int, typer.Option("--interval-sec", help="Seconds between scans.")] = 60,
    count: Annotated[int, typer.Option("--count", help="Number of scan cycles. Use 1 for one-shot.")] = 1,
    include_swarm: Annotated[bool, typer.Option("--swarm/--no-swarm", help="Include Docker Swarm health snapshot.")] = True,
    include_logs: Annotated[bool, typer.Option("--logs", help="Include Swarm logs for unhealthy services.")] = False,
    remember: Annotated[bool, typer.Option("--remember/--no-remember", help="Persist alert summaries to long-term memory.")] = True,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Per-check timeout seconds.")] = 5,
    output: Annotated[str, typer.Option("--output", help="Optional JSONL output path.")] = "",
    report_md: Annotated[str, typer.Option("--report-md", help="Optional markdown report output path.")] = "",
    as_json: Annotated[bool, typer.Option("--json", help="Print watch snapshots as JSON.")] = False,
) -> None:
    snapshots = _run_watch_snapshots(
        interval_sec=interval_sec,
        count=count,
        include_swarm=include_swarm,
        include_logs=include_logs,
        remember=remember,
        timeout_sec=timeout_sec,
        output=Path(output).expanduser() if output.strip() else None,
    )
    if report_md.strip():
        out_path = Path(report_md).expanduser()
        _write_text_file(out_path, _render_watch_report_markdown(snapshots))
        typer.echo(f"Watch report exported: {out_path}")
    if as_json or (not _console):
        typer.echo(json.dumps(snapshots, ensure_ascii=False, indent=2))
        return
    for snapshot in snapshots:
        _render_watch_snapshot(snapshot)


@app.command("actions")
def actions(
    ctx: typer.Context,
    from_watch: Annotated[str, typer.Option("--from-watch", help="Watch snapshot JSON path. Defaults to latest watch.")] = "",
    as_json: Annotated[bool, typer.Option("--json", help="Print action inbox as JSON.")] = False,
    report_md: Annotated[str, typer.Option("--report-md", help="Optional markdown action report path.")] = "",
    run_id: Annotated[int, typer.Option("--run", help="Run a recommended action by ID. Default is dry-run unless global --execute is set.")] = 0,
) -> None:
    options = _merged_options(
        ctx,
        execute=None,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=None,
        audit_log=None,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=None,
        provider=None,
        max_steps=None,
    )
    snapshot = _load_latest_watch_snapshot(Path(from_watch).expanduser() if from_watch.strip() else None)
    inbox = _build_action_inbox_from_watch(snapshot)
    if report_md.strip():
        out_path = Path(report_md).expanduser()
        _write_text_file(out_path, _render_action_inbox_markdown(inbox))
        typer.echo(f"Action report exported: {out_path}")
    if as_json or (not _console):
        typer.echo(json.dumps(inbox, ensure_ascii=False, indent=2))
    else:
        _render_action_inbox(inbox)
    if run_id > 0:
        _run_action_inbox_item(
            inbox=inbox,
            action_id=run_id,
            options=options,
            execute_mode=bool(options["execute"]),
        )


@app.command("autopilot")
def autopilot(
    ctx: typer.Context,
    goal: Annotated[str, typer.Argument(help="Natural-language objective for the autopilot run.")] = "巡检当前环境并给出下一步行动",
    include_swarm: Annotated[bool, typer.Option("--swarm/--no-swarm", help="Include Docker Swarm diagnosis.")] = True,
    include_logs: Annotated[bool, typer.Option("--logs", help="Include logs for unhealthy Swarm services.")] = False,
    remember: Annotated[bool, typer.Option("--remember/--no-remember", help="Persist watch alerts to incident memory.")] = True,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Per-check timeout seconds.")] = 5,
    plan_fix: Annotated[bool, typer.Option("--fix", help="Generate a fix plan after observing and building actions.")] = False,
    apply_fix: Annotated[bool, typer.Option("--apply", help="Generate and apply the fix plan using the current execute mode.")] = False,
    report_md: Annotated[str, typer.Option("--report-md", help="Optional markdown autopilot report path.")] = "",
    as_json: Annotated[bool, typer.Option("--json", help="Print autopilot report as JSON.")] = False,
) -> None:
    options = _merged_options(
        ctx,
        execute=None,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=None,
        audit_log=None,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=None,
        provider=None,
        max_steps=None,
    )
    report = _run_autopilot_cycle(
        goal=goal,
        include_swarm=include_swarm,
        include_logs=include_logs,
        remember=remember,
        timeout_sec=timeout_sec,
    )
    if report_md.strip():
        out_path = Path(report_md).expanduser()
        _write_text_file(out_path, _render_autopilot_report_markdown(report))
        typer.echo(f"Autopilot report exported: {out_path}")
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _render_autopilot_report(report)

    if plan_fix or apply_fix:
        _run_fix(
            instruction=_build_autopilot_fix_instruction(goal, report),
            apply=apply_fix,
            max_apply_steps=6,
            allow_high_risk=False,
            auto_approve_low_risk=True,
            export_plan_md="",
            export_plan_json="",
            execute=bool(options["execute"]),
            approve=bool(options["approve"]),
            interactive_approval=bool(options["interactive_approval"]),
            stream_output=bool(options["stream_output"]),
            verbose_reasoning=bool(options["verbose_reasoning"]),
            approval_mode=str(options["approval_mode"]),
            audit_log=str(options["audit_log"]),
            lock_file=str(options["lock_file"]),
            session_file=str(options["session_file"]),
            deny_tool=list(options["deny_tool"]),
            deny_prefix=list(options["deny_prefix"]),
            tool_pack=list(options["tool_pack"]),
            remote_gateway=list(options["remote_gateway"]),
            model=str(options["model"]),
            provider=str(options["provider"]),
            max_steps=int(options["max_steps"]),
        )


@app.command("doctor")
def doctor(
    ctx: typer.Context,
    profile_file: Annotated[str, typer.Option("--profile-file", help="Target profile JSON path.")] = settings.target_profile_file,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Probe timeout seconds.")] = 6,
    dry_run_probe: Annotated[bool, typer.Option("--dry-run-probe", help="Run probe checks in dry-run mode.")] = False,
    auto_fix: Annotated[bool, typer.Option("--auto-fix", help="Apply safe auto-fixes for doctor findings.")] = False,
    autofix: Annotated[bool, typer.Option("--autofix", help="一键自动修复常见问题（推荐）。")] = False,
    write_backup: Annotated[bool, typer.Option("--write-backup", help="Backup target profile before auto-fix updates.")] = False,
    strict: Annotated[bool, typer.Option("--strict", help="Treat warnings as failure (CI-friendly).")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print doctor report as JSON.")] = False,
) -> None:
    options = _merged_options(
        ctx,
        execute=None,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=None,
        audit_log=None,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=None,
        provider=None,
        max_steps=None,
    )
    target_store = TargetEnvStore(Path(profile_file))
    target = target_store.load()
    report = _collect_doctor_report(
        target=target,
        timeout_sec=timeout_sec,
        dry_run_probe=dry_run_probe,
        audit_log=Path(str(options["audit_log"])),
    )
    enable_autofix = bool(auto_fix or autofix)
    if enable_autofix:
        auto_payload = _run_doctor_autofix_flow(
            profile_file=Path(profile_file),
            timeout_sec=timeout_sec,
            execute_probe=(not dry_run_probe),
            write_backup=write_backup,
            audit_log=Path(str(options["audit_log"])),
            prompt_for_api_key=True,
            provider=str(options["provider"]),
            secrets_file=None,
        )
        target = target_store.load()
        report = _collect_doctor_report(
            target=target,
            timeout_sec=timeout_sec,
            dry_run_probe=dry_run_probe,
            audit_log=Path(str(options["audit_log"])),
        )
        report["autofix"] = auto_payload
    summary_obj = report.get("summary", {})
    if isinstance(summary_obj, dict):
        strict_healthy = _doctor_is_healthy(summary_obj, strict=strict)
        summary_obj["strict_mode"] = strict
        summary_obj["strict_healthy"] = strict_healthy
    else:
        strict_healthy = True
    report["gate"] = _build_doctor_gate(report, strict=strict)
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _render_doctor_report(report)
    if strict and (not strict_healthy):
        raise typer.Exit(code=2)


@app.command("install-doctor")
def install_doctor(
    as_json: Annotated[bool, typer.Option("--json", help="Print install doctor report as JSON.")] = False,
) -> None:
    report = _collect_install_doctor_report()
    report["gate"] = _build_doctor_gate(report, strict=False)
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _render_doctor_report(report)


@app.command("login")
def login(
    provider: Annotated[str, typer.Option("--provider", help=f"Provider: {provider_mode_help_text()}")] = "openai",
    api_key: Annotated[str, typer.Option("--api-key", help="Provider API Key. If empty, prompt securely.")] = "",
    secrets_file: Annotated[str, typer.Option("--secrets-file", help="Secrets JSON file path.")] = "",
) -> None:
    mode = str(provider or "openai").strip().lower()
    if mode not in PROVIDER_SPECS:
        raise typer.BadParameter(provider_mode_error_text())
    store = SecretStore(Path(secrets_file).expanduser() if secrets_file.strip() else None)
    key = api_key.strip()
    if not key:
        key = typer.prompt(f"请输入 {PROVIDER_SPECS[mode].label} API Key", hide_input=True).strip()
    if not key:
        raise typer.BadParameter("API Key 不能为空")
    store.set_api_key(mode, key)
    masked = store.masked_api_key(mode) or "***"
    typer.echo(f"{PROVIDER_SPECS[mode].label} API Key 已保存: {masked} ({store.path})")
    typer.echo("现在可直接运行：lazysre")


@app.command("logout")
def logout(
    provider: Annotated[str, typer.Option("--provider", help=f"Provider: {provider_mode_help_text()}")] = "openai",
    secrets_file: Annotated[str, typer.Option("--secrets-file", help="Secrets JSON file path.")] = "",
) -> None:
    mode = str(provider or "openai").strip().lower()
    if mode not in PROVIDER_SPECS:
        raise typer.BadParameter(provider_mode_error_text())
    store = SecretStore(Path(secrets_file).expanduser() if secrets_file.strip() else None)
    removed = store.clear_api_key(mode)
    if removed:
        typer.echo(f"已清除本地 {PROVIDER_SPECS[mode].label} API Key。")
        return
    typer.echo(f"本地未找到可清除的 {PROVIDER_SPECS[mode].label} API Key。")


@app.command("init")
def init(
    ctx: typer.Context,
    profile_file: Annotated[str, typer.Option("--profile-file", help="Target profile JSON path.")] = settings.target_profile_file,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Probe timeout seconds.")] = 6,
    execute_probe: Annotated[bool, typer.Option("--execute-probe/--dry-run-probe", help="Execute probe commands during init.")] = True,
    secrets_file: Annotated[str, typer.Option("--secrets-file", help="Secrets JSON file path.")] = "",
) -> None:
    options = _merged_options(
        ctx,
        execute=None,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=None,
        audit_log=None,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=None,
        provider=None,
        max_steps=None,
    )
    report = _interactive_init_wizard(
        profile_file=Path(profile_file),
        timeout_sec=timeout_sec,
        execute_probe=execute_probe,
        audit_log=Path(str(options["audit_log"])),
        provider=str(options["provider"]),
        secrets_file=Path(secrets_file).expanduser() if secrets_file.strip() else None,
    )
    if _console:
        _render_setup_report(report)
    else:
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))


@app.command("quickstart")
def quickstart(
    ctx: typer.Context,
    api_key: Annotated[str, typer.Option("--api-key", help="Provider API Key. Empty means prompt when needed.")] = "",
    profile_file: Annotated[str, typer.Option("--profile-file", help="Target profile JSON path.")] = settings.target_profile_file,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Probe timeout seconds.")] = 6,
    execute_probe: Annotated[bool, typer.Option("--execute-probe/--dry-run-probe", help="Execute real probe checks.")] = True,
    autofix: Annotated[bool, typer.Option("--autofix/--no-autofix", help="Apply safe target auto-fix before final probe.")] = True,
    write_backup: Annotated[bool, typer.Option("--write-backup", help="Backup target profile when autofix updates it.")] = False,
    prompt_for_api_key: Annotated[bool, typer.Option("--prompt-api-key/--no-prompt-api-key", help="Prompt to set API key when missing.")] = True,
    secrets_file: Annotated[str, typer.Option("--secrets-file", help="Secrets JSON file path.")] = "",
    as_json: Annotated[bool, typer.Option("--json", help="Print quickstart report as JSON.")] = False,
) -> None:
    options = _merged_options(
        ctx,
        execute=None,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=None,
        audit_log=None,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=None,
        provider=None,
        max_steps=None,
    )
    report = _run_quickstart(
        profile_file=Path(profile_file),
        timeout_sec=timeout_sec,
        execute_probe=execute_probe,
        autofix=autofix,
        write_backup=write_backup,
        audit_log=Path(str(options["audit_log"])),
        api_key=api_key,
        prompt_for_api_key=prompt_for_api_key,
        provider=str(options["provider"]),
        secrets_file=Path(secrets_file).expanduser() if secrets_file.strip() else None,
    )
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _render_setup_report(report)


@app.command("reset")
def reset(
    reset_onboarding: Annotated[bool, typer.Option("--onboarding/--no-onboarding", help="Reset onboarding marker.")] = True,
    reset_chat_mode: Annotated[bool, typer.Option("--chat-mode/--no-chat-mode", help="Reset persisted chat execute/dry-run mode.")] = True,
    reset_session: Annotated[bool, typer.Option("--session/--no-session", help="Clear chat history session turns.")] = False,
    session_file: Annotated[str, typer.Option("--session-file", help="Session memory file path.")] = ".data/lsre-session.json",
) -> None:
    changed: list[str] = []
    if reset_onboarding and _remove_file_if_exists(Path(settings.data_dir) / "lsre-onboarding.json"):
        changed.append("onboarding")
    if reset_chat_mode and _remove_file_if_exists(_chat_state_file()):
        changed.append("chat-mode")
    if reset_session:
        SessionStore(Path(session_file)).clear()
        changed.append("session")
    if changed:
        typer.echo(f"reset done: {', '.join(changed)}")
        return
    typer.echo("nothing to reset.")


@app.command("setup")
def setup(
    ctx: typer.Context,
    profile_file: Annotated[str, typer.Option("--profile-file", help="Target profile JSON path.")] = settings.target_profile_file,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Probe timeout seconds.")] = 6,
    execute_probe: Annotated[bool, typer.Option("--execute-probe/--dry-run-probe", help="Execute probe commands for real checks.")] = True,
    apply_defaults: Annotated[bool, typer.Option("--apply-defaults/--no-apply-defaults", help="Fill empty target config with built-in defaults.")] = True,
    write_marker: Annotated[bool, typer.Option("--write-marker/--no-write-marker", help="Write first-run marker file under .data/.")] = True,
    as_json: Annotated[bool, typer.Option("--json", help="Print setup report as JSON.")] = False,
) -> None:
    options = _merged_options(
        ctx,
        execute=None,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=None,
        audit_log=None,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=None,
        provider=None,
        max_steps=None,
    )
    report = _run_first_run_setup(
        profile_file=Path(profile_file),
        timeout_sec=timeout_sec,
        execute_probe=execute_probe,
        apply_defaults=apply_defaults,
        audit_log=Path(str(options["audit_log"])),
        write_marker=write_marker,
        provider=str(options["provider"]),
    )
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _render_setup_report(report)


@app.command("report")
def report(
    ctx: typer.Context,
    output: Annotated[str, typer.Option("--output", help="Output report file path.")] = "",
    fmt: Annotated[str, typer.Option("--format", help="Report format: markdown|json")] = "markdown",
    limit: Annotated[int, typer.Option("--limit", help="Recent session turns to include.")] = 20,
    include_doctor: Annotated[bool, typer.Option("--include-doctor", help="Include doctor snapshot in report.")] = True,
    include_memory: Annotated[bool, typer.Option("--include-memory", help="Include recent memory cases in report.")] = True,
    push_to_git: Annotated[bool, typer.Option("--push-to-git", help="Archive report to reports/ and git-push automatically.")] = False,
    git_remote: Annotated[str, typer.Option("--git-remote", help="Git remote used by --push-to-git.")] = "origin",
    git_message: Annotated[str, typer.Option("--git-message", help="Custom commit message for --push-to-git.")] = "",
) -> None:
    options = _merged_options(
        ctx,
        execute=None,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=None,
        audit_log=None,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=None,
        provider=None,
        max_steps=None,
    )
    result = _export_incident_report(
        session_file=Path(str(options["session_file"])),
        target_profile_file=Path(settings.target_profile_file),
        include_doctor=include_doctor,
        include_memory=include_memory,
        turn_limit=limit,
        audit_log=Path(str(options["audit_log"])),
        fmt=fmt,
        output=output,
        push_to_git=push_to_git,
        git_remote=git_remote,
        git_message=git_message,
    )
    typer.echo(f"Report exported: {result['out_path']}")
    archived = str(result.get("archived_path", "")).strip()
    if archived:
        if bool(result.get("pushed", False)):
            typer.echo(f"Report archived & pushed: {archived}")
        else:
            typer.echo(f"Report archived (no changes to push): {archived}")


@template_app.command("list")
def template_list() -> None:
    templates = list_remediation_templates()
    if not (_console and Table):
        payload = [item.to_dict() for item in templates]
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    table = Table(title="LazySRE Remediation Templates")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Risk", style="yellow", no_wrap=True)
    table.add_column("Aliases", style="green")
    table.add_column("Description", style="white")
    for item in templates:
        table.add_row(
            item.name,
            item.risk_level,
            ", ".join(item.aliases[:4]),
            item.description,
        )
    _console.print(table)


@template_app.command("show")
def template_show(
    name: Annotated[str, typer.Argument(help="Template name or alias.")],
) -> None:
    template = get_remediation_template(name)
    if not template:
        raise typer.BadParameter(f"template not found: {name}")
    payload = render_remediation_template(template=template, overrides={})
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@template_app.command("run")
def template_run(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Template name or alias.")],
    var: Annotated[list[str], typer.Option("--var", help="Template variables, format key=value, repeatable.")] = [],
    apply: Annotated[bool, typer.Option("--apply", help="Execute generated apply commands with confirmation gate.")] = False,
    max_apply_steps: Annotated[int, typer.Option("--max-apply-steps", help="Max number of apply commands to execute.")] = 6,
    allow_high_risk: Annotated[bool, typer.Option("--allow-high-risk", help="Allow high/critical risk steps in apply mode.")] = False,
    auto_approve_low_risk: Annotated[bool, typer.Option("--auto-approve-low-risk", help="Auto-approve low-risk steps in apply mode.")] = False,
    execute: Annotated[bool | None, typer.Option("--execute", help="Override execution mode for apply steps.")] = None,
    approval_mode: Annotated[str | None, typer.Option(help="Override policy: strict|balanced|permissive")] = None,
    audit_log: Annotated[str | None, typer.Option(help="Override audit jsonl path.")] = None,
    model: Annotated[str | None, typer.Option(help="Override model.")] = None,
    provider: Annotated[str | None, typer.Option(help=f"Override provider: {provider_mode_help_text()}")] = None,
) -> None:
    options = _merged_options(
        ctx,
        execute=execute,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=approval_mode,
        audit_log=audit_log,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=model,
        provider=provider,
        max_steps=None,
    )
    _run_remediation_template(
        template_name=name,
        var_items=list(var),
        apply=apply,
        max_apply_steps=max(1, min(max_apply_steps, 30)),
        allow_high_risk=allow_high_risk,
        auto_approve_low_risk=auto_approve_low_risk,
        execute=bool(options["execute"]),
        approval_mode=str(options["approval_mode"]),
        audit_log=str(options["audit_log"]),
        model=str(options["model"]),
        provider=str(options["provider"]),
    )


@app.command("approve")
def approve_plan(
    ctx: typer.Context,
    steps: Annotated[str, typer.Option("--steps", help="Step indexes to execute, e.g. 1,3-5. Empty means list only.")] = "",
    execute: Annotated[bool | None, typer.Option("--execute", help="Override execution mode.")] = None,
    approval_mode: Annotated[str | None, typer.Option(help="Override policy: strict|balanced|permissive")] = None,
    audit_log: Annotated[str | None, typer.Option(help="Override audit jsonl path.")] = None,
    allow_high_risk: Annotated[bool, typer.Option("--allow-high-risk", help="Allow high/critical risk steps.")] = False,
    auto_approve_low_risk: Annotated[bool, typer.Option("--auto-approve-low-risk", help="Auto-approve low-risk steps.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Skip per-step confirmation for selected steps.")] = False,
    with_impact: Annotated[bool, typer.Option("--with-impact", help="Generate impact statement for each step.")] = False,
    model: Annotated[str | None, typer.Option(help="Override model.")] = None,
    provider: Annotated[str | None, typer.Option(help=f"Override provider: {provider_mode_help_text()}")] = None,
) -> None:
    options = _merged_options(
        ctx,
        execute=execute,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=approval_mode,
        audit_log=audit_log,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=model,
        provider=provider,
        max_steps=None,
    )
    _approve_last_fix_plan(
        steps=steps,
        execute=bool(options["execute"]),
        approval_mode=str(options["approval_mode"]),
        audit_log=str(options["audit_log"]),
        allow_high_risk=allow_high_risk,
        auto_approve_low_risk=auto_approve_low_risk,
        yes=yes,
        with_impact=with_impact,
        model=str(options["model"]),
        provider=str(options["provider"]),
    )


@app.command("undo")
def undo_last_plan(
    ctx: typer.Context,
    execute: Annotated[bool | None, typer.Option("--execute", help="Override execution mode for rollback.")] = None,
    approval_mode: Annotated[str | None, typer.Option(help="Override policy: strict|balanced|permissive")] = None,
    audit_log: Annotated[str | None, typer.Option(help="Override audit jsonl path.")] = None,
    max_steps: Annotated[int, typer.Option("--max-steps", help="Max rollback steps to run.")] = 6,
    model: Annotated[str | None, typer.Option(help="Override model.")] = None,
    provider: Annotated[str | None, typer.Option(help=f"Override provider: {provider_mode_help_text()}")] = None,
) -> None:
    options = _merged_options(
        ctx,
        execute=execute,
        approve=None,
        interactive_approval=None,
        stream_output=None,
        verbose_reasoning=None,
        approval_mode=approval_mode,
        audit_log=audit_log,
        lock_file=None,
        session_file=None,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=model,
        provider=provider,
        max_steps=None,
    )
    _undo_last_fix_plan(
        max_rollback_steps=max(1, min(max_steps, 30)),
        execute=bool(options["execute"]),
        approval_mode=str(options["approval_mode"]),
        audit_log=str(options["audit_log"]),
        model=str(options["model"]),
        provider=str(options["provider"]),
    )


@app.command("chat")
def chat(
    ctx: typer.Context,
    execute: Annotated[bool | None, typer.Option("--execute", help="Override execution mode.")] = None,
    approve: Annotated[bool | None, typer.Option("--approve", help="Override approval gate acknowledgement.")] = None,
    interactive_approval: Annotated[bool | None, typer.Option("--interactive-approval/--no-interactive-approval", help="Override interactive approval prompt.")] = None,
    stream_output: Annotated[bool | None, typer.Option("--stream-output/--no-stream-output", help="Override token streaming mode.")] = None,
    verbose_reasoning: Annotated[bool | None, typer.Option("--verbose-reasoning/--no-verbose-reasoning", help="Override reasoning verbosity.")] = None,
    approval_mode: Annotated[str | None, typer.Option(help="Override policy: strict|balanced|permissive")] = None,
    audit_log: Annotated[str | None, typer.Option(help="Override audit jsonl path.")] = None,
    lock_file: Annotated[str | None, typer.Option(help="Override tool pack lock file path.")] = None,
    session_file: Annotated[str | None, typer.Option(help="Override session memory file path.")] = None,
    deny_tool: Annotated[list[str] | None, typer.Option("--deny-tool", help="Override deny tool names.")] = None,
    deny_prefix: Annotated[list[str] | None, typer.Option("--deny-prefix", help="Override deny tool prefixes.")] = None,
    tool_pack: Annotated[list[str] | None, typer.Option("--tool-pack", help="Override tool packs.")] = None,
    remote_gateway: Annotated[list[str] | None, typer.Option("--remote-gateway", help="Override remote gateways.")] = None,
    model: Annotated[str | None, typer.Option(help="Override model.")] = None,
    provider: Annotated[str | None, typer.Option(help=f"Override provider: {provider_mode_help_text()}")] = None,
    max_steps: Annotated[int | None, typer.Option(help="Override max function-calling iterations.")] = None,
) -> None:
    options = _merged_options(
        ctx,
        execute=execute,
        approve=approve,
        interactive_approval=interactive_approval,
        stream_output=stream_output,
        verbose_reasoning=verbose_reasoning,
        approval_mode=approval_mode,
        audit_log=audit_log,
        lock_file=lock_file,
        session_file=session_file,
        deny_tool=deny_tool,
        deny_prefix=deny_prefix,
        tool_pack=tool_pack,
        remote_gateway=remote_gateway,
        model=model,
        provider=provider,
        max_steps=max_steps,
    )
    _assistant_chat_loop(options)


@app.command("fix")
def fix_instruction(
    ctx: typer.Context,
    instruction: Annotated[str, typer.Argument(help='Incident instruction, e.g. lsre fix "payment service slow"')],
    apply: Annotated[bool, typer.Option("--apply", help="Apply suggested commands step-by-step with confirmations.")] = False,
    max_apply_steps: Annotated[int, typer.Option("--max-apply-steps", help="Max number of suggested commands to execute.")] = 6,
    allow_high_risk: Annotated[bool, typer.Option("--allow-high-risk", help="Allow high/critical risk steps in apply mode.")] = False,
    auto_approve_low_risk: Annotated[bool, typer.Option("--auto-approve-low-risk", help="Auto-approve low-risk steps in apply mode.")] = False,
    export_plan_md: Annotated[str, typer.Option("--export-plan-md", help="Export fix plan markdown path.")] = "",
    export_plan_json: Annotated[str, typer.Option("--export-plan-json", help="Export fix plan json path.")] = "",
    execute: Annotated[bool | None, typer.Option("--execute", help="Override execution mode for apply steps.")] = None,
    approve: Annotated[bool | None, typer.Option("--approve", help="Override approval gate acknowledgement for diagnosis phase.")] = None,
    interactive_approval: Annotated[bool | None, typer.Option("--interactive-approval/--no-interactive-approval", help="Override interactive approval prompt for diagnosis phase.")] = None,
    stream_output: Annotated[bool | None, typer.Option("--stream-output/--no-stream-output", help="Override token streaming mode.")] = None,
    verbose_reasoning: Annotated[bool | None, typer.Option("--verbose-reasoning/--no-verbose-reasoning", help="Override reasoning verbosity.")] = None,
    approval_mode: Annotated[str | None, typer.Option(help="Override policy: strict|balanced|permissive")] = None,
    audit_log: Annotated[str | None, typer.Option(help="Override audit jsonl path.")] = None,
    lock_file: Annotated[str | None, typer.Option(help="Override tool pack lock file path.")] = None,
    session_file: Annotated[str | None, typer.Option(help="Override session memory file path.")] = None,
    deny_tool: Annotated[list[str] | None, typer.Option("--deny-tool", help="Override deny tool names.")] = None,
    deny_prefix: Annotated[list[str] | None, typer.Option("--deny-prefix", help="Override deny tool prefixes.")] = None,
    tool_pack: Annotated[list[str] | None, typer.Option("--tool-pack", help="Override tool packs.")] = None,
    remote_gateway: Annotated[list[str] | None, typer.Option("--remote-gateway", help="Override remote gateways.")] = None,
    model: Annotated[str | None, typer.Option(help="Override model.")] = None,
    provider: Annotated[str | None, typer.Option(help=f"Override provider: {provider_mode_help_text()}")] = None,
    max_steps: Annotated[int | None, typer.Option(help="Override max function-calling iterations.")] = None,
) -> None:
    options = _merged_options(
        ctx,
        execute=execute,
        approve=approve,
        interactive_approval=interactive_approval,
        stream_output=stream_output,
        verbose_reasoning=verbose_reasoning,
        approval_mode=approval_mode,
        audit_log=audit_log,
        lock_file=lock_file,
        session_file=session_file,
        deny_tool=deny_tool,
        deny_prefix=deny_prefix,
        tool_pack=tool_pack,
        remote_gateway=remote_gateway,
        model=model,
        provider=provider,
        max_steps=max_steps,
    )
    _run_fix(
        instruction=instruction,
        apply=apply,
        max_apply_steps=max(1, min(max_apply_steps, 30)),
        allow_high_risk=allow_high_risk,
        auto_approve_low_risk=auto_approve_low_risk,
        export_plan_md=export_plan_md,
        export_plan_json=export_plan_json,
        execute=bool(options["execute"]),
        approve=bool(options["approve"]),
        interactive_approval=bool(options["interactive_approval"]),
        stream_output=bool(options["stream_output"]),
        verbose_reasoning=bool(options["verbose_reasoning"]),
        approval_mode=str(options["approval_mode"]),
        audit_log=str(options["audit_log"]),
        lock_file=str(options["lock_file"]),
        session_file=str(options["session_file"]),
        deny_tool=list(options["deny_tool"]),
        deny_prefix=list(options["deny_prefix"]),
        tool_pack=list(options["tool_pack"]),
        remote_gateway=list(options["remote_gateway"]),
        model=str(options["model"]),
        provider=str(options["provider"]),
        max_steps=int(options["max_steps"]),
    )


def _merged_options(
    ctx: typer.Context,
    *,
    execute: bool | None,
    approve: bool | None,
    interactive_approval: bool | None,
    stream_output: bool | None,
    verbose_reasoning: bool | None,
    approval_mode: str | None,
    audit_log: str | None,
    lock_file: str | None,
    session_file: str | None,
    deny_tool: list[str] | None,
    deny_prefix: list[str] | None,
    tool_pack: list[str] | None,
    remote_gateway: list[str] | None,
    model: str | None,
    provider: str | None,
    max_steps: int | None,
) -> dict[str, object]:
    base = dict(ctx.obj or {})
    if execute is not None:
        base["execute"] = execute
    if approve is not None:
        base["approve"] = approve
    if interactive_approval is not None:
        base["interactive_approval"] = interactive_approval
    if stream_output is not None:
        base["stream_output"] = stream_output
    if verbose_reasoning is not None:
        base["verbose_reasoning"] = verbose_reasoning
    if approval_mode is not None:
        base["approval_mode"] = approval_mode
    if audit_log is not None:
        base["audit_log"] = audit_log
    if lock_file is not None:
        base["lock_file"] = lock_file
    if session_file is not None:
        base["session_file"] = session_file
    if deny_tool is not None:
        base["deny_tool"] = list(deny_tool)
    if deny_prefix is not None:
        base["deny_prefix"] = list(deny_prefix)
    if tool_pack is not None:
        base["tool_pack"] = list(tool_pack)
    if remote_gateway is not None:
        base["remote_gateway"] = list(remote_gateway)
    if model is not None:
        base["model"] = model
    if provider is not None:
        base["provider"] = provider
    if max_steps is not None:
        base["max_steps"] = max_steps
    if "execute" not in base:
        base["execute"] = False
    if "approve" not in base:
        base["approve"] = False
    if "interactive_approval" not in base:
        base["interactive_approval"] = True
    if "stream_output" not in base:
        base["stream_output"] = True
    if "verbose_reasoning" not in base:
        base["verbose_reasoning"] = False
    if "approval_mode" not in base:
        base["approval_mode"] = "balanced"
    if "audit_log" not in base:
        base["audit_log"] = ".data/lsre-audit.jsonl"
    if "lock_file" not in base:
        base["lock_file"] = ".data/lsre-tool-lock.json"
    if "session_file" not in base:
        base["session_file"] = ".data/lsre-session.json"
    if "deny_tool" not in base:
        base["deny_tool"] = []
    if "deny_prefix" not in base:
        base["deny_prefix"] = []
    if "tool_pack" not in base:
        base["tool_pack"] = ["builtin"]
    if "remote_gateway" not in base:
        base["remote_gateway"] = []
    if "model" not in base:
        base["model"] = settings.model_name
    if "provider" not in base:
        base["provider"] = "auto"
    if "max_steps" not in base:
        base["max_steps"] = 6
    return base


def _run_once(
    *,
    instruction: str,
    execute: bool,
    approve: bool,
    interactive_approval: bool,
    stream_output: bool,
    verbose_reasoning: bool,
    approval_mode: str,
    audit_log: str,
    lock_file: str,
    session_file: str,
    deny_tool: list[str],
    deny_prefix: list[str],
    tool_pack: list[str],
    remote_gateway: list[str],
    model: str,
    provider: str,
    max_steps: int,
) -> None:
    context_window = ContextWindowManager()
    session = SessionStore(Path(session_file))
    session_hint = session.build_context_hint(instruction)
    dialogue_context = session.build_dialogue_context(max_chars=2200)
    memory_context = _build_memory_context(instruction)
    prompt = instruction
    if session_hint:
        prompt = f"{instruction}\n\n[session]\n{session_hint}"
    if dialogue_context:
        prompt = f"{prompt}\n\n[dialogue]\n{dialogue_context}"
    if memory_context:
        prompt = f"{prompt}\n\n[memory]\n{memory_context}"
    prompt = context_window.fit_text(prompt, max_chars=9000)

    streamed_chunks: list[str] = []
    stream_enabled = bool(_console and stream_output and verbose_reasoning)

    def _stream_text(delta: str) -> None:
        if not _console:
            return
        streamed_chunks.append(delta)
        _console.print(delta, end="")

    if _console and (not stream_enabled):
        with _console.status("[bold cyan]AI思考中...[/]"):
            result = asyncio.run(
                _dispatch(
                    instruction=prompt,
                    execute=execute,
                    approve=approve,
                    interactive_approval=interactive_approval,
                    approval_mode=approval_mode,
                    audit_log=audit_log,
                lock_file=lock_file,
                deny_tool=deny_tool,
                deny_prefix=deny_prefix,
                tool_pack=tool_pack,
                remote_gateway=remote_gateway,
                model=model,
                provider=provider,
                max_steps=max_steps,
                text_stream=None,
                conversation_context=dialogue_context,
                memory_context=memory_context,
            )
            )
    else:
        result = asyncio.run(
            _dispatch(
                instruction=prompt,
                execute=execute,
                approve=approve,
                interactive_approval=interactive_approval,
                approval_mode=approval_mode,
                audit_log=audit_log,
                lock_file=lock_file,
                deny_tool=deny_tool,
                deny_prefix=deny_prefix,
                tool_pack=tool_pack,
                remote_gateway=remote_gateway,
                model=model,
                provider=provider,
                max_steps=max_steps,
                text_stream=_stream_text if stream_enabled else None,
                conversation_context=dialogue_context,
                memory_context=memory_context,
            )
        )
    if _console and streamed_chunks:
        _console.print("")
    session.append_turn(user_input=instruction, result=result)

    if _console:
        _render_timeline(result.events)
    else:
        for event in result.events:
            if event.kind in {"tool_call", "tool_output", "llm_turn"}:
                detail = json.dumps(event.data, ensure_ascii=False)
                typer.echo(f"[{event.kind}] {event.message} {detail}")
    if _console:
        if verbose_reasoning:
            if Markdown and (not streamed_chunks):
                _console.print(Panel(Markdown(result.final_text), title="LazySRE", border_style="blue"))
            elif (not streamed_chunks):
                _console.print(result.final_text)
        else:
            _render_compact_result(result, title="LazySRE")
    else:
        typer.echo(result.final_text)


def _run_fix(
    *,
    instruction: str,
    apply: bool,
    max_apply_steps: int,
    allow_high_risk: bool,
    auto_approve_low_risk: bool,
    export_plan_md: str,
    export_plan_json: str,
    execute: bool,
    approve: bool,
    interactive_approval: bool,
    stream_output: bool,
    verbose_reasoning: bool,
    approval_mode: str,
    audit_log: str,
    lock_file: str,
    session_file: str,
    deny_tool: list[str],
    deny_prefix: list[str],
    tool_pack: list[str],
    remote_gateway: list[str],
    model: str,
    provider: str,
    max_steps: int,
) -> None:
    context_window = ContextWindowManager()
    session = SessionStore(Path(session_file))
    session_hint = session.build_context_hint(instruction)
    dialogue_context = session.build_dialogue_context(max_chars=2200)
    memory_context = _build_memory_context(instruction)
    prompt = compose_fix_instruction(instruction)
    if session_hint:
        prompt = f"{prompt}\n\n[session]\n{session_hint}"
    if dialogue_context:
        prompt = f"{prompt}\n\n[dialogue]\n{dialogue_context}"
    if memory_context:
        prompt = f"{prompt}\n\n[memory]\n{memory_context}"
    watch_context = _build_latest_watch_context(instruction)
    if watch_context:
        prompt = f"{prompt}\n\n[latest_watch]\n{watch_context}"
    prompt = context_window.fit_text(prompt, max_chars=9500)

    streamed_chunks: list[str] = []
    stream_enabled = bool(_console and stream_output and verbose_reasoning)

    def _stream_text(delta: str) -> None:
        if not _console:
            return
        streamed_chunks.append(delta)
        _console.print(delta, end="")

    if _console and (not stream_enabled):
        with _console.status("[bold cyan]AI 生成修复计划中...[/]"):
            result = asyncio.run(
                _dispatch(
                    instruction=prompt,
                    execute=execute,
                    approve=approve,
                    interactive_approval=interactive_approval,
                    approval_mode=approval_mode,
                    audit_log=audit_log,
                    lock_file=lock_file,
                    deny_tool=deny_tool,
                    deny_prefix=deny_prefix,
                    tool_pack=tool_pack,
                    remote_gateway=remote_gateway,
                    model=model,
                    provider=provider,
                    max_steps=max_steps,
                    text_stream=None,
                    conversation_context=dialogue_context,
                    memory_context=memory_context,
                )
            )
    else:
        result = asyncio.run(
            _dispatch(
                instruction=prompt,
                execute=execute,
                approve=approve,
                interactive_approval=interactive_approval,
                approval_mode=approval_mode,
                audit_log=audit_log,
                lock_file=lock_file,
                deny_tool=deny_tool,
                deny_prefix=deny_prefix,
                tool_pack=tool_pack,
                remote_gateway=remote_gateway,
                model=model,
                provider=provider,
                max_steps=max_steps,
                text_stream=_stream_text if stream_enabled else None,
                conversation_context=dialogue_context,
                memory_context=memory_context,
            )
        )
    if _console and streamed_chunks:
        _console.print("")
    session.append_turn(user_input=f"[fix] {instruction}", result=result)

    if _console:
        _render_timeline(result.events)
        if verbose_reasoning:
            if Markdown and (not streamed_chunks):
                _console.print(Panel(Markdown(result.final_text), title="Fix Plan", border_style="magenta"))
            elif (not streamed_chunks):
                _console.print(result.final_text)
        else:
            _render_compact_result(result, title="Fix Plan")
    else:
        typer.echo(result.final_text)

    plan = extract_fix_plan(result.final_text)
    _render_fix_summary(plan, max_apply_steps=max_apply_steps)
    selected_preview = plan.apply_commands[:max_apply_steps]
    md_path = Path(export_plan_md.strip() or ".data/lsre-fix-last.md")
    json_path = Path(export_plan_json.strip() or ".data/lsre-fix-last.json")
    _write_text_file(md_path, result.final_text)
    _write_json_file(
        json_path,
        build_plan_record(
            instruction=instruction,
            plan=plan,
            final_text=result.final_text,
            selected_apply_commands=selected_preview,
            approval_mode=approval_mode,
        ),
    )
    typer.echo(f"修复计划已导出: md={md_path} json={json_path}")

    if not apply:
        typer.echo("计划已生成。若需分步执行，请加 --apply。")
        return
    if not plan.apply_commands:
        typer.echo("未从计划中识别到可执行命令，已跳过执行。")
        return

    exec_summary = _execute_fix_plan_steps(
        plan=plan,
        max_apply_steps=max_apply_steps,
        execute=execute,
        approval_mode=approval_mode,
        audit_log=audit_log,
        allow_high_risk=allow_high_risk,
        auto_approve_low_risk=auto_approve_low_risk,
        model=model,
        provider=provider,
    )

    _persist_successful_fix_case(
        instruction=instruction,
        final_text=result.final_text,
        plan=plan,
        plan_md_path=md_path,
        exec_summary=exec_summary,
        apply=apply,
        execute=execute,
    )

    if plan.rollback_commands:
        typer.echo("\n可回滚命令：")
        for cmd in plan.rollback_commands:
            typer.echo(f"- {cmd}")


async def _dispatch(
    *,
    instruction: str,
    execute: bool,
    approve: bool,
    interactive_approval: bool,
    approval_mode: str,
    audit_log: str,
    lock_file: str,
    deny_tool: list[str],
    deny_prefix: list[str],
    tool_pack: list[str],
    remote_gateway: list[str],
    model: str,
    provider: str,
    max_steps: int,
    text_stream=None,
    conversation_context: str = "",
    memory_context: str = "",
):
    mode = (provider or "auto").strip().lower()
    if mode not in {"auto", "mock", *PROVIDER_SPECS.keys()}:
        raise typer.BadParameter(provider_mode_error_text())
    ap_mode = (approval_mode or "balanced").strip().lower()
    if ap_mode not in {"strict", "balanced", "permissive"}:
        raise typer.BadParameter("approval_mode must be one of strict/balanced/permissive")
    _, resolved_model, llm = _build_cli_llm(provider=mode, model=model)

    dispatcher = Dispatcher(
        llm=llm,
        registry=build_default_registry(
            permission_context=ToolPermissionContext.from_iterables(
                deny_names=deny_tool,
                deny_prefixes=deny_prefix,
            ),
            tool_packs=tool_pack,
            remote_gateways=remote_gateway,
            lock_file=Path(lock_file),
        ),
        executor=SafeExecutor(
            dry_run=(not execute),
            approval_mode=ap_mode,
            approval_granted=approve,
            approval_callback=_build_approval_callback(enabled=interactive_approval and execute),
            audit_logger=AuditLogger(Path(audit_log)),
        ),
        model=resolved_model,
        max_steps=max(1, min(max_steps, 12)),
        text_stream=text_stream,
        system_prompt=_build_system_prompt(
            conversation_context=conversation_context,
            memory_context=memory_context,
        ),
    )
    return await dispatcher.run(instruction)


def _build_approval_callback(*, enabled: bool):
    if not enabled:
        return None

    def _callback(command: list[str], decision: PolicyDecision) -> bool:
        report = build_risk_report(command, decision)
        lines = [
            "变更风险报告",
            f"- 风险等级: {decision.risk_level}",
            f"- 风险分值: {report.get('risk_score', '-')}",
            f"- 影响范围: {report.get('impact_scope', '-')}",
            f"- 爆炸半径: {report.get('blast_radius', '-')}",
            f"- 目标命令: {' '.join(command)}",
        ]
        if decision.reasons:
            lines.append("- 风险原因:")
            for reason in decision.reasons:
                lines.append(f"  - {reason}")
        rollback = str(report.get("rollback", "")).strip()
        if rollback:
            lines.append(f"- 回滚建议: {rollback}")
        text = "\n".join(lines)
        if _console and Panel:
            _console.print(Panel(text, border_style="yellow"))
        else:
            typer.echo(text)
        try:
            approved = typer.confirm("确认执行该变更吗？", default=False)
        except (EOFError, KeyboardInterrupt):
            return False
        return bool(approved)

    return _callback


@target_app.command("show")
def target_show(
    profile_file: Annotated[str, typer.Option("--profile-file", help="Target profile JSON path.")] = settings.target_profile_file,
) -> None:
    store = TargetEnvStore(Path(profile_file))
    payload = store.load().to_safe_dict()
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@target_app.command("set")
def target_set(
    profile_file: Annotated[str, typer.Option("--profile-file", help="Target profile JSON path.")] = settings.target_profile_file,
    prometheus_url: Annotated[str | None, typer.Option("--prometheus-url", help="Prometheus base URL.")] = None,
    k8s_api_url: Annotated[str | None, typer.Option("--k8s-api-url", help="Kubernetes API URL.")] = None,
    k8s_context: Annotated[str | None, typer.Option("--k8s-context", help="kubectl context name.")] = None,
    k8s_namespace: Annotated[str | None, typer.Option("--k8s-namespace", help="Default Kubernetes namespace.")] = None,
    k8s_bearer_token: Annotated[str | None, typer.Option("--k8s-bearer-token", help="Kubernetes bearer token.")] = None,
    k8s_verify_tls: Annotated[bool | None, typer.Option("--k8s-verify-tls/--k8s-skip-tls-verify", help="TLS verification for Kubernetes API.")] = None,
) -> None:
    store = TargetEnvStore(Path(profile_file))
    updated = store.update(
        prometheus_url=prometheus_url,
        k8s_api_url=k8s_api_url,
        k8s_context=k8s_context,
        k8s_namespace=k8s_namespace,
        k8s_bearer_token=k8s_bearer_token,
        k8s_verify_tls=k8s_verify_tls,
    )
    typer.echo(json.dumps(updated.to_safe_dict(), ensure_ascii=False, indent=2))


@target_app.command("probe")
def target_probe(
    ctx: typer.Context,
    profile_file: Annotated[str, typer.Option("--profile-file", help="Target profile JSON path.")] = settings.target_profile_file,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Probe timeout seconds.")] = 6,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview probe commands without executing.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON report.")] = False,
) -> None:
    target = TargetEnvStore(Path(profile_file)).load()
    base = dict(ctx.obj or {})
    audit_path = Path(str(base.get("audit_log", ".data/lsre-audit.jsonl")))
    report = asyncio.run(
        probe_target_environment(
            target,
            executor=SafeExecutor(
                dry_run=dry_run,
                approval_mode="permissive",
                approval_granted=True,
                audit_logger=AuditLogger(audit_path),
            ),
            timeout_sec=timeout_sec,
        )
    )
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _render_probe_report(report)


@target_profile_app.command("list")
def target_profile_list(
    profiles_file: Annotated[str, typer.Option("--profiles-file", help="Profiles store JSON path.")] = settings.target_profiles_file,
) -> None:
    store = ClusterProfileStore(Path(profiles_file))
    active = store.get_active()
    names = store.list_profiles()
    if not (_console and Table):
        typer.echo(json.dumps({"active": active, "profiles": names}, ensure_ascii=False, indent=2))
        return
    table = Table(title="Target Profiles")
    table.add_column("Name", style="cyan")
    table.add_column("Active", style="green", no_wrap=True)
    for name in names:
        table.add_row(name, "yes" if name == active else "")
    _console.print(table)


@target_profile_app.command("current")
def target_profile_current(
    profiles_file: Annotated[str, typer.Option("--profiles-file", help="Profiles store JSON path.")] = settings.target_profiles_file,
) -> None:
    store = ClusterProfileStore(Path(profiles_file))
    active = store.get_active()
    payload = {"active": active or "", "profiles_file": str(profiles_file)}
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@target_profile_app.command("save")
def target_profile_save(
    name: Annotated[str, typer.Argument(help="Profile name.")],
    profiles_file: Annotated[str, typer.Option("--profiles-file", help="Profiles store JSON path.")] = settings.target_profiles_file,
    profile_file: Annotated[str, typer.Option("--profile-file", help="Current target profile JSON path.")] = settings.target_profile_file,
    activate: Annotated[bool, typer.Option("--activate/--no-activate", help="Set saved profile as active.")] = True,
) -> None:
    env = TargetEnvStore(Path(profile_file)).load()
    store = ClusterProfileStore(Path(profiles_file))
    store.upsert_profile(name, env, activate=activate)
    typer.echo(f"Saved profile: {name} (activate={activate})")


@target_profile_app.command("use")
def target_profile_use(
    name: Annotated[str, typer.Argument(help="Profile name to activate.")],
    profiles_file: Annotated[str, typer.Option("--profiles-file", help="Profiles store JSON path.")] = settings.target_profiles_file,
    profile_file: Annotated[str, typer.Option("--profile-file", help="Current target profile JSON path.")] = settings.target_profile_file,
) -> None:
    store = ClusterProfileStore(Path(profiles_file))
    ok = store.activate(name, target_profile_file=Path(profile_file))
    if not ok:
        raise typer.BadParameter(f"profile not found: {name}")
    typer.echo(f"Activated profile: {name}")


@target_profile_app.command("show")
def target_profile_show(
    name: Annotated[str, typer.Argument(help="Profile name. Use @active for active profile.")],
    profiles_file: Annotated[str, typer.Option("--profiles-file", help="Profiles store JSON path.")] = settings.target_profiles_file,
) -> None:
    store = ClusterProfileStore(Path(profiles_file))
    key = name
    if name.strip() == "@active":
        key = store.get_active()
    env = store.get_profile(key)
    if not env:
        raise typer.BadParameter(f"profile not found: {name}")
    payload = env.to_safe_dict()
    payload["name"] = key
    payload["active"] = (key == store.get_active())
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@target_profile_app.command("remove")
def target_profile_remove(
    name: Annotated[str, typer.Argument(help="Profile name.")],
    profiles_file: Annotated[str, typer.Option("--profiles-file", help="Profiles store JSON path.")] = settings.target_profiles_file,
    yes: Annotated[bool, typer.Option("--yes", help="Skip confirmation prompt.")] = False,
) -> None:
    if not yes:
        if not typer.confirm(f"确认删除 profile {name} 吗？", default=False):
            typer.echo("Canceled.")
            return
    store = ClusterProfileStore(Path(profiles_file))
    removed = store.remove_profile(name)
    if not removed:
        raise typer.BadParameter(f"profile not found: {name}")
    typer.echo(f"Removed profile: {name}")


@target_profile_app.command("export")
def target_profile_export(
    output: Annotated[str, typer.Option("--output", help="Export file path (.json).")] = "",
    name: Annotated[list[str], typer.Option("--name", help="Profile name filter. Can be repeated.")] = [],
    profiles_file: Annotated[str, typer.Option("--profiles-file", help="Profiles store JSON path.")] = settings.target_profiles_file,
) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_path = Path(output.strip() or f".data/lsre-target-profiles-export-{stamp}.json")
    store = ClusterProfileStore(Path(profiles_file))
    payload = store.export_payload(names=list(name))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    count = len(payload.get("profiles", {})) if isinstance(payload.get("profiles", {}), dict) else 0
    typer.echo(f"Exported {count} profiles -> {out_path}")


@target_profile_app.command("import")
def target_profile_import(
    input_file: Annotated[str, typer.Option("--input", help="Import file path (.json).")],
    merge: Annotated[bool, typer.Option("--merge/--replace", help="Merge into existing profiles or replace all.")] = True,
    activate: Annotated[str, typer.Option("--activate", help="Activate profile after import. Use @active for imported active profile.")] = "",
    profiles_file: Annotated[str, typer.Option("--profiles-file", help="Profiles store JSON path.")] = settings.target_profiles_file,
    profile_file: Annotated[str, typer.Option("--profile-file", help="Current target profile JSON path.")] = settings.target_profile_file,
) -> None:
    in_path = Path(input_file)
    if not in_path.exists():
        raise typer.BadParameter(f"import file not found: {input_file}")
    try:
        raw = json.loads(in_path.read_text(encoding="utf-8"))
    except Exception:
        raise typer.BadParameter(f"import file is not valid json: {input_file}") from None
    if not isinstance(raw, dict):
        raise typer.BadParameter("import payload must be a JSON object")

    store = ClusterProfileStore(Path(profiles_file))
    try:
        result = store.import_payload(raw, merge=merge)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    activated = ""
    activate_value = activate.strip()
    if activate_value:
        activated = str(result.get("active", "")).strip() if activate_value == "@active" else activate_value
        if not activated:
            raise typer.BadParameter("import payload has no active profile to activate")
        ok = store.activate(activated, target_profile_file=Path(profile_file))
        if not ok:
            raise typer.BadParameter(f"profile not found after import: {activated}")

    typer.echo(
        "Imported profiles: "
        f"imported={result.get('imported', 0)} "
        f"created={result.get('created', 0)} "
        f"updated={result.get('updated', 0)} "
        f"total={result.get('total', 0)}"
    )
    if activated:
        typer.echo(f"Activated profile: {activated}")


@history_app.command("show")
def history_show(
    ctx: typer.Context,
    session_file: Annotated[str | None, typer.Option("--session-file", help="Override session file path.")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Number of turns to display.")] = 10,
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    store = SessionStore(_resolve_session_file(ctx, session_file))
    turns = store.recent_turns(limit=limit)
    if as_json or (not _console):
        typer.echo(json.dumps(turns, ensure_ascii=False, indent=2))
        return
    table = Table(title="Session History")
    table.add_column("#", style="cyan", no_wrap=True)
    table.add_column("User", style="white")
    table.add_column("Assistant", style="green")
    for idx, item in enumerate(turns, 1):
        table.add_row(str(idx), item["user"][:100], item["assistant"][:140])
    _console.print(table)


@history_app.command("clear")
def history_clear(
    ctx: typer.Context,
    session_file: Annotated[str | None, typer.Option("--session-file", help="Override session file path.")] = None,
    yes: Annotated[bool, typer.Option("--yes", help="Skip confirmation prompt.")] = False,
) -> None:
    store = SessionStore(_resolve_session_file(ctx, session_file))
    if not yes:
        if not typer.confirm("确认清空会话历史吗？", default=False):
            typer.echo("Canceled.")
            return
    store.clear()
    typer.echo("Session history cleared.")


@history_app.command("export")
def history_export(
    ctx: typer.Context,
    session_file: Annotated[str | None, typer.Option("--session-file", help="Override session file path.")] = None,
    output: Annotated[str, typer.Option("--output", help="Output markdown file path.")] = ".data/lsre-session-history.md",
    limit: Annotated[int, typer.Option("--limit", help="Number of turns to export.")] = 30,
) -> None:
    store = SessionStore(_resolve_session_file(ctx, session_file))
    content = store.export_markdown(limit=limit)
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")
    typer.echo(f"Exported: {out_path}")


@memory_app.command("show")
def memory_show(
    limit: Annotated[int, typer.Option("--limit", help="Number of memory cases to display.")] = 10,
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    store = _open_incident_memory_store()
    if not store:
        typer.echo("memory store is unavailable.")
        return
    rows = store.list_recent(limit=limit)
    if as_json or (not _console):
        payload = [
            {
                "id": item.id,
                "created_at": item.created_at,
                "symptom": item.symptom,
                "root_cause": item.root_cause,
                "fix_commands": item.fix_commands,
                "rollback_commands": item.rollback_commands,
                "metadata": item.metadata,
            }
            for item in rows
        ]
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    _render_memory_cases(rows, title="Incident Memory (Recent)")


@memory_app.command("search")
def memory_search(
    query: Annotated[str, typer.Argument(help="Search query for similar incidents.")],
    limit: Annotated[int, typer.Option("--limit", help="Max similar cases to return.")] = 5,
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    store = _open_incident_memory_store()
    if not store:
        typer.echo("memory store is unavailable.")
        return
    rows = store.search_similar(query, limit=limit)
    if as_json or (not _console):
        payload = [
            {
                "id": item.id,
                "created_at": item.created_at,
                "score": item.score,
                "symptom": item.symptom,
                "root_cause": item.root_cause,
                "fix_commands": item.fix_commands,
                "rollback_commands": item.rollback_commands,
                "metadata": item.metadata,
            }
            for item in rows
        ]
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    _render_memory_cases(rows, title=f"Incident Memory Search: {query}")


@runbook_app.command("list")
def runbook_list(
    runbook_file: Annotated[str, typer.Option("--runbook-file", help="Runbook store JSON path.")] = settings.runbook_store_file,
    custom_only: Annotated[bool, typer.Option("--custom-only", help="Show custom runbooks only.")] = False,
) -> None:
    store = RunbookStore(Path(runbook_file))
    items = store.list_custom() if custom_only else all_runbooks(store=store)
    if not (_console and Table):
        for item in items:
            typer.echo(f"{item.name} [{item.mode}] ({item.source}) {item.title}")
        return
    table = Table(title="Runbooks")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Mode", style="magenta", no_wrap=True)
    table.add_column("Source", style="yellow", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Description", style="green")
    for item in items:
        table.add_row(item.name, item.mode, item.source, item.title, item.description)
    _console.print(table)


@runbook_app.command("show")
def runbook_show(
    name: Annotated[str, typer.Argument(help="Runbook name.")],
    runbook_file: Annotated[str, typer.Option("--runbook-file", help="Runbook store JSON path.")] = settings.runbook_store_file,
) -> None:
    item = find_runbook(name, store=RunbookStore(Path(runbook_file)))
    if not item:
        raise typer.BadParameter(f"runbook not found: {name}")
    payload = {
        "name": item.name,
        "title": item.title,
        "mode": item.mode,
        "source": item.source,
        "description": item.description,
        "instruction": item.instruction,
        "variables": item.variables,
    }
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@runbook_app.command("add")
def runbook_add(
    name: Annotated[str, typer.Argument(help="Runbook name.")],
    title: Annotated[str, typer.Option("--title", help="Runbook title.")],
    instruction: Annotated[str, typer.Option("--instruction", help="Instruction template (supports {vars}).")],
    mode: Annotated[str, typer.Option("--mode", help="Runbook mode: diagnose|fix")] = "diagnose",
    description: Annotated[str, typer.Option("--description", help="Short description.")] = "",
    var: Annotated[list[str], typer.Option("--var", "-v", help="Default vars key=value, can be repeated.")] = [],
    runbook_file: Annotated[str, typer.Option("--runbook-file", help="Runbook store JSON path.")] = settings.runbook_store_file,
    force: Annotated[bool, typer.Option("--force", help="Overwrite if already exists (including builtin names).")] = False,
) -> None:
    store = RunbookStore(Path(runbook_file))
    existing = find_runbook(name, store=store)
    if existing and (not force):
        raise typer.BadParameter(f"runbook already exists: {name}. use --force to overwrite.")
    try:
        default_vars = parse_runbook_vars(var)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    template = RunbookTemplate(
        name=name.strip().lower(),
        title=title.strip(),
        mode=mode.strip().lower(),
        instruction=instruction.strip(),
        description=description.strip(),
        variables=default_vars,
        source="custom",
    )
    try:
        store.upsert(template)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Saved runbook: {template.name} ({template.mode})")


@runbook_app.command("remove")
def runbook_remove(
    name: Annotated[str, typer.Argument(help="Runbook name.")],
    runbook_file: Annotated[str, typer.Option("--runbook-file", help="Runbook store JSON path.")] = settings.runbook_store_file,
    yes: Annotated[bool, typer.Option("--yes", help="Skip confirmation prompt.")] = False,
) -> None:
    store = RunbookStore(Path(runbook_file))
    custom = store.get_custom(name)
    if not custom:
        raise typer.BadParameter(f"custom runbook not found: {name}")
    if not yes:
        if not typer.confirm(f"确认删除自定义 runbook {name} 吗？", default=False):
            typer.echo("Canceled.")
            return
    removed = store.remove(name)
    if not removed:
        raise typer.BadParameter(f"custom runbook not found: {name}")
    typer.echo(f"Removed runbook: {name}")


@runbook_app.command("export")
def runbook_export(
    output: Annotated[str, typer.Option("--output", help="Export file path (.json).")] = "",
    name: Annotated[list[str], typer.Option("--name", help="Runbook name filter. Can be repeated.")] = [],
    scope: Annotated[str, typer.Option("--scope", help="Export scope: custom|effective")] = "custom",
    runbook_file: Annotated[str, typer.Option("--runbook-file", help="Runbook store JSON path.")] = settings.runbook_store_file,
) -> None:
    store = RunbookStore(Path(runbook_file))
    try:
        payload = store.export_payload(names=list(name), scope=scope)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_path = Path(output.strip() or f".data/lsre-runbooks-export-{stamp}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    count = len(payload.get("runbooks", {})) if isinstance(payload.get("runbooks", {}), dict) else 0
    typer.echo(f"Exported {count} runbooks -> {out_path}")


@runbook_app.command("import")
def runbook_import(
    input_file: Annotated[str, typer.Option("--input", help="Import file path (.json).")],
    merge: Annotated[bool, typer.Option("--merge/--replace", help="Merge into existing custom runbooks or replace all.")] = True,
    runbook_file: Annotated[str, typer.Option("--runbook-file", help="Runbook store JSON path.")] = settings.runbook_store_file,
) -> None:
    in_path = Path(input_file)
    if not in_path.exists():
        raise typer.BadParameter(f"import file not found: {input_file}")
    try:
        raw = json.loads(in_path.read_text(encoding="utf-8"))
    except Exception:
        raise typer.BadParameter(f"import file is not valid json: {input_file}") from None
    if not isinstance(raw, dict):
        raise typer.BadParameter("import payload must be a JSON object")
    store = RunbookStore(Path(runbook_file))
    try:
        result = store.import_payload(raw, merge=merge)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(
        "Imported runbooks: "
        f"imported={result.get('imported', 0)} "
        f"created={result.get('created', 0)} "
        f"updated={result.get('updated', 0)} "
        f"skipped_invalid={result.get('skipped_invalid', 0)} "
        f"total={result.get('total', 0)}"
    )


@runbook_app.command("run")
def runbook_run(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Runbook name.")],
    apply: Annotated[bool, typer.Option("--apply", help="Apply generated fix steps (fix runbooks only).")] = False,
    var: Annotated[list[str], typer.Option("--var", "-v", help="Runbook variables in key=value format. Can be repeated.")] = [],
    extra: Annotated[str, typer.Option("--extra", help="Extra context appended to runbook instruction.")] = "",
    runbook_file: Annotated[str, typer.Option("--runbook-file", help="Runbook store JSON path.")] = settings.runbook_store_file,
    execute: Annotated[bool | None, typer.Option("--execute", help="Override execution mode.")] = None,
    approve: Annotated[bool | None, typer.Option("--approve", help="Override approval flag.")] = None,
    interactive_approval: Annotated[bool | None, typer.Option("--interactive-approval/--no-interactive-approval", help="Override interactive approval prompt.")] = None,
    stream_output: Annotated[bool | None, typer.Option("--stream-output/--no-stream-output", help="Override stream output mode.")] = None,
    verbose_reasoning: Annotated[bool | None, typer.Option("--verbose-reasoning/--no-verbose-reasoning", help="Override reasoning verbosity.")] = None,
    approval_mode: Annotated[str | None, typer.Option(help="Override policy: strict|balanced|permissive")] = None,
    audit_log: Annotated[str | None, typer.Option(help="Override audit jsonl path.")] = None,
    lock_file: Annotated[str | None, typer.Option(help="Override tool pack lock file path.")] = None,
    session_file: Annotated[str | None, typer.Option(help="Override session file path.")] = None,
    model: Annotated[str | None, typer.Option(help="Override model.")] = None,
    provider: Annotated[str | None, typer.Option(help=f"Override provider: {provider_mode_help_text()}")] = None,
    max_steps: Annotated[int | None, typer.Option(help="Override max function-calling iterations.")] = None,
) -> None:
    template = find_runbook(name, store=RunbookStore(Path(runbook_file)))
    if not template:
        raise typer.BadParameter(f"runbook not found: {name}")
    options = _merged_options(
        ctx,
        execute=execute,
        approve=approve,
        interactive_approval=interactive_approval,
        stream_output=stream_output,
        verbose_reasoning=verbose_reasoning,
        approval_mode=approval_mode,
        audit_log=audit_log,
        lock_file=lock_file,
        session_file=session_file,
        deny_tool=None,
        deny_prefix=None,
        tool_pack=None,
        remote_gateway=None,
        model=model,
        provider=provider,
        max_steps=max_steps,
    )
    try:
        var_items = _compose_runbook_var_items(
            template=template,
            text=" ".join([extra] + [str(x) for x in list(var)]),
            options=options,
            base_items=list(var),
            profile_file=Path(settings.target_profile_file),
        )
        instruction = _prepare_runbook_instruction(
            template=template,
            var_items=var_items,
            extra=extra,
            profile_file=Path(settings.target_profile_file),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    _execute_runbook(
        template=template,
        instruction=instruction,
        apply=apply,
        options=options,
    )


@runbook_app.command("render")
def runbook_render(
    name: Annotated[str, typer.Argument(help="Runbook name.")],
    var: Annotated[list[str], typer.Option("--var", "-v", help="Runbook variables in key=value format. Can be repeated.")] = [],
    extra: Annotated[str, typer.Option("--extra", help="Extra context appended to rendered instruction.")] = "",
    runbook_file: Annotated[str, typer.Option("--runbook-file", help="Runbook store JSON path.")] = settings.runbook_store_file,
    as_json: Annotated[bool, typer.Option("--json", help="Print rendered payload as JSON.")] = False,
) -> None:
    template = find_runbook(name, store=RunbookStore(Path(runbook_file)))
    if not template:
        raise typer.BadParameter(f"runbook not found: {name}")
    try:
        var_items = _compose_runbook_var_items(
            template=template,
            text=" ".join([extra] + [str(x) for x in list(var)]),
            options={"session_file": ".data/lsre-session.json"},
            base_items=list(var),
            profile_file=Path(settings.target_profile_file),
        )
        resolved = _resolve_runbook_vars(
            template=template,
            var_items=var_items,
            profile_file=Path(settings.target_profile_file),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    rendered = template.instruction.format(**resolved)
    if extra.strip():
        rendered = f"{rendered}\n\n[runbook-extra]\n{extra.strip()}"
    payload = {
        "name": template.name,
        "mode": template.mode,
        "source": template.source,
        "resolved_vars": resolved,
        "rendered_instruction": rendered,
    }
    if as_json or (not _console):
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    _console.print(Panel(rendered, title=f"Runbook Render: {template.name}", border_style="cyan"))


def _runbook_placeholder_keys(template: RunbookTemplate) -> set[str]:
    return {
        str(field_name).strip()
        for _, field_name, _, _ in Formatter().parse(template.instruction)
        if str(field_name or "").strip()
    }


def _extract_runbook_var_items_from_text(text: str, *, allowed_keys: set[str]) -> list[str]:
    lowered = str(text or "").lower()
    found: dict[str, str] = {}

    base_items = _extract_template_var_items_from_text(text)
    for item in base_items:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        k = key.strip()
        v = value.strip()
        if (not k) or (not v) or (k not in allowed_keys):
            continue
        found[k] = v

    for key, value in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*([^\s,;，；]+)", str(text or "")):
        k = str(key).strip()
        v = str(value).strip()
        if (not k) or (not v) or (k not in allowed_keys):
            continue
        found[k] = v

    if ("service" in allowed_keys) and ("service" not in found):
        service_before_cn = re.search(r"\b([a-z0-9-]{2,40})\s*服务\b", lowered)
        if service_before_cn:
            candidate = str(service_before_cn.group(1)).strip()
            if not re.fullmatch(r"p\d{2,3}(?:ms)?", candidate):
                found["service"] = candidate

    if ("p95_ms" in allowed_keys) and ("p95_ms" not in found):
        match = re.search(r"p95(?:\s*阈值|阈值|目标)?\s*(?:[:=为到是]?\s*)?(\d{2,5})\s*ms?", lowered)
        if match:
            found["p95_ms"] = str(match.group(1))
    if ("p99_ms" in allowed_keys) and ("p99_ms" not in found):
        match = re.search(r"p99(?:\s*阈值|阈值|目标)?\s*(?:[:=为到是]?\s*)?(\d{2,5})\s*ms?", lowered)
        if match:
            found["p99_ms"] = str(match.group(1))
    if ("replicas" in allowed_keys) and ("replicas" not in found):
        replicas = _extract_requested_replicas(text)
        if replicas > 0:
            found["replicas"] = str(replicas)

    preferred = ["namespace", "service", "workload", "pod", "container", "image", "replicas", "p95_ms", "p99_ms"]
    out: list[str] = []
    for key in preferred:
        if key in found:
            out.append(f"{key}={found[key]}")
    for key in sorted(found.keys()):
        if key in preferred:
            continue
        out.append(f"{key}={found[key]}")
    return out


def _compose_runbook_var_items(
    *,
    template: RunbookTemplate,
    text: str,
    options: dict[str, object],
    base_items: list[str] | None = None,
    profile_file: Path,
) -> list[str]:
    merged: dict[str, str] = {}
    if base_items:
        merged.update(parse_runbook_vars(base_items))

    allowed_keys = _runbook_placeholder_keys(template) | set(template.variables.keys())
    common_keys = {"namespace", "service", "workload", "pod", "container", "image", "replicas", "p95_ms", "p99_ms"}
    allowed_keys = {k for k in (allowed_keys | common_keys) if str(k).strip()}

    for item in _extract_runbook_var_items_from_text(text, allowed_keys=allowed_keys):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        k = key.strip()
        v = value.strip()
        if (not k) or (not v) or (k in merged) or (k not in allowed_keys):
            continue
        merged[k] = v

    context_vars = _target_runbook_context_vars(profile_file=profile_file)
    for key, value in context_vars.items():
        k = str(key).strip()
        v = str(value).strip()
        if (not k) or (not v) or (k in merged) or (k not in allowed_keys):
            continue
        merged[k] = v

    session_file = Path(str(options.get("session_file", ".data/lsre-session.json")))
    try:
        entities = SessionStore(session_file).entities()
    except Exception:
        entities = {}
    fallback_map = {
        "namespace": str(entities.get("last_namespace", "")).strip(),
        "service": str(entities.get("last_service", "")).strip(),
        "pod": str(entities.get("last_pod", "")).strip(),
    }
    for key, value in fallback_map.items():
        if key in merged or key not in allowed_keys or (not value):
            continue
        merged[key] = value
    if ("workload" in allowed_keys) and ("workload" not in merged) and merged.get("service"):
        merged["workload"] = f"deploy/{merged['service']}"

    preferred = ["namespace", "service", "workload", "pod", "container", "image", "replicas", "p95_ms", "p99_ms"]
    out: list[str] = []
    for key in preferred:
        if key in merged and str(merged[key]).strip():
            out.append(f"{key}={merged[key]}")
    for key in sorted(merged.keys()):
        if key in preferred:
            continue
        value = str(merged[key]).strip()
        if value:
            out.append(f"{key}={value}")
    return out


def _target_runbook_context_vars(*, profile_file: Path) -> dict[str, str]:
    target = TargetEnvStore(profile_file).load()
    active_profile = ClusterProfileStore.default().get_active().strip()
    values: dict[str, str] = {}
    if target.k8s_namespace.strip():
        values["namespace"] = target.k8s_namespace.strip()
    if target.k8s_context.strip():
        values["k8s_context"] = target.k8s_context.strip()
    if target.k8s_api_url.strip():
        values["k8s_api_url"] = target.k8s_api_url.strip()
    if target.prometheus_url.strip():
        values["prometheus_url"] = target.prometheus_url.strip()
    if active_profile:
        values["target_profile"] = active_profile
    return values


def _resolve_runbook_vars(
    *,
    template: RunbookTemplate,
    var_items: list[str],
    profile_file: Path,
) -> dict[str, str]:
    cli_vars = parse_runbook_vars(var_items)
    context_vars = _target_runbook_context_vars(profile_file=profile_file)
    merged_vars = dict(context_vars)
    merged_vars.update(cli_vars)
    _, resolved_vars = render_runbook_instruction(template, overrides=merged_vars)
    return resolved_vars


def _prepare_runbook_instruction(
    *,
    template: RunbookTemplate,
    var_items: list[str],
    extra: str,
    profile_file: Path,
) -> str:
    resolved_vars = _resolve_runbook_vars(
        template=template,
        var_items=var_items,
        profile_file=profile_file,
    )
    instruction = template.instruction.format(**resolved_vars)
    if extra.strip():
        instruction = f"{instruction}\n\n[runbook-extra]\n{extra.strip()}"
    if resolved_vars:
        instruction = (
            f"{instruction}\n\n[runbook-vars]\n"
            + ", ".join(f"{k}={v}" for k, v in sorted(resolved_vars.items()))
        )
    return instruction


def _parse_chat_runbook_var_extra(tokens: list[str]) -> tuple[list[str], str]:
    var_items: list[str] = []
    extra_tokens: list[str] = []
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if token == "--var":
            if idx + 1 >= len(tokens):
                raise ValueError("missing value for --var")
            var_items.append(tokens[idx + 1])
            idx += 2
            continue
        if token.startswith("--var="):
            value = token.split("=", 1)[1].strip()
            if not value:
                raise ValueError("missing value for --var")
            var_items.append(value)
            idx += 1
            continue
        if "=" in token:
            var_items.append(token)
        else:
            extra_tokens.append(token)
        idx += 1
    return var_items, " ".join(extra_tokens).strip()


def _parse_chat_runbook_command(tail: str) -> dict[str, object]:
    text = tail.strip()
    if not text:
        return {"action": "list", "custom_only": False, "runbook_file": settings.runbook_store_file}
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise ValueError(f"invalid quoting: {exc}") from exc
    if not tokens:
        return {"action": "list", "custom_only": False, "runbook_file": settings.runbook_store_file}

    def _opt_value(args: list[str], idx: int, key: str) -> tuple[str, int]:
        token = args[idx]
        if token == key:
            if idx + 1 >= len(args):
                raise ValueError(f"missing value for {key}")
            return args[idx + 1], idx + 2
        if token.startswith(f"{key}="):
            return token.split("=", 1)[1], idx + 1
        raise ValueError(f"invalid option format: {token}")

    subcmd = tokens[0].lower()
    if subcmd in {"list", "ls"}:
        custom_only = False
        runbook_file = settings.runbook_store_file
        idx = 1
        while idx < len(tokens):
            token = tokens[idx]
            if token == "--custom-only":
                custom_only = True
                idx += 1
                continue
            if token == "--runbook-file" or token.startswith("--runbook-file="):
                runbook_file, idx = _opt_value(tokens, idx, "--runbook-file")
                continue
            raise ValueError(f"unknown option for list: {token}")
        return {"action": "list", "custom_only": custom_only, "runbook_file": runbook_file}

    def _parse_run_args(args: list[str]) -> tuple[str, bool, list[str], str]:
        runbook_file = settings.runbook_store_file
        apply = False
        cleaned: list[str] = []
        idx = 0
        while idx < len(args):
            token = args[idx]
            if token == "--runbook-file" or token.startswith("--runbook-file="):
                runbook_file, idx = _opt_value(args, idx, "--runbook-file")
                continue
            if token == "--apply":
                apply = True
                idx += 1
                continue
            cleaned.append(token)
            idx += 1
        var_items, extra = _parse_chat_runbook_var_extra(cleaned)
        return runbook_file, apply, var_items, extra

    if subcmd in {"show", "render"}:
        if len(tokens) < 2:
            raise ValueError(f"usage: /runbook {subcmd} <name> [k=v]")
        name = tokens[1]
        runbook_file = settings.runbook_store_file
        args = tokens[2:]
        cleaned: list[str] = []
        idx = 0
        while idx < len(args):
            token = args[idx]
            if token == "--runbook-file" or token.startswith("--runbook-file="):
                runbook_file, idx = _opt_value(args, idx, "--runbook-file")
                continue
            cleaned.append(token)
            idx += 1
        var_items, extra = _parse_chat_runbook_var_extra(cleaned)
        return {
            "action": subcmd,
            "name": name,
            "var_items": var_items,
            "extra": extra,
            "runbook_file": runbook_file,
        }

    if subcmd == "add":
        if len(tokens) < 2:
            raise ValueError("usage: /runbook add <name> --title <title> --instruction <text>")
        name = tokens[1]
        title = ""
        instruction = ""
        mode = "diagnose"
        description = ""
        force = False
        runbook_file = settings.runbook_store_file
        var_items: list[str] = []
        args = tokens[2:]
        idx = 0
        while idx < len(args):
            token = args[idx]
            if token == "--title" or token.startswith("--title="):
                title, idx = _opt_value(args, idx, "--title")
                continue
            if token == "--instruction" or token.startswith("--instruction="):
                instruction, idx = _opt_value(args, idx, "--instruction")
                continue
            if token == "--mode" or token.startswith("--mode="):
                mode, idx = _opt_value(args, idx, "--mode")
                continue
            if token == "--description" or token.startswith("--description="):
                description, idx = _opt_value(args, idx, "--description")
                continue
            if token == "--runbook-file" or token.startswith("--runbook-file="):
                runbook_file, idx = _opt_value(args, idx, "--runbook-file")
                continue
            if token == "--var" or token.startswith("--var="):
                value, idx = _opt_value(args, idx, "--var")
                var_items.append(value)
                continue
            if token == "--force":
                force = True
                idx += 1
                continue
            if "=" in token:
                var_items.append(token)
                idx += 1
                continue
            raise ValueError(f"unknown option for add: {token}")
        if not title.strip():
            raise ValueError("missing --title")
        if not instruction.strip():
            raise ValueError("missing --instruction")
        return {
            "action": "add",
            "name": name,
            "title": title,
            "instruction": instruction,
            "mode": mode,
            "description": description,
            "var_items": var_items,
            "force": force,
            "runbook_file": runbook_file,
        }

    if subcmd == "remove":
        if len(tokens) < 2:
            raise ValueError("usage: /runbook remove <name> [--yes]")
        name = tokens[1]
        yes = False
        runbook_file = settings.runbook_store_file
        idx = 2
        while idx < len(tokens):
            token = tokens[idx]
            if token == "--yes":
                yes = True
                idx += 1
                continue
            if token == "--runbook-file" or token.startswith("--runbook-file="):
                runbook_file, idx = _opt_value(tokens, idx, "--runbook-file")
                continue
            raise ValueError(f"unknown option for remove: {token}")
        return {"action": "remove", "name": name, "yes": yes, "runbook_file": runbook_file}

    if subcmd == "export":
        output = ""
        scope = "custom"
        names: list[str] = []
        runbook_file = settings.runbook_store_file
        idx = 1
        while idx < len(tokens):
            token = tokens[idx]
            if token == "--output" or token.startswith("--output="):
                output, idx = _opt_value(tokens, idx, "--output")
                continue
            if token == "--scope" or token.startswith("--scope="):
                scope, idx = _opt_value(tokens, idx, "--scope")
                continue
            if token == "--name" or token.startswith("--name="):
                value, idx = _opt_value(tokens, idx, "--name")
                names.append(value)
                continue
            if token == "--runbook-file" or token.startswith("--runbook-file="):
                runbook_file, idx = _opt_value(tokens, idx, "--runbook-file")
                continue
            raise ValueError(f"unknown option for export: {token}")
        return {
            "action": "export",
            "output": output,
            "scope": scope,
            "names": names,
            "runbook_file": runbook_file,
        }

    if subcmd == "import":
        input_file = ""
        merge = True
        runbook_file = settings.runbook_store_file
        idx = 1
        while idx < len(tokens):
            token = tokens[idx]
            if token == "--input" or token.startswith("--input="):
                input_file, idx = _opt_value(tokens, idx, "--input")
                continue
            if token == "--merge":
                merge = True
                idx += 1
                continue
            if token == "--replace":
                merge = False
                idx += 1
                continue
            if token == "--runbook-file" or token.startswith("--runbook-file="):
                runbook_file, idx = _opt_value(tokens, idx, "--runbook-file")
                continue
            raise ValueError(f"unknown option for import: {token}")
        if not input_file.strip():
            raise ValueError("missing --input")
        return {"action": "import", "input_file": input_file, "merge": merge, "runbook_file": runbook_file}

    if subcmd == "run":
        if len(tokens) < 2:
            raise ValueError("usage: /runbook run <name> [--apply] [k=v]")
        runbook_file, apply, var_items, extra = _parse_run_args(tokens[2:])
        return {
            "action": "run",
            "name": tokens[1],
            "var_items": var_items,
            "extra": extra,
            "apply": apply,
            "runbook_file": runbook_file,
        }

    runbook_file, apply, var_items, extra = _parse_run_args(tokens[1:])
    return {
        "action": "run",
        "name": tokens[0],
        "var_items": var_items,
        "extra": extra,
        "apply": apply,
        "runbook_file": runbook_file,
    }


def _parse_chat_report_command(tail: str) -> dict[str, object]:
    text = tail.strip()
    tokens: list[str] = []
    if text:
        try:
            tokens = shlex.split(text)
        except ValueError as exc:
            raise ValueError(f"invalid quoting: {exc}") from exc

    result: dict[str, object] = {
        "fmt": "markdown",
        "output": "",
        "limit": 20,
        "include_doctor": True,
        "include_memory": True,
        "push_to_git": False,
        "git_remote": "origin",
        "git_message": "",
    }
    if tokens and (not tokens[0].startswith("-")) and tokens[0].lower() in {"markdown", "json"}:
        result["fmt"] = tokens[0].lower()
        tokens = tokens[1:]

    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if token == "--format" or token.startswith("--format="):
            value = token.split("=", 1)[1] if token.startswith("--format=") else ""
            if not value:
                idx += 1
                if idx >= len(tokens):
                    raise ValueError("missing value for --format")
                value = tokens[idx]
            result["fmt"] = value.strip().lower()
            idx += 1
            continue
        if token == "--output" or token.startswith("--output="):
            value = token.split("=", 1)[1] if token.startswith("--output=") else ""
            if not value:
                idx += 1
                if idx >= len(tokens):
                    raise ValueError("missing value for --output")
                value = tokens[idx]
            result["output"] = value.strip()
            idx += 1
            continue
        if token == "--limit" or token.startswith("--limit="):
            value = token.split("=", 1)[1] if token.startswith("--limit=") else ""
            if not value:
                idx += 1
                if idx >= len(tokens):
                    raise ValueError("missing value for --limit")
                value = tokens[idx]
            try:
                limit = int(value)
            except Exception:
                raise ValueError("limit must be integer") from None
            if limit <= 0:
                raise ValueError("limit must be > 0")
            result["limit"] = limit
            idx += 1
            continue
        if token in {"--include-doctor", "--doctor"}:
            result["include_doctor"] = True
            idx += 1
            continue
        if token == "--no-doctor":
            result["include_doctor"] = False
            idx += 1
            continue
        if token in {"--include-memory", "--memory"}:
            result["include_memory"] = True
            idx += 1
            continue
        if token == "--no-memory":
            result["include_memory"] = False
            idx += 1
            continue
        if token == "--push-to-git":
            result["push_to_git"] = True
            idx += 1
            continue
        if token == "--git-remote" or token.startswith("--git-remote="):
            value = token.split("=", 1)[1] if token.startswith("--git-remote=") else ""
            if not value:
                idx += 1
                if idx >= len(tokens):
                    raise ValueError("missing value for --git-remote")
                value = tokens[idx]
            result["git_remote"] = value.strip()
            idx += 1
            continue
        if token == "--git-message" or token.startswith("--git-message="):
            value = token.split("=", 1)[1] if token.startswith("--git-message=") else ""
            if not value:
                idx += 1
                if idx >= len(tokens):
                    raise ValueError("missing value for --git-message")
                value = tokens[idx]
            result["git_message"] = value
            idx += 1
            continue
        raise ValueError(f"unknown option for report: {token}")
    return result


def _build_system_prompt(*, conversation_context: str = "", memory_context: str = "") -> str:
    env = TargetEnvStore().load()
    active_profile = ClusterProfileStore.default().get_active() or "(none)"
    target_summary = (
        f"target_profile={active_profile}\n"
        f"prometheus_url={env.prometheus_url or '(unset)'}\n"
        f"k8s_api_url={env.k8s_api_url or '(unset)'}\n"
        f"k8s_context={env.k8s_context or '(unset)'}\n"
        f"k8s_namespace={env.k8s_namespace or 'default'}"
    )
    return BrainContext(
        target_summary=target_summary,
        conversation_context=conversation_context,
        memory_context=memory_context,
    ).render()


@pack_app.command("list")
def pack_list(
    index: Annotated[str, typer.Option("--index", help="Marketplace index JSON path or URL.")],
) -> None:
    packs = asyncio.run(load_marketplace_index(index))
    if not packs:
        typer.echo("No packs found.")
        return
    for item in packs:
        sign_mark = "signed" if item.signature else "unsigned"
        typer.echo(f"{item.name}@{item.version} -> {item.module} [{sign_mark}]")


@pack_app.command("pin")
def pack_pin(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Pack name in marketplace index.")],
    version: Annotated[str | None, typer.Option("--version", help="Pack version. Defaults to latest in index.")] = None,
    index: Annotated[str, typer.Option("--index", help="Marketplace index JSON path or URL.")] = "",
    lock_file: Annotated[str | None, typer.Option("--lock-file", help="Override tool pack lock file path.")] = None,
    hmac_key: Annotated[str, typer.Option("--hmac-key", help="Optional HMAC key for signature verification.")] = "",
    require_signature: Annotated[bool, typer.Option("--require-signature", help="Require valid signature before pin.")] = False,
    skip_digest_check: Annotated[bool, typer.Option("--skip-digest-check", help="Skip local module digest check.")] = False,
) -> None:
    if not index.strip():
        raise typer.BadParameter("index is required")
    packs = asyncio.run(load_marketplace_index(index))
    selected = find_marketplace_pack(packs, name=name, version=version)
    if not selected:
        raise typer.BadParameter(f"pack not found in index: {name} version={version or 'latest'}")

    if selected.signature:
        if not hmac_key.strip():
            if require_signature:
                raise typer.BadParameter("signature exists but --hmac-key is missing")
        elif not verify_pack_signature(selected, hmac_key):
            raise typer.BadParameter("signature verify failed")
    elif require_signature:
        raise typer.BadParameter("pack has no signature but --require-signature is set")

    if (not skip_digest_check) and selected.digest_sha256:
        actual = compute_module_digest(selected.module)
        if actual.lower() != selected.digest_sha256.lower():
            raise typer.BadParameter(
                f"module digest mismatch: expected={selected.digest_sha256} actual={actual}"
            )

    store = ToolPackLockStore(_resolve_lock_file(ctx, lock_file))
    store.upsert(
        LockedPack(
            name=selected.name,
            version=selected.version,
            module=selected.module,
            digest_sha256=selected.digest_sha256,
            source=index,
            signature=selected.signature,
        )
    )
    typer.echo(
        f"Pinned {selected.name}@{selected.version} to {store.path} "
        f"(module={selected.module})"
    )


@pack_app.command("show")
def pack_show(
    ctx: typer.Context,
    lock_file: Annotated[str | None, typer.Option("--lock-file", help="Override tool pack lock file path.")] = None,
) -> None:
    store = ToolPackLockStore(_resolve_lock_file(ctx, lock_file))
    items = store.list()
    if not items:
        typer.echo("No pinned packs.")
        return
    for item in items:
        sign_mark = "signed" if item.signature else "unsigned"
        typer.echo(f"{item.name}@{item.version} -> {item.module} [{sign_mark}]")


def _resolve_lock_file(ctx: typer.Context, lock_file: str | None) -> Path:
    if lock_file and lock_file.strip():
        return Path(lock_file)
    obj = dict(ctx.obj or {})
    candidate = str(obj.get("lock_file", ".data/lsre-tool-lock.json")).strip()
    return Path(candidate or ".data/lsre-tool-lock.json")


app.add_typer(pack_app, name="pack")
target_app.add_typer(target_profile_app, name="profile")
app.add_typer(target_app, name="target")
app.add_typer(history_app, name="history")
app.add_typer(memory_app, name="memory")
app.add_typer(runbook_app, name="runbook")
app.add_typer(template_app, name="template")


def _render_timeline(events) -> None:
    if not (_console and Table):
        return
    rows: list[tuple[str, str, str]] = []
    for event in events:
        if event.kind == "llm_turn":
            duration = str(event.data.get("duration_ms", "-"))
            rows.append(("llm", event.message, f"{duration} ms"))
        elif event.kind == "tool_output":
            duration = str(event.data.get("duration_ms", "-"))
            rows.append(("tool", event.message, f"{duration} ms"))
    if not rows:
        return
    table = Table(title="Execution Timeline")
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Step", style="white")
    table.add_column("Duration", style="green", justify="right")
    for row in rows[-18:]:
        table.add_row(*row)
    _console.print(table)


def _render_probe_report(report: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    summary = dict(report.get("summary", {})) if isinstance(report, dict) else {}
    checks = dict(report.get("checks", {})) if isinstance(report, dict) else {}
    title = (
        f"Target Probe ({summary.get('ok_count', 0)}/{summary.get('total', 0)}) "
        f"{'OK' if summary.get('all_ok') else 'Degraded'}"
    )
    table = Table(title=title)
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", style="white", no_wrap=True)
    table.add_column("Exit", style="green", no_wrap=True)
    table.add_column("Detail", style="white")
    for name, row in checks.items():
        item = row if isinstance(row, dict) else {}
        ok = bool(item.get("ok"))
        status = "ok" if ok else "failed"
        detail = str(item.get("stdout_preview", "") or item.get("stderr_preview", ""))[:160]
        table.add_row(str(name), status, str(item.get("exit_code", "-")), detail)
    _console.print(table)


def _render_memory_cases(cases: list[MemoryCase], *, title: str) -> None:
    if not (_console and Table):
        if not cases:
            typer.echo("No memory cases found.")
            return
        for item in cases:
            typer.echo(
                f"- id={item.id} score={item.score:.2f} symptom={item.symptom} "
                f"root_cause={item.root_cause}"
            )
        return
    table = Table(title=title)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Score", style="magenta", no_wrap=True)
    table.add_column("Symptom", style="white")
    table.add_column("Root Cause", style="green")
    table.add_column("Fix Cmds", style="yellow", no_wrap=True)
    if not cases:
        _console.print(table)
        return
    for item in cases:
        table.add_row(
            str(item.id),
            f"{item.score:.2f}",
            item.symptom[:120],
            item.root_cause[:140],
            str(len(item.fix_commands)),
        )
    _console.print(table)


def _execute_runbook(
    *,
    template: RunbookTemplate,
    instruction: str,
    apply: bool,
    options: dict[str, object],
) -> None:
    typer.echo(f"Running runbook: {template.name} ({template.mode}) - {template.title}")
    if template.mode == "fix":
        _run_fix(
            instruction=instruction,
            apply=apply,
            max_apply_steps=6,
            allow_high_risk=False,
            auto_approve_low_risk=False,
            export_plan_md="",
            export_plan_json="",
            execute=bool(options["execute"]),
            approve=bool(options["approve"]),
            interactive_approval=bool(options["interactive_approval"]),
            stream_output=bool(options["stream_output"]),
            verbose_reasoning=bool(options["verbose_reasoning"]),
            approval_mode=str(options["approval_mode"]),
            audit_log=str(options["audit_log"]),
            lock_file=str(options["lock_file"]),
            session_file=str(options["session_file"]),
            deny_tool=list(options["deny_tool"]),
            deny_prefix=list(options["deny_prefix"]),
            tool_pack=list(options["tool_pack"]),
            remote_gateway=list(options["remote_gateway"]),
            model=str(options["model"]),
            provider=str(options["provider"]),
            max_steps=int(options["max_steps"]),
        )
        return
    _run_once(
        instruction=instruction,
        execute=bool(options["execute"]),
        approve=bool(options["approve"]),
        interactive_approval=bool(options["interactive_approval"]),
        stream_output=bool(options["stream_output"]),
        verbose_reasoning=bool(options["verbose_reasoning"]),
        approval_mode=str(options["approval_mode"]),
        audit_log=str(options["audit_log"]),
        lock_file=str(options["lock_file"]),
        session_file=str(options["session_file"]),
        deny_tool=list(options["deny_tool"]),
        deny_prefix=list(options["deny_prefix"]),
        tool_pack=list(options["tool_pack"]),
        remote_gateway=list(options["remote_gateway"]),
        model=str(options["model"]),
        provider=str(options["provider"]),
        max_steps=int(options["max_steps"]),
    )


def _build_incident_report_payload(
    *,
    session_file: Path,
    target_profile_file: Path,
    include_doctor: bool,
    include_memory: bool,
    memory_limit: int,
    turn_limit: int,
    audit_log: Path,
) -> dict[str, object]:
    session = SessionStore(session_file)
    turns = session.recent_turns(limit=turn_limit)
    target = TargetEnvStore(target_profile_file).load()
    active_profile = ClusterProfileStore.default().get_active()

    last_fix_payload: dict[str, object] = {}
    fix_path = Path(".data/lsre-fix-last.json")
    if fix_path.exists():
        try:
            raw = json.loads(fix_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                last_fix_payload = raw
        except Exception:
            last_fix_payload = {}

    doctor_payload: dict[str, object] | None = None
    if include_doctor:
        doctor_payload = _collect_doctor_report(
            target=target,
            timeout_sec=4,
            dry_run_probe=True,
            audit_log=audit_log,
        )
        doctor_summary = doctor_payload.get("summary", {})
        if isinstance(doctor_summary, dict):
            doctor_summary["strict_mode"] = False
            doctor_summary["strict_healthy"] = _doctor_is_healthy(doctor_summary, strict=False)
        doctor_payload["gate"] = _build_doctor_gate(doctor_payload, strict=False)

    memory_rows: list[dict[str, object]] = []
    if include_memory:
        store = _open_incident_memory_store()
        if store:
            for item in store.list_recent(limit=memory_limit):
                memory_rows.append(
                    {
                        "id": item.id,
                        "created_at": item.created_at,
                        "score": item.score,
                        "symptom": item.symptom,
                        "root_cause": item.root_cause,
                        "fix_commands": item.fix_commands,
                    }
                )

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "active_target_profile": active_profile,
        "target": target.to_safe_dict(),
        "session": {
            "session_file": str(session_file),
            "turns": turns,
            "turn_count": len(turns),
        },
        "last_fix_plan": last_fix_payload,
        "doctor": doctor_payload,
        "memory_recent": memory_rows,
    }


def _render_incident_report_markdown(payload: dict[str, object]) -> str:
    lines = ["# LazySRE Incident Report", ""]
    lines.append(f"- Generated(UTC): {payload.get('generated_at_utc', '-')}")
    lines.append(f"- Active Target Profile: {payload.get('active_target_profile', '-') or '(none)'}")
    lines.append("")

    target = payload.get("target", {})
    if isinstance(target, dict):
        lines.append("## Target Environment")
        lines.append("")
        lines.append(f"- Prometheus: {target.get('prometheus_url', '(unset)')}")
        lines.append(f"- K8s API: {target.get('k8s_api_url', '(unset)')}")
        lines.append(f"- K8s Context: {target.get('k8s_context', '(unset)')}")
        lines.append(f"- K8s Namespace: {target.get('k8s_namespace', '(unset)')}")
        lines.append("")

    last_fix = payload.get("last_fix_plan", {})
    if isinstance(last_fix, dict) and last_fix:
        lines.append("## Last Fix Plan")
        lines.append("")
        lines.append(f"- Instruction: {last_fix.get('instruction', '-')}")
        lines.append(f"- Generated At: {last_fix.get('generated_at', '-')}")
        plan_obj = last_fix.get("plan", {})
        if isinstance(plan_obj, dict):
            apply_cmds = plan_obj.get("apply_commands", [])
            rollback_cmds = plan_obj.get("rollback_commands", [])
            lines.append(f"- Apply Commands: {len(apply_cmds) if isinstance(apply_cmds, list) else 0}")
            lines.append(f"- Rollback Commands: {len(rollback_cmds) if isinstance(rollback_cmds, list) else 0}")
        lines.append("")

    doctor = payload.get("doctor", {})
    if isinstance(doctor, dict) and doctor:
        summary = doctor.get("summary", {})
        gate = doctor.get("gate", {})
        lines.append("## Doctor Snapshot")
        lines.append("")
        if isinstance(summary, dict):
            lines.append(
                f"- Summary: pass={summary.get('pass', 0)} warn={summary.get('warn', 0)} error={summary.get('error', 0)}"
            )
        if isinstance(gate, dict):
            lines.append(
                f"- Gate: healthy={gate.get('healthy', False)} blocking={gate.get('blocking_count', 0)} exit_code_advice={gate.get('exit_code_advice', 0)}"
            )
        lines.append("")

    turns_block = payload.get("session", {})
    turns = []
    if isinstance(turns_block, dict):
        raw_turns = turns_block.get("turns", [])
        if isinstance(raw_turns, list):
            turns = raw_turns
    lines.append("## Recent Session Turns")
    lines.append("")
    if not turns:
        lines.append("(empty)")
        lines.append("")
    else:
        for idx, item in enumerate(turns, 1):
            if not isinstance(item, dict):
                continue
            lines.append(f"### Turn {idx}")
            lines.append("")
            lines.append(f"User: {str(item.get('user', ''))}")
            lines.append("")
            lines.append(f"Assistant: {str(item.get('assistant', ''))[:500]}")
            lines.append("")

    memory_recent = payload.get("memory_recent", [])
    lines.append("## Memory Cases")
    lines.append("")
    if not isinstance(memory_recent, list) or (not memory_recent):
        lines.append("(empty)")
        lines.append("")
    else:
        for item in memory_recent:
            if not isinstance(item, dict):
                continue
            lines.append(f"- #{item.get('id', '-')}: {item.get('symptom', '-')}")
            lines.append(f"  root_cause={item.get('root_cause', '-')}")
    lines.append("")
    return "\n".join(lines).strip() + "\n"


def _export_incident_report(
    *,
    session_file: Path,
    target_profile_file: Path,
    include_doctor: bool,
    include_memory: bool,
    turn_limit: int,
    audit_log: Path,
    fmt: str,
    output: str,
    push_to_git: bool,
    git_remote: str,
    git_message: str,
) -> dict[str, object]:
    payload = _build_incident_report_payload(
        session_file=session_file,
        target_profile_file=target_profile_file,
        include_doctor=include_doctor,
        include_memory=include_memory,
        memory_limit=5,
        turn_limit=turn_limit,
        audit_log=audit_log,
    )
    chosen = fmt.strip().lower()
    if chosen not in {"markdown", "json"}:
        raise typer.BadParameter("format must be markdown or json")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output_value = output.strip()
    if not output_value:
        output_value = _default_report_output_path(fmt=chosen, stamp=stamp, push_to_git=push_to_git)
    out_path = Path(output_value)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if chosen == "json":
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        out_path.write_text(_render_incident_report_markdown(payload), encoding="utf-8")

    result: dict[str, object] = {"out_path": str(out_path), "archived_path": "", "pushed": False}
    if push_to_git:
        archived_path = _archive_report_for_git(out_path, stamp=stamp)
        commit_message = git_message.strip() or f"chore(report): archive incident report {stamp}"
        pushed = _push_report_to_git(
            archived_path=archived_path,
            remote=git_remote.strip() or "origin",
            commit_message=commit_message,
        )
        result["archived_path"] = str(archived_path)
        result["pushed"] = bool(pushed)
    return result


def _default_report_output_path(*, fmt: str, stamp: str, push_to_git: bool) -> str:
    suffix = "md" if fmt == "markdown" else "json"
    if push_to_git:
        return f"reports/lsre-report-{stamp}.{suffix}"
    return f".data/lsre-report-{stamp}.{suffix}"


def _archive_report_for_git(path: Path, *, stamp: str) -> Path:
    if path.parts and path.parts[0] == "reports":
        return path
    archive_dir = Path("reports")
    archive_dir.mkdir(parents=True, exist_ok=True)
    archived = archive_dir / f"lsre-report-{stamp}{path.suffix or '.md'}"
    if path.resolve() == archived.resolve():
        return archived
    content = path.read_text(encoding="utf-8")
    archived.write_text(content, encoding="utf-8")
    return archived


def _run_git_command(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _push_report_to_git(*, archived_path: Path, remote: str, commit_message: str) -> bool:
    if not shutil.which("git"):
        raise typer.BadParameter("git is not installed; cannot use --push-to-git")
    if not archived_path.exists():
        raise typer.BadParameter(f"report archive file not found: {archived_path}")

    repo_check = _run_git_command(["rev-parse", "--is-inside-work-tree"])
    if repo_check.returncode != 0:
        raise typer.BadParameter("current directory is not a git repository")

    add_result = _run_git_command(["add", "--", str(archived_path)])
    if add_result.returncode != 0:
        stderr = (add_result.stderr or add_result.stdout or "").strip()
        raise typer.BadParameter(f"git add failed: {stderr or 'unknown error'}")

    commit_result = _run_git_command(["commit", "-m", commit_message])
    if commit_result.returncode != 0:
        output = ((commit_result.stdout or "") + "\n" + (commit_result.stderr or "")).lower()
        if ("nothing to commit" in output) or ("no changes added to commit" in output):
            return False
        stderr = (commit_result.stderr or commit_result.stdout or "").strip()
        raise typer.BadParameter(f"git commit failed: {stderr or 'unknown error'}")

    push_result = _run_git_command(["push", remote, "HEAD"])
    if push_result.returncode != 0:
        stderr = (push_result.stderr or push_result.stdout or "").strip()
        raise typer.BadParameter(f"git push failed: {stderr or 'unknown error'}")
    return True


def _collect_runtime_status(
    *,
    session_file: Path,
    profile_file: Path,
    include_probe: bool,
    execute_probe: bool,
    timeout_sec: int,
    audit_log: Path,
) -> dict[str, object]:
    session_store = SessionStore(session_file)
    payload = session_store.load()
    turns = payload.get("turns", []) if isinstance(payload, dict) else []
    last_user = ""
    if isinstance(turns, list) and turns:
        tail = turns[-1]
        if isinstance(tail, dict):
            last_user = str(tail.get("user", "")).strip()

    target_store = TargetEnvStore(profile_file)
    target = target_store.load()
    memory_db = _resolve_memory_db_path()
    active_profile = ClusterProfileStore.default().get_active()

    snapshot: dict[str, object] = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "active_target_profile": active_profile,
        "target_profile_file": str(profile_file),
        "session_file": str(session_file),
        "target": target.to_safe_dict(),
        "session": {
            "turns": len(turns) if isinstance(turns, list) else 0,
            "last_user": last_user[:160],
        },
        "last_fix_plan": _read_last_fix_plan_summary(Path(".data/lsre-fix-last.json")),
        "memory": {
            "db_path": str(memory_db),
            "cases": _count_memory_cases(memory_db),
        },
    }

    if include_probe:
        report = asyncio.run(
            probe_target_environment(
                target,
                executor=SafeExecutor(
                    dry_run=(not execute_probe),
                    approval_mode="permissive",
                    approval_granted=True,
                    audit_logger=AuditLogger(audit_log),
                ),
                timeout_sec=timeout_sec,
            )
        )
        snapshot["probe"] = {
            "mode": "execute" if execute_probe else "dry-run",
            "timeout_sec": timeout_sec,
            "summary": report.get("summary", {}),
            "checks": report.get("checks", {}),
        }
    return snapshot


def _collect_environment_discovery(
    *,
    timeout_sec: int = 5,
    secrets_file: Path | None = None,
) -> dict[str, object]:
    per_check_timeout = max(1, min(int(timeout_sec or 5), 8))
    checks: list[dict[str, object]] = []
    discoveries: dict[str, object] = {}

    checks.append(_doctor_python_check())

    docker_path = shutil.which("docker") or ""
    checks.append(_scan_binary_check("docker", docker_path, optional=True))
    if docker_path:
        docker_payload = _scan_docker_environment(docker_path, timeout_sec=per_check_timeout)
        discoveries["docker"] = docker_payload.get("discovery", {})
        checks.extend(list(docker_payload.get("checks", [])))
    else:
        discoveries["docker"] = {"available": False}

    kubectl_path = shutil.which("kubectl") or ""
    checks.append(_scan_binary_check("kubectl", kubectl_path, optional=True))
    if kubectl_path:
        k8s_payload = _scan_kubernetes_environment(kubectl_path, timeout_sec=per_check_timeout)
        discoveries["kubernetes"] = k8s_payload.get("discovery", {})
        checks.extend(list(k8s_payload.get("checks", [])))
    else:
        discoveries["kubernetes"] = {"available": False}

    prometheus_payload = _scan_prometheus_environment(timeout_sec=per_check_timeout)
    discoveries["prometheus"] = prometheus_payload.get("discovery", {})
    checks.extend(list(prometheus_payload.get("checks", [])))

    provider_payload = _scan_provider_environment(secrets_file=secrets_file)
    discoveries["providers"] = provider_payload.get("discovery", {})
    checks.extend(list(provider_payload.get("checks", [])))

    issues = [
        {
            "name": str(item.get("name", "")),
            "severity": str(item.get("severity", "")),
            "detail": str(item.get("detail", "")),
            "hint": str(item.get("hint", "")),
        }
        for item in checks
        if str(item.get("severity", "")).lower() != "pass"
    ]
    summary = _summarize_doctor_checks(checks)
    usable_targets = []
    docker_discovery = discoveries.get("docker", {})
    if isinstance(docker_discovery, dict) and bool(docker_discovery.get("reachable")):
        usable_targets.append("docker")
    if isinstance(docker_discovery, dict) and bool(docker_discovery.get("swarm_active")):
        usable_targets.append("docker-swarm")
    k8s_discovery = discoveries.get("kubernetes", {})
    if isinstance(k8s_discovery, dict) and bool(k8s_discovery.get("reachable")):
        usable_targets.append("kubernetes")
    prometheus_discovery = discoveries.get("prometheus", {})
    if isinstance(prometheus_discovery, dict) and bool(prometheus_discovery.get("reachable")):
        usable_targets.append("prometheus")

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "read-only/no-secret",
        "timeout_sec": per_check_timeout,
        "summary": summary,
        "usable_targets": usable_targets,
        "discoveries": discoveries,
        "checks": checks,
        "issues": issues,
        "suggestions": _build_environment_scan_suggestions(discoveries, usable_targets, issues),
        "next_actions": _build_environment_scan_next_actions(checks, usable_targets),
    }


def _scan_binary_check(name: str, path: str, *, optional: bool) -> dict[str, object]:
    ok = bool(path)
    return {
        "name": f"binary.{name}",
        "ok": ok,
        "severity": "pass" if ok else ("warn" if optional else "error"),
        "detail": path or "(not found)",
        "hint": "" if ok else f"如需纳管 {name}，请安装 {name} 并确保在 PATH 中可用",
    }


def _scan_docker_environment(docker_path: str, *, timeout_sec: int) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    discovery: dict[str, object] = {"available": True, "reachable": False, "swarm_active": False}

    version_probe = _safe_run_command([docker_path, "version", "--format", "{{.Server.Version}}"], timeout_sec=timeout_sec)
    if bool(version_probe.get("ok")):
        version = str(version_probe.get("stdout", "")).strip()
        discovery["reachable"] = True
        discovery["server_version"] = version
        checks.append(_scan_check("docker.version", True, "pass", version or "reachable"))
    else:
        detail = _probe_detail(version_probe)
        checks.append(
            _scan_check(
                "docker.version",
                False,
                "warn",
                detail,
                "Docker 已安装但当前用户无法访问 daemon，请检查 docker 是否运行以及 socket 权限",
            )
        )
        return {"discovery": discovery, "checks": checks}

    swarm_probe = _safe_run_command(
        [docker_path, "info", "--format", "{{.Swarm.LocalNodeState}}"],
        timeout_sec=timeout_sec,
    )
    swarm_state = str(swarm_probe.get("stdout", "")).strip().lower() if bool(swarm_probe.get("ok")) else ""
    discovery["swarm_state"] = swarm_state or "unknown"
    discovery["swarm_active"] = swarm_state == "active"
    checks.append(
        _scan_check(
            "docker.swarm",
            swarm_state == "active",
            "pass" if swarm_state == "active" else "warn",
            swarm_state or _probe_detail(swarm_probe),
            "" if swarm_state == "active" else "未检测到 active Swarm；如果只是单机 Docker 可忽略",
        )
    )

    exited_probe = _safe_run_command(
        [
            docker_path,
            "ps",
            "-a",
            "--filter",
            "status=exited",
            "--format",
            "{{.Names}}\t{{.Status}}",
        ],
        timeout_sec=timeout_sec,
    )
    exited_lines = _non_empty_lines(str(exited_probe.get("stdout", "")))
    discovery["exited_containers"] = len(exited_lines)
    checks.append(
        _scan_check(
            "docker.exited_containers",
            bool(exited_probe.get("ok")) and len(exited_lines) == 0,
            "pass" if bool(exited_probe.get("ok")) and len(exited_lines) == 0 else "warn",
            "none" if not exited_lines else _preview_lines(exited_lines, limit=5),
            "" if not exited_lines else "发现已退出容器，可用 docker logs <container> 查看原因",
        )
    )

    if discovery["swarm_active"]:
        service_probe = _safe_run_command(
            [
                docker_path,
                "service",
                "ls",
                "--format",
                "{{.Name}}\t{{.Replicas}}\t{{.Image}}",
            ],
            timeout_sec=timeout_sec,
        )
        service_lines = _non_empty_lines(str(service_probe.get("stdout", "")))
        discovery["swarm_services"] = len(service_lines)
        checks.append(
            _scan_check(
                "docker.swarm_services",
                bool(service_probe.get("ok")),
                "pass" if bool(service_probe.get("ok")) else "warn",
                "none" if not service_lines else _preview_lines(service_lines, limit=6),
                "" if bool(service_probe.get("ok")) else "无法列出 Swarm service，请确认当前节点/权限",
            )
        )
    return {"discovery": discovery, "checks": checks}


def _scan_kubernetes_environment(kubectl_path: str, *, timeout_sec: int) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    discovery: dict[str, object] = {"available": True, "reachable": False}

    context_probe = _safe_run_command([kubectl_path, "config", "current-context"], timeout_sec=timeout_sec)
    context_name = str(context_probe.get("stdout", "")).strip() if bool(context_probe.get("ok")) else ""
    discovery["context"] = context_name
    checks.append(
        _scan_check(
            "k8s.current_context",
            bool(context_name),
            "pass" if context_name else "warn",
            context_name or _probe_detail(context_probe),
            "" if context_name else "未发现 kubeconfig context；无需手填 token，配置 kubeconfig 后 LazySRE 会自动读取",
        )
    )
    if not context_name:
        return {"discovery": discovery, "checks": checks}

    nodes_probe = _safe_run_command(
        [kubectl_path, "get", "nodes", "--request-timeout=5s", "-o", "name"],
        timeout_sec=timeout_sec,
    )
    node_lines = _non_empty_lines(str(nodes_probe.get("stdout", "")))
    discovery["reachable"] = bool(nodes_probe.get("ok"))
    discovery["nodes"] = len(node_lines)
    checks.append(
        _scan_check(
            "k8s.nodes",
            bool(nodes_probe.get("ok")),
            "pass" if bool(nodes_probe.get("ok")) else "warn",
            f"nodes={len(node_lines)}" if bool(nodes_probe.get("ok")) else _probe_detail(nodes_probe),
            "" if bool(nodes_probe.get("ok")) else "kubectl 无法访问集群，请检查 kubeconfig、网络或 RBAC 权限",
        )
    )

    pods_probe = _safe_run_command(
        [kubectl_path, "get", "pods", "-A", "--no-headers", "--request-timeout=5s"],
        timeout_sec=timeout_sec,
    )
    pod_lines = _non_empty_lines(str(pods_probe.get("stdout", "")))
    problem_pods = _extract_problem_pod_lines(pod_lines)
    discovery["pods"] = len(pod_lines)
    discovery["problem_pods"] = len(problem_pods)
    if bool(pods_probe.get("ok")):
        checks.append(
            _scan_check(
                "k8s.problem_pods",
                len(problem_pods) == 0,
                "pass" if len(problem_pods) == 0 else "warn",
                "none" if not problem_pods else _preview_lines(problem_pods, limit=6),
                "" if not problem_pods else "发现异常 Pod，可直接说：帮我排查这些异常 Pod",
            )
        )
    else:
        checks.append(
            _scan_check(
                "k8s.problem_pods",
                False,
                "warn",
                _probe_detail(pods_probe),
                "无法列出 Pod，请检查 RBAC 是否允许 list pods",
            )
        )

    events_probe = _safe_run_command(
        [
            kubectl_path,
            "get",
            "events",
            "-A",
            "--field-selector",
            "type=Warning",
            "--sort-by=.lastTimestamp",
            "--no-headers",
            "--request-timeout=5s",
        ],
        timeout_sec=timeout_sec,
    )
    event_lines = _non_empty_lines(str(events_probe.get("stdout", "")))
    recent_warnings = event_lines[-6:]
    discovery["warning_events"] = len(event_lines)
    if bool(events_probe.get("ok")):
        checks.append(
            _scan_check(
                "k8s.warning_events",
                len(recent_warnings) == 0,
                "pass" if len(recent_warnings) == 0 else "warn",
                "none" if not recent_warnings else _preview_lines(recent_warnings, limit=6),
                "" if not recent_warnings else "发现 Warning Events，可直接说：分析最近的 K8s Warning Events",
            )
        )
    else:
        checks.append(
            _scan_check(
                "k8s.warning_events",
                False,
                "warn",
                _probe_detail(events_probe),
                "无法读取 Events；不影响 Docker/Swarm 体检，K8s 诊断需要相应 RBAC",
            )
        )
    return {"discovery": discovery, "checks": checks}


def _scan_prometheus_environment(*, timeout_sec: int) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    discovery: dict[str, object] = {"reachable": False, "url": ""}
    curl_path = shutil.which("curl") or ""
    checks.append(_scan_binary_check("curl", curl_path, optional=True))
    if not curl_path:
        return {"discovery": discovery, "checks": checks}
    candidates = _prometheus_candidate_urls()
    discovery["candidates"] = candidates
    last_detail = ""
    for url in candidates:
        endpoint = f"{url.rstrip('/')}/-/ready"
        probe = _safe_run_command(
            [curl_path, "-fsS", "--max-time", str(max(1, min(timeout_sec, 3))), endpoint],
            timeout_sec=max(2, min(timeout_sec + 1, 5)),
        )
        if bool(probe.get("ok")):
            discovery["reachable"] = True
            discovery["url"] = url
            checks.append(_scan_check("prometheus.ready", True, "pass", url))
            return {"discovery": discovery, "checks": checks}
        last_detail = _probe_detail(probe)
    checks.append(
        _scan_check(
            "prometheus.ready",
            False,
            "warn",
            last_detail or f"not reachable: {', '.join(candidates)}",
            "如有 Prometheus，可设置 TARGET_PROMETHEUS_URL 或执行 lsre target set --prometheus-url <url>",
        )
    )
    return {"discovery": discovery, "checks": checks}


def _scan_provider_environment(*, secrets_file: Path | None) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    provider_checks = _build_provider_setup_checks(secrets_file=secrets_file)
    configured = [
        str(row.get("provider", name))
        for name, row in provider_checks.items()
        if isinstance(row, dict) and bool(row.get("ok"))
    ]
    checks.append(
        _scan_check(
            "llm.provider_key",
            bool(configured),
            "pass" if configured else "warn",
            ", ".join(configured) if configured else "(unset)",
            "" if configured else "环境扫描不需要 Key；需要真实 AI 诊断时执行 lsre login --provider openai（或 anthropic/gemini/deepseek/qwen/kimi）",
        )
    )
    return {
        "discovery": {
            "configured": configured,
            "available_providers": list(PROVIDER_SPECS.keys()),
        },
        "checks": checks,
    }


def _scan_check(
    name: str,
    ok: bool,
    severity: str,
    detail: str,
    hint: str = "",
) -> dict[str, object]:
    return {
        "name": name,
        "ok": ok,
        "severity": severity,
        "detail": str(detail or "")[:500],
        "hint": hint,
    }


def _probe_detail(probe: dict[str, object]) -> str:
    text = str(probe.get("stdout", "") or probe.get("stderr", "") or "").strip()
    if not text:
        text = f"exit_code={probe.get('exit_code', '-')}"
    return text[:500]


def _non_empty_lines(text: str) -> list[str]:
    return [line.strip() for line in str(text or "").splitlines() if line.strip()]


def _preview_lines(lines: list[str], *, limit: int) -> str:
    preview = lines[: max(1, limit)]
    suffix = "" if len(lines) <= limit else f"\n... +{len(lines) - limit} more"
    return "\n".join(preview) + suffix


def _extract_problem_pod_lines(lines: list[str]) -> list[str]:
    problems: list[str] = []
    healthy_statuses = {"running", "completed", "succeeded"}
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        namespace, name, ready, status = parts[:4]
        restarts = parts[4] if len(parts) > 4 else "0"
        restart_count = 0
        match = re.match(r"(\d+)", restarts)
        if match:
            restart_count = int(match.group(1))
        if status.lower() not in healthy_statuses or restart_count > 0:
            problems.append(f"{namespace}/{name} status={status} ready={ready} restarts={restarts}")
    return problems


def _prometheus_candidate_urls() -> list[str]:
    candidates: list[str] = []
    for raw in (
        os.environ.get("TARGET_PROMETHEUS_URL", ""),
        os.environ.get("PROMETHEUS_URL", ""),
        settings.target_prometheus_url,
        "http://127.0.0.1:9090",
        "http://localhost:9090",
    ):
        url = str(raw or "").strip().rstrip("/")
        if url and url not in candidates:
            candidates.append(url)
    return candidates


def _build_environment_scan_next_actions(checks: list[dict[str, object]], usable_targets: list[str]) -> list[str]:
    actions: list[str] = []
    if usable_targets:
        actions.append(f"可直接开始自然语言诊断：lazysre \"检查 {'/'.join(usable_targets)} 当前问题\"")
    else:
        actions.append("未发现可直接访问的运维目标；建议先确认 docker daemon 或 kubectl kubeconfig 是否可用")
    for item in checks:
        if str(item.get("severity", "")).lower() == "pass":
            continue
        hint = str(item.get("hint", "")).strip()
        if hint and hint not in actions:
            actions.append(hint)
    return actions[:8]


def _build_environment_scan_suggestions(
    discoveries: dict[str, object],
    usable_targets: list[str],
    issues: list[dict[str, object]],
) -> list[str]:
    suggestions: list[str] = []
    docker_discovery = discoveries.get("docker", {})
    k8s_discovery = discoveries.get("kubernetes", {})
    prometheus_discovery = discoveries.get("prometheus", {})
    providers = discoveries.get("providers", {})
    if isinstance(docker_discovery, dict) and bool(docker_discovery.get("swarm_active")):
        suggestions.append("分析 Docker Swarm 服务健康")
        suggestions.append("列出 Swarm 副本异常的服务并给修复建议")
    elif isinstance(docker_discovery, dict) and bool(docker_discovery.get("reachable")):
        suggestions.append("检查 Docker 容器有没有异常退出")
    if isinstance(k8s_discovery, dict) and bool(k8s_discovery.get("reachable")):
        suggestions.append("检查 K8s 异常 Pod 和 Warning Events")
    if isinstance(prometheus_discovery, dict) and bool(prometheus_discovery.get("reachable")):
        suggestions.append("用 Prometheus 分析当前资源瓶颈")
    if issues:
        first_issue = str(issues[0].get("name", "当前问题"))
        suggestions.append(f"解释 {first_issue} 为什么是问题")
    if isinstance(providers, dict) and not list(providers.get("configured", [])):
        suggestions.append("先用 mock 模式预览诊断，或执行 login 接入真实 AI")
    if not usable_targets:
        suggestions.append("帮我解释为什么当前机器还不能被 LazySRE 纳管")
    deduped: list[str] = []
    seen: set[str] = set()
    for item in suggestions:
        text = item.strip()
        if text and text not in seen:
            seen.add(text)
            deduped.append(text)
    return deduped[:5]


def _render_environment_discovery(report: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    summary = report.get("summary", {})
    targets = report.get("usable_targets", [])
    target_text = ", ".join(str(x) for x in targets) if isinstance(targets, list) and targets else "none"
    summary_text = (
        f"mode={report.get('mode', 'read-only')} usable_targets={target_text} "
        f"pass={summary.get('pass', 0)} warn={summary.get('warn', 0)} error={summary.get('error', 0)}"
    )
    if Panel:
        _console.print(Panel(summary_text, title="Environment Scan", border_style="cyan"))
    table = Table(title="Auto Discovery Checks")
    table.add_column("Check", style="cyan")
    table.add_column("Severity", style="white", no_wrap=True)
    table.add_column("Detail", style="white")
    table.add_column("Hint", style="yellow")
    for raw in report.get("checks", []):
        item = raw if isinstance(raw, dict) else {}
        table.add_row(
            str(item.get("name", "-")),
            str(item.get("severity", "-")).upper(),
            str(item.get("detail", "-"))[:180],
            str(item.get("hint", ""))[:180],
        )
    _console.print(table)
    actions = report.get("next_actions", [])
    suggestions = report.get("suggestions", [])
    if isinstance(suggestions, list) and suggestions and Panel:
        _console.print(
            Panel(
                "\n".join(f"{idx}. {item}" for idx, item in enumerate(suggestions, 1)),
                title="Try Saying This",
                border_style="magenta",
            )
        )
    if isinstance(actions, list) and actions and Panel:
        _console.print(Panel("\n".join(f"- {item}" for item in actions), title="Next Actions", border_style="green"))


def _collect_swarm_health_report(
    *,
    service_filter: str = "",
    include_logs: bool = False,
    tail: int = 80,
    timeout_sec: int = 6,
) -> dict[str, object]:
    docker_path = shutil.which("docker") or ""
    per_check_timeout = max(1, min(int(timeout_sec or 6), 10))
    tail = max(20, min(int(tail or 80), 500))
    checks: list[dict[str, object]] = [_scan_binary_check("docker", docker_path, optional=False)]
    if not docker_path:
        return {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "ok": False,
            "service_filter": service_filter,
            "summary": _summarize_doctor_checks(checks),
            "checks": checks,
            "services": [],
            "unhealthy_services": [],
            "tasks": [],
            "logs": [],
            "recommendations": ["安装 Docker 并确保当前用户可以访问 docker daemon"],
        }

    swarm_probe = _safe_run_command([docker_path, "info", "--format", "{{.Swarm.LocalNodeState}}"], timeout_sec=per_check_timeout)
    swarm_state = str(swarm_probe.get("stdout", "")).strip().lower() if bool(swarm_probe.get("ok")) else ""
    swarm_active = swarm_state == "active"
    checks.append(
        _scan_check(
            "docker.swarm",
            swarm_active,
            "pass" if swarm_active else "warn",
            swarm_state or _probe_detail(swarm_probe),
            "" if swarm_active else "当前 Docker 未处于 Swarm active 状态；如果这是单机 Docker，可用 lazysre scan 查看容器问题",
        )
    )
    if not swarm_active:
        return {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "ok": False,
            "service_filter": service_filter,
            "summary": _summarize_doctor_checks(checks),
            "checks": checks,
            "services": [],
            "unhealthy_services": [],
            "tasks": [],
            "logs": [],
            "recommendations": ["未检测到 Docker Swarm，可直接说：检查 Docker 容器有没有异常退出"],
        }

    nodes_probe = _safe_run_command(
        [docker_path, "node", "ls", "--format", "{{.Hostname}}\t{{.Status}}\t{{.Availability}}\t{{.ManagerStatus}}"],
        timeout_sec=per_check_timeout,
    )
    node_rows = _parse_swarm_node_lines(str(nodes_probe.get("stdout", "")))
    bad_nodes = [
        row
        for row in node_rows
        if str(row.get("status", "")).lower() != "ready"
        or str(row.get("availability", "")).lower() not in {"active", ""}
    ]
    checks.append(
        _scan_check(
            "swarm.nodes",
            bool(nodes_probe.get("ok")) and not bad_nodes,
            "pass" if bool(nodes_probe.get("ok")) and not bad_nodes else "warn",
            "all ready" if not bad_nodes else _preview_lines([json.dumps(x, ensure_ascii=False) for x in bad_nodes], limit=6),
            "" if not bad_nodes else "存在非 Ready/Active 节点，请检查节点网络、磁盘或 Docker daemon",
        )
    )

    services_probe = _safe_run_command(
        [docker_path, "service", "ls", "--format", "{{.Name}}\t{{.Mode}}\t{{.Replicas}}\t{{.Image}}"],
        timeout_sec=per_check_timeout,
    )
    services = _parse_swarm_service_lines(str(services_probe.get("stdout", "")))
    if service_filter.strip():
        needle = service_filter.strip().lower()
        services = [row for row in services if needle in str(row.get("name", "")).lower()]
    unhealthy = [row for row in services if bool(row.get("unhealthy"))]
    checks.append(
        _scan_check(
            "swarm.services",
            bool(services_probe.get("ok")) and not unhealthy,
            "pass" if bool(services_probe.get("ok")) and not unhealthy else "warn",
            f"services={len(services)} unhealthy={len(unhealthy)}" if bool(services_probe.get("ok")) else _probe_detail(services_probe),
            "" if not unhealthy else "存在副本未达期望的 service，建议查看 service ps 和 logs",
        )
    )

    selected = [str(row.get("name", "")) for row in (unhealthy or services) if str(row.get("name", "")).strip()]
    task_reports: list[dict[str, object]] = []
    log_reports: list[dict[str, object]] = []
    for name in selected[:8]:
        ps_probe = _safe_run_command(
            [
                docker_path,
                "service",
                "ps",
                name,
                "--no-trunc",
                "--format",
                "{{.Name}}\t{{.CurrentState}}\t{{.Error}}\t{{.Node}}",
            ],
            timeout_sec=per_check_timeout,
        )
        task_reports.append(
            {
                "service": name,
                "ok": bool(ps_probe.get("ok")),
                "tasks": _parse_swarm_task_lines(str(ps_probe.get("stdout", ""))),
                "stderr": str(ps_probe.get("stderr", ""))[:500],
            }
        )
        if include_logs:
            logs_probe = _safe_run_command(
                [docker_path, "service", "logs", "--tail", str(tail), name],
                timeout_sec=per_check_timeout,
            )
            log_reports.append(
                {
                    "service": name,
                    "ok": bool(logs_probe.get("ok")),
                    "logs": str(logs_probe.get("stdout", ""))[:5000],
                    "stderr": str(logs_probe.get("stderr", ""))[:1000],
                }
            )

    recommendations = _build_swarm_recommendations(
        services=services,
        unhealthy=unhealthy,
        bad_nodes=bad_nodes,
        include_logs=include_logs,
    )
    root_causes = _classify_swarm_root_causes(
        unhealthy=unhealthy,
        bad_nodes=bad_nodes,
        task_reports=task_reports,
        log_reports=log_reports,
    )
    summary = _summarize_doctor_checks(checks)
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "ok": bool(summary.get("error", 0) == 0 and len(unhealthy) == 0 and len(bad_nodes) == 0),
        "service_filter": service_filter,
        "include_logs": include_logs,
        "summary": summary,
        "checks": checks,
        "nodes": node_rows,
        "bad_nodes": bad_nodes,
        "services": services[:80],
        "unhealthy_services": unhealthy[:40],
        "tasks": task_reports,
        "logs": log_reports,
        "root_causes": root_causes,
        "recommendations": recommendations,
    }


def _parse_swarm_service_lines(raw: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in _non_empty_lines(raw):
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, mode, replicas, image = parts[:4]
        running = 0
        desired = 0
        if "/" in replicas:
            left, right = replicas.split("/", 1)
            running = _safe_int(left)
            desired = _safe_int(right)
        rows.append(
            {
                "name": name,
                "mode": mode,
                "replicas": replicas,
                "running": running,
                "desired": desired,
                "image": image,
                "unhealthy": desired > 0 and running < desired,
            }
        )
    return rows


def _parse_swarm_node_lines(raw: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in _non_empty_lines(raw):
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        rows.append(
            {
                "hostname": parts[0],
                "status": parts[1],
                "availability": parts[2],
                "manager_status": parts[3],
            }
        )
    return rows


def _parse_swarm_task_lines(raw: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in _non_empty_lines(raw):
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        rows.append(
            {
                "name": parts[0],
                "state": parts[1],
                "error": parts[2],
                "node": parts[3],
            }
        )
    return rows[:60]


def _build_swarm_recommendations(
    *,
    services: list[dict[str, object]],
    unhealthy: list[dict[str, object]],
    bad_nodes: list[dict[str, object]],
    include_logs: bool,
) -> list[str]:
    items: list[str] = []
    if unhealthy:
        for row in unhealthy[:3]:
            name = str(row.get("name", ""))
            items.append(f"查看 {name} 的任务失败原因：lazysre swarm --service {name} --logs")
            items.append(f"自然语言继续：为什么 {name} 副本不足？")
    elif services:
        items.append("Swarm service 副本状态正常，可继续说：检查这些服务最近日志有没有错误")
    if bad_nodes:
        items.append("存在异常节点，建议检查节点磁盘、网络和 docker daemon 状态")
    if unhealthy and not include_logs:
        items.append("如需日志证据，可加 --logs 或直接说：看异常服务日志")
    if not services:
        items.append("没有发现 service；请确认当前节点是否为 Swarm manager 或是否有权限")
    return items[:8]


def _classify_swarm_root_causes(
    *,
    unhealthy: list[dict[str, object]],
    bad_nodes: list[dict[str, object]],
    task_reports: list[dict[str, object]],
    log_reports: list[dict[str, object]],
) -> list[dict[str, str]]:
    causes: list[dict[str, str]] = []
    if bad_nodes:
        causes.append(
            {
                "category": "swarm_node_unavailable",
                "severity": "high",
                "evidence": f"bad_nodes={len(bad_nodes)}",
                "advice": "先恢复节点 Ready/Active，再观察 service 是否自动调度恢复。",
            }
        )
    for service in unhealthy:
        service_name = str(service.get("name", "service"))
        service_text_parts: list[str] = [json.dumps(service, ensure_ascii=False)]
        for report in task_reports:
            if not isinstance(report, dict) or str(report.get("service", "")) != service_name:
                continue
            service_text_parts.append(json.dumps(report.get("tasks", []), ensure_ascii=False))
            service_text_parts.append(str(report.get("stderr", "")))
        for report in log_reports:
            if not isinstance(report, dict) or str(report.get("service", "")) != service_name:
                continue
            service_text_parts.append(str(report.get("logs", "")))
            service_text_parts.append(str(report.get("stderr", "")))
        evidence_text = "\n".join(service_text_parts).lower()
        category, advice = _classify_swarm_text(evidence_text)
        causes.append(
            {
                "category": category,
                "severity": "high" if category != "swarm_service_replicas_unhealthy" else "medium",
                "service": service_name,
                "evidence": _compact_swarm_evidence(evidence_text),
                "advice": advice,
            }
        )
    return causes[:12]


def _classify_swarm_text(text: str) -> tuple[str, str]:
    lowered = text.lower()
    if any(k in lowered for k in ("no such image", "pull access denied", "manifest unknown", "not found", "denied")):
        return (
            "swarm_image_pull_failed",
            "检查镜像 tag、仓库登录状态和节点到镜像仓库的网络；修复后使用 docker service update --image 或 --force 滚动恢复。",
        )
    if any(k in lowered for k in ("port is already allocated", "bind: address already in use", "port already in use")):
        return (
            "swarm_port_conflict",
            "检查发布端口是否被宿主机进程或其他 service 占用，必要时调整 published port 后滚动更新。",
        )
    if any(k in lowered for k in ("no suitable node", "constraints not satisfied", "insufficient resources")):
        return (
            "swarm_scheduler_no_suitable_node",
            "检查 node 资源、placement constraint、label、磁盘和内存压力，先恢复可调度节点。",
        )
    if any(k in lowered for k in ("oom", "out of memory", "killed")):
        return (
            "swarm_task_oom",
            "检查容器内存限制和应用内存曲线，必要时先扩容/调高 limit，再分析泄漏。",
        )
    if any(k in lowered for k in ("rejected", "failed", "shutdown", "starting", "pending")):
        return (
            "swarm_task_rejected_or_crashing",
            "查看 service ps 与 logs 的首个错误，优先确认镜像、端口、配置和依赖连通性。",
        )
    return (
        "swarm_service_replicas_unhealthy",
        "副本未达期望但证据不足；建议加 --logs 重新检查 task error 和应用日志。",
    )


def _compact_swarm_evidence(text: str) -> str:
    lines = _non_empty_lines(text)
    interesting = [
        line
        for line in lines
        if any(k in line.lower() for k in ("error", "failed", "rejected", "denied", "no such image", "oom", "port", "constraint"))
    ]
    return _preview_lines(interesting or lines, limit=4)[:500] if lines else ""


def _render_swarm_health_report(report: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    summary = report.get("summary", {})
    summary_text = (
        f"ok={report.get('ok', False)} services={len(report.get('services', []))} "
        f"unhealthy={len(report.get('unhealthy_services', []))} "
        f"bad_nodes={len(report.get('bad_nodes', []))} "
        f"warn={summary.get('warn', 0)} error={summary.get('error', 0)}"
    )
    if Panel:
        _console.print(Panel(summary_text, title="Swarm Health", border_style="cyan"))
    service_table = Table(title="Swarm Services")
    service_table.add_column("Service", style="cyan")
    service_table.add_column("Replicas", style="white", no_wrap=True)
    service_table.add_column("Image", style="white")
    service_table.add_column("Status", style="yellow")
    for row in list(report.get("services", []))[:30]:
        if not isinstance(row, dict):
            continue
        service_table.add_row(
            str(row.get("name", "-")),
            str(row.get("replicas", "-")),
            str(row.get("image", "-"))[:80],
            "UNHEALTHY" if bool(row.get("unhealthy")) else "OK",
        )
    _console.print(service_table)
    task_lines: list[str] = []
    for task_report in list(report.get("tasks", []))[:8]:
        if not isinstance(task_report, dict):
            continue
        task_lines.append(f"[{task_report.get('service', '-')}]")
        for task in list(task_report.get("tasks", []))[:6]:
            if isinstance(task, dict):
                task_lines.append(
                    f"- {task.get('name', '-')} state={task.get('state', '-')} "
                    f"node={task.get('node', '-')} error={task.get('error', '')}"
                )
    if task_lines and Panel:
        _console.print(Panel("\n".join(task_lines), title="Task Evidence", border_style="yellow"))
    root_causes = report.get("root_causes", [])
    if isinstance(root_causes, list) and root_causes and Panel:
        lines = []
        for item in root_causes[:8]:
            if isinstance(item, dict):
                lines.append(
                    f"- {item.get('category', '-')} service={item.get('service', '-')} "
                    f"severity={item.get('severity', '-')} advice={item.get('advice', '')}"
                )
        if lines:
            _console.print(Panel("\n".join(lines), title="Root Cause Classifier", border_style="magenta"))
    recommendations = report.get("recommendations", [])
    if isinstance(recommendations, list) and recommendations and Panel:
        _console.print(Panel("\n".join(f"- {item}" for item in recommendations), title="Recommendations", border_style="green"))


def _run_watch_snapshots(
    *,
    interval_sec: int,
    count: int,
    include_swarm: bool,
    include_logs: bool,
    timeout_sec: int,
    remember: bool = True,
    output: Path | None = None,
) -> list[dict[str, object]]:
    cycles = max(1, min(int(count or 1), 1000))
    interval = max(1, min(int(interval_sec or 60), 24 * 60 * 60))
    snapshots: list[dict[str, object]] = []
    remembered: set[str] = set()
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
    for idx in range(cycles):
        snapshot = _collect_watch_snapshot(
            cycle=idx + 1,
            include_swarm=include_swarm,
            include_logs=include_logs,
            timeout_sec=timeout_sec,
        )
        snapshots.append(snapshot)
        _write_latest_watch_snapshot(snapshot)
        if remember:
            signature = _watch_alert_signature(snapshot)
            if signature and signature not in remembered:
                remembered.add(signature)
                _persist_watch_alert_memory(snapshot)
        if output:
            with output.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(snapshot, ensure_ascii=False) + "\n")
        if idx < cycles - 1:
            time.sleep(interval)
    return snapshots


def _latest_watch_file() -> Path:
    return Path(settings.data_dir) / "lsre-watch-last.json"


def _write_latest_watch_snapshot(snapshot: dict[str, object]) -> Path:
    path = _latest_watch_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _load_latest_watch_snapshot(path: Path | None = None) -> dict[str, object]:
    candidate = path or _latest_watch_file()
    if not candidate.exists():
        return {}
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _collect_watch_snapshot(
    *,
    cycle: int,
    include_swarm: bool,
    include_logs: bool,
    timeout_sec: int,
) -> dict[str, object]:
    scan_report = _collect_environment_discovery(timeout_sec=timeout_sec, secrets_file=None)
    swarm_report: dict[str, object] | None = None
    if include_swarm:
        swarm_report = _collect_swarm_health_report(
            include_logs=include_logs,
            timeout_sec=timeout_sec,
            tail=120 if include_logs else 80,
        )
    alerts = _build_watch_alerts(scan_report=scan_report, swarm_report=swarm_report)
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cycle": cycle,
        "ok": len(alerts) == 0,
        "alerts": alerts,
        "scan_summary": scan_report.get("summary", {}),
        "usable_targets": scan_report.get("usable_targets", []),
        "scan_issues": scan_report.get("issues", [])[:12] if isinstance(scan_report.get("issues", []), list) else [],
        "swarm": {
            "ok": swarm_report.get("ok", False) if isinstance(swarm_report, dict) else None,
            "summary": swarm_report.get("summary", {}) if isinstance(swarm_report, dict) else {},
            "unhealthy_services": swarm_report.get("unhealthy_services", []) if isinstance(swarm_report, dict) else [],
            "bad_nodes": swarm_report.get("bad_nodes", []) if isinstance(swarm_report, dict) else [],
            "root_causes": swarm_report.get("root_causes", []) if isinstance(swarm_report, dict) else [],
            "recommendations": swarm_report.get("recommendations", []) if isinstance(swarm_report, dict) else [],
        },
        "suggestions": scan_report.get("suggestions", []),
    }


def _build_watch_alerts(
    *,
    scan_report: dict[str, object],
    swarm_report: dict[str, object] | None,
) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    for issue in scan_report.get("issues", []):
        if not isinstance(issue, dict):
            continue
        name = str(issue.get("name", ""))
        severity = str(issue.get("severity", "warn"))
        if severity == "pass":
            continue
        if name in {"llm.provider_key", "prometheus.ready"}:
            continue
        alerts.append(
            {
                "source": "scan",
                "severity": severity,
                "name": name,
                "detail": str(issue.get("detail", ""))[:240],
                "hint": str(issue.get("hint", ""))[:240],
            }
        )
    if isinstance(swarm_report, dict):
        for row in list(swarm_report.get("unhealthy_services", []))[:10]:
            if isinstance(row, dict):
                alerts.append(
                    {
                        "source": "swarm",
                        "severity": "warn",
                        "name": str(row.get("name", "service")),
                        "detail": f"replicas={row.get('replicas', '-')}",
                        "hint": f"lazysre swarm --service {row.get('name', '')} --logs",
                    }
                )
        for row in list(swarm_report.get("root_causes", []))[:10]:
            if isinstance(row, dict):
                alerts.append(
                    {
                        "source": "swarm-root-cause",
                        "severity": str(row.get("severity", "warn")),
                        "name": str(row.get("category", "swarm_root_cause")),
                        "detail": f"service={row.get('service', '-')} evidence={row.get('evidence', '')}"[:240],
                        "hint": str(row.get("advice", ""))[:240],
                    }
                )
        for row in list(swarm_report.get("bad_nodes", []))[:10]:
            if isinstance(row, dict):
                alerts.append(
                    {
                        "source": "swarm",
                        "severity": "warn",
                        "name": str(row.get("hostname", "node")),
                        "detail": f"status={row.get('status', '-')} availability={row.get('availability', '-')}",
                        "hint": "检查节点网络、磁盘和 docker daemon 状态",
                    }
                )
    return alerts[:30]


def _watch_alert_signature(snapshot: dict[str, object]) -> str:
    alerts = snapshot.get("alerts", [])
    if not isinstance(alerts, list) or not alerts:
        return ""
    parts: list[str] = []
    for item in alerts[:12]:
        if not isinstance(item, dict):
            continue
        parts.append(
            "|".join(
                [
                    str(item.get("source", "")),
                    str(item.get("name", "")),
                    str(item.get("detail", ""))[:80],
                ]
            )
        )
    return "\n".join(parts)


def _persist_watch_alert_memory(snapshot: dict[str, object]) -> None:
    alerts = snapshot.get("alerts", [])
    if not isinstance(alerts, list) or not alerts:
        return
    root_causes: list[str] = []
    swarm = snapshot.get("swarm", {})
    if isinstance(swarm, dict):
        for item in list(swarm.get("root_causes", []))[:6]:
            if isinstance(item, dict):
                root_causes.append(
                    f"{item.get('category', 'unknown')} service={item.get('service', '-')} advice={item.get('advice', '')}"
                )
    if not root_causes:
        root_causes = [
            f"{item.get('source', 'scan')}:{item.get('name', 'alert')} {item.get('detail', '')}"
            for item in alerts[:6]
            if isinstance(item, dict)
        ]
    fix_commands: list[str] = []
    rollback_commands: list[str] = []
    for item in alerts[:8]:
        if not isinstance(item, dict):
            continue
        hint = str(item.get("hint", "")).strip()
        if hint.startswith("lazysre "):
            fix_commands.append(hint)
    try:
        store = _open_incident_memory_store()
        if not store:
            return
        store.add_case(
            symptom="watch alerts: " + "; ".join(
                f"{item.get('source', '-')}/{item.get('name', '-')}"
                for item in alerts[:6]
                if isinstance(item, dict)
            ),
            root_cause="\n".join(root_causes)[:1200] or "watch detected alerts",
            fix_commands=fix_commands[:6],
            rollback_commands=rollback_commands,
            metadata={
                "source": "lsre-watch",
                "cycle": snapshot.get("cycle", 1),
                "generated_at_utc": snapshot.get("generated_at_utc", ""),
                "alert_count": len(alerts),
            },
        )
    except Exception:
        return


def _render_watch_snapshot(snapshot: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(snapshot, ensure_ascii=False, indent=2))
        return
    alerts = snapshot.get("alerts", [])
    summary_text = (
        f"cycle={snapshot.get('cycle', 1)} ok={snapshot.get('ok', False)} "
        f"alerts={len(alerts) if isinstance(alerts, list) else 0} "
        f"targets={', '.join(str(x) for x in snapshot.get('usable_targets', [])) or 'none'}"
    )
    if Panel:
        _console.print(Panel(summary_text, title="LazySRE Watch", border_style="cyan"))
    table = Table(title="Watch Alerts")
    table.add_column("Source", style="cyan")
    table.add_column("Severity", style="white", no_wrap=True)
    table.add_column("Name", style="yellow")
    table.add_column("Detail", style="white")
    table.add_column("Hint", style="green")
    if isinstance(alerts, list):
        for raw in alerts:
            item = raw if isinstance(raw, dict) else {}
            table.add_row(
                str(item.get("source", "-")),
                str(item.get("severity", "-")),
                str(item.get("name", "-")),
                str(item.get("detail", "-"))[:140],
                str(item.get("hint", ""))[:140],
            )
    _console.print(table)


def _render_watch_report_markdown(snapshots: list[dict[str, object]]) -> str:
    generated = datetime.now(timezone.utc).isoformat()
    lines = [
        "# LazySRE Watch Report",
        "",
        f"- Generated: {generated}",
        f"- Snapshots: {len(snapshots)}",
        "",
    ]
    total_alerts = sum(len(s.get("alerts", [])) for s in snapshots if isinstance(s.get("alerts", []), list))
    unhealthy_services = 0
    root_causes: list[dict[str, object]] = []
    for snapshot in snapshots:
        swarm = snapshot.get("swarm", {})
        if isinstance(swarm, dict):
            unhealthy = swarm.get("unhealthy_services", [])
            if isinstance(unhealthy, list):
                unhealthy_services += len(unhealthy)
            causes = swarm.get("root_causes", [])
            if isinstance(causes, list):
                root_causes.extend([item for item in causes if isinstance(item, dict)])
    lines.extend(
        [
            "## Summary",
            "",
            f"- Total alerts: {total_alerts}",
            f"- Unhealthy Swarm service observations: {unhealthy_services}",
            f"- Classified root causes: {len(root_causes)}",
            "",
        ]
    )
    if root_causes:
        lines.extend(["## Root Causes", ""])
        for item in root_causes[:20]:
            lines.append(
                f"- `{item.get('category', 'unknown')}` service=`{item.get('service', '-')}` "
                f"severity=`{item.get('severity', '-')}`"
            )
            advice = str(item.get("advice", "")).strip()
            if advice:
                lines.append(f"  Advice: {advice}")
        lines.append("")
    lines.extend(["## Alerts", ""])
    if total_alerts == 0:
        lines.append("- No alerts detected.")
    else:
        for snapshot in snapshots:
            cycle = snapshot.get("cycle", "-")
            for alert in snapshot.get("alerts", []):
                if not isinstance(alert, dict):
                    continue
                lines.append(
                    f"- cycle={cycle} source=`{alert.get('source', '-')}` "
                    f"name=`{alert.get('name', '-')}` severity=`{alert.get('severity', '-')}`"
                )
                detail = str(alert.get("detail", "")).strip()
                hint = str(alert.get("hint", "")).strip()
                if detail:
                    lines.append(f"  Detail: {detail[:300]}")
                if hint:
                    lines.append(f"  Hint: {hint[:300]}")
    lines.append("")
    lines.extend(["## Suggested Commands", ""])
    suggested = _extract_watch_suggested_commands(snapshots)
    if suggested:
        lines.extend(["```bash", *suggested, "```"])
    else:
        lines.append("- No direct commands suggested.")
    lines.append("")
    return "\n".join(lines)


def _build_action_inbox_from_watch(snapshot: dict[str, object]) -> dict[str, object]:
    if not snapshot:
        return {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": "latest-watch",
            "ok": False,
            "actions": [],
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0},
            "message": "No watch snapshot found. Run: lazysre watch --count 1",
        }
    actions: list[dict[str, object]] = []
    seen: set[str] = set()
    swarm = snapshot.get("swarm", {})
    if isinstance(swarm, dict):
        for cause in list(swarm.get("root_causes", []))[:12]:
            if not isinstance(cause, dict):
                continue
            action = _action_from_swarm_root_cause(cause)
            if action:
                _append_action(actions, seen, action)
        for service in list(swarm.get("unhealthy_services", []))[:12]:
            if not isinstance(service, dict):
                continue
            action = _action_from_unhealthy_swarm_service(service)
            _append_action(actions, seen, action)
    alerts = snapshot.get("alerts", [])
    if isinstance(alerts, list):
        for alert in alerts[:20]:
            if not isinstance(alert, dict):
                continue
            action = _action_from_watch_alert(alert)
            if action:
                _append_action(actions, seen, action)
    for idx, action in enumerate(actions, 1):
        action["id"] = idx
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for action in actions:
        sev = str(action.get("severity", "low"))
        if sev not in severity_counts:
            sev = "low"
        severity_counts[sev] += 1
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "latest-watch",
        "watch_generated_at_utc": snapshot.get("generated_at_utc", ""),
        "ok": bool(actions),
        "summary": {"total": len(actions), **severity_counts},
        "actions": actions,
        "message": "" if actions else "No actionable watch findings. Run lazysre watch --count 1 --logs for deeper evidence.",
    }


def _append_action(actions: list[dict[str, object]], seen: set[str], action: dict[str, object]) -> None:
    key = str(action.get("dedupe_key", "") or action.get("command", "") or action.get("title", ""))
    if not key or key in seen:
        return
    seen.add(key)
    action.pop("dedupe_key", None)
    actions.append(action)


def _action_from_swarm_root_cause(cause: dict[str, object]) -> dict[str, object] | None:
    category = str(cause.get("category", "")).strip()
    service = str(cause.get("service", "")).strip()
    severity = str(cause.get("severity", "medium")).strip() or "medium"
    advice = str(cause.get("advice", "")).strip()
    if not category:
        return None
    template = ""
    command = ""
    title = category
    if category == "swarm_image_pull_failed":
        template = "swarm-image-pull-failed"
        title = f"修复 Swarm 镜像拉取失败: {service or 'service'}"
        command = f"lazysre template run {template} --var service={service or 'SERVICE'} --apply"
    elif category in {"swarm_service_replicas_unhealthy", "swarm_task_rejected_or_crashing"}:
        template = "swarm-replicas-unhealthy"
        title = f"恢复 Swarm 副本健康: {service or 'service'}"
        command = f"lazysre template run {template} --var service={service or 'SERVICE'} --apply"
    elif category == "swarm_port_conflict":
        title = f"排查 Swarm 端口冲突: {service or 'service'}"
        command = f"lazysre swarm --service {service or 'SERVICE'} --logs"
    elif category == "swarm_scheduler_no_suitable_node":
        title = f"排查 Swarm 调度失败: {service or 'service'}"
        command = "lazysre swarm --logs"
    elif category == "swarm_task_oom":
        title = f"排查 Swarm OOM: {service or 'service'}"
        command = f"lazysre swarm --service {service or 'SERVICE'} --logs"
    else:
        command = f"lazysre swarm --service {service} --logs" if service else "lazysre swarm --logs"
    return {
        "title": title,
        "source": "swarm-root-cause",
        "severity": "high" if severity == "high" else "medium",
        "risk_level": "high" if template else "low",
        "template": template,
        "variables": {"service": service} if service else {},
        "command": command,
        "reason": advice or str(cause.get("evidence", ""))[:240],
        "dedupe_key": f"cause:{category}:{service}:{command}",
    }


def _action_from_unhealthy_swarm_service(service: dict[str, object]) -> dict[str, object]:
    name = str(service.get("name", "")).strip()
    return {
        "title": f"查看 Swarm service 失败任务: {name or 'service'}",
        "source": "swarm",
        "severity": "medium",
        "risk_level": "low",
        "template": "",
        "variables": {"service": name} if name else {},
        "command": f"lazysre swarm --service {name or 'SERVICE'} --logs",
        "reason": f"replicas={service.get('replicas', '-')}",
        "dedupe_key": f"service:{name}",
    }


def _action_from_watch_alert(alert: dict[str, object]) -> dict[str, object] | None:
    hint = str(alert.get("hint", "")).strip()
    name = str(alert.get("name", "")).strip()
    source = str(alert.get("source", "watch")).strip()
    severity = str(alert.get("severity", "low")).strip()
    if hint.startswith("lazysre "):
        return {
            "title": f"执行建议: {name or source}",
            "source": source,
            "severity": "medium" if severity == "warn" else severity,
            "risk_level": "low",
            "template": "",
            "variables": {},
            "command": hint,
            "reason": str(alert.get("detail", ""))[:240],
            "dedupe_key": f"hint:{hint}",
        }
    if name == "docker.version":
        return {
            "title": "修复 Docker daemon 访问权限",
            "source": source,
            "severity": "medium",
            "risk_level": "low",
            "template": "",
            "variables": {},
            "command": "lazysre scan",
            "reason": "Docker 已安装但当前用户无法访问 daemon；修复后重新扫描。",
            "dedupe_key": "docker-daemon-access",
        }
    if name.startswith("k8s."):
        return {
            "title": f"补齐 K8s 访问能力: {name}",
            "source": source,
            "severity": "low",
            "risk_level": "low",
            "template": "",
            "variables": {},
            "command": "lazysre scan",
            "reason": str(alert.get("hint", "") or alert.get("detail", ""))[:240],
            "dedupe_key": f"k8s-access:{name}",
        }
    return None


def _render_action_inbox(inbox: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(inbox, ensure_ascii=False, indent=2))
        return
    summary = inbox.get("summary", {})
    summary_text = (
        f"actions={summary.get('total', 0)} high={summary.get('high', 0)} "
        f"medium={summary.get('medium', 0)} low={summary.get('low', 0)}"
    )
    if Panel:
        _console.print(Panel(summary_text, title="Action Inbox", border_style="cyan"))
    table = Table(title="Recommended Actions")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="yellow", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Command", style="green")
    for raw in inbox.get("actions", []):
        item = raw if isinstance(raw, dict) else {}
        table.add_row(
            str(item.get("id", "-")),
            str(item.get("severity", "-")),
            str(item.get("title", "-"))[:80],
            str(item.get("command", ""))[:120],
        )
    _console.print(table)


def _render_action_inbox_markdown(inbox: dict[str, object]) -> str:
    lines = [
        "# LazySRE Action Inbox",
        "",
        f"- Generated: {inbox.get('generated_at_utc', '')}",
        f"- Watch Snapshot: {inbox.get('watch_generated_at_utc', '')}",
        "",
        "## Actions",
        "",
    ]
    actions = inbox.get("actions", [])
    if not isinstance(actions, list) or not actions:
        lines.append(str(inbox.get("message", "No actions.")))
        lines.append("")
        return "\n".join(lines)
    for item in actions:
        if not isinstance(item, dict):
            continue
        lines.append(f"### {item.get('id', '-')}. {item.get('title', '-')}")
        lines.append("")
        lines.append(f"- Severity: `{item.get('severity', '-')}`")
        lines.append(f"- Risk: `{item.get('risk_level', '-')}`")
        if str(item.get("template", "")).strip():
            lines.append(f"- Template: `{item.get('template')}`")
        reason = str(item.get("reason", "")).strip()
        if reason:
            lines.append(f"- Reason: {reason}")
        command = str(item.get("command", "")).strip()
        if command:
            lines.extend(["", "```bash", command, "```", ""])
    return "\n".join(lines)


def _find_action_inbox_item(inbox: dict[str, object], action_id: int) -> dict[str, object] | None:
    actions = inbox.get("actions", [])
    if not isinstance(actions, list):
        return None
    for raw in actions:
        if not isinstance(raw, dict):
            continue
        try:
            current = int(raw.get("id", 0))
        except Exception:
            current = 0
        if current == action_id:
            return raw
    return None


def _run_action_inbox_item(
    *,
    inbox: dict[str, object],
    action_id: int,
    options: dict[str, object],
    execute_mode: bool,
) -> bool:
    item = _find_action_inbox_item(inbox, action_id)
    if not item:
        typer.echo(f"Action not found: {action_id}")
        return False
    title = str(item.get("title", f"action {action_id}")).strip()
    command = str(item.get("command", "")).strip()
    if not command:
        typer.echo(f"Action {action_id} has no command.")
        return False
    typer.echo(f"Running action {action_id}: {title}")
    return _run_action_command(
        command,
        options=options,
        execute_mode=execute_mode,
    )


def _run_action_command(command_text: str, *, options: dict[str, object], execute_mode: bool) -> bool:
    try:
        tokens = shlex.split(command_text)
    except ValueError as exc:
        typer.echo(f"无法解析行动命令: {exc}")
        return False
    if not tokens:
        typer.echo("行动命令为空。")
        return False
    if tokens[0] in {"lazysre", "lsre"}:
        tokens = tokens[1:]
    if len(tokens) >= 3 and tokens[:3] == ["python", "-m", "lazysre"]:
        tokens = tokens[3:]
    if not tokens:
        typer.echo("行动命令缺少 LazySRE 子命令。")
        return False

    subcommand = tokens[0]
    if subcommand == "template":
        try:
            parsed = _parse_chat_template_command(shlex.join(tokens[1:]))
        except ValueError as exc:
            typer.echo(f"template action parse failed: {exc}")
            return False
        action = str(parsed.get("action", "list"))
        if action == "list":
            template_list()
            return True
        if action == "show":
            template_show(name=str(parsed.get("name", "")))
            return True
        _run_remediation_template(
            template_name=str(parsed.get("name", "")),
            var_items=[str(x) for x in list(parsed.get("var_items", []))],
            apply=bool(parsed.get("apply", False)),
            max_apply_steps=int(parsed.get("max_apply_steps", 6)),
            allow_high_risk=bool(parsed.get("allow_high_risk", False)),
            auto_approve_low_risk=bool(parsed.get("auto_approve_low_risk", True)),
            execute=_resolve_execute_for_apply_request(
                execute_mode,
                label=f"执行行动项模板 {parsed.get('name', '')}",
                apply=bool(parsed.get("apply", False)),
            ),
            approval_mode=str(options["approval_mode"]),
            audit_log=str(options["audit_log"]),
            model=str(options["model"]),
            provider=str(options["provider"]),
        )
        return True

    if subcommand == "swarm":
        service = ""
        include_logs = False
        tail = 120
        idx = 1
        while idx < len(tokens):
            token = tokens[idx]
            if token == "--logs":
                include_logs = True
                idx += 1
                continue
            if token == "--service":
                idx += 1
                if idx < len(tokens):
                    service = tokens[idx]
                idx += 1
                continue
            if token.startswith("--service="):
                service = token.split("=", 1)[1]
                idx += 1
                continue
            if token == "--tail":
                idx += 1
                if idx < len(tokens):
                    tail = max(1, min(_safe_int(tokens[idx]), 1000))
                idx += 1
                continue
            if token.startswith("--tail="):
                tail = max(1, min(_safe_int(token.split("=", 1)[1]), 1000))
                idx += 1
                continue
            idx += 1
        report = _collect_swarm_health_report(
            service_filter=service,
            include_logs=include_logs,
            tail=tail,
            timeout_sec=6,
        )
        if _console:
            _render_swarm_health_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return True

    if subcommand == "scan":
        report = _collect_environment_discovery(timeout_sec=5, secrets_file=None)
        if _console:
            _render_environment_discovery(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return True

    if subcommand == "fix":
        instruction = " ".join(tokens[1:]).strip() or "修复巡检发现的问题"
        _run_fix(
            instruction=instruction,
            apply=False,
            max_apply_steps=6,
            allow_high_risk=False,
            auto_approve_low_risk=True,
            export_plan_md="",
            export_plan_json="",
            execute=execute_mode,
            approve=bool(options["approve"]),
            interactive_approval=bool(options["interactive_approval"]),
            stream_output=bool(options["stream_output"]),
            verbose_reasoning=bool(options["verbose_reasoning"]),
            approval_mode=str(options["approval_mode"]),
            audit_log=str(options["audit_log"]),
            lock_file=str(options["lock_file"]),
            session_file=str(options["session_file"]),
            deny_tool=list(options["deny_tool"]),
            deny_prefix=list(options["deny_prefix"]),
            tool_pack=list(options["tool_pack"]),
            remote_gateway=list(options["remote_gateway"]),
            model=str(options["model"]),
            provider=str(options["provider"]),
            max_steps=int(options["max_steps"]),
        )
        return True

    if subcommand in {"kubectl", "docker", "curl"}:
        _execute_fix_plan_steps(
            plan=FixPlan(apply_commands=[shlex.join(tokens)], rollback_commands=[]),
            max_apply_steps=1,
            execute=execute_mode,
            approval_mode=str(options["approval_mode"]),
            audit_log=str(options["audit_log"]),
            allow_high_risk=False,
            auto_approve_low_risk=True,
            model=str(options["model"]),
            provider=str(options["provider"]),
        )
        return True

    typer.echo(f"暂不支持自动执行该行动命令: {command_text}")
    return False


def _latest_autopilot_file() -> Path:
    return Path(settings.data_dir) / "lsre-autopilot-last.json"


def _write_latest_autopilot_report(report: dict[str, object]) -> Path:
    path = _latest_autopilot_file()
    _write_json_file(path, report)
    return path


def _run_autopilot_cycle(
    *,
    goal: str,
    include_swarm: bool,
    include_logs: bool,
    remember: bool,
    timeout_sec: int,
) -> dict[str, object]:
    scan_report = _collect_environment_discovery(timeout_sec=timeout_sec, secrets_file=None)
    snapshots = _run_watch_snapshots(
        interval_sec=60,
        count=1,
        include_swarm=include_swarm,
        include_logs=include_logs,
        remember=remember,
        timeout_sec=timeout_sec,
        output=None,
    )
    watch_snapshot = snapshots[-1] if snapshots else {}
    action_inbox = _build_action_inbox_from_watch(watch_snapshot)
    report = _build_autopilot_report(
        goal=goal,
        scan_report=scan_report,
        watch_snapshot=watch_snapshot,
        action_inbox=action_inbox,
    )
    _write_latest_autopilot_report(report)
    return report


def _build_autopilot_report(
    *,
    goal: str,
    scan_report: dict[str, object],
    watch_snapshot: dict[str, object],
    action_inbox: dict[str, object],
) -> dict[str, object]:
    scan_summary = scan_report.get("summary", {})
    if not isinstance(scan_summary, dict):
        scan_summary = {}
    action_summary = action_inbox.get("summary", {})
    if not isinstance(action_summary, dict):
        action_summary = {}
    scan_warn = int(scan_summary.get("warn", 0) or 0)
    scan_error = int(scan_summary.get("error", 0) or 0)
    action_total = int(action_summary.get("total", 0) or 0)
    alert_count = len(watch_snapshot.get("alerts", [])) if isinstance(watch_snapshot.get("alerts", []), list) else 0
    needs_attention = bool(scan_warn or scan_error or alert_count or action_total)
    actions = action_inbox.get("actions", [])
    first_action = actions[0] if isinstance(actions, list) and actions and isinstance(actions[0], dict) else {}
    commands: list[str] = []
    first_command = str(first_action.get("command", "")).strip()
    if first_command:
        commands.append(first_command)
    commands.append("lazysre actions")
    if needs_attention:
        commands.append('lazysre fix "修复巡检发现的问题"')
    else:
        commands.append("lazysre watch --count 1")
    commands = _dedupe_strings(commands)[:6]
    usable_targets = scan_report.get("usable_targets", [])
    if not isinstance(usable_targets, list):
        usable_targets = []
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "autopilot",
        "goal": str(goal or "").strip() or "巡检当前环境并给出下一步行动",
        "status": "needs_attention" if needs_attention else "clear",
        "ok": not needs_attention,
        "summary": {
            "scan_warn": scan_warn,
            "scan_error": scan_error,
            "watch_alerts": alert_count,
            "actions": action_total,
            "usable_targets": len(usable_targets),
        },
        "usable_targets": usable_targets[:8],
        "scan": {
            "summary": scan_summary,
            "issues": scan_report.get("issues", [])[:12] if isinstance(scan_report.get("issues", []), list) else [],
            "suggestions": scan_report.get("suggestions", [])[:8] if isinstance(scan_report.get("suggestions", []), list) else [],
        },
        "watch": {
            "generated_at_utc": watch_snapshot.get("generated_at_utc", ""),
            "ok": bool(watch_snapshot.get("ok", False)),
            "alerts": watch_snapshot.get("alerts", [])[:20] if isinstance(watch_snapshot.get("alerts", []), list) else [],
        },
        "action_inbox": action_inbox,
        "recommended_commands": commands,
        "next_step": _build_autopilot_next_step(needs_attention=needs_attention, first_action=first_action),
    }


def _build_autopilot_next_step(*, needs_attention: bool, first_action: dict[str, object]) -> str:
    command = str(first_action.get("command", "")).strip()
    title = str(first_action.get("title", "")).strip()
    if command:
        prefix = f"优先处理：{title}。" if title else "优先处理首个建议动作。"
        return f"{prefix}建议先执行或审阅：{command}"
    if needs_attention:
        return '已有异常证据但没有直接动作，建议执行：lazysre fix "修复巡检发现的问题"'
    return "当前没有发现明确异常，建议保持 watch 定期巡检。"


def _dedupe_strings(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _render_autopilot_report(report: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    summary = report.get("summary", {})
    summary_text = (
        f"status={report.get('status', '-')} "
        f"targets={summary.get('usable_targets', 0)} "
        f"scan_warn={summary.get('scan_warn', 0)} "
        f"scan_error={summary.get('scan_error', 0)} "
        f"watch_alerts={summary.get('watch_alerts', 0)} "
        f"actions={summary.get('actions', 0)}"
    )
    if Panel:
        _console.print(Panel(summary_text, title="LazySRE Autopilot", border_style="cyan"))
        _console.print(Panel(str(report.get("next_step", "")), title="Next Step", border_style="green"))
    commands = report.get("recommended_commands", [])
    table = Table(title="Autopilot Commands")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Command", style="green")
    if isinstance(commands, list):
        for idx, command in enumerate(commands[:8], 1):
            table.add_row(str(idx), str(command))
    _console.print(table)
    inbox = report.get("action_inbox", {})
    if isinstance(inbox, dict):
        _render_action_inbox(inbox)


def _render_autopilot_report_markdown(report: dict[str, object]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# LazySRE Autopilot Report",
        "",
        f"- Generated: {report.get('generated_at_utc', '')}",
        f"- Goal: {report.get('goal', '')}",
        f"- Status: `{report.get('status', '-')}`",
        f"- Usable targets: `{summary.get('usable_targets', 0)}`",
        f"- Scan warn/error: `{summary.get('scan_warn', 0)}/{summary.get('scan_error', 0)}`",
        f"- Watch alerts: `{summary.get('watch_alerts', 0)}`",
        f"- Actions: `{summary.get('actions', 0)}`",
        "",
        "## Next Step",
        "",
        str(report.get("next_step", "")),
        "",
        "## Recommended Commands",
        "",
    ]
    commands = report.get("recommended_commands", [])
    if isinstance(commands, list) and commands:
        lines.extend(["```bash", *[str(item) for item in commands], "```", ""])
    else:
        lines.extend(["- No commands suggested.", ""])
    inbox = report.get("action_inbox", {})
    if isinstance(inbox, dict):
        lines.extend(["## Action Inbox", "", _render_action_inbox_markdown(inbox)])
    return "\n".join(lines)


def _build_autopilot_fix_instruction(goal: str, report: dict[str, object]) -> str:
    compact = {
        "goal": report.get("goal", goal),
        "status": report.get("status", ""),
        "summary": report.get("summary", {}),
        "next_step": report.get("next_step", ""),
        "recommended_commands": report.get("recommended_commands", []),
        "actions": (report.get("action_inbox", {}) if isinstance(report.get("action_inbox", {}), dict) else {}).get("actions", [])[:6],
    }
    return (
        f"{goal or '修复当前环境问题'}\n\n"
        "[autopilot]\n"
        f"{json.dumps(compact, ensure_ascii=False, indent=2)}\n\n"
        "请基于 autopilot 已收集的证据生成最小风险修复计划，优先只读验证，再给出写操作和回滚命令。"
    )


def _extract_watch_suggested_commands(snapshots: list[dict[str, object]]) -> list[str]:
    commands: list[str] = []
    seen: set[str] = set()
    for snapshot in snapshots:
        alerts = snapshot.get("alerts", [])
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            hint = str(alert.get("hint", "")).strip()
            if hint.startswith("lazysre ") and hint not in seen:
                seen.add(hint)
                commands.append(hint)
    return commands[:12]


def _safe_int(value: str) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return 0


def _default_memory_db_path() -> Path:
    return Path.home() / ".lazysre" / "history_db"


def _resolve_memory_db_path() -> Path:
    primary = _default_memory_db_path()
    try:
        primary.parent.mkdir(parents=True, exist_ok=True)
        return primary
    except Exception:
        fallback = Path(".data/lsre-history_db")
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback


def _open_incident_memory_store() -> IncidentMemoryStore | None:
    try:
        return IncidentMemoryStore(_resolve_memory_db_path())
    except Exception:
        return None


def _count_memory_cases(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        with sqlite3.connect(path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM incident_memory").fetchone()
            return int(row[0]) if row else 0
    except Exception:
        return 0


def _read_last_fix_plan_summary(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"exists": False}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"exists": False, "invalid": True}
    if not isinstance(payload, dict):
        return {"exists": False, "invalid": True}
    plan = payload.get("plan", {})
    apply_cmds = []
    if isinstance(plan, dict):
        raw = plan.get("apply_commands", [])
        if isinstance(raw, list):
            apply_cmds = [str(x).strip() for x in raw if str(x).strip()]
    return {
        "exists": True,
        "generated_at": str(payload.get("generated_at", "")),
        "instruction": str(payload.get("instruction", ""))[:180],
        "apply_commands": len(apply_cmds),
        "path": str(path),
    }


def _render_status_snapshot(snapshot: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(snapshot, ensure_ascii=False, indent=2))
        return
    table = Table(title="LazySRE Runtime Status")
    table.add_column("Item", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    session = snapshot.get("session", {})
    session_turns = "-"
    session_last = ""
    if isinstance(session, dict):
        session_turns = str(session.get("turns", "-"))
        session_last = str(session.get("last_user", ""))
    target = snapshot.get("target", {})
    target_payload = target if isinstance(target, dict) else {}

    table.add_row("Generated", str(snapshot.get("generated_at_utc", "-")))
    table.add_row("Active Target Profile", str(snapshot.get("active_target_profile", "-") or "(none)"))
    table.add_row("Session Turns", session_turns)
    table.add_row("Last User Input", session_last or "-")
    table.add_row("Prometheus", str(target_payload.get("prometheus_url", "-") or "-"))
    table.add_row("K8s API", str(target_payload.get("k8s_api_url", "-") or "-"))
    table.add_row("K8s Context", str(target_payload.get("k8s_context", "-") or "-"))
    table.add_row("K8s Namespace", str(target_payload.get("k8s_namespace", "-") or "-"))
    memory = snapshot.get("memory", {})
    if isinstance(memory, dict):
        table.add_row("Memory Cases", str(memory.get("cases", 0)))
    last_fix = snapshot.get("last_fix_plan", {})
    if isinstance(last_fix, dict):
        if bool(last_fix.get("exists")):
            table.add_row("Last Fix", str(last_fix.get("instruction", "-")) or "-")
            table.add_row("Fix Cmds", str(last_fix.get("apply_commands", 0)))
        else:
            table.add_row("Last Fix", "none")
    probe = snapshot.get("probe", {})
    if isinstance(probe, dict):
        summary = probe.get("summary", {})
        if isinstance(summary, dict):
            table.add_row(
                "Probe",
                f"{probe.get('mode', '-')}: {summary.get('ok_count', 0)}/{summary.get('total', 0)}",
            )
    _console.print(table)


def _collect_install_doctor_report() -> dict[str, object]:
    checks: list[dict[str, object]] = []

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = (sys.version_info.major, sys.version_info.minor) >= (3, 11)
    checks.append(
        {
            "name": "runtime.python_version",
            "ok": py_ok,
            "severity": "pass" if py_ok else "error",
            "detail": f"{py_ver} ({sys.executable})",
            "hint": "" if py_ok else "请安装 Python 3.11+",
        }
    )

    try:
        import lazysre as _lazy_mod  # noqa: F401

        checks.append(
            {
                "name": "runtime.lazysre_import",
                "ok": True,
                "severity": "pass",
                "detail": "import lazysre ok",
                "hint": "",
            }
        )
    except Exception as exc:
        checks.append(
            {
                "name": "runtime.lazysre_import",
                "ok": False,
                "severity": "error",
                "detail": str(exc)[:220],
                "hint": "执行 python -m pip install lazysre 或重新安装项目",
            }
        )

    node_path = shutil.which("node") or ""
    node_ok = bool(node_path)
    checks.append(
        {
            "name": "runtime.node_binary",
            "ok": node_ok,
            "severity": "pass" if node_ok else "warn",
            "detail": node_path or "(not found)",
            "hint": "" if node_ok else "如需 npm 全局安装，请安装 Node.js 18+",
        }
    )

    npm_path = shutil.which("npm") or ""
    npm_ok = bool(npm_path)
    checks.append(
        {
            "name": "runtime.npm_binary",
            "ok": npm_ok,
            "severity": "pass" if npm_ok else "warn",
            "detail": npm_path or "(not found)",
            "hint": "" if npm_ok else "如需 npm 全局安装，请安装 npm",
        }
    )

    if npm_ok:
        npm_probe = _safe_run_command([npm_path, "-v"], timeout_sec=5)
        checks.append(
            {
                "name": "runtime.npm_version",
                "ok": bool(npm_probe.get("ok")),
                "severity": "pass" if bool(npm_probe.get("ok")) else "warn",
                "detail": str(npm_probe.get("stdout", "") or npm_probe.get("stderr", ""))[:200],
                "hint": "" if bool(npm_probe.get("ok")) else "检查 npm 与 node 是否同时可用",
            }
        )
        auth_probe = _safe_run_command([npm_path, "whoami"], timeout_sec=6)
        checks.append(
            {
                "name": "runtime.npm_auth",
                "ok": bool(auth_probe.get("ok")),
                "severity": "pass" if bool(auth_probe.get("ok")) else "warn",
                "detail": str(auth_probe.get("stdout", "") or auth_probe.get("stderr", ""))[:220],
                "hint": "" if bool(auth_probe.get("ok")) else "仅在本地直发 npm 时需要 npm 登录；GitHub Actions 可使用 NPM_TOKEN",
            }
        )

    gh_path = shutil.which("gh") or ""
    gh_ok = bool(gh_path)
    checks.append(
        {
            "name": "runtime.gh_cli",
            "ok": gh_ok,
            "severity": "pass" if gh_ok else "warn",
            "detail": gh_path or "(not found)",
            "hint": "" if gh_ok else "建议安装 gh 以便检查仓库 Secrets 与 workflow",
        }
    )
    if gh_ok:
        gh_probe = _safe_run_command([gh_path, "auth", "status"], timeout_sec=7)
        checks.append(
            {
                "name": "runtime.gh_auth",
                "ok": bool(gh_probe.get("ok")),
                "severity": "pass" if bool(gh_probe.get("ok")) else "warn",
                "detail": str(gh_probe.get("stdout", "") or gh_probe.get("stderr", ""))[:220],
                "hint": "" if bool(gh_probe.get("ok")) else "执行 gh auth login 后可自动检查 NPM_TOKEN 等配置",
            }
        )

    summary = _summarize_doctor_checks(checks)
    return {
        "checks": checks,
        "summary": summary,
    }


def _safe_run_command(command: list[str], *, timeout_sec: int) -> dict[str, object]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=float(timeout_sec),
            check=False,
        )
    except Exception as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc), "exit_code": -1}
    return {
        "ok": completed.returncode == 0,
        "stdout": (completed.stdout or "").strip(),
        "stderr": (completed.stderr or "").strip(),
        "exit_code": int(completed.returncode),
    }


def _run_first_run_setup(
    *,
    profile_file: Path,
    timeout_sec: int,
    execute_probe: bool,
    apply_defaults: bool,
    audit_log: Path,
    write_marker: bool,
    provider: str = "auto",
    secrets_file: Path | None = None,
) -> dict[str, object]:
    store = TargetEnvStore(profile_file)
    target = store.load()
    setup_actions: list[str] = []
    if apply_defaults:
        updates = _compute_setup_default_updates(target)
        if updates:
            target = store.update(**updates)
            setup_actions.extend(
                f"set {key}={value}" if key != "k8s_bearer_token" else "set k8s_bearer_token=(hidden)"
                for key, value in updates.items()
            )

    install_report = _collect_install_doctor_report()
    provider_checks = _build_provider_setup_checks(secrets_file=secrets_file)
    selected_provider = provider if str(provider or "").strip() else "auto"
    active_provider = (
        str(selected_provider).strip().lower()
        if str(selected_provider).strip().lower() in PROVIDER_SPECS
        else _resolve_default_provider(secrets_file=secrets_file)
    )
    active_provider_check = provider_checks.get(active_provider, {})
    probe_report = asyncio.run(
        probe_target_environment(
            target,
            executor=SafeExecutor(
                dry_run=(not execute_probe),
                approval_mode="permissive",
                approval_granted=True,
                audit_logger=AuditLogger(audit_log),
            ),
            timeout_sec=timeout_sec,
        )
    )
    probe_summary = dict(probe_report.get("summary", {})) if isinstance(probe_report, dict) else {}
    provider_ok = bool(active_provider_check.get("ok"))
    install_summary = dict(install_report.get("summary", {})) if isinstance(install_report, dict) else {}
    install_errors = int(install_summary.get("error", 0))
    probe_ok = bool(probe_summary.get("all_ok"))
    ready = bool(provider_ok and install_errors == 0 and probe_ok)

    next_actions = _build_setup_next_actions(
        provider_ok=provider_ok,
        active_provider=active_provider,
        install_report=install_report,
        probe_report=probe_report,
    )
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile_file": str(profile_file),
        "execute_probe": execute_probe,
        "apply_defaults": apply_defaults,
        "actions": setup_actions,
        "ready": ready,
        "active_provider": active_provider,
        "providers": provider_checks,
        "install": install_report,
        "probe": probe_report,
        "next_actions": next_actions,
    }
    if write_marker:
        marker = _write_setup_marker(report)
        report["marker_file"] = str(marker)
    return report


def _run_quickstart(
    *,
    profile_file: Path,
    timeout_sec: int,
    execute_probe: bool,
    autofix: bool,
    write_backup: bool,
    audit_log: Path,
    api_key: str,
    prompt_for_api_key: bool,
    provider: str,
    secrets_file: Path | None,
) -> dict[str, object]:
    quick_actions: list[str] = []
    secret_store = SecretStore(secrets_file)
    login_provider = _resolve_setup_provider(provider, secrets_file=secrets_file)
    key = str(api_key or "").strip()
    if key:
        secret_store.set_api_key(login_provider, key)
        quick_actions.append(f"{login_provider}_api_key saved from --api-key")
    elif (not _resolve_provider_api_key(login_provider, secrets_file=secrets_file)) and prompt_for_api_key and _stdin_interactive():
        if typer.confirm(f"检测到未配置 {PROVIDER_SPECS[login_provider].label} API Key，是否现在配置？", default=True):
            typed = typer.prompt(f"{PROVIDER_SPECS[login_provider].label} API Key", hide_input=True).strip()
            if typed:
                secret_store.set_api_key(login_provider, typed)
                quick_actions.append(f"{login_provider}_api_key saved from prompt")

    report = _run_first_run_setup(
        profile_file=profile_file,
        timeout_sec=timeout_sec,
        execute_probe=execute_probe,
        apply_defaults=True,
        audit_log=audit_log,
        write_marker=True,
        provider=provider,
        secrets_file=secrets_file,
    )
    if autofix:
        auto_payload = _run_doctor_autofix_flow(
            profile_file=profile_file,
            timeout_sec=timeout_sec,
            execute_probe=execute_probe,
            write_backup=write_backup,
            audit_log=audit_log,
            prompt_for_api_key=prompt_for_api_key,
            provider=provider,
            secrets_file=secrets_file,
        )
        report = _run_first_run_setup(
            profile_file=profile_file,
            timeout_sec=timeout_sec,
            execute_probe=execute_probe,
            apply_defaults=True,
            audit_log=audit_log,
            write_marker=True,
            provider=provider,
            secrets_file=secrets_file,
        )
        report["autofix"] = auto_payload
    report["quickstart"] = {
        "actions": quick_actions,
        "autofix_enabled": bool(autofix),
    }
    return report


def _run_doctor_autofix_flow(
    *,
    profile_file: Path,
    timeout_sec: int,
    execute_probe: bool,
    write_backup: bool,
    audit_log: Path,
    prompt_for_api_key: bool,
    provider: str,
    secrets_file: Path | None,
) -> dict[str, object]:
    target_store = TargetEnvStore(profile_file)
    target = target_store.load()
    target_autofix = _apply_doctor_autofix(target_store, target, write_backup=write_backup)
    api_key_saved = False
    login_provider = _resolve_setup_provider(provider, secrets_file=secrets_file)
    if (not _resolve_provider_api_key(login_provider, secrets_file=secrets_file)) and prompt_for_api_key and _stdin_interactive():
        if typer.confirm(f"检测到未配置 {PROVIDER_SPECS[login_provider].label} API Key，是否现在配置？", default=True):
            typed = typer.prompt(f"{PROVIDER_SPECS[login_provider].label} API Key", hide_input=True).strip()
            if typed:
                SecretStore(secrets_file).set_api_key(login_provider, typed)
                api_key_saved = True
    setup_report = _run_first_run_setup(
        profile_file=profile_file,
        timeout_sec=timeout_sec,
        execute_probe=execute_probe,
        apply_defaults=True,
        audit_log=audit_log,
        write_marker=True,
        provider=provider,
        secrets_file=secrets_file,
    )
    return {
        "target_autofix": target_autofix,
        "provider_api_key_saved": api_key_saved,
        "provider": login_provider,
        "post_setup_ready": bool(setup_report.get("ready")),
        "post_setup_next_actions": list(setup_report.get("next_actions", []))[:8]
        if isinstance(setup_report.get("next_actions"), list)
        else [],
    }


def _interactive_init_wizard(
    *,
    profile_file: Path,
    timeout_sec: int,
    execute_probe: bool,
    audit_log: Path,
    provider: str,
    secrets_file: Path | None,
) -> dict[str, object]:
    typer.echo("LazySRE 初始化向导（约 30 秒）")
    store = TargetEnvStore(profile_file)
    target = store.load()
    secret_store = SecretStore(secrets_file)

    login_provider = _resolve_setup_provider(provider, secrets_file=secrets_file)
    existing_key = _resolve_provider_api_key(login_provider, secrets_file=secrets_file)
    if existing_key:
        masked = secret_store.masked_api_key(login_provider) or "***"
        typer.echo(f"已检测到 {PROVIDER_SPECS[login_provider].label} Key: {masked}")
    else:
        if typer.confirm(f"是否现在配置 {PROVIDER_SPECS[login_provider].label} API Key？", default=True):
            api_key = typer.prompt(f"{PROVIDER_SPECS[login_provider].label} API Key", hide_input=True).strip()
            if api_key:
                secret_store.set_api_key(login_provider, api_key)
                typer.echo("API Key 已保存。")

    prom_default = str(target.prometheus_url or settings.target_prometheus_url or "").strip()
    api_default = str(target.k8s_api_url or settings.target_k8s_api_url or "").strip()
    ctx_default = str(target.k8s_context or settings.target_k8s_context or "").strip()
    ns_default = str(target.k8s_namespace or settings.target_k8s_namespace or "default").strip() or "default"
    verify_tls_default = bool(target.k8s_verify_tls)

    prometheus_url = typer.prompt("Prometheus URL", default=prom_default).strip()
    k8s_api_url = typer.prompt("K8s API URL", default=api_default).strip()
    k8s_context = typer.prompt("kubectl context", default=ctx_default).strip()
    k8s_namespace = typer.prompt("默认 namespace", default=ns_default).strip() or "default"
    k8s_verify_tls = typer.confirm("是否校验 K8s TLS 证书？", default=verify_tls_default)

    store.update(
        prometheus_url=prometheus_url,
        k8s_api_url=k8s_api_url,
        k8s_context=k8s_context,
        k8s_namespace=k8s_namespace,
        k8s_verify_tls=k8s_verify_tls,
    )

    report = _run_first_run_setup(
        profile_file=profile_file,
        timeout_sec=timeout_sec,
        execute_probe=execute_probe,
        apply_defaults=False,
        audit_log=audit_log,
        write_marker=True,
        provider=provider,
        secrets_file=secrets_file,
    )
    return report


def _compute_setup_default_updates(target) -> dict[str, object]:
    updates: dict[str, object] = {}
    if not str(getattr(target, "prometheus_url", "") or "").strip():
        candidate = str(settings.target_prometheus_url or "").strip()
        if candidate:
            updates["prometheus_url"] = candidate
    if not str(getattr(target, "k8s_api_url", "") or "").strip():
        candidate = str(settings.target_k8s_api_url or "").strip()
        if candidate:
            updates["k8s_api_url"] = candidate
    if not str(getattr(target, "k8s_context", "") or "").strip():
        candidate = str(settings.target_k8s_context or "").strip()
        if candidate:
            updates["k8s_context"] = candidate
    if not str(getattr(target, "k8s_namespace", "") or "").strip():
        candidate = str(settings.target_k8s_namespace or "").strip() or "default"
        updates["k8s_namespace"] = candidate
    return updates


def _resolve_setup_provider(provider: str, *, secrets_file: Path | None = None) -> str:
    normalized = str(provider or "auto").strip().lower()
    if normalized in PROVIDER_SPECS:
        return normalized
    return _resolve_default_provider(secrets_file=secrets_file)


def _build_provider_setup_checks(*, secrets_file: Path | None = None) -> dict[str, dict[str, object]]:
    checks: dict[str, dict[str, object]] = {}
    for provider, spec in PROVIDER_SPECS.items():
        raw = _resolve_provider_api_key(provider, secrets_file=secrets_file)
        masked = ""
        if raw:
            masked = f"{raw[:4]}...{raw[-4:]}" if len(raw) > 12 else "***"
        env_present = False
        if provider == "openai":
            env_present = bool(str(settings.openai_api_key or "").strip())
        elif provider == "anthropic":
            env_present = bool(str(settings.anthropic_api_key or "").strip())
        elif provider == "gemini":
            env_present = bool(str(settings.gemini_api_key or "").strip())
        elif provider == "deepseek":
            env_present = bool(str(settings.deepseek_api_key or "").strip())
        elif provider == "qwen":
            env_present = bool(str(settings.qwen_api_key or "").strip())
        elif provider == "kimi":
            env_present = bool(str(settings.kimi_api_key or "").strip())
        source = "env" if env_present else ("secrets" if raw else "unset")
        checks[provider] = {
            "name": f"runtime.{spec.secret_key}",
            "provider": provider,
            "label": spec.label,
            "ok": bool(raw),
            "severity": "pass" if raw else "error",
            "detail": f"{masked or '(unset)'} ({source})",
            "hint": "" if raw else f"执行 lsre login --provider {provider} 保存 API Key（或设置 {' / '.join(spec.env_names)}）",
        }
    return checks


def _build_setup_next_actions(
    *,
    provider_ok: bool,
    active_provider: str,
    install_report: dict[str, object],
    probe_report: dict[str, object],
) -> list[str]:
    actions: list[str] = []
    if not provider_ok:
        actions.append(f"lsre login --provider {active_provider}")
    checks = install_report.get("checks", [])
    if isinstance(checks, list):
        for item in checks:
            if not isinstance(item, dict):
                continue
            if bool(item.get("ok")):
                continue
            hint = str(item.get("hint", "")).strip()
            if hint:
                actions.append(hint)
    probe_checks = probe_report.get("checks", {})
    if isinstance(probe_checks, dict):
        for name, row in probe_checks.items():
            if not isinstance(row, dict):
                continue
            if bool(row.get("ok")):
                continue
            stderr_preview = str(row.get("stderr_preview", "")).strip()
            if stderr_preview:
                actions.append(f"{name}: {stderr_preview}")
    deduped: list[str] = []
    seen: set[str] = set()
    for item in actions:
        text = item.strip()
        if (not text) or (text in seen):
            continue
        seen.add(text)
        deduped.append(text)
    return deduped[:12]


def _write_setup_marker(report: dict[str, object]) -> Path:
    marker = Path(settings.data_dir) / "lsre-onboarding.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return marker


def _write_first_scan_marker(report: dict[str, object]) -> Path:
    marker = Path(settings.data_dir) / "lsre-onboarding.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "ready": False,
        "first_scan_done": True,
        "scan_summary": report.get("summary", {}),
        "usable_targets": report.get("usable_targets", []),
        "issues": report.get("issues", [])[:8] if isinstance(report.get("issues", []), list) else [],
        "suggestions": report.get("suggestions", [])[:5] if isinstance(report.get("suggestions", []), list) else [],
        "next_actions": report.get("next_actions", [])[:8] if isinstance(report.get("next_actions", []), list) else [],
    }
    marker.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return marker


def _show_first_run_setup_hint_once() -> None:
    marker = Path(settings.data_dir) / "lsre-onboarding.json"
    if marker.exists():
        return
    typer.echo("首次使用可先运行 /scan 自动体检；需要补齐配置时再用 /quickstart 或 /init。")


def _chat_state_file() -> Path:
    return Path(settings.data_dir) / "lsre-chat-state.json"


def _load_chat_runtime_state(default_execute: bool) -> bool:
    path = _chat_state_file()
    if not path.exists():
        return default_execute
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default_execute
    if not isinstance(payload, dict):
        return default_execute
    return bool(payload.get("execute_mode", default_execute))


def _save_chat_runtime_state(execute_mode: bool) -> None:
    path = _chat_state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"execute_mode": bool(execute_mode)}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _remove_file_if_exists(path: Path) -> bool:
    try:
        if not path.exists():
            return False
        path.unlink()
        return True
    except Exception:
        return False


def _maybe_auto_bootstrap_on_first_chat(options: dict[str, object]) -> None:
    marker = Path(settings.data_dir) / "lsre-onboarding.json"
    if marker.exists():
        return
    typer.echo("首次启动：正在自动扫描当前机器（只读，不需要 K8s token）...")
    report = _collect_environment_discovery(timeout_sec=5, secrets_file=None)
    _write_first_scan_marker(report)
    if _console:
        _render_environment_discovery(report)
    else:
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
    typer.echo("你可以直接复制上面的建议来问我；需要交互式配置时再输入 /init。")


def _maybe_offer_one_click_env_fix(options: dict[str, object]) -> None:
    marker = Path(settings.data_dir) / "lsre-onboarding.json"
    if marker.exists():
        try:
            payload = json.loads(marker.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        if isinstance(payload, dict) and bool(payload.get("ready")):
            return
    quick = _run_first_run_setup(
        profile_file=Path(settings.target_profile_file),
        timeout_sec=4,
        execute_probe=False,
        apply_defaults=False,
        audit_log=Path(str(options["audit_log"])),
        write_marker=False,
        provider=str(options["provider"]),
        secrets_file=None,
    )
    if bool(quick.get("ready")):
        return
    typer.echo("检测到环境未完全就绪。可直接输入“修复环境”或 /quickstart 一键自动修复。")


def _resolve_provider_api_key(provider: str, *, secrets_file: Path | None = None) -> str:
    normalized = str(provider or "").strip().lower()
    if normalized == "openai":
        env_key = str(settings.openai_api_key or "").strip()
        if env_key:
            return env_key
    elif normalized == "anthropic":
        env_key = str(settings.anthropic_api_key or "").strip()
        if env_key:
            return env_key
    elif normalized == "gemini":
        env_key = str(settings.gemini_api_key or "").strip()
        if env_key:
            return env_key
    elif normalized == "deepseek":
        env_key = str(settings.deepseek_api_key or "").strip()
        if env_key:
            return env_key
    elif normalized == "qwen":
        env_key = str(settings.qwen_api_key or "").strip()
        if env_key:
            return env_key
    elif normalized == "kimi":
        env_key = str(settings.kimi_api_key or "").strip()
        if env_key:
            return env_key
    elif normalized == "mock":
        return ""

    if normalized not in PROVIDER_SPECS:
        return ""
    return SecretStore(secrets_file).get_api_key(normalized)


def _resolve_openai_api_key(*, secrets_file: Path | None = None) -> str:
    return _resolve_provider_api_key("openai", secrets_file=secrets_file)


def _resolve_default_provider(*, secrets_file: Path | None = None) -> str:
    for candidate in PROVIDER_SPECS:
        if _resolve_provider_api_key(candidate, secrets_file=secrets_file):
            return candidate
    return "mock"


def _build_cli_llm(
    *,
    provider: str,
    model: str,
    secrets_file: Path | None = None,
):
    mode = (provider or "auto").strip().lower()
    if mode == "auto":
        mode = _resolve_default_provider(secrets_file=secrets_file)

    if mode == "mock":
        return mode, resolve_model_name("openai", model), MockFunctionCallingLLM()

    api_key = _resolve_provider_api_key(mode, secrets_file=secrets_file)
    if not api_key:
        spec = PROVIDER_SPECS[mode]
        raise typer.BadParameter(
            f"缺少 {spec.label} API Key。请执行：lsre login --provider {mode} "
            f"（或设置 {' / '.join(spec.env_names)}）",
        )

    resolved_model = resolve_model_name(mode, model)
    if mode == "openai":
        return mode, resolved_model, OpenAIResponsesLLM(api_key)
    if mode == "anthropic":
        return mode, resolved_model, AnthropicMessagesLLM(api_key)
    if mode == "gemini":
        return mode, resolved_model, GeminiFunctionCallingLLM(api_key)
    spec = get_provider_spec(mode)
    if spec.compatible:
        return (
            mode,
            resolved_model,
            OpenAICompatibleFunctionCallingLLM(
                api_key=api_key,
                provider=mode,
                base_url=spec.base_url or "",
            ),
        )
    raise typer.BadParameter(provider_mode_error_text())


def _stdin_interactive() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except Exception:
        return False


def _render_setup_report(report: dict[str, object]) -> None:
    if not (_console and Table and Panel):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return

    summary = Table(title="LazySRE Setup Wizard")
    summary.add_column("Item", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Ready", "yes" if bool(report.get("ready")) else "no")
    summary.add_row("Execute Probe", "yes" if bool(report.get("execute_probe")) else "no (dry-run)")
    summary.add_row("Profile File", str(report.get("profile_file", "-")))
    summary.add_row("Generated", str(report.get("generated_at_utc", "-")))
    _console.print(summary)

    providers = report.get("providers", {})
    if isinstance(providers, dict) and providers:
        provider_table = Table(title="LLM Providers")
        provider_table.add_column("Provider", style="cyan")
        provider_table.add_column("Status", style="white")
        provider_table.add_column("Detail", style="white")
        for provider in PROVIDER_SPECS:
            row = providers.get(provider)
            if not isinstance(row, dict):
                continue
            provider_table.add_row(
                str(row.get("label", provider)),
                "PASS" if bool(row.get("ok")) else "FAIL",
                str(row.get("detail", "")),
            )
        _console.print(provider_table)

    install = report.get("install", {})
    if isinstance(install, dict):
        install_checks = install.get("checks", [])
        install_table = Table(title="Install Diagnostics")
        install_table.add_column("Check", style="cyan")
        install_table.add_column("Status", style="white")
        install_table.add_column("Detail", style="white")
        if isinstance(install_checks, list):
            for row in install_checks:
                if not isinstance(row, dict):
                    continue
                install_table.add_row(
                    str(row.get("name", "-")),
                    "PASS" if bool(row.get("ok")) else str(row.get("severity", "warn")).upper(),
                    str(row.get("detail", ""))[:160],
                )
        _console.print(install_table)

    probe = report.get("probe", {})
    if isinstance(probe, dict):
        checks = probe.get("checks", {})
        probe_table = Table(title="Target Probe")
        probe_table.add_column("Check", style="cyan")
        probe_table.add_column("Status", style="white")
        probe_table.add_column("Exit", style="green", no_wrap=True)
        probe_table.add_column("Detail", style="white")
        if isinstance(checks, dict):
            for name, row in checks.items():
                if not isinstance(row, dict):
                    continue
                detail = str(row.get("stdout_preview", "") or row.get("stderr_preview", ""))
                probe_table.add_row(
                    str(name),
                    "OK" if bool(row.get("ok")) else "FAIL",
                    str(row.get("exit_code", "-")),
                    detail[:160],
                )
        _console.print(probe_table)

    actions = report.get("next_actions", [])
    if isinstance(actions, list) and actions:
        lines = ["建议下一步："] + [f"- {str(item)}" for item in actions]
        _console.print(Panel("\n".join(lines), border_style="yellow"))
    elif bool(report.get("ready")):
        _console.print(
            Panel(
                "环境已满足可用条件。建议开始：lsre chat",
                border_style="green",
            )
        )


def _collect_doctor_report(
    *,
    target,
    timeout_sec: int,
    dry_run_probe: bool,
    audit_log: Path,
) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    checks.append(_doctor_python_check())
    for name in ("kubectl", "docker", "curl"):
        checks.append(_doctor_binary_check(name))
    checks.extend(_doctor_target_checks(target))
    probe_report = asyncio.run(
        probe_target_environment(
            target,
            executor=SafeExecutor(
                dry_run=dry_run_probe,
                approval_mode="permissive",
                approval_granted=True,
                audit_logger=AuditLogger(audit_log),
            ),
            timeout_sec=timeout_sec,
        )
    )
    probe_checks = probe_report.get("checks", {})
    if isinstance(probe_checks, dict):
        for name, row in probe_checks.items():
            if isinstance(row, dict):
                checks.append(_doctor_probe_check(str(name), row, dry_run_probe=dry_run_probe))
    summary = _summarize_doctor_checks(checks)
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "probe_mode": "dry-run" if dry_run_probe else "execute",
        "target": target.to_safe_dict(),
        "checks": checks,
        "summary": summary,
    }


def _doctor_python_check() -> dict[str, object]:
    ok = (sys.version_info.major, sys.version_info.minor) >= (3, 11)
    severity = "pass" if ok else "error"
    hint = "" if ok else "请升级到 Python 3.11+"
    return {
        "name": "python.version",
        "ok": ok,
        "severity": severity,
        "detail": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "hint": hint,
    }


def _doctor_binary_check(name: str) -> dict[str, object]:
    path = shutil.which(name)
    ok = bool(path)
    severity = "pass" if ok else "error"
    hint = "" if ok else f"请安装 {name} 并确保在 PATH 中可用"
    return {
        "name": f"binary.{name}",
        "ok": ok,
        "severity": severity,
        "detail": path or "not found",
        "hint": hint,
    }


def _doctor_target_checks(target) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    prom = (target.prometheus_url or "").strip()
    checks.append(
        {
            "name": "target.prometheus_url",
            "ok": bool(prom),
            "severity": "pass" if prom else "warn",
            "detail": prom or "(unset)",
            "hint": "" if prom else "使用 lsre target set --prometheus-url <url> 配置",
        }
    )
    k8s_api = (target.k8s_api_url or "").strip()
    checks.append(
        {
            "name": "target.k8s_api_url",
            "ok": bool(k8s_api),
            "severity": "pass" if k8s_api else "warn",
            "detail": k8s_api or "(unset)",
            "hint": "" if k8s_api else "使用 lsre target set --k8s-api-url <url> 配置",
        }
    )
    ns = (target.k8s_namespace or "").strip()
    checks.append(
        {
            "name": "target.k8s_namespace",
            "ok": bool(ns),
            "severity": "pass" if ns else "warn",
            "detail": ns or "(unset)",
            "hint": "" if ns else "使用 lsre target set --k8s-namespace <ns> 配置",
        }
    )
    has_auth = bool((target.k8s_context or "").strip() or (target.k8s_bearer_token or "").strip())
    checks.append(
        {
            "name": "target.k8s_auth",
            "ok": has_auth,
            "severity": "pass" if has_auth else "warn",
            "detail": "context/token present" if has_auth else "missing context and token",
            "hint": "" if has_auth else "建议配置 k8s context 或 bearer token",
        }
    )
    return checks


def _apply_doctor_autofix(
    target_store: TargetEnvStore,
    target,
    *,
    write_backup: bool = False,
) -> dict[str, object]:
    updates, actions = _compute_doctor_autofix(target)
    backup_path = ""
    if updates:
        if write_backup:
            backup_path = _backup_target_profile(target_store.path)
            if backup_path:
                actions.insert(0, f"backup target profile -> {backup_path}")
        target_store.update(**updates)
    return {
        "changed": bool(updates),
        "updates": updates,
        "applied": actions,
        "backup_path": backup_path,
    }


def _compute_doctor_autofix(target) -> tuple[dict[str, object], list[str]]:
    updates: dict[str, object] = {}
    actions: list[str] = []

    if not str(target.k8s_namespace or "").strip():
        updates["k8s_namespace"] = "default"
        actions.append("set k8s_namespace=default")
    if not str(target.prometheus_url or "").strip() and settings.target_prometheus_url.strip():
        updates["prometheus_url"] = settings.target_prometheus_url.strip()
        actions.append("set prometheus_url from default settings")
    if not str(target.k8s_api_url or "").strip() and settings.target_k8s_api_url.strip():
        updates["k8s_api_url"] = settings.target_k8s_api_url.strip()
        actions.append("set k8s_api_url from default settings")
    if not str(target.k8s_context or "").strip():
        detected = _detect_kubectl_current_context()
        if detected:
            updates["k8s_context"] = detected
            actions.append(f"set k8s_context={detected}")
    return updates, actions


def _detect_kubectl_current_context() -> str:
    if not shutil.which("kubectl"):
        return ""
    try:
        completed = subprocess.run(
            ["kubectl", "config", "current-context"],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    return (completed.stdout or "").strip()


def _backup_target_profile(path: Path) -> str:
    if not path.exists():
        return ""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.bak-{timestamp}")
    try:
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)
    except Exception:
        return ""
    return str(backup)


def _doctor_probe_check(name: str, payload: dict[str, object], *, dry_run_probe: bool) -> dict[str, object]:
    ok = bool(payload.get("ok"))
    stderr_text = str(payload.get("stderr_preview", "")).lower()
    detail = str(payload.get("stdout_preview", "") or payload.get("stderr_preview", "") or "")
    if ok:
        severity = "pass"
        hint = ""
    elif ("empty" in stderr_text) or ("not configured" in stderr_text):
        severity = "warn"
        hint = "先补齐 target 配置，再执行 doctor"
    else:
        severity = "warn" if dry_run_probe else "error"
        hint = "检查网络连通性、账号权限与 API 地址"
    return {
        "name": f"probe.{name}",
        "ok": ok,
        "severity": severity,
        "detail": detail[:220],
        "hint": hint,
    }


def _summarize_doctor_checks(checks: list[dict[str, object]]) -> dict[str, int | bool]:
    passed = 0
    warned = 0
    errored = 0
    for item in checks:
        sev = str(item.get("severity", "")).strip().lower()
        if sev == "pass":
            passed += 1
        elif sev == "warn":
            warned += 1
        else:
            errored += 1
    total = len(checks)
    healthy = errored == 0
    return {
        "total": total,
        "pass": passed,
        "warn": warned,
        "error": errored,
        "healthy": healthy,
    }


def _doctor_is_healthy(summary: dict[str, object], *, strict: bool) -> bool:
    errors = int(summary.get("error", 0))
    warns = int(summary.get("warn", 0))
    if strict:
        return (errors == 0) and (warns == 0)
    return errors == 0


def _build_doctor_gate(report: dict[str, object], *, strict: bool) -> dict[str, object]:
    checks = report.get("checks", [])
    blocking_levels = {"error", "warn"} if strict else {"error"}
    blocking: list[dict[str, str]] = []
    if isinstance(checks, list):
        for raw in checks:
            item = raw if isinstance(raw, dict) else {}
            severity = str(item.get("severity", "")).strip().lower()
            if severity not in blocking_levels:
                continue
            blocking.append(
                {
                    "name": str(item.get("name", "")),
                    "severity": severity,
                    "hint": str(item.get("hint", "")),
                }
            )
    healthy = len(blocking) == 0
    exit_code_advice = 0 if healthy else (2 if strict else 1)
    return {
        "strict_mode": strict,
        "healthy": healthy,
        "blocking_count": len(blocking),
        "blocking_checks": blocking,
        "exit_code_advice": exit_code_advice,
    }


def _render_doctor_report(report: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    summary = report.get("summary", {})
    summary_text = (
        f"pass={summary.get('pass', 0)} warn={summary.get('warn', 0)} "
        f"error={summary.get('error', 0)} healthy={summary.get('healthy', False)}"
    )
    if bool(summary.get("strict_mode")):
        summary_text = f"{summary_text} strict_healthy={summary.get('strict_healthy', False)}"
    gate = report.get("gate", {})
    if isinstance(gate, dict):
        summary_text = (
            f"{summary_text} gate_blocking={gate.get('blocking_count', 0)} "
            f"exit_code_advice={gate.get('exit_code_advice', 0)}"
        )
    autofix = report.get("autofix", {})
    if isinstance(autofix, dict) and ("changed" in autofix):
        summary_text = (
            f"{summary_text} autofix_changed={autofix.get('changed', False)}"
        )
    if Panel:
        _console.print(Panel(summary_text, title="Doctor Summary", border_style="cyan"))
    checks = report.get("checks", [])
    table = Table(title="Doctor Checks")
    table.add_column("Check", style="cyan")
    table.add_column("Severity", style="white", no_wrap=True)
    table.add_column("Detail", style="white")
    table.add_column("Hint", style="yellow")
    if isinstance(checks, list):
        for raw in checks:
            item = raw if isinstance(raw, dict) else {}
            sev = str(item.get("severity", "-"))
            table.add_row(
                str(item.get("name", "-")),
                sev,
                str(item.get("detail", "-"))[:180],
                str(item.get("hint", ""))[:180],
            )
    _console.print(table)
    if isinstance(autofix, dict):
        applied = autofix.get("applied", [])
        if isinstance(applied, list) and applied:
            lines = [str(x) for x in applied if str(x).strip()]
            if lines and Panel:
                _console.print(Panel("\n".join(lines), title="Auto Fix Applied", border_style="green"))


def _render_fix_summary(plan: FixPlan, *, max_apply_steps: int) -> None:
    apply_preview = plan.apply_commands[:max_apply_steps]
    if _console and Table:
        table = Table(title="Fix Commands")
        table.add_column("#", style="cyan", no_wrap=True)
        table.add_column("Apply", style="white")
        table.add_column("Rollback", style="green")
        length = max(len(apply_preview), len(plan.rollback_commands), 1)
        for idx in range(length):
            apply = apply_preview[idx] if idx < len(apply_preview) else ""
            rollback = plan.rollback_commands[idx] if idx < len(plan.rollback_commands) else ""
            table.add_row(str(idx + 1), apply, rollback)
        _console.print(table)
        return
    typer.echo("Apply commands:")
    for cmd in apply_preview:
        typer.echo(f"- {cmd}")
    if plan.rollback_commands:
        typer.echo("Rollback commands:")
        for cmd in plan.rollback_commands:
            typer.echo(f"- {cmd}")


def _render_compact_result(result, *, title: str) -> None:
    status = _extract_named_field(result.final_text, ["status", "状态"])
    risk = _extract_named_field(result.final_text, ["risk level", "风险等级"])
    reasoning = _extract_named_field(result.final_text, ["reasoning", "推理", "诊断"])
    tools = _extract_tool_calls(result.events)
    commands = _extract_command_candidates(result.final_text, max_items=10)

    if _console and Table and Panel:
        lines: list[str] = []
        if status:
            lines.append(f"Status: {status}")
        if risk:
            lines.append(f"Risk Level: {risk}")
        if reasoning:
            lines.append(f"Reasoning: {reasoning}")
        if not lines:
            lines.append((result.final_text or "(empty)").strip()[:260])
        _console.print(Panel("\n".join(lines), title=f"{title} Summary", border_style="blue"))

        if tools:
            tool_table = Table(title="Tool Calls")
            tool_table.add_column("#", style="cyan", no_wrap=True)
            tool_table.add_column("Tool", style="white")
            for idx, tool in enumerate(tools, 1):
                tool_table.add_row(str(idx), tool)
            _console.print(tool_table)

        if commands:
            cmd_table = Table(title="Recommended Commands")
            cmd_table.add_column("#", style="cyan", no_wrap=True)
            cmd_table.add_column("Command", style="green")
            for idx, command in enumerate(commands, 1):
                cmd_table.add_row(str(idx), command)
            _console.print(cmd_table)
        return

    if status:
        typer.echo(f"Status: {status}")
    if risk:
        typer.echo(f"Risk Level: {risk}")
    if reasoning:
        typer.echo(f"Reasoning: {reasoning}")
    if tools:
        typer.echo("Tool Calls:")
        for item in tools:
            typer.echo(f"- {item}")
    if commands:
        typer.echo("Recommended Commands:")
        for item in commands:
            typer.echo(f"- {item}")
    elif not any([status, risk, reasoning, tools]):
        typer.echo((result.final_text or "(empty)").strip())


def _extract_named_field(text: str, names: list[str]) -> str:
    if not text.strip():
        return ""
    pattern = re.compile(
        r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?\s*([a-zA-Z\u4e00-\u9fff ]+)\s*(?:\*\*)?\s*[:：]\s*(.+)$"
    )
    normalized = {item.strip().lower() for item in names}
    for match in pattern.finditer(text):
        key = match.group(1).strip().lower()
        if key in normalized:
            return match.group(2).strip()[:240]
    return ""


def _extract_tool_calls(events) -> list[str]:
    seen: set[str] = set()
    calls: list[str] = []
    for event in events:
        if event.kind != "tool_call":
            continue
        name = (event.message or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        calls.append(name)
    return calls[:12]


def _extract_command_candidates(text: str, *, max_items: int) -> list[str]:
    items: list[str] = []
    seen: set[str] = set()
    plan = extract_fix_plan(text)
    for cmd in plan.apply_commands:
        _append_command(items, seen, cmd, max_items=max_items)
    blocks = re.findall(r"```(?:bash|sh|shell)?\n(.*?)```", text or "", flags=re.IGNORECASE | re.DOTALL)
    for block in blocks:
        for raw in block.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            _append_command(items, seen, line, max_items=max_items)
    for raw in (text or "").splitlines():
        line = raw.strip().strip("`")
        if not line:
            continue
        if _looks_like_shell_command(line):
            _append_command(items, seen, line, max_items=max_items)
    return items


def _append_command(items: list[str], seen: set[str], value: str, *, max_items: int) -> None:
    cmd = value.strip()
    if (not cmd) or (cmd in seen):
        return
    seen.add(cmd)
    if len(items) < max_items:
        items.append(cmd)


def _looks_like_shell_command(text: str) -> bool:
    prefixes = (
        "kubectl ",
        "docker ",
        "curl ",
        "helm ",
        "systemctl ",
        "journalctl ",
        "ssh ",
        "lsre ",
        "python ",
        "python3 ",
        "bash ",
        "sh ",
    )
    lowered = text.lower()
    return lowered.startswith(prefixes)


def _render_step_risk(
    step_index: int,
    total_steps: int,
    command_text: str,
    risk_report: dict[str, object],
    impact_statement: str = "",
) -> None:
    lines = [
        f"Step {step_index}/{total_steps}",
        f"- 命令: {command_text}",
        f"- 风险等级: {risk_report.get('risk_level', '-')}",
        f"- 风险分值: {risk_report.get('risk_score', '-')}",
        f"- 影响范围: {risk_report.get('impact_scope', '-')}",
        f"- 爆炸半径: {risk_report.get('blast_radius', '-')}",
        f"- 回滚建议: {risk_report.get('rollback', '-')}",
    ]
    if impact_statement.strip():
        lines.append(f"- Impact Statement: {impact_statement.strip()}")
    text = "\n".join(lines)
    if _console and Panel:
        _console.print(Panel(text, border_style="yellow"))
    else:
        typer.echo(text)


def _render_step_result(step_index: int, total_steps: int, result) -> None:
    status = "ok" if result.ok else "failed"
    lines = [
        f"Step {step_index}/{total_steps} result: {status}",
        f"- exit_code: {result.exit_code}",
    ]
    if result.stdout.strip():
        lines.append(f"- stdout: {result.stdout[:300]}")
    if result.stderr.strip():
        lines.append(f"- stderr: {result.stderr[:300]}")
    text = "\n".join(lines)
    if _console and Panel:
        border = "green" if result.ok else "red"
        _console.print(Panel(text, border_style=border))
    else:
        typer.echo(text)


def _render_chat_short_help() -> None:
    lines = [
        "LazySRE Chat 快捷命令",
        "- /help: 查看帮助",
        "- /scan: 零配置自动扫描本机 Docker/Swarm/K8s/Prometheus（不需要 K8s token）",
        "- /swarm [--logs]: 检查 Docker Swarm 服务、副本、任务失败证据",
        "- /watch [--count N]: 持续巡检并输出异常摘要",
        "- /actions [id]: 把最近一次巡检结果整理成编号行动清单，可直接执行某个建议",
        "- /autopilot [目标]: 自动扫描 -> 巡检 -> 行动清单，可加 --fix 生成修复计划",
        "- /mode: 查看当前执行模式（dry-run/execute）",
        "- /mode execute|dry-run: 切换执行模式",
        "- /context: 查看会话记忆（最近 pod/service/namespace）",
        "- 输入容错：/quikstart /stauts /templete 会自动纠正",
        "- 自然语言目标配置：把 namespace 设成 prod / 把 prometheus 设成 http://x:9090",
        "- 自然语言多集群：保存当前为 prod 并切换 / 切到 prod 集群 / 看看当前profile",
        "- 自然语言档案管理：导出profile到 .data/p.json / 从 .data/p.json 导入profile / 删除profile prod（需确认）",
        "- /reset: 重置引导与聊天模式记忆",
        "- /undo: 回滚最近一次修复计划",
        "- /init: 交互式初始化（API Key + 目标环境 + 探测）",
        "- /quickstart: 一键自动修复环境并完成快速就绪",
        f"- /login [--provider {provider_mode_help_text()}]: 保存对应 Provider API Key",
        "- /setup [--dry-run-probe]: 首次启动向导（安装检查+目标探测+LLM Key）",
        "- /status: 查看当前会话、目标配置、最近修复计划",
        "- /status probe: 追加目标探测摘要（dry-run）",
        "- /doctor: 运行环境预检（依赖/配置/连通性）",
        "- /doctor install: 安装环境自检（python/node/npm/gh）",
        "- /doctor fix: 执行安全自动修复后再预检",
        "- /doctor strict: 严格模式（warn 也视为不健康）",
        "- /template list: 查看一键修复模板库",
        "- /template show <name>: 查看模板详情",
        "- /template run <name> [--apply] [--var k=v]: 运行模板（支持审批门禁）",
        "- /runbook list: 查看 runbook 模板",
        "- /runbook show <name>: 查看 runbook 定义",
        "- /runbook render <name> [k=v]: 预览渲染后的 runbook 指令",
        "- /runbook add <name> --title ... --instruction ... [--mode fix] [k=v]: 新增 runbook",
        "- /runbook remove <name> [--yes]: 删除自定义 runbook",
        "- /runbook export --output <file> [--scope custom|effective]: 导出 runbook",
        "- /runbook import --input <file> [--merge|--replace]: 导入 runbook",
        "- /runbook run <name> [--apply] [k=v]: 执行 runbook（fix 模板可直接 apply）",
        "- /runbook <name> [--apply] [k=v]: 执行 runbook（简写）",
        "- /report [--format json] [--no-doctor] [--push-to-git]: 导出复盘报告",
        "- /fix <问题>: 进入修复计划模式",
        "- /apply: 执行最近一次修复计划",
        "- /undo: 执行最近一次修复计划的回滚命令",
        "- 自然语言快捷动作：看它日志 / 重启它 / 扩容到3（自动补全对象）",
        "- /approve: 查看审批队列",
        "- /approve 1,3-4: 执行指定步骤",
        "- 自然语言审批：看审批队列 / 执行第1步 / 执行步骤:1,3-4",
        "- 自然语言策略：先只跑只读步骤再执行写操作 / 解释第2步为什么执行",
        "- /memory: 查看最近故障记忆",
        "- /memory <query>: 检索相似历史案例",
        "- exit / quit: 退出",
    ]
    text = "\n".join(lines)
    if _console and Panel:
        _console.print(Panel(text, border_style="cyan"))
    else:
        typer.echo(text)


def _normalize_natural_language_text(text: str) -> str:
    normalized = str(text or "")
    replacements = [
        (r"\bquikstart\b", "quickstart"),
        (r"\bquick[-_\s]?start\b", "quickstart"),
        (r"\bstauts\b", "status"),
        (r"\bstaus\b", "status"),
        (r"\btemplete\b", "template"),
        (r"\btemplte\b", "template"),
        (r"\brunbok\b", "runbook"),
        (r"\baprove\b", "approve"),
        (r"\bmemroy\b", "memory"),
        (r"\bsacn\b", "scan"),
        (r"\bactons\b", "actions"),
        (r"\bauto[-_\s]?pilot\b", "autopilot"),
    ]
    for pattern, replacement in replacements:
        normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)
    normalized = normalized.replace("模版", "模板")
    return normalized


def _normalize_slash_command_text(text: str) -> str:
    raw = str(text or "").strip()
    if (not raw) or (not raw.startswith("/")):
        return raw
    parts = raw.split(maxsplit=1)
    head = parts[0]
    tail = parts[1] if len(parts) > 1 else ""
    command = head[1:].strip().lower()
    if not command:
        return raw
    aliases = {
        "qs": "quickstart",
        "quick-start": "quickstart",
        "quikstart": "quickstart",
        "stauts": "status",
        "staus": "status",
        "templete": "template",
        "templte": "template",
        "runbok": "runbook",
        "aprove": "approve",
        "memroy": "memory",
        "sacn": "scan",
        "actons": "actions",
        "auto-pilot": "autopilot",
        "hepl": "help",
    }
    known = [
        "help",
        "h",
        "mode",
        "context",
        "ctx",
        "reset",
        "login",
        "init",
        "quickstart",
        "scan",
        "swarm",
        "watch",
        "actions",
        "autopilot",
        "setup",
        "status",
        "doctor",
        "runbook",
        "report",
        "template",
        "fix",
        "approve",
        "undo",
        "memory",
        "apply",
    ]
    corrected = aliases.get(command, "")
    if not corrected:
        match = get_close_matches(command, known, n=1, cutoff=0.78)
        if match:
            corrected = match[0]
    if (not corrected) or (corrected == command):
        return raw
    if tail:
        return f"/{corrected} {tail}"
    return f"/{corrected}"


def _normalize_chat_input_text(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return raw
    if raw.startswith("/"):
        return _normalize_slash_command_text(raw)
    return _normalize_natural_language_text(raw)


def _assistant_chat_loop(options: dict[str, object]) -> None:
    typer.echo("LazySRE 已启动，直接说需求即可（输入 exit/quit 退出）。")
    typer.echo("示例：1) 帮我排查 payment 延迟 2) 一键修复 CrashLoopBackOff")
    typer.echo("不需要记命令，直接用自然语言说你想做什么。")
    typer.echo("快速上手：扫描环境 / 检查状态 / 修复环境 / 看审批队列 / 保存当前为 prod 并切换")
    _maybe_auto_bootstrap_on_first_chat(options)
    _maybe_offer_one_click_env_fix(options)
    runtime_execute = _load_chat_runtime_state(bool(options["execute"]))
    _render_mode_hint(runtime_execute)
    while True:
        try:
            line = typer.prompt("lsre")
        except (EOFError, KeyboardInterrupt):
            typer.echo("")
            break
        text = line.strip()
        if not text:
            continue
        normalized_text = _normalize_chat_input_text(text)
        if normalized_text != text:
            typer.echo(f"已自动纠正输入：{normalized_text}")
            text = normalized_text
        if text.lower() in {"exit", "quit"}:
            break
        if _looks_like_help_request(text):
            _render_chat_short_help()
            continue
        if _looks_like_switch_execute_request(text):
            runtime_execute = True
            _save_chat_runtime_state(runtime_execute)
            _render_mode_hint(runtime_execute)
            continue
        if _looks_like_switch_dry_run_request(text):
            runtime_execute = False
            _save_chat_runtime_state(runtime_execute)
            _render_mode_hint(runtime_execute)
            continue
        if (not text.startswith("/")) and _handle_natural_intent(text, options, runtime_execute):
            continue
        if text.lower() in {"/help", "/h"}:
            _render_chat_short_help()
            continue
        if text.lower() in {"/mode", "/mode show"}:
            _render_mode_hint(runtime_execute)
            continue
        if text.lower() in {"/context", "/ctx"}:
            _render_context_snapshot(options, execute_mode=runtime_execute)
            continue
        if text.lower().startswith("/scan"):
            report = _collect_environment_discovery(timeout_sec=5, secrets_file=None)
            if _console:
                _render_environment_discovery(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/swarm"):
            tail = text[len("/swarm") :].strip()
            include_logs = "--logs" in tail.lower() or "日志" in tail
            service_name = _extract_swarm_service_name(tail)
            report = _collect_swarm_health_report(
                service_filter=service_name,
                include_logs=include_logs,
                tail=120 if include_logs else 80,
                timeout_sec=6,
            )
            if _console:
                _render_swarm_health_report(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/watch"):
            count_match = re.search(r"--count\s+(\d+)", text, flags=re.IGNORECASE)
            count = int(count_match.group(1)) if count_match else 1
            include_logs = "--logs" in text.lower() or "日志" in text
            snapshots = _run_watch_snapshots(
                interval_sec=60,
                count=count,
                include_swarm=True,
                include_logs=include_logs,
                timeout_sec=5,
                output=None,
            )
            if _console:
                for snapshot in snapshots:
                    _render_watch_snapshot(snapshot)
            else:
                typer.echo(json.dumps(snapshots, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/actions"):
            tail = text[len("/actions") :].strip()
            snapshot = _load_latest_watch_snapshot(None)
            inbox = _build_action_inbox_from_watch(snapshot)
            if _console:
                _render_action_inbox(inbox)
            else:
                typer.echo(json.dumps(inbox, ensure_ascii=False, indent=2))
            action_id = _extract_action_id_from_text(tail)
            if action_id > 0:
                _run_action_inbox_item(
                    inbox=inbox,
                    action_id=action_id,
                    options=options,
                    execute_mode=runtime_execute,
                )
            continue
        if text.lower().startswith("/autopilot"):
            tail = text[len("/autopilot") :].strip()
            include_logs = "--logs" in tail.lower() or "日志" in tail
            plan_fix = "--fix" in tail.lower() or "修复计划" in tail
            apply_fix = "--apply" in tail.lower() or "执行修复" in tail
            goal = re.sub(r"--(?:logs|fix|apply)\b", "", tail, flags=re.IGNORECASE).strip()
            report = _run_autopilot_cycle(
                goal=goal or "巡检当前环境并给出下一步行动",
                include_swarm=True,
                include_logs=include_logs,
                remember=True,
                timeout_sec=5,
            )
            if _console:
                _render_autopilot_report(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            if plan_fix or apply_fix:
                _run_fix(
                    instruction=_build_autopilot_fix_instruction(goal, report),
                    apply=apply_fix,
                    max_apply_steps=6,
                    allow_high_risk=False,
                    auto_approve_low_risk=True,
                    export_plan_md="",
                    export_plan_json="",
                    execute=_resolve_execute_for_apply_request(
                        runtime_execute,
                        label="Autopilot 修复执行",
                        apply=apply_fix,
                    ),
                    approve=bool(options["approve"]),
                    interactive_approval=bool(options["interactive_approval"]),
                    stream_output=bool(options["stream_output"]),
                    verbose_reasoning=bool(options["verbose_reasoning"]),
                    approval_mode=str(options["approval_mode"]),
                    audit_log=str(options["audit_log"]),
                    lock_file=str(options["lock_file"]),
                    session_file=str(options["session_file"]),
                    deny_tool=list(options["deny_tool"]),
                    deny_prefix=list(options["deny_prefix"]),
                    tool_pack=list(options["tool_pack"]),
                    remote_gateway=list(options["remote_gateway"]),
                    model=str(options["model"]),
                    provider=str(options["provider"]),
                    max_steps=int(options["max_steps"]),
                )
            continue
        if text.lower().startswith("/mode "):
            tail = text[len("/mode ") :].strip().lower()
            if tail in {"execute", "exec", "on", "real"}:
                runtime_execute = True
                _save_chat_runtime_state(runtime_execute)
                _render_mode_hint(runtime_execute)
                continue
            if tail in {"dry-run", "dryrun", "preview", "off"}:
                runtime_execute = False
                _save_chat_runtime_state(runtime_execute)
                _render_mode_hint(runtime_execute)
                continue
            typer.echo("用法：/mode execute 或 /mode dry-run")
            continue
        if text.lower().startswith("/reset"):
            reset(reset_onboarding=True, reset_chat_mode=True, reset_session=False, session_file=str(options["session_file"]))
            runtime_execute = _load_chat_runtime_state(bool(options["execute"]))
            _render_mode_hint(runtime_execute)
            continue
        if text.lower().startswith("/login"):
            login(provider=str(options["provider"]), api_key="", secrets_file="")
            continue
        if text.lower().startswith("/init"):
            report = _interactive_init_wizard(
                profile_file=Path(settings.target_profile_file),
                timeout_sec=6,
                execute_probe=True,
                audit_log=Path(str(options["audit_log"])),
                provider=str(options["provider"]),
                secrets_file=None,
            )
            if _console:
                _render_setup_report(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/quickstart"):
            report = _run_quickstart(
                profile_file=Path(settings.target_profile_file),
                timeout_sec=6,
                execute_probe=True,
                autofix=True,
                write_backup=False,
                audit_log=Path(str(options["audit_log"])),
                api_key="",
                prompt_for_api_key=True,
                provider=str(options["provider"]),
                secrets_file=None,
            )
            if _console:
                _render_setup_report(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/setup"):
            setup_execute_probe = "--dry-run-probe" not in text.lower()
            report = _run_first_run_setup(
                profile_file=Path(settings.target_profile_file),
                timeout_sec=6,
                execute_probe=setup_execute_probe,
                apply_defaults=True,
                audit_log=Path(str(options["audit_log"])),
                write_marker=True,
                provider=str(options["provider"]),
            )
            if _console:
                _render_setup_report(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/status"):
            include_probe = "probe" in text.lower()
            snapshot = _collect_runtime_status(
                session_file=Path(str(options["session_file"])),
                profile_file=Path(settings.target_profile_file),
                include_probe=include_probe,
                execute_probe=False,
                timeout_sec=6,
                audit_log=Path(str(options["audit_log"])),
            )
            if _console:
                _render_status_snapshot(snapshot)
            else:
                typer.echo(json.dumps(snapshot, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/doctor"):
            doctor_text = text.lower()
            if " install" in doctor_text or "--install" in doctor_text:
                report = _collect_install_doctor_report()
                report["gate"] = _build_doctor_gate(report, strict=False)
                if _console:
                    _render_doctor_report(report)
                else:
                    typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
                continue
            auto_fix = (" fix" in doctor_text) or ("--auto-fix" in doctor_text)
            strict_mode = (" strict" in doctor_text) or ("--strict" in doctor_text)
            write_backup = (" backup" in doctor_text) or ("--write-backup" in doctor_text)
            target_store = TargetEnvStore()
            target = target_store.load()
            autofix_payload: dict[str, object] | None = None
            if auto_fix:
                autofix_payload = _apply_doctor_autofix(
                    target_store,
                    target,
                    write_backup=write_backup,
                )
                target = target_store.load()
            report = _collect_doctor_report(
                target=target,
                timeout_sec=6,
                dry_run_probe=False,
                audit_log=Path(str(options["audit_log"])),
            )
            if autofix_payload is not None:
                report["autofix"] = autofix_payload
            summary_obj = report.get("summary", {})
            if isinstance(summary_obj, dict):
                summary_obj["strict_mode"] = strict_mode
                summary_obj["strict_healthy"] = _doctor_is_healthy(summary_obj, strict=strict_mode)
            report["gate"] = _build_doctor_gate(report, strict=strict_mode)
            if _console:
                _render_doctor_report(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/runbook"):
            tail = text[len("/runbook") :].strip()
            try:
                command = _parse_chat_runbook_command(tail)
            except ValueError as exc:
                typer.echo(f"runbook 命令格式错误: {exc}")
                continue
            action = str(command.get("action", ""))
            if action == "list":
                runbook_list(
                    runbook_file=str(command.get("runbook_file", settings.runbook_store_file)),
                    custom_only=bool(command.get("custom_only", False)),
                )
                continue
            if action == "add":
                try:
                    runbook_add(
                        name=str(command.get("name", "")),
                        title=str(command.get("title", "")),
                        instruction=str(command.get("instruction", "")),
                        mode=str(command.get("mode", "diagnose")),
                        description=str(command.get("description", "")),
                        var=list(command.get("var_items", [])),
                        runbook_file=str(command.get("runbook_file", settings.runbook_store_file)),
                        force=bool(command.get("force", False)),
                    )
                except typer.BadParameter as exc:
                    typer.echo(f"runbook add failed: {exc}")
                continue
            if action == "remove":
                try:
                    runbook_remove(
                        name=str(command.get("name", "")),
                        runbook_file=str(command.get("runbook_file", settings.runbook_store_file)),
                        yes=bool(command.get("yes", False)),
                    )
                except typer.BadParameter as exc:
                    typer.echo(f"runbook remove failed: {exc}")
                continue
            if action == "export":
                try:
                    runbook_export(
                        output=str(command.get("output", "")),
                        name=[str(x) for x in list(command.get("names", []))],
                        scope=str(command.get("scope", "custom")),
                        runbook_file=str(command.get("runbook_file", settings.runbook_store_file)),
                    )
                except typer.BadParameter as exc:
                    typer.echo(f"runbook export failed: {exc}")
                continue
            if action == "import":
                try:
                    runbook_import(
                        input_file=str(command.get("input_file", "")),
                        merge=bool(command.get("merge", True)),
                        runbook_file=str(command.get("runbook_file", settings.runbook_store_file)),
                    )
                except typer.BadParameter as exc:
                    typer.echo(f"runbook import failed: {exc}")
                continue

            runbook_name = str(command.get("name", ""))
            runbook_file = str(command.get("runbook_file", settings.runbook_store_file))
            template = find_runbook(runbook_name, store=RunbookStore(Path(runbook_file)))
            if not template:
                typer.echo(f"runbook not found: {runbook_name}")
                continue
            try:
                base_var_items = [str(x) for x in list(command.get("var_items", []))]
                auto_var_items = _compose_runbook_var_items(
                    template=template,
                    text=" ".join([text, str(command.get("extra", ""))] + base_var_items),
                    options=options,
                    base_items=base_var_items,
                    profile_file=Path(settings.target_profile_file),
                )
                instruction = _prepare_runbook_instruction(
                    template=template,
                    var_items=auto_var_items,
                    extra=str(command.get("extra", "")),
                    profile_file=Path(settings.target_profile_file),
                )
            except ValueError as exc:
                typer.echo(str(exc))
                continue

            if action == "show":
                payload = {
                    "name": template.name,
                    "title": template.title,
                    "mode": template.mode,
                    "source": template.source,
                    "description": template.description,
                    "instruction": template.instruction,
                    "rendered_instruction": instruction,
                }
                typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
                continue
            if action == "render":
                typer.echo(instruction)
                continue
            _execute_runbook(
                template=template,
                instruction=instruction,
                apply=bool(command.get("apply", False)),
                options=options,
            )
            continue
        if text.lower().startswith("/report"):
            tail = text[len("/report") :].strip()
            try:
                report_cmd = _parse_chat_report_command(tail)
            except ValueError as exc:
                typer.echo(f"report 命令格式错误: {exc}")
                continue
            try:
                result = _export_incident_report(
                    session_file=Path(str(options["session_file"])),
                    target_profile_file=Path(settings.target_profile_file),
                    include_doctor=bool(report_cmd.get("include_doctor", True)),
                    include_memory=bool(report_cmd.get("include_memory", True)),
                    turn_limit=int(report_cmd.get("limit", 20)),
                    audit_log=Path(str(options["audit_log"])),
                    fmt=str(report_cmd.get("fmt", "markdown")),
                    output=str(report_cmd.get("output", "")),
                    push_to_git=bool(report_cmd.get("push_to_git", False)),
                    git_remote=str(report_cmd.get("git_remote", "origin")),
                    git_message=str(report_cmd.get("git_message", "")),
                )
            except typer.BadParameter as exc:
                typer.echo(f"report 生成失败: {exc}")
                continue
            typer.echo(f"Report exported: {result['out_path']}")
            archived = str(result.get("archived_path", "")).strip()
            if archived:
                if bool(result.get("pushed", False)):
                    typer.echo(f"Report archived & pushed: {archived}")
                else:
                    typer.echo(f"Report archived (no changes to push): {archived}")
            continue
        if text.lower().startswith("/template"):
            tail = text[len("/template") :].strip()
            try:
                parsed = _parse_chat_template_command(tail)
            except ValueError as exc:
                typer.echo(f"template 命令格式错误: {exc}")
                continue
            action = str(parsed.get("action", "list"))
            if action == "list":
                template_list()
                continue
            if action == "show":
                name = str(parsed.get("name", "")).strip()
                if not name:
                    typer.echo("用法：/template show <name>")
                    continue
                try:
                    template_show(name=name)
                except typer.BadParameter as exc:
                    typer.echo(str(exc))
                continue
            _run_remediation_template(
                template_name=str(parsed.get("name", "")),
                var_items=_compose_template_var_items(
                    " ".join([text] + [str(x) for x in list(parsed.get("var_items", []))]),
                    options,
                    base_items=[str(x) for x in list(parsed.get("var_items", []))],
                ),
                apply=bool(parsed.get("apply", False)),
                max_apply_steps=int(parsed.get("max_apply_steps", 6)),
                allow_high_risk=bool(parsed.get("allow_high_risk", False)),
                auto_approve_low_risk=bool(parsed.get("auto_approve_low_risk", False)),
                execute=_resolve_execute_for_apply_request(
                    runtime_execute,
                    label="模板修复执行",
                    apply=bool(parsed.get("apply", False)),
                ),
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                model=str(options["model"]),
                provider=str(options["provider"]),
            )
            continue
        if text.lower().startswith("/fix "):
            fix_text = text[5:].strip()
            if not fix_text:
                typer.echo("用法：/fix <问题描述>")
                continue
            text = fix_text
        if text.lower().startswith("/approve"):
            tail = text[len("/approve") :].strip()
            _approve_last_fix_plan(
                steps=tail,
                execute=runtime_execute,
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                allow_high_risk=False,
                auto_approve_low_risk=False,
                yes=False,
                with_impact=False,
                model=str(options["model"]),
                provider=str(options["provider"]),
            )
            continue
        if text.lower() in {"/undo", "/rollback", "/revert"}:
            _undo_last_fix_plan(
                max_rollback_steps=6,
                execute=_resolve_execute_for_apply_request(
                    runtime_execute,
                    label="回滚最近修复",
                    apply=True,
                ),
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                model=str(options["model"]),
                provider=str(options["provider"]),
            )
            continue
        if text.lower().startswith("/memory"):
            tail = text[len("/memory") :].strip()
            store = _open_incident_memory_store()
            if not store:
                typer.echo("memory store is unavailable.")
                continue
            if tail:
                rows = store.search_similar(tail, limit=5)
                _render_memory_cases(rows, title=f"Incident Memory Search: {tail}")
            else:
                rows = store.list_recent(limit=8)
                _render_memory_cases(rows, title="Incident Memory (Recent)")
            continue
        if text.lower() in {"/apply", "/apply-last"}:
            _apply_last_fix_plan(
                max_apply_steps=6,
                execute=_resolve_execute_for_apply_request(
                    runtime_execute,
                    label="执行最近修复计划",
                    apply=True,
                ),
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                model=str(options["model"]),
                provider=str(options["provider"]),
                allow_high_risk=True,
                auto_approve_low_risk=True,
            )
            continue

        if _looks_like_approval_queue_request(text):
            _approve_last_fix_plan(
                steps="list",
                execute=runtime_execute,
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                allow_high_risk=False,
                auto_approve_low_risk=False,
                yes=False,
                with_impact=_looks_like_with_impact_request(text),
                model=str(options["model"]),
                provider=str(options["provider"]),
            )
            continue

        if _looks_like_explain_step_request(text):
            _explain_last_fix_plan_steps(
                text=text,
                approval_mode=str(options["approval_mode"]),
                model=str(options["model"]),
                provider=str(options["provider"]),
            )
            continue

        if _looks_like_apply_request(text):
            selected_steps = _extract_apply_step_selection(text)
            low_risk_only = _looks_like_low_risk_apply_request(text)
            force_high_risk = _looks_like_force_high_risk_apply_request(text)
            read_then_write = _looks_like_read_then_write_strategy_request(text)
            if read_then_write:
                _apply_last_fix_plan_read_then_write(
                    steps=selected_steps,
                    execute=_resolve_execute_for_apply_request(
                        runtime_execute,
                        label="执行修复计划写操作阶段",
                        apply=True,
                    ),
                    approval_mode=str(options["approval_mode"]),
                    audit_log=str(options["audit_log"]),
                    model=str(options["model"]),
                    provider=str(options["provider"]),
                    allow_high_risk=bool((not low_risk_only) or force_high_risk),
                    auto_approve_low_risk=True,
                )
                continue
            if selected_steps:
                _approve_last_fix_plan(
                    steps=selected_steps,
                    execute=_resolve_execute_for_apply_request(
                        runtime_execute,
                        label=f"执行修复计划步骤 {selected_steps}",
                        apply=True,
                    ),
                    approval_mode=str(options["approval_mode"]),
                    audit_log=str(options["audit_log"]),
                    allow_high_risk=bool(force_high_risk and (not low_risk_only)),
                    auto_approve_low_risk=True,
                    yes=False,
                    with_impact=_looks_like_with_impact_request(text),
                    model=str(options["model"]),
                    provider=str(options["provider"]),
                )
                continue
            _apply_last_fix_plan(
                max_apply_steps=6,
                execute=_resolve_execute_for_apply_request(
                    runtime_execute,
                    label="执行最近修复计划",
                    apply=True,
                ),
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                model=str(options["model"]),
                provider=str(options["provider"]),
                allow_high_risk=bool((not low_risk_only) or force_high_risk),
                auto_approve_low_risk=True,
            )
            continue

        if _looks_like_undo_request(text):
            _undo_last_fix_plan(
                max_rollback_steps=6,
                execute=_resolve_execute_for_apply_request(
                    runtime_execute,
                    label="回滚最近修复",
                    apply=True,
                ),
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                model=str(options["model"]),
                provider=str(options["provider"]),
            )
            continue

        if _looks_like_init_request(text):
            report = _interactive_init_wizard(
                profile_file=Path(settings.target_profile_file),
                timeout_sec=6,
                execute_probe=True,
                audit_log=Path(str(options["audit_log"])),
                provider=str(options["provider"]),
                secrets_file=None,
            )
            if _console:
                _render_setup_report(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            continue

        if _looks_like_fix_request(text):
            auto_fix_requested = _looks_like_auto_fix_request(text)
            template_candidate, apply_requested = maybe_detect_quick_fix_intent(text)
            if template_candidate:
                auto_vars = _compose_template_var_items(text, options)
                if apply_requested:
                    _run_remediation_template(
                        template_name=template_candidate.name,
                        var_items=auto_vars,
                        apply=True,
                        max_apply_steps=6,
                        allow_high_risk=True,
                        auto_approve_low_risk=True,
                        execute=_resolve_execute_for_apply_request(
                            runtime_execute,
                            label=f"一键修复模板 {template_candidate.name}",
                            apply=True,
                        ),
                        approval_mode=str(options["approval_mode"]),
                        audit_log=str(options["audit_log"]),
                        model=str(options["model"]),
                        provider=str(options["provider"]),
                    )
                    continue
                typer.echo(
                    f"检测到可用一键修复模板：{template_candidate.name}。"
                    f"可执行：/template run {template_candidate.name} --apply"
                )
                continue
            _run_fix(
                instruction=text,
                apply=auto_fix_requested,
                max_apply_steps=6,
                allow_high_risk=False,
                auto_approve_low_risk=True,
                export_plan_md="",
                export_plan_json="",
                execute=_resolve_execute_for_apply_request(
                    runtime_execute,
                    label="自动修复执行",
                    apply=auto_fix_requested,
                ),
                approve=bool(options["approve"]),
                interactive_approval=bool(options["interactive_approval"]),
                stream_output=bool(options["stream_output"]),
                verbose_reasoning=bool(options["verbose_reasoning"]),
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                lock_file=str(options["lock_file"]),
                session_file=str(options["session_file"]),
                deny_tool=list(options["deny_tool"]),
                deny_prefix=list(options["deny_prefix"]),
                tool_pack=list(options["tool_pack"]),
                remote_gateway=list(options["remote_gateway"]),
                model=str(options["model"]),
                provider=str(options["provider"]),
                max_steps=int(options["max_steps"]),
            )
            continue

        _run_once(
            instruction=text,
            execute=runtime_execute,
            approve=bool(options["approve"]),
            interactive_approval=bool(options["interactive_approval"]),
            stream_output=bool(options["stream_output"]),
            verbose_reasoning=bool(options["verbose_reasoning"]),
            approval_mode=str(options["approval_mode"]),
            audit_log=str(options["audit_log"]),
            lock_file=str(options["lock_file"]),
            session_file=str(options["session_file"]),
            deny_tool=list(options["deny_tool"]),
            deny_prefix=list(options["deny_prefix"]),
            tool_pack=list(options["tool_pack"]),
            remote_gateway=list(options["remote_gateway"]),
            model=str(options["model"]),
            provider=str(options["provider"]),
            max_steps=int(options["max_steps"]),
        )


def _handle_natural_intent(text: str, options: dict[str, object], execute_mode: bool) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    if _maybe_handle_target_profile_natural_intent(text):
        return True
    if _looks_like_target_show_request(text):
        payload = TargetEnvStore(Path(settings.target_profile_file)).load().to_safe_dict()
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return True
    if _looks_like_target_update_request(text):
        if _apply_target_updates_from_text(text):
            return True
    if _looks_like_context_request(text):
        _render_context_snapshot(options, execute_mode=execute_mode)
        return True
    if _looks_like_reset_request(text):
        reset(
            reset_onboarding=True,
            reset_chat_mode=True,
            reset_session=False,
            session_file=str(options["session_file"]),
        )
        return True
    if _looks_like_autopilot_request(text):
        report = _run_autopilot_cycle(
            goal=text,
            include_swarm=True,
            include_logs=any(k in lowered for k in ("日志", "logs")),
            remember=True,
            timeout_sec=5,
        )
        if _console:
            _render_autopilot_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        if _looks_like_fix_request(text) or _looks_like_auto_fix_request(text):
            _run_fix(
                instruction=_build_autopilot_fix_instruction(text, report),
                apply=_looks_like_auto_fix_request(text),
                max_apply_steps=6,
                allow_high_risk=False,
                auto_approve_low_risk=True,
                export_plan_md="",
                export_plan_json="",
                execute=_resolve_execute_for_apply_request(
                    execute_mode,
                    label="Autopilot 自动修复",
                    apply=_looks_like_auto_fix_request(text),
                ),
                approve=bool(options["approve"]),
                interactive_approval=bool(options["interactive_approval"]),
                stream_output=bool(options["stream_output"]),
                verbose_reasoning=bool(options["verbose_reasoning"]),
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                lock_file=str(options["lock_file"]),
                session_file=str(options["session_file"]),
                deny_tool=list(options["deny_tool"]),
                deny_prefix=list(options["deny_prefix"]),
                tool_pack=list(options["tool_pack"]),
                remote_gateway=list(options["remote_gateway"]),
                model=str(options["model"]),
                provider=str(options["provider"]),
                max_steps=int(options["max_steps"]),
            )
        return True
    if _looks_like_action_run_request(text):
        snapshot = _load_latest_watch_snapshot(None)
        inbox = _build_action_inbox_from_watch(snapshot)
        action_id = _extract_action_id_from_text(text)
        if action_id <= 0:
            typer.echo("请指定要执行的行动编号，例如：执行第1个建议")
            return True
        _run_action_inbox_item(
            inbox=inbox,
            action_id=action_id,
            options=options,
            execute_mode=execute_mode,
        )
        return True
    if _looks_like_actions_request(text):
        snapshot = _load_latest_watch_snapshot(None)
        inbox = _build_action_inbox_from_watch(snapshot)
        if _console:
            _render_action_inbox(inbox)
        else:
            typer.echo(json.dumps(inbox, ensure_ascii=False, indent=2))
        return True
    if _looks_like_scan_request(text):
        report = _collect_environment_discovery(timeout_sec=5, secrets_file=None)
        if _console:
            _render_environment_discovery(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return True
    if _looks_like_swarm_diagnose_request(text):
        include_logs = any(k in lowered for k in ("日志", "logs", "错误栈", "报错"))
        report = _collect_swarm_health_report(
            service_filter=_extract_swarm_service_name(text),
            include_logs=include_logs,
            tail=160 if include_logs else 80,
            timeout_sec=6,
        )
        if _console:
            _render_swarm_health_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return True
    if _looks_like_watch_request(text):
        snapshots = _run_watch_snapshots(
            interval_sec=60,
            count=1,
            include_swarm=True,
            include_logs=any(k in lowered for k in ("日志", "logs")),
            timeout_sec=5,
            output=None,
        )
        if _console:
            for snapshot in snapshots:
                _render_watch_snapshot(snapshot)
        else:
            typer.echo(json.dumps(snapshots, ensure_ascii=False, indent=2))
        return True
    if _looks_like_quickstart_request(text):
        report = _run_quickstart(
            profile_file=Path(settings.target_profile_file),
            timeout_sec=6,
            execute_probe=True,
            autofix=True,
            write_backup=False,
            audit_log=Path(str(options["audit_log"])),
            api_key="",
            prompt_for_api_key=True,
            provider=str(options["provider"]),
            secrets_file=None,
        )
        if _console:
            _render_setup_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return True
    if _looks_like_init_request(text):
        report = _interactive_init_wizard(
            profile_file=Path(settings.target_profile_file),
            timeout_sec=6,
            execute_probe=True,
            audit_log=Path(str(options["audit_log"])),
            provider=str(options["provider"]),
            secrets_file=None,
        )
        if _console:
            _render_setup_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return True
    if _looks_like_status_request(text):
        include_probe = any(k in lowered for k in ("probe", "探测", "连通性", "健康检查"))
        snapshot = _collect_runtime_status(
            session_file=Path(str(options["session_file"])),
            profile_file=Path(settings.target_profile_file),
            include_probe=include_probe,
            execute_probe=False,
            timeout_sec=6,
            audit_log=Path(str(options["audit_log"])),
        )
        if _console:
            _render_status_snapshot(snapshot)
        else:
            typer.echo(json.dumps(snapshot, ensure_ascii=False, indent=2))
        return True
    if _looks_like_install_doctor_request(text):
        report = _collect_install_doctor_report()
        report["gate"] = _build_doctor_gate(report, strict=False)
        if _console:
            _render_doctor_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return True
    if _looks_like_doctor_request(text):
        strict_mode = ("strict" in lowered) or ("严格" in lowered)
        auto_fix = any(k in lowered for k in ("自动修复", "自动修正", "自动修复一下"))
        target_store = TargetEnvStore()
        target = target_store.load()
        autofix_payload: dict[str, object] | None = None
        if auto_fix:
            autofix_payload = _apply_doctor_autofix(
                target_store,
                target,
                write_backup=False,
            )
            target = target_store.load()
        report = _collect_doctor_report(
            target=target,
            timeout_sec=6,
            dry_run_probe=False,
            audit_log=Path(str(options["audit_log"])),
        )
        if autofix_payload is not None:
            report["autofix"] = autofix_payload
        summary_obj = report.get("summary", {})
        if isinstance(summary_obj, dict):
            summary_obj["strict_mode"] = strict_mode
            summary_obj["strict_healthy"] = _doctor_is_healthy(summary_obj, strict=strict_mode)
        report["gate"] = _build_doctor_gate(report, strict=strict_mode)
        if _console:
            _render_doctor_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return True
    if _looks_like_template_library_request(text):
        template_list()
        return True
    if _maybe_execute_quick_k8s_action(text, options, execute_mode=execute_mode):
        return True
    template_candidate, apply_requested = maybe_detect_quick_fix_intent(text)
    if template_candidate and (apply_requested or _looks_like_template_advice_request(text)):
        auto_vars = _compose_template_var_items(text, options)
        _run_remediation_template(
            template_name=template_candidate.name,
            var_items=auto_vars,
            apply=apply_requested,
            max_apply_steps=6,
            allow_high_risk=True,
            auto_approve_low_risk=True,
            execute=_resolve_execute_for_apply_request(
                execute_mode,
                label=f"自然语言模板修复 {template_candidate.name}",
                apply=apply_requested,
            ),
            approval_mode=str(options["approval_mode"]),
            audit_log=str(options["audit_log"]),
            model=str(options["model"]),
            provider=str(options["provider"]),
        )
        return True
    if _looks_like_report_request(text):
        fmt = "json" if "json" in lowered else "markdown"
        push_to_git = any(k in lowered for k in ("push", "git", "提交", "归档到仓库"))
        result = _export_incident_report(
            session_file=Path(str(options["session_file"])),
            target_profile_file=Path(settings.target_profile_file),
            include_doctor=True,
            include_memory=True,
            turn_limit=20,
            audit_log=Path(str(options["audit_log"])),
            fmt=fmt,
            output="",
            push_to_git=push_to_git,
            git_remote="origin",
            git_message="",
        )
        typer.echo(f"Report exported: {result['out_path']}")
        archived = str(result.get("archived_path", "")).strip()
        if archived:
            if bool(result.get("pushed", False)):
                typer.echo(f"Report archived & pushed: {archived}")
            else:
                typer.echo(f"Report archived (no changes to push): {archived}")
        return True
    if _looks_like_memory_request(text):
        store = _open_incident_memory_store()
        if not store:
            typer.echo("memory store is unavailable.")
            return True
        rows = store.search_similar(text, limit=5)
        if rows:
            _render_memory_cases(rows, title=f"Incident Memory Search: {text[:40]}")
        else:
            _render_memory_cases(store.list_recent(limit=8), title="Incident Memory (Recent)")
        return True
    return False


def _run_remediation_template(
    *,
    template_name: str,
    var_items: list[str],
    apply: bool,
    max_apply_steps: int,
    allow_high_risk: bool,
    auto_approve_low_risk: bool,
    execute: bool,
    approval_mode: str,
    audit_log: str,
    model: str,
    provider: str,
) -> None:
    template = get_remediation_template(template_name)
    if not template:
        candidate = match_template_for_text(template_name)
        if candidate:
            template = candidate
    if not template:
        typer.echo(f"template not found: {template_name}")
        return
    target = TargetEnvStore().load()
    defaults = {
        "namespace": str(target.k8s_namespace or "default"),
    }
    overrides = parse_remediation_var_items(var_items)
    overrides = {**defaults, **overrides}
    rendered = render_remediation_template(template=template, overrides=overrides)
    diagnose_commands = [str(x) for x in list(rendered.get("diagnose_commands", []))]
    apply_commands = [str(x) for x in list(rendered.get("apply_commands", []))]
    rollback_commands = [str(x) for x in list(rendered.get("rollback_commands", []))]
    payload = {
        "template": rendered.get("template", {}),
        "variables": rendered.get("variables", {}),
        "diagnose_commands": diagnose_commands,
        "apply_commands": apply_commands,
        "rollback_commands": rollback_commands,
    }
    if _console and Panel:
        _console.print(
            Panel(
                json.dumps(payload, ensure_ascii=False, indent=2),
                title=f"Template: {template.name}",
                border_style="magenta",
            )
        )
    else:
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))

    if not apply:
        typer.echo("仅预览模板。加 --apply 执行修复命令。")
        return

    plan = FixPlan(apply_commands=apply_commands, rollback_commands=rollback_commands)
    _write_json_file(
        Path(".data/lsre-fix-last.json"),
        build_plan_record(
            instruction=f"[template] {template.name}",
            plan=plan,
            final_text=json.dumps(payload, ensure_ascii=False),
            selected_apply_commands=apply_commands[:max_apply_steps],
            approval_mode=approval_mode,
        ),
    )
    exec_summary = _execute_fix_plan_steps(
        plan=plan,
        max_apply_steps=max_apply_steps,
        execute=execute,
        approval_mode=approval_mode,
        audit_log=audit_log,
        allow_high_risk=allow_high_risk,
        auto_approve_low_risk=auto_approve_low_risk,
        model=model,
        provider=provider,
    )
    _persist_successful_fix_case(
        instruction=f"[template] {template.name}",
        final_text=json.dumps(payload, ensure_ascii=False),
        plan=plan,
        plan_md_path=Path(".data/lsre-template-last.md"),
        exec_summary=exec_summary,
        apply=apply,
        execute=execute,
    )
    if plan.rollback_commands:
        typer.echo("\n可回滚命令：")
        for cmd in plan.rollback_commands:
            typer.echo(f"- {cmd}")


def _parse_chat_template_command(tail: str) -> dict[str, object]:
    tokens = shlex.split(tail or "")
    if not tokens:
        return {"action": "list"}

    action = tokens[0].lower()
    if action in {"list", "ls"}:
        return {"action": "list"}
    if action == "show":
        if len(tokens) < 2:
            raise ValueError("missing template name for show")
        return {"action": "show", "name": tokens[1]}
    if action == "run":
        if len(tokens) < 2:
            raise ValueError("missing template name for run")
        return _parse_chat_template_run(name=tokens[1], tail_tokens=tokens[2:])
    if action.startswith("-"):
        raise ValueError(f"unknown template action: {action}")
    return _parse_chat_template_run(name=tokens[0], tail_tokens=tokens[1:])


def _parse_chat_template_run(*, name: str, tail_tokens: list[str]) -> dict[str, object]:
    result: dict[str, object] = {
        "action": "run",
        "name": name,
        "apply": False,
        "max_apply_steps": 6,
        "allow_high_risk": False,
        "auto_approve_low_risk": False,
        "var_items": [],
    }
    vars_out: list[str] = []
    idx = 0
    while idx < len(tail_tokens):
        token = tail_tokens[idx]
        if token == "--apply":
            result["apply"] = True
            idx += 1
            continue
        if token == "--allow-high-risk":
            result["allow_high_risk"] = True
            idx += 1
            continue
        if token == "--auto-approve-low-risk":
            result["auto_approve_low_risk"] = True
            idx += 1
            continue
        if token in {"--max-apply-steps"} or token.startswith("--max-apply-steps="):
            value = token.split("=", 1)[1] if token.startswith("--max-apply-steps=") else ""
            if not value:
                idx += 1
                if idx >= len(tail_tokens):
                    raise ValueError("missing value for --max-apply-steps")
                value = tail_tokens[idx]
            try:
                result["max_apply_steps"] = max(1, min(int(value), 30))
            except Exception:
                raise ValueError("max-apply-steps must be integer") from None
            idx += 1
            continue
        if token == "--var":
            idx += 1
            if idx >= len(tail_tokens):
                raise ValueError("missing value for --var")
            vars_out.append(tail_tokens[idx])
            idx += 1
            continue
        if token.startswith("--var="):
            vars_out.append(token.split("=", 1)[1])
            idx += 1
            continue
        if "=" in token and (not token.startswith("--")):
            vars_out.append(token)
            idx += 1
            continue
        raise ValueError(f"unknown option for template run: {token}")
    result["var_items"] = vars_out
    return result


def _execute_fix_plan_steps(
    *,
    plan: FixPlan,
    max_apply_steps: int,
    execute: bool,
    approval_mode: str,
    audit_log: str,
    allow_high_risk: bool,
    auto_approve_low_risk: bool,
    model: str,
    provider: str,
    skip_confirm: bool = False,
) -> dict[str, int]:
    executor = SafeExecutor(
        dry_run=(not execute),
        approval_mode=approval_mode,
        approval_granted=True,  # step-level y/n confirmation already enforced below
        audit_logger=AuditLogger(Path(audit_log)),
    )
    selected = plan.apply_commands[:max_apply_steps]
    total = len(selected)
    skipped_high_risk = 0
    executed = 0
    succeeded = 0
    failed = 0
    for idx, command_text in enumerate(selected, 1):
        try:
            command = shlex.split(command_text)
        except ValueError as exc:
            typer.echo(f"[step {idx}/{total}] 无法解析命令，跳过: {command_text} ({exc})")
            continue
        if not command:
            continue
        decision = assess_command(command, approval_mode=approval_mode)
        report = build_risk_report(command, decision)
        impact_statement = _generate_impact_statement(
            command_text=command_text,
            report=report,
            model=model,
            provider=provider,
        )
        _render_step_risk(idx, total, command_text, report, impact_statement=impact_statement)
        risk_level = str(report.get("risk_level", "low")).strip().lower()
        allow_execute, need_confirm = evaluate_apply_guardrail(
            risk_level=risk_level,
            allow_high_risk=allow_high_risk,
            auto_approve_low_risk=auto_approve_low_risk,
        )
        if not execute:
            need_confirm = False
        if risk_level == "low":
            need_confirm = False
        if not allow_execute:
            skipped_high_risk += 1
            typer.echo(f"[step {idx}/{total}] 已跳过高风险步骤（如需执行请加 --allow-high-risk）")
            continue
        if (not skip_confirm) and need_confirm and (
            not typer.confirm(f"[step {idx}/{total}] 是否执行该步骤？", default=False)
        ):
            continue
        if not need_confirm:
            if execute:
                typer.echo(f"[step {idx}/{total}] low-risk 自动执行（无需确认）")
            else:
                typer.echo(f"[step {idx}/{total}] dry-run 预演自动执行（无需确认）")
        result_exec = asyncio.run(executor.run(command))
        executed += 1
        if result_exec.ok:
            succeeded += 1
        else:
            failed += 1
        _render_step_result(idx, total, result_exec)
        if (not result_exec.ok) and (not skip_confirm) and (
            not typer.confirm("步骤失败，是否继续后续步骤？", default=False)
        ):
            break
    if skipped_high_risk:
        typer.echo(f"共跳过 {skipped_high_risk} 个高风险步骤。")
    return {
        "executed": executed,
        "succeeded": succeeded,
        "failed": failed,
        "skipped_high_risk": skipped_high_risk,
    }


def _apply_last_fix_plan(
    *,
    max_apply_steps: int,
    execute: bool,
    approval_mode: str,
    audit_log: str,
    model: str,
    provider: str,
    allow_high_risk: bool = False,
    auto_approve_low_risk: bool = False,
) -> None:
    plan = _load_last_fix_plan()
    if not plan:
        return
    _render_fix_summary(plan, max_apply_steps=max_apply_steps)
    _execute_fix_plan_steps(
        plan=plan,
        max_apply_steps=max_apply_steps,
        execute=execute,
        approval_mode=approval_mode,
        audit_log=audit_log,
        allow_high_risk=allow_high_risk,
        auto_approve_low_risk=auto_approve_low_risk,
        model=model,
        provider=provider,
    )
    if plan.rollback_commands:
        typer.echo("\n可回滚命令：")
        for cmd in plan.rollback_commands:
            typer.echo(f"- {cmd}")


def _select_fix_plan_steps(plan: FixPlan, steps: str) -> FixPlan | None:
    normalized = str(steps or "").strip()
    if not normalized:
        return plan
    selected_indexes = _parse_step_selection(normalized, max_step=len(plan.apply_commands))
    if not selected_indexes:
        typer.echo("未解析到可执行步骤。示例：1,3-4")
        return None
    selected_cmds = [plan.apply_commands[idx - 1] for idx in sorted(selected_indexes)]
    if not selected_cmds:
        typer.echo("所选步骤没有可执行命令。")
        return None
    return FixPlan(apply_commands=selected_cmds, rollback_commands=plan.rollback_commands)


def _split_fix_plan_read_write_commands(plan: FixPlan, *, approval_mode: str) -> tuple[list[str], list[str]]:
    read_only: list[str] = []
    writes: list[str] = []
    for command_text in plan.apply_commands:
        token = str(command_text or "").strip()
        if not token:
            continue
        try:
            command = shlex.split(token)
        except ValueError:
            writes.append(token)
            continue
        if not command:
            continue
        decision = assess_command(command, approval_mode=approval_mode)
        if decision.risk_level == "low":
            read_only.append(token)
        else:
            writes.append(token)
    return read_only, writes


def _apply_last_fix_plan_read_then_write(
    *,
    steps: str,
    execute: bool,
    approval_mode: str,
    audit_log: str,
    model: str,
    provider: str,
    allow_high_risk: bool,
    auto_approve_low_risk: bool,
) -> None:
    plan = _load_last_fix_plan()
    if not plan:
        return
    selected_plan = _select_fix_plan_steps(plan, steps)
    if not selected_plan:
        return
    read_only_cmds, write_cmds = _split_fix_plan_read_write_commands(selected_plan, approval_mode=approval_mode)
    if not read_only_cmds and not write_cmds:
        typer.echo("最近修复计划没有可执行命令。")
        return

    if read_only_cmds:
        typer.echo("阶段 1/2：先执行只读步骤（实时取证）")
        _execute_fix_plan_steps(
            plan=FixPlan(apply_commands=read_only_cmds, rollback_commands=[]),
            max_apply_steps=len(read_only_cmds),
            execute=True,
            approval_mode=approval_mode,
            audit_log=audit_log,
            allow_high_risk=True,
            auto_approve_low_risk=True,
            model=model,
            provider=provider,
            skip_confirm=True,
        )
    else:
        typer.echo("阶段 1/2：没有只读步骤，跳过。")

    if not write_cmds:
        typer.echo("阶段 2/2：没有写操作步骤，流程完成。")
        return
    typer.echo("阶段 2/2：执行写操作步骤")
    _execute_fix_plan_steps(
        plan=FixPlan(apply_commands=write_cmds, rollback_commands=[]),
        max_apply_steps=len(write_cmds),
        execute=execute,
        approval_mode=approval_mode,
        audit_log=audit_log,
        allow_high_risk=allow_high_risk,
        auto_approve_low_risk=auto_approve_low_risk,
        model=model,
        provider=provider,
    )


def _build_step_explanation(
    *,
    step: int,
    command_text: str,
    approval_mode: str,
    model: str,
    provider: str,
) -> dict[str, str]:
    output = {
        "step": str(step),
        "command": command_text,
        "risk_level": "unknown",
        "risk_score": "-",
        "scope": "-",
        "reasoning": "命令解析失败，建议手工确认后执行。",
        "impact": "",
        "rollback": "-",
    }
    try:
        command = shlex.split(command_text)
    except ValueError:
        return output
    if not command:
        return output
    decision = assess_command(command, approval_mode=approval_mode)
    report = build_risk_report(command, decision)
    impact = _generate_impact_statement(
        command_text=command_text,
        report=report,
        model=model,
        provider=provider,
    )
    reasons = [str(x).strip() for x in decision.reasons if str(x).strip()]
    output["risk_level"] = str(report.get("risk_level", "unknown"))
    output["risk_score"] = str(report.get("risk_score", "-"))
    output["scope"] = str(report.get("impact_scope", "-"))
    output["reasoning"] = "；".join(reasons[:2]) if reasons else "建议先观察执行结果。"
    output["impact"] = impact
    output["rollback"] = str(report.get("rollback", "-"))
    return output


def _explain_last_fix_plan_steps(
    *,
    text: str,
    approval_mode: str,
    model: str,
    provider: str,
) -> None:
    plan = _load_last_fix_plan()
    if not plan:
        return
    steps = _extract_step_selection_from_text(text)
    if steps:
        selected_indexes = sorted(_parse_step_selection(steps, max_step=len(plan.apply_commands)))
        if not selected_indexes:
            typer.echo("未识别到要讲解的步骤。示例：解释第2步 / 解释步骤:1,3-4")
            return
    else:
        selected_indexes = list(range(1, min(len(plan.apply_commands), 3) + 1))

    explanations = [
        _build_step_explanation(
            step=idx,
            command_text=plan.apply_commands[idx - 1],
            approval_mode=approval_mode,
            model=model,
            provider=provider,
        )
        for idx in selected_indexes
    ]
    if _console and Panel:
        lines: list[str] = []
        for item in explanations:
            lines.extend(
                [
                    f"[step {item['step']}] {item['command']}",
                    f"原因: {item['reasoning']}",
                    f"风险: {item['risk_level']} (score={item['risk_score']}) / scope={item['scope']}",
                    f"影响: {item['impact'] or '-'}",
                    f"回滚: {item['rollback']}",
                    "",
                ]
            )
        _console.print(Panel("\n".join(lines).strip(), title="Plan Step Explain", border_style="cyan"))
        return
    for item in explanations:
        typer.echo(f"[step {item['step']}] {item['command']}")
        typer.echo(f"原因: {item['reasoning']}")
        typer.echo(f"风险: {item['risk_level']} (score={item['risk_score']}) / scope={item['scope']}")
        typer.echo(f"影响: {item['impact'] or '-'}")
        typer.echo(f"回滚: {item['rollback']}")
        typer.echo("")


def _undo_last_fix_plan(
    *,
    max_rollback_steps: int,
    execute: bool,
    approval_mode: str,
    audit_log: str,
    model: str,
    provider: str,
) -> None:
    plan = _load_last_fix_plan()
    if not plan:
        return
    if not plan.rollback_commands:
        typer.echo("最近修复计划未提供回滚命令。")
        return
    rollback_plan = FixPlan(
        apply_commands=plan.rollback_commands[:max_rollback_steps],
        rollback_commands=[],
    )
    typer.echo("准备执行回滚命令：")
    for cmd in rollback_plan.apply_commands:
        typer.echo(f"- {cmd}")
    _execute_fix_plan_steps(
        plan=rollback_plan,
        max_apply_steps=max_rollback_steps,
        execute=execute,
        approval_mode=approval_mode,
        audit_log=audit_log,
        allow_high_risk=True,
        auto_approve_low_risk=True,
        model=model,
        provider=provider,
    )


def _approve_last_fix_plan(
    *,
    steps: str,
    execute: bool,
    approval_mode: str,
    audit_log: str,
    allow_high_risk: bool,
    auto_approve_low_risk: bool,
    yes: bool,
    with_impact: bool,
    model: str,
    provider: str,
) -> None:
    plan = _load_last_fix_plan()
    if not plan:
        return
    queue = _build_approval_queue(
        plan=plan,
        approval_mode=approval_mode,
        with_impact=with_impact,
        model=model,
        provider=provider,
    )
    _render_approval_queue(queue)
    if (not steps.strip()) or (steps.strip().lower() in {"list", "show", "ls"}):
        typer.echo("仅查看审批队列。执行示例：lsre approve --steps 1,3-4 --execute")
        return
    selected_indexes = _parse_step_selection(steps, max_step=len(queue))
    if not selected_indexes:
        typer.echo("未解析到可执行步骤。示例：--steps 1,3-4")
        return
    selected_cmds = [plan.apply_commands[idx - 1] for idx in sorted(selected_indexes)]
    if not selected_cmds:
        typer.echo("所选步骤没有可执行命令。")
        return
    selected_plan = FixPlan(
        apply_commands=selected_cmds,
        rollback_commands=plan.rollback_commands,
    )
    typer.echo(f"准备执行步骤: {', '.join(str(x) for x in sorted(selected_indexes))}")
    _execute_fix_plan_steps(
        plan=selected_plan,
        max_apply_steps=len(selected_plan.apply_commands),
        execute=execute,
        approval_mode=approval_mode,
        audit_log=audit_log,
        allow_high_risk=allow_high_risk,
        auto_approve_low_risk=auto_approve_low_risk,
        model=model,
        provider=provider,
        skip_confirm=yes,
    )


def _load_last_fix_plan() -> FixPlan | None:
    path = Path(".data/lsre-fix-last.json")
    if not path.exists():
        typer.echo("未找到最近修复计划（.data/lsre-fix-last.json）。先说“修复 xxx”生成计划。")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        typer.echo("最近修复计划文件损坏，无法读取。")
        return None
    if not isinstance(payload, dict):
        typer.echo("最近修复计划格式无效。")
        return None
    plan_obj = payload.get("plan", {})
    if not isinstance(plan_obj, dict):
        typer.echo("最近修复计划缺少 plan 字段。")
        return None
    selected = payload.get("selected_apply_commands", [])
    if not isinstance(selected, list):
        selected = []
    apply_commands = [str(x).strip() for x in selected if str(x).strip()]
    if not apply_commands:
        apply_commands = [str(x).strip() for x in plan_obj.get("apply_commands", []) if str(x).strip()]
    rollback_commands = [str(x).strip() for x in plan_obj.get("rollback_commands", []) if str(x).strip()]
    plan = FixPlan(apply_commands=apply_commands, rollback_commands=rollback_commands)
    if not plan.apply_commands:
        typer.echo("最近修复计划没有可执行命令。")
        return None
    return plan


def _build_approval_queue(
    *,
    plan: FixPlan,
    approval_mode: str,
    with_impact: bool,
    model: str,
    provider: str,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for idx, command_text in enumerate(plan.apply_commands, 1):
        risk_level = "unknown"
        score = "-"
        scope = "-"
        impact = ""
        try:
            command = shlex.split(command_text)
            decision = assess_command(command, approval_mode=approval_mode)
            report = build_risk_report(command, decision)
            risk_level = str(report.get("risk_level", "unknown"))
            score = str(report.get("risk_score", "-"))
            scope = str(report.get("impact_scope", "-"))
            if with_impact:
                impact = _generate_impact_statement(
                    command_text=command_text,
                    report=report,
                    model=model,
                    provider=provider,
                )
        except Exception:
            pass
        rows.append(
            {
                "step": str(idx),
                "command": command_text,
                "risk_level": risk_level,
                "risk_score": score,
                "impact_scope": scope,
                "impact": impact,
            }
        )
    return rows


def _render_approval_queue(rows: list[dict[str, str]]) -> None:
    if _console and Table:
        table = Table(title="Approval Queue")
        table.add_column("Step", style="cyan", no_wrap=True)
        table.add_column("Risk", style="white", no_wrap=True)
        table.add_column("Score", style="magenta", no_wrap=True)
        table.add_column("Scope", style="yellow", no_wrap=True)
        table.add_column("Command", style="green")
        for item in rows:
            table.add_row(
                item.get("step", "-"),
                item.get("risk_level", "-"),
                item.get("risk_score", "-"),
                item.get("impact_scope", "-"),
                item.get("command", "")[:180],
            )
        _console.print(table)
        has_impact = any(str(x.get("impact", "")).strip() for x in rows)
        if has_impact:
            lines = []
            for item in rows:
                impact = str(item.get("impact", "")).strip()
                if not impact:
                    continue
                lines.append(f"[step {item.get('step','-')}] {impact}")
            if lines and Panel:
                _console.print(Panel("\n".join(lines), title="Impact Statements", border_style="yellow"))
        return
    typer.echo("Approval Queue:")
    for item in rows:
        typer.echo(
            f"- step={item.get('step','-')} risk={item.get('risk_level','-')} "
            f"score={item.get('risk_score','-')} scope={item.get('impact_scope','-')} "
            f"cmd={item.get('command','')}"
        )


def _parse_step_selection(raw: str, *, max_step: int) -> set[int]:
    selected: set[int] = set()
    text = raw.strip()
    if not text:
        return selected
    for token in [x.strip() for x in text.split(",") if x.strip()]:
        if "-" in token:
            left, right = token.split("-", 1)
            try:
                start = int(left.strip())
                end = int(right.strip())
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            for idx in range(start, end + 1):
                if 1 <= idx <= max_step:
                    selected.add(idx)
            continue
        try:
            idx = int(token)
        except ValueError:
            continue
        if 1 <= idx <= max_step:
            selected.add(idx)
    return selected


def _render_mode_hint(execute_mode: bool) -> None:
    mode = "execute" if execute_mode else "dry-run"
    detail = "真实执行" if execute_mode else "仅预演，不改线上"
    typer.echo(f"当前模式: {mode} ({detail})")


def _render_context_snapshot(options: dict[str, object], *, execute_mode: bool) -> None:
    session = SessionStore(Path(str(options["session_file"])))
    entities = session.entities()
    turns = session.recent_turns(limit=10)
    payload = {
        "mode": "execute" if execute_mode else "dry-run",
        "session_turns": len(turns),
        "entities": entities,
    }
    if not (_console and Table):
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    table = Table(title="LazySRE Context")
    table.add_column("Item", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Mode", payload["mode"])
    table.add_row("Session Turns", str(payload["session_turns"]))
    table.add_row("last_namespace", entities.get("last_namespace", "(none)"))
    table.add_row("last_service", entities.get("last_service", "(none)"))
    table.add_row("last_pod", entities.get("last_pod", "(none)"))
    _console.print(table)


def _resolve_execute_for_apply_request(execute_mode: bool, *, label: str, apply: bool) -> bool:
    if not apply:
        return execute_mode
    if execute_mode:
        return True
    if not _stdin_interactive():
        return False
    try:
        promote = typer.confirm(
            f"{label}: 当前是 dry-run，是否切换为 execute 真实执行？",
            default=False,
        )
    except (EOFError, KeyboardInterrupt):
        return False
    return bool(promote)


def _compose_template_var_items(
    text: str,
    options: dict[str, object],
    *,
    base_items: list[str] | None = None,
) -> list[str]:
    merged: dict[str, str] = {}
    if base_items:
        for raw in base_items:
            token = str(raw).strip()
            if (not token) or ("=" not in token):
                continue
            key, value = token.split("=", 1)
            k = key.strip()
            if not k:
                continue
            merged[k] = value.strip()
    extracted = _extract_template_var_items_from_text(text)
    for raw in extracted:
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        k = key.strip()
        if not k:
            continue
        if k not in merged:
            merged[k] = value.strip()

    entities = SessionStore(Path(str(options["session_file"]))).entities()
    if ("namespace" not in merged) and entities.get("last_namespace"):
        merged["namespace"] = entities["last_namespace"]
    if ("pod" not in merged) and entities.get("last_pod"):
        merged["pod"] = entities["last_pod"]
    if ("service" not in merged) and entities.get("last_service"):
        merged["service"] = entities["last_service"]
    if ("workload" not in merged) and merged.get("service"):
        merged["workload"] = f"deploy/{merged['service']}"

    preferred_order = [
        "namespace",
        "service",
        "workload",
        "pod",
        "container",
        "image",
        "replicas",
        "rollback_replicas",
    ]
    out: list[str] = []
    for key in preferred_order:
        if key in merged and str(merged[key]).strip():
            out.append(f"{key}={merged[key]}")
    for key, value in merged.items():
        if key in preferred_order:
            continue
        if str(value).strip():
            out.append(f"{key}={value}")
    return out


def _extract_target_updates_from_text(text: str) -> dict[str, object]:
    raw = str(text or "")
    lowered = raw.lower()
    updates: dict[str, object] = {}

    def _first(patterns: list[str]) -> str:
        for pattern in patterns:
            match = re.search(pattern, raw, flags=re.IGNORECASE)
            if match:
                return str(match.group(1)).strip()
        return ""

    prom_url = _first(
        [
            r"(?:prometheus(?:\s*url)?)[\s:=：]*(?:是|为|改成|设成|设置为|用)?\s*(https?://[^\s,，;；]+)",
        ]
    )
    if prom_url:
        updates["prometheus_url"] = prom_url.rstrip("/")

    k8s_api_url = _first(
        [
            r"(?:k8s|kubernetes)(?:\s*api)?[\s:=：]*(?:是|为|改成|设成|设置为|用)?\s*(https?://[^\s,，;；]+)",
            r"(?:api[\s_-]*server)[\s:=：]*(?:是|为|改成|设成|设置为|用)?\s*(https?://[^\s,，;；]+)",
        ]
    )
    if k8s_api_url:
        updates["k8s_api_url"] = k8s_api_url.rstrip("/")

    namespace = _first(
        [
            r"(?:namespace|命名空间)[\s:=：]*(?:是|为|改成|设成|设置为|用)?\s*([a-z0-9-]{1,63})",
        ]
    )
    if namespace:
        updates["k8s_namespace"] = namespace

    context = _first(
        [
            r"(?:k8s\s*context|context|集群上下文)[\s:=：]*(?:是|为|改成|设成|设置为|用)?\s*([^\s,，;；]+)",
        ]
    )
    if context:
        updates["k8s_context"] = context

    token = _first(
        [
            r"(?:k8s\s*token|bearer\s*token|token)[\s:=：]*(?:是|为|改成|设成|设置为|用)?\s*([A-Za-z0-9._\-]{12,})",
        ]
    )
    if token:
        updates["k8s_bearer_token"] = token

    disable_tls_keywords = (
        "skip tls",
        "skip-tls",
        "insecure",
        "不校验tls",
        "跳过tls",
        "关闭tls校验",
        "不验证证书",
        "skip verify",
    )
    enable_tls_keywords = (
        "verify tls",
        "开启tls校验",
        "启用tls校验",
        "校验证书",
        "开启证书校验",
    )
    if any(k in lowered for k in disable_tls_keywords):
        updates["k8s_verify_tls"] = False
    elif any(k in lowered for k in enable_tls_keywords):
        updates["k8s_verify_tls"] = True
    return updates


def _apply_target_updates_from_text(text: str) -> bool:
    updates = _extract_target_updates_from_text(text)
    if not updates:
        typer.echo("未识别到可更新的目标配置字段。示例：把 namespace 设成 prod")
        return False
    store = TargetEnvStore(Path(settings.target_profile_file))
    updated = store.update(**updates)
    safe = updated.to_safe_dict()
    changed = ", ".join(sorted(updates.keys()))
    typer.echo(f"目标环境已更新: {changed}")
    typer.echo(json.dumps(safe, ensure_ascii=False, indent=2))
    return True


def _normalize_profile_name(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]", "", str(value or "").strip())
    return token[:40]


def _extract_profile_switch_name(text: str) -> str:
    raw = str(text or "")
    patterns = [
        r"(?:切到|切换到|切换至|激活|使用)\s*([A-Za-z0-9._-]{1,40})(?:\s*(?:集群|profile))?",
        r"(?:use|switch\s+to|activate)\s+([A-Za-z0-9._-]{1,40})",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.IGNORECASE)
        if not match:
            continue
        name = _normalize_profile_name(match.group(1))
        if name:
            return name
    return ""


def _extract_profile_save_request(text: str) -> tuple[str, bool]:
    raw = str(text or "")
    lowered = raw.lower()
    patterns = [
        r"(?:保存(?:当前)?(?:\s*(?:profile|集群|配置))?(?:为|成)?\s*)([A-Za-z0-9._-]{1,40})",
        r"(?:save(?:\s+current)?(?:\s+profile)?(?:\s+as)?\s+)([A-Za-z0-9._-]{1,40})",
    ]
    name = ""
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.IGNORECASE)
        if not match:
            continue
        name = _normalize_profile_name(match.group(1))
        if name:
            break
    if not name:
        return "", False
    activate = any(
        keyword in lowered
        for keyword in [
            "并切换",
            "并激活",
            "并使用",
            "并启用",
            "and switch",
            "and activate",
        ]
    )
    return name, activate


def _tokenize_natural_text(text: str) -> list[str]:
    raw = str(text or "").strip()
    if not raw:
        return []
    try:
        return [x for x in shlex.split(raw) if str(x).strip()]
    except ValueError:
        return [x for x in raw.split() if str(x).strip()]


def _extract_json_path_from_text(text: str) -> str:
    tokens = _tokenize_natural_text(text)
    for token in tokens:
        cleaned = str(token).strip().strip(",，;；。\"'")
        if cleaned.lower().endswith(".json"):
            return cleaned
    fallback = re.search(r"([~./A-Za-z0-9_-]+\.json)", str(text or ""))
    if fallback:
        return str(fallback.group(1)).strip()
    return ""


def _looks_like_target_profile_remove_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    remove_words = ("删除", "移除", "remove", "delete")
    target_words = ("profile", "集群", "环境档案", "当前profile")
    return any(k in lowered for k in remove_words) and any(k in lowered for k in target_words)


def _extract_profile_remove_request(text: str) -> tuple[str, bool]:
    raw = str(text or "")
    lowered = raw.lower()
    patterns = [
        r"(?:删除|移除)\s*(?:profile|集群)\s*([A-Za-z0-9._-]{1,40})",
        r"(?:删除|移除)\s*([A-Za-z0-9._-]{1,40})\s*(?:profile|集群)?",
        r"(?:remove|delete)\s*(?:profile)?\s*([A-Za-z0-9._-]{1,40})",
    ]
    name = ""
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.IGNORECASE)
        if not match:
            continue
        candidate = _normalize_profile_name(match.group(1))
        if candidate and candidate not in {"profile", "cluster"}:
            name = candidate
            break
    confirmed = any(
        keyword in lowered
        for keyword in [
            "确认删除",
            "确定删除",
            "强制删除",
            "--yes",
            "confirm delete",
        ]
    )
    return name, confirmed


def _looks_like_target_profile_export_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    return ("导出" in lowered and ("profile" in lowered or "集群" in lowered or "json" in lowered)) or (
        "export" in lowered and ("profile" in lowered or "json" in lowered)
    )


def _extract_profile_export_request(text: str) -> dict[str, object]:
    raw = str(text or "")
    lowered = raw.lower()
    output = _extract_json_path_from_text(raw)
    names: list[str] = []

    for match in re.finditer(r"(?:导出|export)\s*([A-Za-z0-9._-]{1,40})\s*(?:profile|集群)", raw, flags=re.IGNORECASE):
        candidate = _normalize_profile_name(match.group(1))
        if candidate and candidate not in names:
            names.append(candidate)

    name_field = re.search(r"(?:profiles?|集群)\s*[:：]\s*([A-Za-z0-9._,\-\s]+)", raw, flags=re.IGNORECASE)
    if name_field:
        for token in re.split(r"[,，\s]+", str(name_field.group(1)).strip()):
            candidate = _normalize_profile_name(token)
            if candidate and candidate not in names:
                names.append(candidate)

    if any(k in lowered for k in ["全部", "all"]):
        names = []
    return {"output": output, "names": names}


def _looks_like_target_profile_import_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    return ("导入" in lowered and ("profile" in lowered or "集群" in lowered or "json" in lowered)) or (
        "import" in lowered and ("profile" in lowered or "json" in lowered)
    )


def _extract_profile_import_request(text: str) -> dict[str, object]:
    lowered = str(text or "").lower()
    input_file = _extract_json_path_from_text(text)
    merge = not any(k in lowered for k in ["replace", "覆盖", "替换全部", "全量替换"])
    activate = ""
    match = re.search(
        r"(?:激活|activate)\s*([@A-Za-z0-9._-]{1,40})",
        str(text or ""),
        flags=re.IGNORECASE,
    )
    if match:
        activate = str(match.group(1)).strip()
    elif any(k in lowered for k in ["并激活导入的active", "激活导入active", "activate imported active"]):
        activate = "@active"
    return {"input_file": input_file, "merge": merge, "activate": activate}


def _looks_like_target_profile_list_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "profile list",
        "list profile",
        "列出profile",
        "列出集群",
        "有哪些profile",
        "有哪些集群",
    )
    if any(k in lowered for k in keywords):
        return True
    return ("profile" in lowered and "列出" in lowered) or ("集群" in lowered and "列出" in lowered)


def _looks_like_target_profile_current_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    if _extract_profile_switch_name(text):
        return False
    if _extract_profile_save_request(text)[0]:
        return False
    return any(
        keyword in lowered
        for keyword in [
            "当前profile",
            "current profile",
            "active profile",
            "当前集群",
            "当前激活",
            "当前环境档案",
        ]
    )


def _maybe_handle_target_profile_natural_intent(text: str) -> bool:
    if _looks_like_target_profile_export_request(text):
        req = _extract_profile_export_request(text)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        out_path = Path(str(req.get("output", "")).strip() or f".data/lsre-target-profiles-export-{stamp}.json")
        names = [str(x).strip() for x in list(req.get("names", [])) if str(x).strip()]
        store = ClusterProfileStore(Path(settings.target_profiles_file))
        payload = store.export_payload(names=names)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        count = len(payload.get("profiles", {})) if isinstance(payload.get("profiles", {}), dict) else 0
        typer.echo(f"已导出 {count} 个 profile -> {out_path}")
        return True

    if _looks_like_target_profile_import_request(text):
        req = _extract_profile_import_request(text)
        input_file = str(req.get("input_file", "")).strip()
        if not input_file:
            typer.echo("请提供导入 JSON 文件路径。示例：从 .data/profiles.json 导入 profile")
            return True
        in_path = Path(input_file).expanduser()
        if not in_path.exists():
            typer.echo(f"import file not found: {in_path}")
            return True
        try:
            raw = json.loads(in_path.read_text(encoding="utf-8"))
        except Exception:
            typer.echo(f"import file is not valid json: {in_path}")
            return True
        if not isinstance(raw, dict):
            typer.echo("import payload must be a JSON object")
            return True
        store = ClusterProfileStore(Path(settings.target_profiles_file))
        try:
            result = store.import_payload(raw, merge=bool(req.get("merge", True)))
        except ValueError as exc:
            typer.echo(str(exc))
            return True
        activate_value = str(req.get("activate", "")).strip()
        activated = ""
        if activate_value:
            activated = str(result.get("active", "")).strip() if activate_value == "@active" else activate_value
            if not activated:
                typer.echo("import payload has no active profile to activate")
                return True
            ok = store.activate(activated, target_profile_file=Path(settings.target_profile_file))
            if not ok:
                typer.echo(f"profile not found after import: {activated}")
                return True
        typer.echo(
            "Imported profiles: "
            f"imported={result.get('imported', 0)} "
            f"created={result.get('created', 0)} "
            f"updated={result.get('updated', 0)} "
            f"total={result.get('total', 0)}"
        )
        if activated:
            typer.echo(f"Activated profile: {activated}")
        return True

    if _looks_like_target_profile_remove_request(text):
        name, confirmed = _extract_profile_remove_request(text)
        store = ClusterProfileStore(Path(settings.target_profiles_file))
        if (not name) and ("当前profile" in str(text or "").lower() or "当前集群" in str(text or "")):
            name = store.get_active()
        if not name:
            typer.echo("请指定要删除的 profile 名称。示例：删除 profile prod")
            return True
        if not confirmed:
            if not _stdin_interactive():
                typer.echo(f"删除 profile {name} 需要确认。请使用“确认删除 {name}”重试。")
                return True
            if not typer.confirm(f"确认删除 profile {name} 吗？", default=False):
                typer.echo("Canceled.")
                return True
        removed = store.remove_profile(name)
        if not removed:
            typer.echo(f"profile not found: {name}")
            return True
        typer.echo(f"Removed profile: {name}")
        return True

    save_name, activate = _extract_profile_save_request(text)
    if save_name:
        env = TargetEnvStore(Path(settings.target_profile_file)).load()
        store = ClusterProfileStore(Path(settings.target_profiles_file))
        store.upsert_profile(save_name, env, activate=activate)
        typer.echo(f"已保存 profile: {save_name} (activate={activate})")
        if activate:
            typer.echo(f"已切换到 profile: {save_name}")
        return True

    switch_name = _extract_profile_switch_name(text)
    if switch_name:
        store = ClusterProfileStore(Path(settings.target_profiles_file))
        ok = store.activate(switch_name, target_profile_file=Path(settings.target_profile_file))
        if not ok:
            names = store.list_profiles()
            suffix = f" 可选: {', '.join(names[:8])}" if names else " 当前还没有已保存 profile。"
            typer.echo(f"profile 不存在: {switch_name}.{suffix}")
            return True
        typer.echo(f"已切换到 profile: {switch_name}")
        return True

    if _looks_like_target_profile_current_request(text):
        store = ClusterProfileStore(Path(settings.target_profiles_file))
        active = store.get_active()
        payload: dict[str, object] = {
            "active": active or "",
            "profiles_file": str(settings.target_profiles_file),
        }
        if active:
            env = store.get_profile(active)
            if env:
                payload["target"] = env.to_safe_dict()
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return True

    if _looks_like_target_profile_list_request(text):
        store = ClusterProfileStore(Path(settings.target_profiles_file))
        payload = {
            "active": store.get_active(),
            "profiles": store.list_profiles(),
            "profiles_file": str(settings.target_profiles_file),
        }
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return True
    return False


def _build_quick_k8s_action_plan(text: str, options: dict[str, object]) -> dict[str, object] | None:
    lowered = str(text or "").lower().strip()
    if not lowered:
        return None
    var_items = _compose_template_var_items(text, options)
    vars_map = parse_remediation_var_items(var_items)
    namespace = str(vars_map.get("namespace", "default")).strip() or "default"
    service = str(vars_map.get("service", "")).strip()
    workload = str(vars_map.get("workload", "")).strip()
    pod = str(vars_map.get("pod", "")).strip()
    replicas = _extract_requested_replicas(text)

    if _looks_like_logs_action_request(text):
        commands: list[str] = []
        if pod:
            commands.append(f"kubectl -n {namespace} logs {pod} --tail=200")
        elif service:
            commands.append(f"kubectl -n {namespace} logs -l app={service} --tail=200")
        elif workload.startswith("deploy/"):
            commands.append(f"kubectl -n {namespace} logs -l app={workload.split('/', 1)[1]} --tail=200")
        else:
            return None
        return {
            "label": "快速日志查询",
            "commands": commands,
            "read_only": True,
        }

    if _looks_like_restart_action_request(text):
        commands = []
        resolved_workload = workload
        if (not resolved_workload) and service:
            resolved_workload = f"deploy/{service}"
        if resolved_workload:
            commands.append(f"kubectl -n {namespace} rollout restart {resolved_workload}")
            if resolved_workload.startswith("deploy/"):
                commands.append(f"kubectl -n {namespace} rollout status {resolved_workload} --timeout=180s")
        elif pod:
            commands.append(f"kubectl -n {namespace} delete pod {pod}")
        else:
            return None
        return {
            "label": "快速重启",
            "commands": commands,
            "read_only": False,
        }

    if _looks_like_scale_action_request(text):
        if replicas <= 0:
            return {"label": "快速扩缩容", "commands": [], "read_only": False, "error": "未识别到目标副本数"}
        resolved_workload = workload or (f"deploy/{service}" if service else "")
        if not resolved_workload:
            return None
        commands = [f"kubectl -n {namespace} scale {resolved_workload} --replicas={replicas}"]
        if resolved_workload.startswith("deploy/"):
            commands.append(f"kubectl -n {namespace} rollout status {resolved_workload} --timeout=180s")
        return {
            "label": "快速扩缩容",
            "commands": commands,
            "read_only": False,
        }
    return None


def _maybe_execute_quick_k8s_action(text: str, options: dict[str, object], *, execute_mode: bool) -> bool:
    plan = _build_quick_k8s_action_plan(text, options)
    if not plan:
        return False
    label = str(plan.get("label", "快速动作"))
    error = str(plan.get("error", "")).strip()
    commands = [str(x).strip() for x in list(plan.get("commands", [])) if str(x).strip()]
    if error:
        typer.echo(f"{label}: {error}")
        return True
    if not commands:
        return False
    read_only = bool(plan.get("read_only"))
    execute = bool(execute_mode or read_only)
    if read_only and (not execute_mode):
        typer.echo(f"{label}: 检测到只读动作，dry-run 下已临时执行真实查询。")
    else:
        execute = _resolve_execute_for_apply_request(
            execute_mode,
            label=label,
            apply=True,
        )
    step_plan = FixPlan(apply_commands=commands, rollback_commands=[])
    _execute_fix_plan_steps(
        plan=step_plan,
        max_apply_steps=len(commands),
        execute=execute,
        approval_mode=str(options["approval_mode"]),
        audit_log=str(options["audit_log"]),
        allow_high_risk=True,
        auto_approve_low_risk=True,
        model=str(options["model"]),
        provider=str(options["provider"]),
    )
    return True


def _extract_requested_replicas(text: str) -> int:
    lowered = str(text or "").lower()
    patterns = [
        r"(?:扩容到|缩容到|副本数?|replicas?\s*(?:to|=|:))\s*(\d+)",
        r"(?:scale\s+to)\s*(\d+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, lowered)
        if not match:
            continue
        try:
            value = int(match.group(1))
        except Exception:
            continue
        if value > 0:
            return value
    return 0


def _extract_template_var_items_from_text(text: str) -> list[str]:
    raw = str(text or "")
    lowered = raw.lower()
    found: dict[str, str] = {}

    def set_if(key: str, value: str) -> None:
        v = str(value or "").strip()
        if v:
            found[key] = v

    key_patterns = [
        "namespace",
        "pod",
        "workload",
        "service",
        "container",
        "image",
        "replicas",
        "rollback_replicas",
    ]
    for key in key_patterns:
        for match in re.finditer(
            rf"\b{re.escape(key)}\s*[:=]\s*([^\s,;，。]+)",
            lowered,
            flags=re.IGNORECASE,
        ):
            set_if(key, match.group(1))
        for match in re.finditer(
            rf"\b{re.escape(key)}\s+([a-z0-9][a-z0-9._/-]*)\b",
            lowered,
            flags=re.IGNORECASE,
        ):
            candidate = str(match.group(1)).strip().lower()
            if candidate in {"is", "to", "for", "the", "and", "or", "in", "of"}:
                continue
            if re.fullmatch(r"p\d{2,3}(?:ms)?", candidate):
                continue
            set_if(key, candidate)

    ns_short = re.search(r"(?:^|\s)-n\s+([a-z0-9-]+)\b", lowered)
    if ns_short:
        set_if("namespace", ns_short.group(1))
    ns_long = re.search(r"--namespace\s+([a-z0-9-]+)\b", lowered)
    if ns_long:
        set_if("namespace", ns_long.group(1))
    ns_cn = re.search(r"命名空间\s*[:：]?\s*([a-z0-9-]+)\b", lowered)
    if ns_cn:
        set_if("namespace", ns_cn.group(1))
    ns_alias = re.search(r"\bns\s*[:=]?\s*([a-z0-9-]+)\b", lowered)
    if ns_alias:
        set_if("namespace", ns_alias.group(1))

    workload_slash = re.search(r"\b(deploy/[a-z0-9-]+)\b", lowered)
    if workload_slash:
        set_if("workload", workload_slash.group(1))
    deployment_name = re.search(r"\bdeployment\s+([a-z0-9-]+)\b", lowered)
    if deployment_name and ("workload" not in found):
        set_if("workload", f"deploy/{deployment_name.group(1)}")

    service_cn = re.search(r"服务\s*[:：]?\s*([a-z0-9-]+)\b", lowered)
    if service_cn and ("service" not in found):
        candidate = str(service_cn.group(1)).strip().lower()
        if not re.fullmatch(r"p\d{2,3}(?:ms)?", candidate):
            set_if("service", candidate)
    svc_alias = re.search(r"\bsvc\s*[:=]?\s*([a-z0-9-]+)\b", lowered)
    if svc_alias and ("service" not in found):
        set_if("service", svc_alias.group(1))
    pod_cn = re.search(r"pod\s*[:：]?\s*([a-z0-9][-a-z0-9.]*)", lowered)
    if pod_cn and ("pod" not in found):
        set_if("pod", pod_cn.group(1))

    replicas_cn = re.search(r"副本\s*[:：]?\s*(\d+)\b", lowered)
    if replicas_cn and ("replicas" not in found):
        set_if("replicas", replicas_cn.group(1))
    rollback_cn = re.search(r"回滚副本\s*[:：]?\s*(\d+)\b", lowered)
    if rollback_cn and ("rollback_replicas" not in found):
        set_if("rollback_replicas", rollback_cn.group(1))

    preferred_order = [
        "namespace",
        "service",
        "workload",
        "pod",
        "container",
        "image",
        "replicas",
        "rollback_replicas",
    ]
    out: list[str] = []
    for key in preferred_order:
        if key in found:
            out.append(f"{key}={found[key]}")
    return out


def _looks_like_help_request(text: str) -> bool:
    lowered = text.lower().strip()
    if lowered in {"/help", "/h", "help"}:
        return True
    keywords = (
        "你会什么",
        "怎么用",
        "帮助",
        "help me",
    )
    return any(k in lowered for k in keywords)


def _looks_like_switch_execute_request(text: str) -> bool:
    lowered = text.lower().strip()
    keywords = (
        "切换到执行模式",
        "进入执行模式",
        "开始真实执行",
        "switch to execute",
        "enable execute",
    )
    return any(k in lowered for k in keywords)


def _looks_like_switch_dry_run_request(text: str) -> bool:
    lowered = text.lower().strip()
    keywords = (
        "切换到预演模式",
        "切回dry-run",
        "只预演",
        "不要真实执行",
        "switch to dry-run",
        "disable execute",
    )
    return any(k in lowered for k in keywords)


def _looks_like_reset_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "重置",
        "重置引导",
        "重新开始",
        "reset",
    )
    return any(k in lowered for k in keywords)


def _looks_like_context_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "你记住了什么",
        "上下文",
        "当前上下文",
        "context",
        "最近对象",
    )
    return any(k in lowered for k in keywords)


def _looks_like_target_show_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    if _looks_like_target_update_request(text):
        return False
    keywords = (
        "目标配置",
        "目标环境",
        "target show",
        "查看target",
        "查看目标",
        "当前target",
    )
    return any(k in lowered for k in keywords)


def _looks_like_target_update_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    updates = _extract_target_updates_from_text(text)
    if updates:
        return True
    field_keywords = (
        "prometheus",
        "k8s api",
        "kubernetes api",
        "namespace",
        "命名空间",
        "context",
        "token",
        "tls",
        "证书",
    )
    action_keywords = (
        "设置",
        "设成",
        "改成",
        "改为",
        "配置",
        "更新",
        "set",
        "update",
        "use",
    )
    return any(k in lowered for k in field_keywords) and any(k in lowered for k in action_keywords)


def _looks_like_logs_action_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    if re.search(r"(看|查|查看).{0,4}日志", lowered):
        return True
    keywords = (
        "看日志",
        "查日志",
        "查看日志",
        "logs",
    )
    return any(k in lowered for k in keywords)


def _looks_like_restart_action_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "重启",
        "restart",
        "rollout restart",
    )
    return any(k in lowered for k in keywords)


def _looks_like_scale_action_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "扩容",
        "缩容",
        "scale",
        "副本",
        "replicas",
    )
    return any(k in lowered for k in keywords)


def _looks_like_status_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "查看状态",
        "看看状态",
        "当前状态",
        "系统状态",
        "运行状态",
        "状态总览",
        "show status",
        "runtime status",
    )
    return any(k in lowered for k in keywords)


def _looks_like_scan_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "扫描环境",
        "自动扫描",
        "自动检测环境",
        "检测当前环境",
        "看看当前环境",
        "发现当前环境",
        "列出当前环境问题",
        "scan environment",
        "env scan",
        "environment scan",
    )
    return any(k in lowered for k in keywords)


def _looks_like_swarm_diagnose_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "swarm",
        "docker service",
        "service ls",
        "service ps",
        "服务副本",
        "副本异常",
        "服务有没有异常",
        "服务有异常",
        "服务健康",
        "服务器上的服务",
        "看异常服务",
        "检查服务",
    )
    return any(k in lowered for k in keywords)


def _looks_like_watch_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "持续巡检",
        "开始巡检",
        "巡检一下",
        "定时检查",
        "持续观察",
        "watch",
        "monitor",
    )
    return any(k in lowered for k in keywords)


def _looks_like_actions_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "下一步做什么",
        "接下来做什么",
        "下一步怎么办",
        "下一步建议",
        "行动清单",
        "推荐动作",
        "推荐操作",
        "建议动作",
        "建议操作",
        "可执行动作",
        "action inbox",
        "next action",
        "next steps",
        "what next",
    )
    return any(k in lowered for k in keywords)


def _looks_like_action_run_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    action_words = (
        "建议",
        "动作",
        "行动",
        "推荐",
        "action",
    )
    run_words = (
        "执行",
        "运行",
        "处理",
        "run",
        "apply",
    )
    return any(k in lowered for k in action_words) and any(k in lowered for k in run_words) and _extract_action_id_from_text(text) > 0


def _extract_action_id_from_text(text: str) -> int:
    raw = str(text or "").strip()
    if not raw:
        return 0
    patterns = [
        r"(?:执行|运行|处理|应用)\s*(?:第)?\s*(\d+)\s*(?:个)?\s*(?:建议|动作|行动|推荐)",
        r"(?:建议|动作|行动|推荐)\s*(?:第)?\s*(\d+)",
        r"(?:run|apply)\s+(?:action\s+)?(\d+)",
        r"action\s+(\d+)",
        r"^(\d+)$",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.IGNORECASE)
        if match:
            return _safe_int(match.group(1))
    return 0


def _looks_like_autopilot_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "自动驾驶",
        "自动排查",
        "全自动排查",
        "全自动巡检",
        "自动巡检并",
        "从巡检到修复",
        "自己看着办",
        "帮我看着办",
        "一键排查",
        "一键诊断",
        "一键巡检",
        "autopilot",
        "auto pilot",
        "auto-diagnose",
    )
    return any(k in lowered for k in keywords)


def _extract_swarm_service_name(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    named = _extract_named_field(raw, ["service", "服务"])
    if named:
        return named.split()[0].strip()
    patterns = [
        r"(?:service|服务)\s*[=:：]\s*([A-Za-z0-9_.:/-]+)",
        r"(?:为什么|检查|查看|看|分析)\s+([A-Za-z0-9_.:/-]+)\s+(?:服务|service)",
        r"(?:service|服务)\s+([A-Za-z0-9_.:/-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    tokens = [
        token.strip()
        for token in re.split(r"\s+", raw)
        if token.strip() and not token.startswith("--")
    ]
    stop = {"swarm", "logs", "log", "日志", "检查", "查看", "看", "服务", "service"}
    for token in tokens:
        normalized = token.lower()
        if normalized in stop:
            continue
        if re.match(r"^[A-Za-z0-9_.:/-]{3,}$", token):
            return token
    return ""


def _looks_like_quickstart_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "修复环境",
        "一键修复环境",
        "一键初始化",
        "quickstart",
        "快速就绪",
        "一键就绪",
    )
    return any(k in lowered for k in keywords)


def _looks_like_install_doctor_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "安装检查",
        "安装体检",
        "node环境检查",
        "npm环境检查",
        "install doctor",
        "check install",
    )
    return any(k in lowered for k in keywords)


def _looks_like_doctor_request(text: str) -> bool:
    if _looks_like_install_doctor_request(text):
        return False
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "环境体检",
        "环境检查",
        "健康检查",
        "运行体检",
        "自检",
        "doctor",
    )
    return any(k in lowered for k in keywords)


def _looks_like_report_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "复盘报告",
        "导出报告",
        "生成报告",
        "incident report",
        "export report",
    )
    return any(k in lowered for k in keywords)


def _looks_like_memory_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "历史案例",
        "相似案例",
        "故障记忆",
        "memory case",
    )
    return any(k in lowered for k in keywords)


def _looks_like_template_library_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "模板库",
        "修复模板",
        "有哪些模板",
        "template list",
    )
    return any(k in lowered for k in keywords)


def _looks_like_template_advice_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "怎么办",
        "怎么处理",
        "如何处理",
        "怎么修",
        "how to fix",
    )
    return any(k in lowered for k in keywords)


def _looks_like_fix_request(text: str) -> bool:
    lowered = text.lower()
    if _looks_like_apply_request(text):
        return False
    return any(
        keyword in lowered
        for keyword in [
            "fix",
            "repair",
            "recover",
            "mitigate",
            "修复",
            "恢复",
            "缓解",
            "处理故障",
        ]
    )


def _looks_like_apply_request(text: str) -> bool:
    lowered = text.lower().strip()
    if any(
        keyword in lowered
        for keyword in [
            "执行修复计划",
            "应用修复计划",
            "执行刚才修复",
            "执行计划",
            "apply plan",
            "apply fix",
        ]
    ):
        return True
    return bool(re.search(r"(执行|应用|运行).{0,8}(第\s*\d+\s*步|步骤)", lowered))


def _looks_like_approval_queue_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    if _looks_like_apply_request(text):
        return False
    return any(
        keyword in lowered
        for keyword in [
            "审批队列",
            "审批列表",
            "查看审批",
            "看审批",
            "看看审批",
            "查看计划步骤",
            "计划步骤",
            "approve list",
            "approval queue",
        ]
    )


def _looks_like_with_impact_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    return any(
        keyword in lowered
        for keyword in [
            "影响评估",
            "影响说明",
            "风险说明",
            "impact",
        ]
    )


def _looks_like_low_risk_apply_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    return any(
        keyword in lowered
        for keyword in [
            "低风险",
            "仅低风险",
            "只执行低风险",
            "不要高风险",
            "skip high risk",
            "low risk only",
        ]
    )


def _looks_like_force_high_risk_apply_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    return any(
        keyword in lowered
        for keyword in [
            "允许高风险",
            "高风险也执行",
            "包含高风险",
            "all risk",
            "include high risk",
        ]
    )


def _looks_like_read_then_write_strategy_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    return any(
        keyword in lowered
        for keyword in [
            "先只跑只读",
            "先执行只读",
            "先只读后写",
            "先看后改",
            "read-only first",
            "read only first",
            "observe then apply",
        ]
    )


def _looks_like_explain_step_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    return any(
        keyword in lowered
        for keyword in [
            "解释第",
            "讲解第",
            "为什么执行第",
            "解释步骤",
            "讲解步骤",
            "explain step",
            "explain plan",
        ]
    )


def _extract_step_selection_from_text(text: str) -> str:
    lowered = text.lower().strip()
    if not lowered:
        return ""
    items: list[str] = []
    seen: set[str] = set()

    def _push(token: str) -> None:
        normalized = re.sub(r"\s+", "", token)
        normalized = normalized.replace("到", "-").replace("至", "-").replace("~", "-")
        if (not normalized) or (normalized in seen):
            return
        seen.add(normalized)
        items.append(normalized)

    for value in re.findall(r"(?:步骤|steps?)\s*[:：]\s*([0-9,\-\s到至~]+)", lowered):
        for token in re.findall(r"\d+\s*(?:[-~到至]\s*\d+)?", value):
            _push(token)

    for start, end in re.findall(r"(\d+)\s*[-~到至]\s*(\d+)", lowered):
        _push(f"{start}-{end}")

    for value in re.findall(r"第\s*(\d+)\s*步", lowered):
        _push(value)

    if not items:
        return ""
    return ",".join(items)


def _extract_apply_step_selection(text: str) -> str:
    lowered = text.lower().strip()
    if (not lowered) or (not _looks_like_apply_request(text)):
        return ""
    return _extract_step_selection_from_text(text)


def _looks_like_undo_request(text: str) -> bool:
    lowered = text.lower().strip()
    return any(
        keyword in lowered
        for keyword in [
            "回滚",
            "撤销修复",
            "撤回修复",
            "undo",
            "rollback",
            "revert fix",
        ]
    )


def _looks_like_auto_fix_request(text: str) -> bool:
    lowered = text.lower().strip()
    return any(
        keyword in lowered
        for keyword in [
            "自动修复",
            "直接修复",
            "帮我修好",
            "auto fix",
            "fix it now",
        ]
    )


def _looks_like_init_request(text: str) -> bool:
    lowered = text.lower().strip()
    return any(
        keyword in lowered
        for keyword in [
            "初始化",
            "init lazysre",
            "配置api key",
            "配置 openai key",
            "登录openai",
            "setup lazysre",
        ]
    )


def _build_memory_context(instruction: str) -> str:
    try:
        store = _open_incident_memory_store()
        if not store:
            return ""
        return format_memory_context(store.search_similar(instruction, limit=3))
    except Exception:
        return ""


def _build_latest_watch_context(instruction: str, *, path: Path | None = None, max_chars: int = 3200) -> str:
    if not _looks_like_latest_watch_reference(instruction):
        return ""
    snapshot = _load_latest_watch_snapshot(path)
    if not snapshot:
        return ""
    alerts = snapshot.get("alerts", [])
    swarm = snapshot.get("swarm", {})
    lines = [
        f"Latest watch snapshot at {snapshot.get('generated_at_utc', '(unknown time)')}",
        f"cycle={snapshot.get('cycle', '-')}, ok={snapshot.get('ok', False)}",
        "Alerts:",
    ]
    if isinstance(alerts, list) and alerts:
        for alert in alerts[:12]:
            if isinstance(alert, dict):
                lines.append(
                    f"- source={alert.get('source', '-')} severity={alert.get('severity', '-')} "
                    f"name={alert.get('name', '-')} detail={str(alert.get('detail', ''))[:220]} "
                    f"hint={str(alert.get('hint', ''))[:180]}"
                )
    else:
        lines.append("- none")
    if isinstance(swarm, dict):
        root_causes = swarm.get("root_causes", [])
        if isinstance(root_causes, list) and root_causes:
            lines.append("Swarm root causes:")
            for item in root_causes[:8]:
                if isinstance(item, dict):
                    lines.append(
                        f"- category={item.get('category', '-')} service={item.get('service', '-')} "
                        f"severity={item.get('severity', '-')} advice={str(item.get('advice', ''))[:220]}"
                    )
        recommendations = swarm.get("recommendations", [])
        if isinstance(recommendations, list) and recommendations:
            lines.append("Recommendations:")
            for item in recommendations[:6]:
                lines.append(f"- {str(item)[:220]}")
    return "\n".join(lines)[:max_chars]


def _looks_like_latest_watch_reference(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(
        key in lowered
        for key in (
            "巡检",
            "watch",
            "最新异常",
            "最新告警",
            "刚才的异常",
            "刚才告警",
            "修复异常",
            "处理异常",
        )
    )


def _persist_successful_fix_case(
    *,
    instruction: str,
    final_text: str,
    plan: FixPlan,
    plan_md_path: Path,
    exec_summary: dict[str, int],
    apply: bool,
    execute: bool,
) -> None:
    if not apply:
        return
    if not execute:
        return
    if int(exec_summary.get("executed", 0)) <= 0:
        return
    if int(exec_summary.get("failed", 0)) > 0:
        return
    root_cause = _extract_markdown_section(final_text, "Root Cause")
    if not root_cause:
        root_cause = "unknown"
    try:
        store = _open_incident_memory_store()
        if not store:
            typer.echo("长期记忆不可用（已忽略）")
            return
        store.add_case(
            symptom=instruction,
            root_cause=root_cause,
            fix_commands=plan.apply_commands,
            rollback_commands=plan.rollback_commands,
            metadata={
                "source": "lsre-fix",
                "plan_md": str(plan_md_path),
                "executed_steps": int(exec_summary.get("executed", 0)),
            },
        )
        typer.echo(f"已写入长期记忆库：{store.path}")
    except Exception as exc:
        typer.echo(f"长期记忆写入失败（已忽略）: {exc}")


def _extract_markdown_section(text: str, section_name: str) -> str:
    import re

    pattern = re.compile(
        rf"(?ims)^##\s*{re.escape(section_name)}\s*$\n(?P<body>.*?)(?=^##\s+|\Z)"
    )
    match = pattern.search(text or "")
    if not match:
        return ""
    body = match.group("body").strip()
    lines = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("```"):
            continue
        lines.append(line)
    return " ".join(lines)[:320]


def _generate_impact_statement(
    *,
    command_text: str,
    report: dict[str, object],
    model: str,
    provider: str,
) -> str:
    prompt = (
        "Generate one concise impact statement for an SRE change in Chinese.\n"
        f"Command: {command_text}\n"
        f"Risk: {json.dumps(report, ensure_ascii=False)}\n"
        "Output one sentence only."
    )
    mode = (provider or "auto").strip().lower()
    if mode not in {"auto", *PROVIDER_SPECS.keys()}:
        # deterministic fallback for local/mock mode
        scope = str(report.get("impact_scope", "service"))
        radius = str(report.get("blast_radius", "single target"))
        return f"该操作将影响 {scope}，潜在影响范围为 {radius}，请确认业务窗口与回滚条件。"
    try:
        _, resolved_model, llm = _build_cli_llm(provider=mode, model=model)
        turn = asyncio.run(
            llm.respond(
                model=resolved_model,
                tools=[],
                system_prompt="You are an SRE risk analyst.",
                user_input=prompt,
                text_stream=None,
            )
        )
        statement = (turn.text or "").strip()
        if statement:
            return statement.splitlines()[0][:220]
    except Exception:
        pass
    scope = str(report.get("impact_scope", "service"))
    radius = str(report.get("blast_radius", "single target"))
    return f"该操作将影响 {scope}，潜在影响范围为 {radius}，请确认业务窗口与回滚条件。"


def _write_text_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json_file(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _resolve_session_file(ctx: typer.Context, session_file: str | None) -> Path:
    if session_file and session_file.strip():
        return Path(session_file)
    obj = dict(ctx.obj or {})
    candidate = str(obj.get("session_file", ".data/lsre-session.json")).strip()
    return Path(candidate or ".data/lsre-session.json")


def main() -> None:
    _rewrite_argv_for_default_run(sys.argv)
    app()


def _rewrite_argv_for_default_run(argv: list[str]) -> None:
    if len(argv) <= 1:
        return
    commands = {
        "run",
        "chat",
        "login",
        "logout",
        "init",
        "quickstart",
        "reset",
        "undo",
        "fix",
        "approve",
        "status",
        "scan",
        "swarm",
        "watch",
        "actions",
        "autopilot",
        "doctor",
        "install-doctor",
        "setup",
        "report",
        "template",
        "runbook",
        "pack",
        "target",
        "history",
        "memory",
        "--help",
        "-h",
    }
    options_with_value = {
        "--approval-mode",
        "--audit-log",
        "--lock-file",
        "--session-file",
        "--deny-tool",
        "--deny-prefix",
        "--tool-pack",
        "--remote-gateway",
        "--model",
        "--provider",
        "--max-steps",
    }

    idx = 1
    while idx < len(argv):
        token = argv[idx]
        if token in commands:
            return
        if token.startswith("-"):
            if token in options_with_value and idx + 1 < len(argv):
                idx += 2
                continue
            idx += 1
            continue
        argv.insert(idx, "run")
        return


def _should_launch_assistant(tokens: list[str]) -> bool:
    if not tokens:
        return True
    commands = {
        "run",
        "chat",
        "login",
        "logout",
        "init",
        "quickstart",
        "reset",
        "undo",
        "fix",
        "approve",
        "status",
        "scan",
        "swarm",
        "watch",
        "actions",
        "autopilot",
        "doctor",
        "install-doctor",
        "setup",
        "report",
        "template",
        "runbook",
        "pack",
        "target",
        "history",
        "memory",
        "--help",
        "-h",
    }
    options_with_value = {
        "--approval-mode",
        "--audit-log",
        "--lock-file",
        "--session-file",
        "--deny-tool",
        "--deny-prefix",
        "--tool-pack",
        "--remote-gateway",
        "--model",
        "--provider",
        "--max-steps",
    }
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if token in commands:
            return False
        if token.startswith("-"):
            if token in options_with_value and idx + 1 < len(tokens):
                idx += 2
                continue
            idx += 1
            continue
        return False
    return True


if __name__ == "__main__":
    main()
