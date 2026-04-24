from __future__ import annotations

import asyncio
import contextlib
from difflib import get_close_matches
import io
import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from string import Formatter
import textwrap
from typing import Annotated

import typer

from lazysre import __version__
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
from lazysre.cli.incident import IncidentStore, IncidentRecord, render_incident_markdown
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
from lazysre.cli.types import DispatchEvent, DispatchResult, ExecResult
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
incident_app = typer.Typer(help="Incident lifecycle management.")
runbook_app = typer.Typer(help="Workflow runbook templates.")
template_app = typer.Typer(help="One-click remediation templates.")


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", "-V", help="Show LazySRE version and exit.", is_eager=True)] = False,
    execute: Annotated[bool, typer.Option("--execute", help="Run commands for real. Default is dry-run.")] = False,
    approve: Annotated[bool, typer.Option("--approve", help="Acknowledge policy gate for high-risk commands.")] = False,
    interactive_approval: Annotated[bool, typer.Option("--interactive-approval/--no-interactive-approval", help="Prompt y/n confirmation for risky write actions in execute mode.")] = True,
    stream_output: Annotated[bool, typer.Option("--stream-output/--no-stream-output", help="Stream model tokens in terminal output.")] = True,
    verbose_reasoning: Annotated[bool, typer.Option("--verbose-reasoning/--no-verbose-reasoning", help="Show full AI reasoning content instead of collapsed summary.")] = False,
    approval_mode: Annotated[str, typer.Option(help="Policy level: strict|balanced|permissive")] = "balanced",
    audit_log: Annotated[str, typer.Option(help="Audit jsonl path for command execution records.")] = ".data/lsre-audit.jsonl",
    lock_file: Annotated[str, typer.Option(help="Tool pack lock file path.")] = ".data/lsre-tool-lock.json",
    session_file: Annotated[str, typer.Option(help="Session memory file path.")] = ".data/lsre-session.json",
    incident_file: Annotated[str, typer.Option(help="Incident lifecycle store path.")] = str((Path(settings.data_dir) / "lsre-incident.json").expanduser()),
    deny_tool: Annotated[list[str], typer.Option("--deny-tool", help="Block specific tools by name, can be repeated.")] = [],
    deny_prefix: Annotated[list[str], typer.Option("--deny-prefix", help="Block tools by prefix, can be repeated.")] = [],
    tool_pack: Annotated[list[str], typer.Option("--tool-pack", help="Tool pack spec. e.g. builtin or module:pkg.mod[:factory].")] = ["builtin"],
    remote_gateway: Annotated[list[str], typer.Option("--remote-gateway", help="Remote gateway <name>=<url>[#token]. can be repeated.")] = [],
    model: Annotated[str, typer.Option(help="Model name for LLM dispatcher.")] = settings.model_name,
    provider: Annotated[str, typer.Option(help=f"LLM provider: {provider_mode_help_text()}")] = "auto",
    max_steps: Annotated[int, typer.Option(help="Max function-calling iterations.")] = 6,
) -> None:
    if version:
        typer.echo(_version_text())
        raise typer.Exit()
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
        "incident_file": incident_file,
        "deny_tool": list(deny_tool),
        "deny_prefix": list(deny_prefix),
        "tool_pack": list(tool_pack),
        "remote_gateway": list(remote_gateway),
        "model": model,
        "provider": provider,
        "max_steps": max(1, min(max_steps, 12)),
    }
    if ctx.invoked_subcommand is None and _should_launch_default_tui(sys.argv[1:]):
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
        _run_tui(options, demo=False)
        raise typer.Exit()
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


@app.command("version")
def version_command(
    as_json: Annotated[bool, typer.Option("--json", help="Print version details as JSON.")] = False,
) -> None:
    info = _version_info()
    if as_json:
        typer.echo(json.dumps(info, ensure_ascii=False, indent=2))
        return
    typer.echo(_version_text(info))


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


@app.command("brief")
def brief(
    target: Annotated[str, typer.Argument(help="Optional SSH target for remote briefing. Omit to use target.ssh_target.")] = "",
    include_remote: Annotated[bool, typer.Option("--remote/--no-remote", help="Include saved or provided remote Docker/Swarm target.")] = True,
    logs: Annotated[bool, typer.Option("--logs", help="Include remote Swarm service logs when remote briefing runs.")] = False,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Probe timeout seconds.")] = 5,
    as_json: Annotated[bool, typer.Option("--json", help="Print overview briefing as JSON.")] = False,
) -> None:
    report = _build_overview_brief_report(
        target=target,
        include_remote=include_remote,
        include_logs=logs,
        timeout_sec=timeout_sec,
    )
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _render_overview_brief_report(report)


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
    remote_target: Annotated[str, typer.Option("--remote", help="Run autopilot against an SSH target, e.g. root@192.168.10.101.")] = "",
    service: Annotated[str, typer.Option("--service", help="Optional remote Swarm service filter when --remote is set.")] = "",
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
    if remote_target.strip():
        report = _run_remote_autopilot_cycle(
            goal=goal,
            target=_resolve_ssh_target_arg(remote_target),
            service_filter=service,
            include_logs=include_logs,
            timeout_sec=timeout_sec,
        )
    else:
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


@app.command("remediate")
def remediate(
    ctx: typer.Context,
    objective: Annotated[str, typer.Argument(help="Natural-language remediation objective.")] = "修复当前巡检发现的问题",
    remote_target: Annotated[str, typer.Option("--remote", help="Observe an SSH Docker/Swarm target before planning.")] = "",
    service: Annotated[str, typer.Option("--service", help="Optional remote Swarm service filter.")] = "",
    include_logs: Annotated[bool, typer.Option("--logs", help="Include logs during observation.")] = False,
    apply: Annotated[bool, typer.Option("--apply", help="Apply the remediation plan. Default is dry-run planning.")] = False,
    verify: Annotated[bool, typer.Option("--verify/--no-verify", help="Run read-only verification after apply/planning.")] = True,
    rollback_on_failure: Annotated[bool, typer.Option("--rollback-on-failure", help="Run rollback commands when apply or verify fails in execute mode.")] = False,
    from_last_plan: Annotated[bool, typer.Option("--from-last-plan", help="Use .data/lsre-fix-last.json instead of deriving a plan from observation.")] = False,
    max_apply_steps: Annotated[int, typer.Option("--max-apply-steps", help="Max apply commands to run.")] = 6,
    report_md: Annotated[str, typer.Option("--report-md", help="Optional markdown closed-loop report path.")] = "",
    report_json: Annotated[str, typer.Option("--report-json", help="Optional JSON closed-loop report path.")] = "",
    as_json: Annotated[bool, typer.Option("--json", help="Print closed-loop report as JSON.")] = False,
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
    report = _run_closed_loop_remediation(
        objective=objective,
        remote_target=remote_target,
        service_filter=service,
        include_logs=include_logs,
        apply=apply,
        verify=verify,
        rollback_on_failure=rollback_on_failure,
        from_last_plan=from_last_plan,
        max_apply_steps=max(1, min(max_apply_steps, 30)),
        execute=bool(options["execute"]),
        approval_mode=str(options["approval_mode"]),
        audit_log=str(options["audit_log"]),
        allow_high_risk=False,
        auto_approve_low_risk=True,
        model=str(options["model"]),
        provider=str(options["provider"]),
    )
    exported_reports: dict[str, str] = {}
    json_out_path: Path | None = None
    markdown_out_path: Path | None = None
    if report_json.strip():
        json_out_path = Path(report_json).expanduser()
        exported_reports["json"] = str(json_out_path)
    if report_md.strip():
        markdown_out_path = Path(report_md).expanduser()
        exported_reports["markdown"] = str(markdown_out_path)
    if exported_reports:
        report["exported_reports"] = exported_reports
    if json_out_path:
        _write_json_file(json_out_path, report)
        if not as_json:
            typer.echo(f"Remediation JSON report exported: {json_out_path}")
    if markdown_out_path:
        _write_text_file(markdown_out_path, _render_closed_loop_report_markdown(report))
        if not as_json:
            typer.echo(f"Remediation markdown report exported: {markdown_out_path}")
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _render_closed_loop_report(report)


@app.command("remote")
def remote(
    target: Annotated[str, typer.Argument(help="SSH target, e.g. root@192.168.10.101. Omit to use target.ssh_target.")] = "",
    service: Annotated[str, typer.Option("--service", help="Optional Docker Swarm service filter.")] = "",
    logs: Annotated[bool, typer.Option("--logs", help="Include remote Swarm service logs.")] = False,
    tail: Annotated[int, typer.Option("--tail", help="Remote log/task tail lines.")] = 80,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Per SSH command timeout seconds.")] = 8,
    as_json: Annotated[bool, typer.Option("--json", help="Print remote report as JSON.")] = False,
    report_md: Annotated[str, typer.Option("--report-md", help="Optional markdown remote report path.")] = "",
) -> None:
    resolved_target = _resolve_ssh_target_arg(target)
    report = _collect_remote_docker_report(
        target=resolved_target,
        service_filter=service,
        include_logs=logs,
        tail=tail,
        timeout_sec=timeout_sec,
    )
    if report_md.strip():
        out_path = Path(report_md).expanduser()
        _write_text_file(out_path, _render_remote_docker_report_markdown(report))
        typer.echo(f"Remote report exported: {out_path}")
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _render_remote_docker_report(report)


@app.command("connect")
def connect(
    target: Annotated[str, typer.Argument(help="SSH target, e.g. root@192.168.10.101. Omit to use target.ssh_target.")] = "",
    save_target: Annotated[bool, typer.Option("--save/--no-save", help="Remember the SSH target when SSH connectivity succeeds.")] = True,
    logs: Annotated[bool, typer.Option("--logs", help="Include remote Swarm service logs during the connection check.")] = False,
    tail: Annotated[int, typer.Option("--tail", help="Remote log/task tail lines.")] = 40,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Per SSH command timeout seconds.")] = 8,
    as_json: Annotated[bool, typer.Option("--json", help="Print connection report as JSON.")] = False,
) -> None:
    report = _run_remote_connect_flow(
        target=target,
        save_target=save_target,
        include_logs=logs,
        tail=tail,
        timeout_sec=timeout_sec,
    )
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _render_remote_docker_report(report)
    save_payload = report.get("target_save", {})
    if isinstance(save_payload, dict):
        if bool(save_payload.get("saved")):
            typer.echo(f"默认远程目标已保存: {save_payload.get('target', '')}")
        elif save_target:
            typer.echo(f"未保存默认远程目标: {save_payload.get('reason', 'unknown')}")


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


@app.command("preflight")
def preflight(
    ctx: typer.Context,
    profile_file: Annotated[str, typer.Option("--profile-file", help="Target profile JSON path.")] = settings.target_profile_file,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Probe timeout seconds for doctor checks.")] = 6,
    dry_run_probe: Annotated[bool, typer.Option("--dry-run-probe", help="Run doctor probes in dry-run mode.")] = True,
    strict: Annotated[bool, typer.Option("--strict", help="Treat warnings as failure (CI-friendly).")] = False,
    staged: Annotated[bool, typer.Option("--staged/--all-files", help="Secret scan scope: staged files only (default) or all files.")] = True,
    max_findings: Annotated[int, typer.Option("--max-findings", help="Maximum suspicious token findings to keep.")] = 8,
    as_json: Annotated[bool, typer.Option("--json", help="Print preflight report as JSON.")] = False,
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
    report = _collect_preflight_report(
        profile_file=Path(profile_file),
        timeout_sec=timeout_sec,
        dry_run_probe=dry_run_probe,
        strict=strict,
        staged=staged,
        max_findings=max_findings,
        audit_log=Path(str(options["audit_log"])),
    )
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _render_doctor_report(report)
    gate = report.get("gate", {})
    if strict and isinstance(gate, dict) and (not bool(gate.get("healthy", True))):
        raise typer.Exit(code=2)


@app.command("secret-scan")
def secret_scan(
    staged: Annotated[bool, typer.Option("--staged", help="Only scan files staged in git index.")] = False,
    max_findings: Annotated[int, typer.Option("--max-findings", help="Maximum suspicious token findings to keep.")] = 8,
    fail_on_findings: Annotated[bool, typer.Option("--fail-on-findings", help="Exit code 1 when suspicious tokens are found.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print secret scan report as JSON.")] = False,
) -> None:
    report = _collect_secret_scan_report(staged=staged, max_findings=max_findings)
    report["gate"] = _build_doctor_gate(report, strict=False)
    if as_json or (not _console):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _render_doctor_report(report)
    summary = report.get("summary", {})
    healthy = bool(summary.get("healthy", True)) if isinstance(summary, dict) else True
    if fail_on_findings and (not healthy):
        raise typer.Exit(code=1)


@app.command("login")
def login(
    provider: Annotated[str, typer.Option("--provider", help=f"Provider: {provider_mode_help_text()}")] = "openai",
    api_key: Annotated[str, typer.Option("--api-key", help="Provider API Key. If empty, prompt securely.")] = "",
    base_url: Annotated[str, typer.Option("--base-url", help="Optional API base URL for this provider. Useful for OpenAI-compatible gateways.")] = "",
    model_name: Annotated[str, typer.Option("--model", help="Optional default model name for this provider.")] = "",
    secrets_file: Annotated[str, typer.Option("--secrets-file", help="Secrets JSON file path.")] = "",
) -> None:
    mode = str(provider or "openai").strip().lower()
    if mode not in PROVIDER_SPECS:
        raise typer.BadParameter(provider_mode_error_text())
    store = SecretStore(Path(secrets_file).expanduser() if secrets_file.strip() else None)
    key = api_key.strip()
    if (not key) and (not base_url.strip()) and (not model_name.strip()):
        key = typer.prompt(f"请输入 {PROVIDER_SPECS[mode].label} API Key", hide_input=True).strip()
    changed: list[str] = []
    if key:
        store.set_api_key(mode, key)
        masked = store.masked_api_key(mode) or "***"
        changed.append(f"API Key={masked}")
    elif (not store.get_api_key(mode)) and (not base_url.strip()) and (not model_name.strip()):
        raise typer.BadParameter("API Key 不能为空")
    if base_url.strip():
        store.set_provider_base_url(mode, base_url.strip())
        changed.append(f"base_url={base_url.strip()}")
    if model_name.strip():
        store.set_provider_model(mode, model_name.strip())
        changed.append(f"model={model_name.strip()}")
    if not changed:
        raise typer.BadParameter("至少提供 --api-key、--base-url 或 --model 之一")
    typer.echo(f"{PROVIDER_SPECS[mode].label} 配置已保存: {', '.join(changed)} ({store.path})")
    typer.echo("现在可直接运行：lazysre")


@app.command("logout")
def logout(
    provider: Annotated[str, typer.Option("--provider", help=f"Provider: {provider_mode_help_text()}")] = "openai",
    clear_config: Annotated[bool, typer.Option("--clear-config/--no-clear-config", help="Also clear saved base_url/model for this provider.")] = True,
    secrets_file: Annotated[str, typer.Option("--secrets-file", help="Secrets JSON file path.")] = "",
) -> None:
    mode = str(provider or "openai").strip().lower()
    if mode not in PROVIDER_SPECS:
        raise typer.BadParameter(provider_mode_error_text())
    store = SecretStore(Path(secrets_file).expanduser() if secrets_file.strip() else None)
    removed = store.clear_api_key(mode)
    config_removed = store.clear_provider_runtime_config(mode) if clear_config else False
    if removed or config_removed:
        cleared_items: list[str] = []
        if removed:
            cleared_items.append("API Key")
        if config_removed:
            cleared_items.append("runtime config")
        typer.echo(f"已清除本地 {PROVIDER_SPECS[mode].label} {' + '.join(cleared_items)}。")
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


@app.command("tui")
def tui(
    ctx: typer.Context,
    demo: Annotated[bool, typer.Option("--demo", help="Render a static TUI preview instead of opening fullscreen mode.")] = False,
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
    _run_tui(options, demo=demo)


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
    if "incident_file" not in base:
        base["incident_file"] = str((Path(settings.data_dir) / "lsre-incident.json").expanduser())
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
    runtime_options: dict[str, object] | None = None,
) -> DispatchResult:
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
    if runtime_options is not None:
        note = _maybe_apply_runtime_provider_fallback(runtime_options, result)
        if note:
            typer.echo(note)
    return result


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
    runtime_options: dict[str, object] | None = None,
) -> DispatchResult:
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
        if runtime_options is not None:
            note = _maybe_apply_runtime_provider_fallback(runtime_options, result)
            if note:
                typer.echo(note)
        return result
    if not plan.apply_commands:
        typer.echo("未从计划中识别到可执行命令，已跳过执行。")
        if runtime_options is not None:
            note = _maybe_apply_runtime_provider_fallback(runtime_options, result)
            if note:
                typer.echo(note)
        return result

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
    verify_summary = _execute_read_only_commands(
        _infer_verification_commands(plan),
        stage="verify",
        approval_mode=approval_mode,
        audit_log=audit_log,
    )
    if _console and Panel:
        _console.print(Panel(json.dumps(verify_summary, ensure_ascii=False, indent=2), title="Post-Apply Verification", border_style="green" if int(verify_summary.get("failed", 0) or 0) == 0 else "yellow"))
    else:
        typer.echo("Post-Apply Verification:")
        typer.echo(json.dumps(verify_summary, ensure_ascii=False, indent=2))

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
    if runtime_options is not None:
        note = _maybe_apply_runtime_provider_fallback(runtime_options, result)
        if note:
            typer.echo(note)
    return result


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

    def _new_dispatcher(*, selected_llm, selected_model: str) -> Dispatcher:
        return Dispatcher(
            llm=selected_llm,
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
            model=selected_model,
            max_steps=max(1, min(max_steps, 12)),
            text_stream=text_stream,
            system_prompt=_build_system_prompt(
                conversation_context=conversation_context,
                memory_context=memory_context,
            ),
        )

    try:
        return await _new_dispatcher(selected_llm=llm, selected_model=resolved_model).run(instruction)
    except Exception as exc:
        if not _should_auto_fallback_to_mock(provider_mode=mode, error=exc):
            raise
        reason = _normalize_runtime_exception_message(exc)
        try:
            _, fallback_model, fallback_llm = _build_cli_llm(provider="mock", model=model)
            fallback_result = await _new_dispatcher(selected_llm=fallback_llm, selected_model=fallback_model).run(instruction)
        except Exception:
            raise exc
        fallback_note = (
            f"Provider `{mode}` 调用失败，已自动降级到 mock（仅建议/低风险模式）。"
            f" 原因: {reason[:220]}"
        )
        fallback_result.events.insert(
            0,
            DispatchEvent(
                kind="system",
                message="provider_fallback",
                data={"from": mode, "to": "mock", "reason": reason[:220]},
            ),
        )
        fallback_result.final_text = f"[auto-fallback]\n{fallback_note}\n\n{fallback_result.final_text}"
        return fallback_result


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
    ssh_target: Annotated[str | None, typer.Option("--ssh-target", help="Default SSH target for remote Docker/Swarm diagnosis.")] = None,
    k8s_api_url: Annotated[str | None, typer.Option("--k8s-api-url", help="Kubernetes API URL.")] = None,
    k8s_context: Annotated[str | None, typer.Option("--k8s-context", help="kubectl context name.")] = None,
    k8s_namespace: Annotated[str | None, typer.Option("--k8s-namespace", help="Default Kubernetes namespace.")] = None,
    k8s_bearer_token: Annotated[str | None, typer.Option("--k8s-bearer-token", help="Kubernetes bearer token.")] = None,
    k8s_verify_tls: Annotated[bool | None, typer.Option("--k8s-verify-tls/--k8s-skip-tls-verify", help="TLS verification for Kubernetes API.")] = None,
) -> None:
    store = TargetEnvStore(Path(profile_file))
    updated = store.update(
        prometheus_url=prometheus_url,
        ssh_target=ssh_target,
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
        raise typer.BadParameter(_safe_exception_text(exc)) from exc

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


@incident_app.command("open")
def incident_open(
    ctx: typer.Context,
    title: Annotated[str, typer.Argument(help="Incident title.")],
    severity: Annotated[str, typer.Option("--severity", help="Incident severity: low|medium|high|critical.")] = "high",
    assignee: Annotated[str, typer.Option("--assignee", help="Incident owner/assignee.")] = "-",
    summary: Annotated[str, typer.Option("--summary", help="Incident summary.")] = "",
    source: Annotated[str, typer.Option("--source", help="Incident source label.")] = "manual",
    tag: Annotated[list[str], typer.Option("--tag", help="Incident tags, can repeat.")] = [],
    incident_file: Annotated[str | None, typer.Option("--incident-file", help="Override incident store path.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    store = IncidentStore(_resolve_incident_file(ctx, incident_file))
    try:
        rec = store.open_incident(
            title=title,
            severity=severity,
            assignee=assignee,
            summary=summary,
            source=source,
            tags=list(tag),
        )
    except RuntimeError as exc:
        raise typer.BadParameter(_safe_exception_text(exc)) from None
    if as_json or (not _console):
        typer.echo(json.dumps(rec.to_dict(), ensure_ascii=False, indent=2))
        return
    typer.echo(_render_incident_status_text(rec))


@incident_app.command("status")
def incident_status(
    ctx: typer.Context,
    incident_file: Annotated[str | None, typer.Option("--incident-file", help="Override incident store path.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    store = IncidentStore(_resolve_incident_file(ctx, incident_file))
    rec = store.active()
    if as_json or (not _console):
        typer.echo(json.dumps(rec.to_dict() if rec else {"active": None}, ensure_ascii=False, indent=2))
        return
    typer.echo(_render_incident_status_text(rec))


@incident_app.command("list")
def incident_list(
    ctx: typer.Context,
    limit: Annotated[int, typer.Option("--limit", help="Number of incidents to display.")] = 10,
    incident_file: Annotated[str | None, typer.Option("--incident-file", help="Override incident store path.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    store = IncidentStore(_resolve_incident_file(ctx, incident_file))
    rows = store.list_recent(limit=max(1, limit))
    if as_json or (not _console):
        typer.echo(json.dumps([item.to_dict() for item in rows], ensure_ascii=False, indent=2))
        return
    if not rows:
        typer.echo("Incident list\n- no incidents yet.")
        return
    lines = ["Incident list"]
    for item in rows:
        lines.append(
            f"- {item.id} [{item.status}/{item.severity}] assignee={item.assignee} title={item.title}"
        )
    typer.echo("\n".join(lines))


@incident_app.command("note")
def incident_note(
    ctx: typer.Context,
    text: Annotated[str, typer.Argument(help="Incident note text.")],
    author: Annotated[str, typer.Option("--author", help="Note author label.")] = "user",
    incident_file: Annotated[str | None, typer.Option("--incident-file", help="Override incident store path.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    store = IncidentStore(_resolve_incident_file(ctx, incident_file))
    try:
        rec = store.add_note(text, author=author)
    except RuntimeError as exc:
        raise typer.BadParameter(_safe_exception_text(exc)) from None
    if as_json or (not _console):
        typer.echo(json.dumps(rec.to_dict(), ensure_ascii=False, indent=2))
        return
    typer.echo(_render_incident_status_text(rec))


@incident_app.command("assign")
def incident_assign(
    ctx: typer.Context,
    assignee: Annotated[str, typer.Argument(help="Assignee name.")],
    incident_file: Annotated[str | None, typer.Option("--incident-file", help="Override incident store path.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    store = IncidentStore(_resolve_incident_file(ctx, incident_file))
    try:
        rec = store.set_assignee(assignee)
    except RuntimeError as exc:
        raise typer.BadParameter(_safe_exception_text(exc)) from None
    if as_json or (not _console):
        typer.echo(json.dumps(rec.to_dict(), ensure_ascii=False, indent=2))
        return
    typer.echo(_render_incident_status_text(rec))


@incident_app.command("severity")
def incident_severity(
    ctx: typer.Context,
    level: Annotated[str, typer.Argument(help="Severity: low|medium|high|critical.")],
    incident_file: Annotated[str | None, typer.Option("--incident-file", help="Override incident store path.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    store = IncidentStore(_resolve_incident_file(ctx, incident_file))
    try:
        rec = store.set_severity(level)
    except RuntimeError as exc:
        raise typer.BadParameter(_safe_exception_text(exc)) from None
    if as_json or (not _console):
        typer.echo(json.dumps(rec.to_dict(), ensure_ascii=False, indent=2))
        return
    typer.echo(_render_incident_status_text(rec))


@incident_app.command("timeline")
def incident_timeline(
    ctx: typer.Context,
    limit: Annotated[int, typer.Option("--limit", help="Number of timeline events to show.")] = 12,
    incident_file: Annotated[str | None, typer.Option("--incident-file", help="Override incident store path.")] = None,
) -> None:
    store = IncidentStore(_resolve_incident_file(ctx, incident_file))
    rec = store.active()
    if not rec:
        typer.echo("Incident Timeline\n- no active incident.")
        return
    typer.echo(_render_incident_timeline_text(rec, limit=max(1, limit)))


@incident_app.command("close")
def incident_close(
    ctx: typer.Context,
    resolution: Annotated[str, typer.Option("--resolution", help="Resolution summary when closing incident.")] = "",
    incident_file: Annotated[str | None, typer.Option("--incident-file", help="Override incident store path.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print as JSON.")] = False,
) -> None:
    store = IncidentStore(_resolve_incident_file(ctx, incident_file))
    try:
        rec = store.close_incident(resolution=resolution)
    except RuntimeError as exc:
        raise typer.BadParameter(_safe_exception_text(exc)) from None
    if as_json or (not _console):
        typer.echo(json.dumps(rec.to_dict(), ensure_ascii=False, indent=2))
        return
    typer.echo(_render_incident_status_text(rec))


@incident_app.command("export")
def incident_export(
    ctx: typer.Context,
    output: Annotated[str, typer.Option("--output", help="Output markdown path.")] = "",
    incident_file: Annotated[str | None, typer.Option("--incident-file", help="Override incident store path.")] = None,
) -> None:
    store = IncidentStore(_resolve_incident_file(ctx, incident_file))
    rec = store.active()
    if not rec:
        rows = store.list_recent(limit=1)
        rec = rows[0] if rows else None
    if not rec:
        typer.echo("No incident found to export.")
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_path = Path(output.strip() or str(Path(settings.data_dir) / f"{rec.id.lower()}-{stamp}.md"))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_incident_markdown(rec), encoding="utf-8")
    typer.echo(f"Incident exported: {out_path}")


def _resolve_incident_file(ctx: typer.Context, incident_file: str | None) -> Path:
    if incident_file and incident_file.strip():
        return Path(incident_file).expanduser()
    obj = dict(ctx.obj or {})
    candidate = str(obj.get("incident_file", "")).strip()
    if candidate:
        return Path(candidate).expanduser()
    return _default_incident_file_path()


def _default_incident_file_path() -> Path:
    return (Path(settings.data_dir) / "lsre-incident.json").expanduser()


def _resolve_incident_inline_path(options: dict[str, object]) -> Path:
    candidate = str(options.get("incident_file", "")).strip()
    if candidate:
        return Path(candidate).expanduser()
    return _default_incident_file_path()


def _render_incident_status_text(rec: IncidentRecord | None) -> str:
    if rec is None:
        return "Incident\n- no active incident.\n- use: /incident open <title>"
    lines = [
        "Incident",
        f"- id: {rec.id}",
        f"- title: {rec.title}",
        f"- status: {rec.status}",
        f"- severity: {rec.severity}",
        f"- assignee: {rec.assignee}",
        f"- updated: {rec.updated_at_utc}",
    ]
    if rec.summary:
        lines.append(f"- summary: {rec.summary[:180]}")
    if rec.resolution:
        lines.append(f"- resolution: {rec.resolution[:180]}")
    lines.append("- commands: /incident note <text> | /incident assign <name> | /incident close")
    return "\n".join(lines)


def _render_incident_timeline_text(rec: IncidentRecord, *, limit: int = 12) -> str:
    lines = [f"Incident Timeline ({rec.id})"]
    if not rec.timeline:
        lines.append("- (empty)")
        return "\n".join(lines)
    for item in rec.timeline[-max(1, limit):]:
        lines.append(
            f"- {item.get('at_utc', '-')}: {item.get('kind', '-')}: {item.get('message', '')}"
        )
    return "\n".join(lines)


def _handle_incident_inline_command(text: str, *, path: Path | None = None) -> str:
    raw = str(text or "").strip()
    if not raw.lower().startswith("/incident"):
        return ""
    store = IncidentStore(path or _default_incident_file_path())
    tail = raw[len("/incident") :].strip()
    if not tail or tail in {"show", "status"}:
        return _render_incident_status_text(store.active())
    if tail.startswith("open "):
        title = tail[len("open ") :].strip()
        if not title:
            return "用法：/incident open <title>"
        try:
            rec = store.open_incident(title=title, severity="high", source="chat")
        except RuntimeError as exc:
            return f"incident open failed: {_safe_exception_text(exc)}"
        return _render_incident_status_text(rec)
    if tail.startswith("note "):
        note = tail[len("note ") :].strip()
        if not note:
            return "用法：/incident note <text>"
        try:
            rec = store.add_note(note, author="chat")
        except RuntimeError as exc:
            return f"incident note failed: {_safe_exception_text(exc)}"
        return _render_incident_status_text(rec)
    if tail.startswith("assign "):
        assignee = tail[len("assign ") :].strip()
        if not assignee:
            return "用法：/incident assign <name>"
        try:
            rec = store.set_assignee(assignee)
        except RuntimeError as exc:
            return f"incident assign failed: {_safe_exception_text(exc)}"
        return _render_incident_status_text(rec)
    if tail.startswith("severity "):
        level = tail[len("severity ") :].strip()
        if not level:
            return "用法：/incident severity <low|medium|high|critical>"
        try:
            rec = store.set_severity(level)
        except RuntimeError as exc:
            return f"incident severity failed: {_safe_exception_text(exc)}"
        return _render_incident_status_text(rec)
    if tail in {"timeline", "trace"}:
        rec = store.active()
        if not rec:
            return "Incident Timeline\n- no active incident."
        return _render_incident_timeline_text(rec, limit=12)
    if tail.startswith("close"):
        resolution = tail[len("close") :].strip()
        try:
            rec = store.close_incident(resolution=resolution)
        except RuntimeError as exc:
            return f"incident close failed: {_safe_exception_text(exc)}"
        return _render_incident_status_text(rec)
    if tail.startswith("list"):
        rows = store.list_recent(limit=8)
        if not rows:
            return "Incident list\n- no incidents yet."
        lines = ["Incident list"]
        for item in rows:
            lines.append(f"- {item.id} [{item.status}/{item.severity}] {item.title}")
        return "\n".join(lines)
    if tail.startswith("export"):
        rec = store.active()
        if not rec:
            rows = store.list_recent(limit=1)
            rec = rows[0] if rows else None
        if not rec:
            return "No incident found to export."
        arg = tail[len("export") :].strip()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        out_path = Path(arg or f".data/{rec.id.lower()}-{stamp}.md")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(render_incident_markdown(rec), encoding="utf-8")
        return f"Incident exported: {out_path}"
    return (
        "Incident command usage:\n"
        "- /incident status\n"
        "- /incident open <title>\n"
        "- /incident note <text>\n"
        "- /incident assign <name>\n"
        "- /incident severity <level>\n"
        "- /incident timeline\n"
        "- /incident close [resolution]\n"
        "- /incident list\n"
        "- /incident export [output.md]"
    )


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
        raise typer.BadParameter(_safe_exception_text(exc)) from exc
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
        raise typer.BadParameter(_safe_exception_text(exc)) from exc
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
        raise typer.BadParameter(_safe_exception_text(exc)) from exc
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
        raise typer.BadParameter(_safe_exception_text(exc)) from exc
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
        raise typer.BadParameter(_safe_exception_text(exc)) from exc
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
        raise typer.BadParameter(_safe_exception_text(exc)) from exc
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
    if str(getattr(target, "ssh_target", "")).strip():
        values["ssh_target"] = str(getattr(target, "ssh_target", "")).strip()
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
        raise ValueError(f"invalid quoting: {_safe_exception_text(exc)}") from exc
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
            raise ValueError(f"invalid quoting: {_safe_exception_text(exc)}") from exc

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
app.add_typer(incident_app, name="incident")
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

    payload = {
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
    payload["landscape"] = _build_environment_landscape(payload)
    payload["briefing"] = _build_environment_scan_briefing(payload)
    return payload


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

    server_probe = _safe_run_command(
        [kubectl_path, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"],
        timeout_sec=timeout_sec,
    )
    discovery["server"] = str(server_probe.get("stdout", "")).strip()

    namespace_probe = _safe_run_command(
        [kubectl_path, "config", "view", "--minify", "-o", "jsonpath={.contexts[0].context.namespace}"],
        timeout_sec=timeout_sec,
    )
    discovery["namespace"] = str(namespace_probe.get("stdout", "")).strip() or "default"

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


def _build_environment_scan_briefing(report: dict[str, object]) -> dict[str, object]:
    summary = report.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    landscape = report.get("landscape", {})
    if (not isinstance(landscape, dict)) or (not landscape):
        landscape = _build_environment_landscape(report)
    usable_targets = report.get("usable_targets", [])
    targets = [str(item) for item in usable_targets] if isinstance(usable_targets, list) else []
    issues = report.get("issues", [])
    issue_items = [item for item in issues if isinstance(item, dict)] if isinstance(issues, list) else []
    suggestions = report.get("suggestions", [])
    suggestion_items = [str(item) for item in suggestions] if isinstance(suggestions, list) else []
    next_actions = report.get("next_actions", [])
    action_items = [str(item) for item in next_actions] if isinstance(next_actions, list) else []

    error_count = int(summary.get("error", 0) or 0)
    warn_count = int(summary.get("warn", 0) or 0)
    status = "healthy"
    if error_count:
        status = "blocked"
    elif warn_count or issue_items:
        status = "attention"

    profile_label = str(landscape.get("label", "")).strip()
    profile_summary = str(landscape.get("summary", "")).strip()
    signal_items = [str(item).strip() for item in landscape.get("signals", [])] if isinstance(landscape.get("signals", []), list) else []

    if targets and issue_items:
        headline = (
            f"现场画像：{profile_label or '已发现可纳管环境'}；"
            f"已发现可纳管目标：{', '.join(targets)}，同时有 {len(issue_items)} 个需要关注的问题。"
        )
    elif targets:
        headline = (
            f"现场画像：{profile_label or '已发现可纳管环境'}；"
            f"已发现可纳管目标：{', '.join(targets)}，可以直接开始自然语言诊断。"
        )
    else:
        headline = (
            f"现场画像：{profile_label or 'Bootstrap / Unmanaged'}；"
            "暂未发现可直接访问的运维目标，请先确认 Docker、kubectl 或 Prometheus 配置。"
        )

    evidence = [
        f"checks: pass={summary.get('pass', 0)} warn={warn_count} error={error_count}",
        f"usable_targets={', '.join(targets) if targets else 'none'}",
    ]
    if profile_summary:
        evidence.append(f"profile: {profile_summary}")
    for item in signal_items[:3]:
        evidence.append(f"signal: {item}")
    for item in issue_items[:3]:
        evidence.append(
            f"{item.get('severity', '-')}: {item.get('name', '-')} {str(item.get('detail', '')).strip()[:120]}"
        )

    next_step = ""
    if targets:
        if "docker-swarm" in targets:
            next_step = "lazysre swarm --logs"
        elif "kubernetes" in targets:
            next_step = 'lazysre "检查 K8s 异常 Pod 和 Warning Events"'
        elif "docker" in targets:
            next_step = 'lazysre "检查 Docker 容器有没有异常退出"'
    if not next_step and action_items:
        next_step = next((item for item in action_items if _looks_like_shell_command(item)), "")
    if not next_step and suggestion_items:
        next_step = f'lazysre "{suggestion_items[0]}"'
    if not next_step:
        next_step = "lazysre doctor"

    return {
        "status": status,
        "headline": headline,
        "evidence": evidence[:5],
        "next": next_step,
        "profile": str(landscape.get("profile", "")).strip(),
        "profile_label": profile_label,
        "summary": profile_summary,
        "signals": signal_items[:5],
    }


def _build_environment_landscape(report: dict[str, object]) -> dict[str, object]:
    usable_targets = report.get("usable_targets", [])
    targets = [str(item).strip() for item in usable_targets] if isinstance(usable_targets, list) else []
    target_set = {item for item in targets if item}
    discoveries = report.get("discoveries", {})
    if not isinstance(discoveries, dict):
        discoveries = {}
    docker = discoveries.get("docker", {})
    k8s = discoveries.get("kubernetes", {})
    prometheus = discoveries.get("prometheus", {})
    providers = discoveries.get("providers", {})
    docker = docker if isinstance(docker, dict) else {}
    k8s = k8s if isinstance(k8s, dict) else {}
    prometheus = prometheus if isinstance(prometheus, dict) else {}
    providers = providers if isinstance(providers, dict) else {}

    has_docker = "docker" in target_set
    has_swarm = "docker-swarm" in target_set
    has_k8s = "kubernetes" in target_set
    has_prom = "prometheus" in target_set

    if has_swarm and has_k8s:
        profile = "hybrid-swarm-k8s"
        label = "Hybrid Swarm + K8s"
    elif has_swarm and has_prom:
        profile = "observed-swarm"
        label = "Observed Swarm"
    elif has_swarm:
        profile = "swarm-runtime"
        label = "Swarm Runtime"
    elif has_k8s and has_prom:
        profile = "observed-k8s"
        label = "Observed Kubernetes"
    elif has_k8s:
        profile = "kubernetes-cluster"
        label = "Kubernetes Cluster"
    elif has_docker:
        profile = "docker-host"
        label = "Docker Host"
    elif has_prom:
        profile = "metrics-observer"
        label = "Metrics Observer"
    else:
        profile = "bootstrap"
        label = "Bootstrap / Unmanaged"

    signals: list[str] = []
    if has_swarm:
        service_count = _safe_int(docker.get("swarm_services", 0))
        signals.append(f"Swarm active，services={service_count}")
    elif has_docker:
        version = str(docker.get("server_version", "")).strip()
        signals.append(f"Docker reachable{f'，server={version}' if version else ''}")
    exited = _safe_int(docker.get("exited_containers", 0))
    if exited > 0:
        signals.append(f"Docker exited containers={exited}")
    if has_k8s:
        nodes = _safe_int(k8s.get("nodes", 0))
        problem_pods = _safe_int(k8s.get("problem_pods", 0))
        warning_events = _safe_int(k8s.get("warning_events", 0))
        ns = str(k8s.get("namespace", "")).strip() or "default"
        signals.append(f"K8s reachable，nodes={nodes}，namespace={ns}")
        if problem_pods > 0:
            signals.append(f"K8s problem pods={problem_pods}")
        if warning_events > 0:
            signals.append(f"K8s warning events={warning_events}")
    if has_prom:
        prom_url = str(prometheus.get("url", "")).strip()
        signals.append(f"Prometheus ready{f'，url={prom_url}' if prom_url else ''}")
    configured = providers.get("configured", [])
    if isinstance(configured, list) and configured:
        signals.append(f"AI providers={','.join(str(item) for item in configured[:3])}")
    elif providers:
        signals.append("AI provider 未配置，当前更适合先用 mock 预览")

    summary_parts: list[str] = []
    if has_swarm:
        summary_parts.append(f"swarm={_safe_int(docker.get('swarm_services', 0))} services")
    elif has_docker:
        summary_parts.append("docker reachable")
    if has_k8s:
        summary_parts.append(
            f"k8s nodes={_safe_int(k8s.get('nodes', 0))}/problem_pods={_safe_int(k8s.get('problem_pods', 0))}"
        )
    if has_prom:
        summary_parts.append("prometheus ready")
    if exited > 0:
        summary_parts.append(f"exited_containers={exited}")
    summary = f"{label}; " + ", ".join(summary_parts[:3]) if summary_parts else label

    return {
        "profile": profile,
        "label": label,
        "summary": summary,
        "signals": _dedupe_strings(signals)[:6],
        "targets": targets,
    }


def _infer_runtime_targets(target: TargetEnvironment) -> list[str]:
    inferred_targets: list[str] = []
    if shutil.which("docker"):
        inferred_targets.append("docker")
    if str(target.ssh_target or settings.target_ssh_target or "").strip():
        inferred_targets.append("remote-ssh")
    if str(target.k8s_context or "").strip() or str(target.k8s_api_url or "").strip():
        inferred_targets.append("kubernetes")
    if str(target.prometheus_url or settings.target_prometheus_url or "").strip():
        inferred_targets.append("prometheus")
    watch_snapshot = _load_latest_watch_snapshot(None)
    if isinstance(watch_snapshot, dict):
        watch_targets = watch_snapshot.get("usable_targets", [])
        if isinstance(watch_targets, list):
            inferred_targets.extend(str(item).strip() for item in watch_targets if str(item).strip())
    return _dedupe_strings(inferred_targets)


def _build_environment_drift(marker: dict[str, object], current_targets: list[str]) -> dict[str, object]:
    if not isinstance(marker, dict) or not marker:
        return {"exists": False, "status": "unknown", "headline": "", "signals": [], "top_actions": []}
    baseline_raw = marker.get("usable_targets", [])
    baseline = [str(item).strip() for item in baseline_raw] if isinstance(baseline_raw, list) else []
    current = [str(item).strip() for item in current_targets if str(item).strip()]

    def _normalize_targets(items: list[str]) -> set[str]:
        normalized: set[str] = set()
        for item in items:
            text = str(item).strip().lower()
            if not text:
                continue
            normalized.add("docker" if text == "docker-swarm" else text)
        return normalized

    baseline_set = _normalize_targets(baseline)
    current_set = _normalize_targets(current)
    added = sorted(item for item in current_set if item not in baseline_set)
    removed = sorted(item for item in baseline_set if item not in current_set)

    generated_raw = str(marker.get("generated_at_utc", "")).strip()
    age_hours = 0.0
    if generated_raw:
        try:
            generated_dt = datetime.fromisoformat(generated_raw.replace("Z", "+00:00"))
            age_hours = max(0.0, (datetime.now(timezone.utc) - generated_dt).total_seconds() / 3600.0)
        except Exception:
            age_hours = 0.0

    signals: list[str] = [
        f"baseline={','.join(sorted(baseline_set)) or '(none)'}",
        f"current={','.join(sorted(current_set)) or '(none)'}",
    ]
    if added:
        signals.append(f"added={','.join(added)}")
    if removed:
        signals.append(f"removed={','.join(removed)}")
    if age_hours >= 24:
        signals.append(f"baseline_age_hours={age_hours:.1f}")

    top_actions = ["lazysre scan", "lazysre brief"]
    if "docker" in removed:
        top_actions.append("docker info")
    if "kubernetes" in removed:
        top_actions.append("kubectl config current-context")
    if "remote-ssh" in removed:
        top_actions.append("lazysre connect root@host")

    if added or removed:
        headline = (
            "环境基线发生漂移："
            + (f"新增 {','.join(added)} " if added else "")
            + (f"缺失 {','.join(removed)}" if removed else "")
        ).strip()
        status = "changed"
    elif age_hours >= 24:
        headline = f"环境基线已过期（{age_hours:.1f}h），建议刷新扫描。"
        status = "stale"
    else:
        headline = "环境基线稳定，当前运行时目标与基线一致。"
        status = "stable"

    return {
        "exists": True,
        "status": status,
        "headline": headline,
        "signals": _dedupe_strings(signals)[:6],
        "top_actions": _dedupe_strings(top_actions)[:4],
        "baseline_targets": sorted(baseline_set),
        "current_targets": sorted(current_set),
        "added_targets": added,
        "removed_targets": removed,
    }


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
    landscape = report.get("landscape", {})
    if not isinstance(landscape, dict):
        landscape = _build_environment_landscape(report)
    target_text = ", ".join(str(x) for x in targets) if isinstance(targets, list) and targets else "none"
    summary_text = (
        f"mode={report.get('mode', 'read-only')} usable_targets={target_text} "
        f"pass={summary.get('pass', 0)} warn={summary.get('warn', 0)} error={summary.get('error', 0)}"
    )
    profile_label = str(landscape.get("label", "")).strip()
    if profile_label:
        summary_text = f"{summary_text} profile={profile_label}"
    if Panel:
        _console.print(Panel(summary_text, title="Environment Scan", border_style="cyan"))
    briefing = report.get("briefing", {})
    if isinstance(briefing, dict) and Panel:
        evidence = briefing.get("evidence", [])
        evidence_lines = [f"- {item}" for item in evidence[:5]] if isinstance(evidence, list) else []
        lines = [
            f"状态: {briefing.get('status', '-')}",
            f"环境画像: {briefing.get('profile_label', profile_label or '-')}",
            f"结论: {briefing.get('headline', '-')}",
        ]
        if evidence_lines:
            lines.extend(["证据:", *[str(item) for item in evidence_lines]])
        if str(briefing.get("next", "")).strip():
            lines.append(f"下一步: {briefing.get('next')}")
        _console.print(Panel("\n".join(lines), title="AI Briefing", border_style="magenta"))
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


def _build_overview_brief_report(
    *,
    target: str,
    include_remote: bool,
    include_logs: bool,
    timeout_sec: int,
) -> dict[str, object]:
    scan_report = _collect_environment_discovery(timeout_sec=timeout_sec, secrets_file=None)
    remote_target = _resolve_ssh_target_arg(target) if include_remote else ""
    remote_report: dict[str, object] | None = None
    if remote_target:
        remote_report = _collect_remote_docker_report(
            target=remote_target,
            service_filter="",
            include_logs=include_logs,
            tail=120 if include_logs else 80,
            timeout_sec=timeout_sec,
        )
    report: dict[str, object] = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "overview-brief",
        "mode": "read-only/no-secret",
        "include_remote": bool(remote_report),
        "remote_target": remote_target,
        "scan": scan_report,
        "remote": remote_report,
    }
    report["briefing"] = _build_overview_briefing(scan_report=scan_report, remote_report=remote_report)
    report["recommended_commands"] = _build_overview_recommended_commands(report)
    return report


def _brief_status_rank(status: str) -> int:
    return {"healthy": 0, "clear": 0, "attention": 1, "needs_attention": 1, "blocked": 2}.get(str(status), 1)


def _build_overview_briefing(
    *,
    scan_report: dict[str, object],
    remote_report: dict[str, object] | None,
) -> dict[str, object]:
    scan_briefing = scan_report.get("briefing", {})
    if not isinstance(scan_briefing, dict):
        scan_briefing = _build_environment_scan_briefing(scan_report)
    remote_briefing = {}
    if isinstance(remote_report, dict):
        remote_briefing = remote_report.get("briefing", {})
        if not isinstance(remote_briefing, dict):
            remote_briefing = _build_remote_briefing(remote_report)

    scan_status = str(scan_briefing.get("status", "attention"))
    remote_status = str(remote_briefing.get("status", "")) if remote_briefing else ""
    status = scan_status
    if remote_status and _brief_status_rank(remote_status) > _brief_status_rank(status):
        status = remote_status

    scan_headline = str(scan_briefing.get("headline", "")).strip()
    remote_headline = str(remote_briefing.get("headline", "")).strip()
    if remote_headline:
        headline = f"本机：{scan_headline} 远程：{remote_headline}"
    else:
        headline = f"本机：{scan_headline}"

    evidence: list[str] = []
    for prefix, briefing in (("scan", scan_briefing), ("remote", remote_briefing)):
        raw_evidence = briefing.get("evidence", []) if isinstance(briefing, dict) else []
        if not isinstance(raw_evidence, list):
            continue
        for item in raw_evidence[:3]:
            evidence.append(f"{prefix}: {item}")

    next_step = str(remote_briefing.get("next", "")).strip() if remote_briefing and remote_status in {"blocked", "attention"} else ""
    if not next_step:
        next_step = str(scan_briefing.get("next", "")).strip()
    if not next_step and remote_briefing:
        next_step = str(remote_briefing.get("next", "")).strip()
    if not next_step:
        next_step = "lazysre scan"
    return {
        "status": status,
        "headline": headline.strip(),
        "evidence": evidence[:6],
        "next": next_step,
    }


def _build_overview_recommended_commands(report: dict[str, object]) -> list[str]:
    commands: list[str] = []
    def _push(value: str) -> None:
        command = str(value or "").strip()
        lower = command.lower()
        if (
            re.search(r"[\u4e00-\u9fff]", command)
            and not lower.startswith(("lazysre ", "lsre ", "python -m lazysre"))
        ):
            return
        if command and _looks_like_shell_command(command):
            commands.append(command)

    briefing = report.get("briefing", {})
    if isinstance(briefing, dict) and str(briefing.get("next", "")).strip():
        _push(str(briefing.get("next", "")).strip())
    scan_report = report.get("scan", {})
    if isinstance(scan_report, dict):
        scan_briefing = scan_report.get("briefing", {})
        if isinstance(scan_briefing, dict) and str(scan_briefing.get("next", "")).strip():
            _push(str(scan_briefing.get("next", "")).strip())
        actions = scan_report.get("next_actions", [])
        if isinstance(actions, list):
            for item in actions[:3]:
                _push(str(item))
    remote_report = report.get("remote", {})
    if isinstance(remote_report, dict):
        remote_briefing = remote_report.get("briefing", {})
        if isinstance(remote_briefing, dict) and str(remote_briefing.get("next", "")).strip():
            _push(str(remote_briefing.get("next", "")).strip())
        recommendations = remote_report.get("recommendations", [])
        if isinstance(recommendations, list):
            for item in recommendations[:4]:
                _push(str(item))
    commands.append("lazysre autopilot")
    return _dedupe_strings([item for item in commands if item.strip()])[:8]


def _render_overview_brief_report(report: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    briefing = report.get("briefing", {})
    if isinstance(briefing, dict) and Panel:
        evidence = briefing.get("evidence", [])
        evidence_lines = [f"- {item}" for item in evidence[:6]] if isinstance(evidence, list) else []
        lines = [
            f"状态: {briefing.get('status', '-')}",
            f"结论: {briefing.get('headline', '-')}",
        ]
        if evidence_lines:
            lines.extend(["证据:", *[str(item) for item in evidence_lines]])
        if str(briefing.get("next", "")).strip():
            lines.append(f"下一步: {briefing.get('next')}")
        _console.print(Panel("\n".join(lines), title="LazySRE Brief", border_style="magenta"))
    table = Table(title="Recommended Commands")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Command", style="green")
    commands = report.get("recommended_commands", [])
    if isinstance(commands, list):
        for idx, command in enumerate(commands[:8], 1):
            table.add_row(str(idx), str(command))
    _console.print(table)
    scan_report = report.get("scan", {})
    if isinstance(scan_report, dict):
        scan_briefing = scan_report.get("briefing", {})
        if isinstance(scan_briefing, dict) and Panel:
            _console.print(Panel(str(scan_briefing.get("headline", "")), title="Scan", border_style="cyan"))
    remote_report = report.get("remote", {})
    if isinstance(remote_report, dict):
        remote_briefing = remote_report.get("briefing", {})
        if isinstance(remote_briefing, dict) and Panel:
            _console.print(Panel(str(remote_briefing.get("headline", "")), title="Remote", border_style="cyan"))


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
    posture = _build_swarm_posture(
        summary=summary,
        services=services,
        unhealthy=unhealthy,
        bad_nodes=bad_nodes,
        root_causes=root_causes,
        recommendations=recommendations,
    )
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
        "posture": posture,
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


def _build_swarm_posture(
    *,
    summary: dict[str, object],
    services: list[dict[str, object]],
    unhealthy: list[dict[str, object]],
    bad_nodes: list[dict[str, object]],
    root_causes: list[dict[str, object]],
    recommendations: list[str],
    remote_target: str = "",
) -> dict[str, object]:
    service_items = services if isinstance(services, list) else []
    unhealthy_items = unhealthy if isinstance(unhealthy, list) else []
    bad_node_items = bad_nodes if isinstance(bad_nodes, list) else []
    cause_items = root_causes if isinstance(root_causes, list) else []
    recommendation_items = recommendations if isinstance(recommendations, list) else []
    target_label = f"{remote_target} 远程 " if str(remote_target).strip() else ""

    status = "healthy"
    if int(summary.get("error", 0) or 0) > 0:
        status = "blocked"
    elif unhealthy_items or bad_node_items or cause_items or int(summary.get("warn", 0) or 0) > 0:
        status = "attention"

    focus_service = ""
    focus_category = ""
    focus_advice = ""
    if cause_items and isinstance(cause_items[0], dict):
        focus = cause_items[0]
        focus_service = str(focus.get("service", "")).strip()
        focus_category = str(focus.get("category", "")).strip()
        focus_advice = str(focus.get("advice", "")).strip()

    if bad_node_items:
        names = [
            str(item.get("hostname", item.get("name", "-"))).strip()
            for item in bad_node_items[:3]
            if isinstance(item, dict)
        ]
        headline = f"{target_label}Swarm 当前有 {len(bad_node_items)} 个异常节点：{', '.join([x for x in names if x]) or 'unknown'}。"
    elif focus_category and focus_service:
        headline = f"{target_label}Swarm 主要阻塞点是 {focus_service}，根因倾向 {focus_category}。"
    elif unhealthy_items:
        names = [
            f"{str(item.get('name', '-')).strip()}({str(item.get('replicas', '-')).strip()})"
            for item in unhealthy_items[:4]
            if isinstance(item, dict)
        ]
        headline = f"{target_label}Swarm 有 {len(unhealthy_items)} 个服务副本异常：{', '.join([x for x in names if x]) or 'unknown'}。"
    elif service_items:
        headline = f"{target_label}Swarm service 副本状态整体正常。"
    else:
        headline = f"{target_label}未发现可分析的 Swarm service。"

    signals: list[str] = [
        f"services={len(service_items)}",
        f"unhealthy={len(unhealthy_items)}",
        f"bad_nodes={len(bad_node_items)}",
        f"warn={int(summary.get('warn', 0) or 0)} error={int(summary.get('error', 0) or 0)}",
    ]
    if focus_category:
        signals.append(f"top_root_cause={focus_category}")
    if focus_service:
        signals.append(f"focus_service={focus_service}")
    if focus_advice:
        signals.append(f"advice={focus_advice}")

    top_actions: list[str] = []
    if focus_category and (not remote_target):
        action = _action_from_swarm_root_cause(
            {
                "category": focus_category,
                "service": focus_service,
                "severity": "high",
                "advice": focus_advice,
            }
        )
        if isinstance(action, dict):
            command = str(action.get("command", "")).strip()
            if command and _looks_like_shell_command(command):
                top_actions.append(command)
    if focus_service:
        followup = (
            f"lazysre remote {remote_target} --service {focus_service} --logs"
            if remote_target
            else f"lazysre swarm --service {focus_service} --logs"
        )
        if _looks_like_shell_command(followup):
            top_actions.append(followup)
    for item in recommendation_items:
        text = str(item).strip()
        if text and _looks_like_shell_command(text):
            top_actions.append(text)
    top_actions = _dedupe_strings(top_actions)[:4]

    return {
        "status": status,
        "headline": headline,
        "summary": (
            f"services={len(service_items)} unhealthy={len(unhealthy_items)} "
            f"bad_nodes={len(bad_node_items)} root_causes={len(cause_items)}"
        ),
        "focus_service": focus_service,
        "focus_category": focus_category,
        "focus_advice": focus_advice,
        "signals": _dedupe_strings(signals)[:6],
        "top_actions": top_actions,
    }


def _render_swarm_health_report(report: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    summary = report.get("summary", {})
    posture = report.get("posture", {})
    if not isinstance(posture, dict):
        posture = {}
    summary_text = (
        f"ok={report.get('ok', False)} services={len(report.get('services', []))} "
        f"unhealthy={len(report.get('unhealthy_services', []))} "
        f"bad_nodes={len(report.get('bad_nodes', []))} "
        f"warn={summary.get('warn', 0)} error={summary.get('error', 0)}"
    )
    if Panel:
        _console.print(Panel(summary_text, title="Swarm Health", border_style="cyan"))
    if posture and Panel:
        lines = [
            f"状态: {posture.get('status', '-')}",
            f"结论: {posture.get('headline', '-')}",
            f"摘要: {posture.get('summary', '-')}",
        ]
        signals = posture.get("signals", [])
        if isinstance(signals, list) and signals:
            lines.extend(["信号:", *[f"- {str(item)}" for item in signals[:4]]])
        actions = posture.get("top_actions", [])
        if isinstance(actions, list) and actions:
            lines.extend(["下一步:", *[f"- {str(item)}" for item in actions[:3]]])
        _console.print(Panel("\n".join(lines), title="Swarm Posture", border_style="magenta"))
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


def _collect_remote_docker_report(
    *,
    target: str,
    service_filter: str = "",
    include_logs: bool = False,
    tail: int = 80,
    timeout_sec: int = 8,
) -> dict[str, object]:
    safe_target = _normalize_ssh_target(target)
    per_check_timeout = max(2, min(int(timeout_sec or 8), 20))
    tail = max(20, min(int(tail or 80), 500))
    checks: list[dict[str, object]] = []
    if not safe_target:
        checks.append(_scan_check("ssh.target", False, "error", str(target), "SSH target 格式不合法，示例：root@192.168.10.101"))
        return _remote_report_payload(
            target=str(target),
            include_logs=include_logs,
            service_filter=service_filter,
            checks=checks,
            services=[],
            unhealthy=[],
            nodes=[],
            bad_nodes=[],
            task_reports=[],
            log_reports=[],
            root_causes=[],
            recommendations=["请使用形如 root@192.168.10.101 的 SSH target"],
        )

    ping = _safe_run_ssh_command(safe_target, "printf lazysre-ok", timeout_sec=per_check_timeout)
    checks.append(
        _scan_check(
            "ssh.connect",
            bool(ping.get("ok")) and "lazysre-ok" in str(ping.get("stdout", "")),
            "pass" if bool(ping.get("ok")) and "lazysre-ok" in str(ping.get("stdout", "")) else "error",
            _probe_detail(ping),
            "" if bool(ping.get("ok")) else "无法 SSH 到目标机器，请检查网络、密钥或 ssh-agent；LazySRE 不会保存密码",
        )
    )
    if not bool(ping.get("ok")):
        return _remote_report_payload(
            target=safe_target,
            include_logs=include_logs,
            service_filter=service_filter,
            checks=checks,
            services=[],
            unhealthy=[],
            nodes=[],
            bad_nodes=[],
            task_reports=[],
            log_reports=[],
            root_causes=[],
            recommendations=[f"先确认本机可执行：ssh {safe_target} 'docker version'"],
        )

    version_probe = _safe_run_ssh_command(
        safe_target,
        _remote_shell_command(["docker", "version", "--format", "{{.Server.Version}}"]),
        timeout_sec=per_check_timeout,
    )
    docker_reachable = bool(version_probe.get("ok"))
    checks.append(
        _scan_check(
            "remote.docker.version",
            docker_reachable,
            "pass" if docker_reachable else "warn",
            str(version_probe.get("stdout", "")).strip() or _probe_detail(version_probe),
            "" if docker_reachable else "远程 Docker 不可访问，请检查 docker 是否运行以及当前 SSH 用户权限",
        )
    )
    if not docker_reachable:
        return _remote_report_payload(
            target=safe_target,
            include_logs=include_logs,
            service_filter=service_filter,
            checks=checks,
            services=[],
            unhealthy=[],
            nodes=[],
            bad_nodes=[],
            task_reports=[],
            log_reports=[],
            root_causes=[],
            recommendations=[f"ssh {safe_target} 'docker version'"],
        )

    swarm_probe = _safe_run_ssh_command(
        safe_target,
        _remote_shell_command(["docker", "info", "--format", "{{.Swarm.LocalNodeState}}"]),
        timeout_sec=per_check_timeout,
    )
    swarm_state = str(swarm_probe.get("stdout", "")).strip().lower() if bool(swarm_probe.get("ok")) else ""
    swarm_active = swarm_state == "active"
    checks.append(
        _scan_check(
            "remote.docker.swarm",
            swarm_active,
            "pass" if swarm_active else "warn",
            swarm_state or _probe_detail(swarm_probe),
            "" if swarm_active else "远程 Docker 未处于 active Swarm；如为单机 Docker，可先看 docker ps",
        )
    )

    exited_probe = _safe_run_ssh_command(
        safe_target,
        _remote_shell_command(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                "status=exited",
                "--format",
                "{{.Names}}\t{{.Status}}",
            ]
        ),
        timeout_sec=per_check_timeout,
    )
    exited_lines = _non_empty_lines(str(exited_probe.get("stdout", "")))
    checks.append(
        _scan_check(
            "remote.docker.exited_containers",
            bool(exited_probe.get("ok")) and len(exited_lines) == 0,
            "pass" if bool(exited_probe.get("ok")) and len(exited_lines) == 0 else "warn",
            "none" if not exited_lines else _preview_lines(exited_lines, limit=5),
            "" if not exited_lines else "远程存在已退出容器，可用 remote + logs 进一步查看",
        )
    )

    if not swarm_active:
        return _remote_report_payload(
            target=safe_target,
            include_logs=include_logs,
            service_filter=service_filter,
            checks=checks,
            services=[],
            unhealthy=[],
            nodes=[],
            bad_nodes=[],
            task_reports=[],
            log_reports=[],
            root_causes=[],
            recommendations=[f"lazysre remote {safe_target} --json"],
        )

    nodes_probe = _safe_run_ssh_command(
        safe_target,
        _remote_shell_command(
            ["docker", "node", "ls", "--format", "{{.Hostname}}\t{{.Status}}\t{{.Availability}}\t{{.ManagerStatus}}"]
        ),
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
            "remote.swarm.nodes",
            bool(nodes_probe.get("ok")) and not bad_nodes,
            "pass" if bool(nodes_probe.get("ok")) and not bad_nodes else "warn",
            "all ready" if not bad_nodes else _preview_lines([json.dumps(x, ensure_ascii=False) for x in bad_nodes], limit=6),
            "" if not bad_nodes else "远程 Swarm 存在非 Ready/Active 节点",
        )
    )

    services_probe = _safe_run_ssh_command(
        safe_target,
        _remote_shell_command(["docker", "service", "ls", "--format", "{{.Name}}\t{{.Mode}}\t{{.Replicas}}\t{{.Image}}"]),
        timeout_sec=per_check_timeout,
    )
    services = _parse_swarm_service_lines(str(services_probe.get("stdout", "")))
    if service_filter.strip():
        needle = service_filter.strip().lower()
        services = [row for row in services if needle in str(row.get("name", "")).lower()]
    unhealthy = [row for row in services if bool(row.get("unhealthy"))]
    checks.append(
        _scan_check(
            "remote.swarm.services",
            bool(services_probe.get("ok")) and not unhealthy,
            "pass" if bool(services_probe.get("ok")) and not unhealthy else "warn",
            f"services={len(services)} unhealthy={len(unhealthy)}" if bool(services_probe.get("ok")) else _probe_detail(services_probe),
            "" if not unhealthy else "远程 Swarm 存在副本未达期望的 service",
        )
    )

    selected = [str(row.get("name", "")) for row in (unhealthy or services) if str(row.get("name", "")).strip()]
    task_reports: list[dict[str, object]] = []
    log_reports: list[dict[str, object]] = []
    for name in selected[:8]:
        ps_probe = _safe_run_ssh_command(
            safe_target,
            _remote_shell_command(
                [
                    "docker",
                    "service",
                    "ps",
                    name,
                    "--no-trunc",
                    "--format",
                    "{{.Name}}\t{{.CurrentState}}\t{{.Error}}\t{{.Node}}",
                ]
            ),
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
            logs_probe = _safe_run_ssh_command(
                safe_target,
                _remote_shell_command(["docker", "service", "logs", "--tail", str(tail), name]),
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

    root_causes = _classify_swarm_root_causes(
        unhealthy=unhealthy,
        bad_nodes=bad_nodes,
        task_reports=task_reports,
        log_reports=log_reports,
    )
    recommendations = _build_remote_recommendations(
        target=safe_target,
        unhealthy=unhealthy,
        bad_nodes=bad_nodes,
        include_logs=include_logs,
        service_filter=service_filter,
    )
    return _remote_report_payload(
        target=safe_target,
        include_logs=include_logs,
        service_filter=service_filter,
        checks=checks,
        services=services,
        unhealthy=unhealthy,
        nodes=node_rows,
        bad_nodes=bad_nodes,
        task_reports=task_reports,
        log_reports=log_reports,
        root_causes=root_causes,
        recommendations=recommendations,
    )


def _remote_report_check_ok(report: dict[str, object], name: str) -> bool:
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        return False
    for raw in checks:
        item = raw if isinstance(raw, dict) else {}
        if str(item.get("name", "")).strip() == name:
            return bool(item.get("ok"))
    return False


def _remember_ssh_target_from_report(
    report: dict[str, object],
    *,
    profile_file: Path,
) -> dict[str, object]:
    target = _normalize_ssh_target(str(report.get("target", "") or ""))
    if not target:
        return {"saved": False, "target": "", "reason": "invalid ssh target"}
    if not _remote_report_check_ok(report, "ssh.connect"):
        return {"saved": False, "target": target, "reason": "ssh connectivity check failed"}
    store = TargetEnvStore(profile_file)
    current = store.load()
    already_saved = current.ssh_target.strip() == target
    if not already_saved:
        store.update(ssh_target=target)
    return {
        "saved": True,
        "target": target,
        "reason": "already saved" if already_saved else "ssh connectivity verified",
    }


def _run_remote_connect_flow(
    *,
    target: str,
    save_target: bool,
    include_logs: bool,
    tail: int,
    timeout_sec: int,
) -> dict[str, object]:
    resolved_target = _resolve_ssh_target_arg(target)
    report = _collect_remote_docker_report(
        target=resolved_target,
        service_filter="",
        include_logs=include_logs,
        tail=tail,
        timeout_sec=timeout_sec,
    )
    if save_target:
        report["target_save"] = _remember_ssh_target_from_report(
            report,
            profile_file=Path(settings.target_profile_file),
        )
    else:
        report["target_save"] = {
            "saved": False,
            "target": _normalize_ssh_target(str(report.get("target", "") or "")),
            "reason": "save disabled",
        }
    if "briefing" not in report:
        report["briefing"] = _build_remote_briefing(report)
    return report


def _remote_report_payload(
    *,
    target: str,
    include_logs: bool,
    service_filter: str,
    checks: list[dict[str, object]],
    services: list[dict[str, object]],
    unhealthy: list[dict[str, object]],
    nodes: list[dict[str, str]],
    bad_nodes: list[dict[str, str]],
    task_reports: list[dict[str, object]],
    log_reports: list[dict[str, object]],
    root_causes: list[dict[str, object]],
    recommendations: list[str],
) -> dict[str, object]:
    summary = _summarize_doctor_checks(checks)
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "remote-ssh",
        "target": target,
        "ok": bool(summary.get("error", 0) == 0 and len(unhealthy) == 0 and len(bad_nodes) == 0),
        "service_filter": service_filter,
        "include_logs": include_logs,
        "summary": summary,
        "checks": checks,
        "nodes": nodes,
        "bad_nodes": bad_nodes,
        "services": services,
        "unhealthy_services": unhealthy,
        "tasks": task_reports,
        "logs": log_reports,
        "root_causes": root_causes,
        "recommendations": recommendations,
    }
    payload["posture"] = _build_swarm_posture(
        summary=summary,
        services=services,
        unhealthy=unhealthy,
        bad_nodes=bad_nodes,
        root_causes=root_causes,
        recommendations=recommendations,
        remote_target=target,
    )
    payload["briefing"] = _build_remote_briefing(payload)
    return payload


def _remote_report_check(report: dict[str, object], name: str) -> dict[str, object]:
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        return {}
    for raw in checks:
        item = raw if isinstance(raw, dict) else {}
        if str(item.get("name", "")).strip() == name:
            return item
    return {}


def _build_remote_briefing(report: dict[str, object]) -> dict[str, object]:
    target = str(report.get("target", "") or "").strip() or "(unknown)"
    summary = report.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    unhealthy = report.get("unhealthy_services", [])
    unhealthy_items = unhealthy if isinstance(unhealthy, list) else []
    bad_nodes = report.get("bad_nodes", [])
    bad_node_items = bad_nodes if isinstance(bad_nodes, list) else []
    root_causes = report.get("root_causes", [])
    cause_items = root_causes if isinstance(root_causes, list) else []
    recommendations = report.get("recommendations", [])
    recommendation_items = recommendations if isinstance(recommendations, list) else []

    ssh_check = _remote_report_check(report, "ssh.connect")
    docker_check = _remote_report_check(report, "remote.docker.version")
    swarm_check = _remote_report_check(report, "remote.docker.swarm")
    status = "healthy" if bool(report.get("ok")) else "attention"
    evidence: list[str] = []

    if not _normalize_ssh_target(target):
        status = "blocked"
        headline = "SSH 目标格式不合法，LazySRE 还不能开始远程诊断。"
    elif ssh_check and not bool(ssh_check.get("ok")):
        status = "blocked"
        headline = f"无法连接远程服务器 {target}，优先检查网络、SSH Key 或 ssh-agent。"
        detail = str(ssh_check.get("detail", "") or "").strip()
        if detail:
            evidence.append(detail[:180])
    elif docker_check and not bool(docker_check.get("ok")):
        status = "attention"
        headline = f"{target} 的 SSH 已连通，但 Docker 当前不可访问。"
        detail = str(docker_check.get("detail", "") or "").strip()
        if detail:
            evidence.append(detail[:180])
    elif swarm_check and not bool(swarm_check.get("ok")):
        status = "attention"
        headline = f"{target} 的 Docker 可访问，但没有检测到 active Swarm。"
        detail = str(swarm_check.get("detail", "") or "").strip()
        if detail:
            evidence.append(f"Swarm state: {detail[:120]}")
    elif unhealthy_items:
        status = "attention"
        names = [
            f"{str(item.get('name', '-'))}({str(item.get('replicas', '-'))})"
            for item in unhealthy_items[:4]
            if isinstance(item, dict)
        ]
        headline = f"发现 {len(unhealthy_items)} 个远程 Swarm 服务副本异常：{', '.join(names) or 'unknown'}。"
    elif bad_node_items:
        status = "attention"
        names = [
            str(item.get("hostname", item.get("name", "-")))
            for item in bad_node_items[:4]
            if isinstance(item, dict)
        ]
        headline = f"发现 {len(bad_node_items)} 个远程 Swarm 节点状态异常：{', '.join(names) or 'unknown'}。"
    else:
        headline = f"{target} 远程 Docker/Swarm 只读体检未发现阻断性异常。"

    if not evidence:
        evidence.append(
            f"checks: pass={summary.get('pass', 0)} warn={summary.get('warn', 0)} error={summary.get('error', 0)}"
        )
    if cause_items:
        first = cause_items[0] if isinstance(cause_items[0], dict) else {}
        category = str(first.get("category", "unknown"))
        service = str(first.get("service", "-"))
        advice = str(first.get("advice", "")).strip()
        evidence.append(f"root_cause={category} service={service}" + (f" advice={advice[:120]}" if advice else ""))

    next_step = str(recommendation_items[0]).strip() if recommendation_items else ""
    if not next_step:
        next_step = f"lazysre remote {target} --json" if _normalize_ssh_target(target) else "lazysre connect root@host"
    return {
        "status": status,
        "headline": headline,
        "evidence": evidence[:4],
        "next": next_step,
    }


def _build_remote_recommendations(
    *,
    target: str,
    unhealthy: list[dict[str, object]],
    bad_nodes: list[dict[str, str]],
    include_logs: bool,
    service_filter: str,
) -> list[str]:
    items: list[str] = []
    for row in unhealthy[:5]:
        name = str(row.get("name", "")).strip()
        if name:
            items.append(f"lazysre remote {target} --service {name} --logs")
            items.append(f"lazysre fix \"远程 {target} 的 {name} 服务异常\"")
    if bad_nodes:
        items.append(f"lazysre remote {target} --json")
    if service_filter.strip() and not include_logs:
        items.append(f"lazysre remote {target} --service {service_filter.strip()} --logs")
    if not items:
        items.append(f"lazysre remote {target} --json")
    return _dedupe_strings(items)[:8]


def _render_remote_docker_report(report: dict[str, object]) -> None:
    if not (_console and Table):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    summary = report.get("summary", {})
    posture = report.get("posture", {})
    if not isinstance(posture, dict):
        posture = {}
    summary_text = (
        f"target={report.get('target', '-')} ok={report.get('ok', False)} "
        f"pass={summary.get('pass', 0)} warn={summary.get('warn', 0)} error={summary.get('error', 0)} "
        f"unhealthy_services={len(report.get('unhealthy_services', [])) if isinstance(report.get('unhealthy_services', []), list) else 0}"
    )
    if Panel:
        _console.print(Panel(summary_text, title="Remote Docker/Swarm", border_style="cyan"))
    if posture and Panel:
        lines = [
            f"状态: {posture.get('status', '-')}",
            f"结论: {posture.get('headline', '-')}",
            f"摘要: {posture.get('summary', '-')}",
        ]
        signals = posture.get("signals", [])
        if isinstance(signals, list) and signals:
            lines.extend(["信号:", *[f"- {str(item)}" for item in signals[:4]]])
        actions = posture.get("top_actions", [])
        if isinstance(actions, list) and actions:
            lines.extend(["下一步:", *[f"- {str(item)}" for item in actions[:3]]])
        _console.print(Panel("\n".join(lines), title="Swarm Posture", border_style="magenta"))
    briefing = report.get("briefing", {})
    if isinstance(briefing, dict) and Panel:
        evidence = briefing.get("evidence", [])
        evidence_lines = [f"- {item}" for item in evidence[:4]] if isinstance(evidence, list) else []
        lines = [
            f"状态: {briefing.get('status', '-')}",
            f"结论: {briefing.get('headline', '-')}",
        ]
        if evidence_lines:
            lines.extend(["证据:", *[str(item) for item in evidence_lines]])
        if str(briefing.get("next", "")).strip():
            lines.append(f"下一步: {briefing.get('next')}")
        _console.print(Panel("\n".join(lines), title="AI Briefing", border_style="magenta"))
    table = Table(title="Remote Checks")
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
    if report.get("root_causes") and Panel:
        lines = []
        for item in list(report.get("root_causes", []))[:8]:
            if isinstance(item, dict):
                lines.append(
                    f"- {item.get('category', 'unknown')} service={item.get('service', '-')} "
                    f"severity={item.get('severity', '-')}: {item.get('advice', '')}"
                )
        _console.print(Panel("\n".join(lines), title="Remote Root Causes", border_style="red"))
    recommendations = report.get("recommendations", [])
    if isinstance(recommendations, list) and recommendations and Panel:
        _console.print(Panel("\n".join(f"- {item}" for item in recommendations), title="Recommendations", border_style="green"))


def _render_remote_docker_report_markdown(report: dict[str, object]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# LazySRE Remote Docker/Swarm Report",
        "",
        f"- Generated: {report.get('generated_at_utc', '')}",
        f"- Target: `{report.get('target', '-')}`",
        f"- OK: `{report.get('ok', False)}`",
        f"- Summary: pass={summary.get('pass', 0)} warn={summary.get('warn', 0)} error={summary.get('error', 0)}",
        "",
        "## Briefing",
        "",
    ]
    briefing = report.get("briefing", {})
    if isinstance(briefing, dict) and briefing:
        lines.append(f"- Status: `{briefing.get('status', '-')}`")
        lines.append(f"- Headline: {briefing.get('headline', '-')}")
        evidence = briefing.get("evidence", [])
        if isinstance(evidence, list) and evidence:
            lines.append(f"- Evidence: {'; '.join(str(item) for item in evidence[:4])}")
        if str(briefing.get("next", "")).strip():
            lines.append(f"- Next: `{briefing.get('next')}`")
    else:
        lines.append("- No briefing generated.")
    lines.extend([
        "",
        "## Checks",
        "",
    ])
    for raw in report.get("checks", []):
        if not isinstance(raw, dict):
            continue
        lines.append(f"- `{raw.get('name', '-')}` severity=`{raw.get('severity', '-')}` detail={raw.get('detail', '-')}")
    lines.append("")
    root_causes = report.get("root_causes", [])
    lines.extend(["## Root Causes", ""])
    if isinstance(root_causes, list) and root_causes:
        for item in root_causes:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- `{item.get('category', 'unknown')}` service=`{item.get('service', '-')}` "
                f"severity=`{item.get('severity', '-')}`"
            )
            advice = str(item.get("advice", "")).strip()
            if advice:
                lines.append(f"  Advice: {advice}")
    else:
        lines.append("- No remote root causes classified.")
    lines.append("")
    recommendations = report.get("recommendations", [])
    lines.extend(["## Recommended Commands", ""])
    if isinstance(recommendations, list) and recommendations:
        lines.extend(["```bash", *[str(item) for item in recommendations], "```", ""])
    else:
        lines.append("- No direct commands suggested.")
    return "\n".join(lines)


def _normalize_ssh_target(target: str) -> str:
    value = str(target or "").strip()
    if not value:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+", value):
        return ""
    return value


def _resolve_ssh_target_arg(target: str) -> str:
    value = str(target or "").strip()
    if value in {"", "@target", "@active", "@ssh", "target"}:
        return str(TargetEnvStore(Path(settings.target_profile_file)).load().ssh_target or "").strip()
    return _normalize_ssh_target(value)


def _remote_shell_command(args: list[str]) -> str:
    return " ".join(shlex.quote(str(item)) for item in args)


def _safe_run_ssh_command(target: str, remote_command: str, *, timeout_sec: int) -> dict[str, object]:
    safe_target = _normalize_ssh_target(target)
    if not safe_target:
        return {"ok": False, "stdout": "", "stderr": "invalid ssh target", "exit_code": 2}
    timeout = max(2, min(int(timeout_sec or 8), 30))
    ssh_config = os.environ.get("LAZYSRE_SSH_CONFIG", "").strip()
    config_args: list[str] = []
    if ssh_config.lower() in {"default", "system", "user"}:
        config_args = []
    elif ssh_config:
        config_args = ["-F", ssh_config]
    else:
        # Avoid broken user SSH config from making explicit root@ip targets unusable.
        config_args = ["-F", "/dev/null"]
    return _safe_run_command(
        [
            "ssh",
            *config_args,
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={timeout}",
            safe_target,
            remote_command,
        ],
        timeout_sec=timeout + 2,
    )


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


def _latest_quick_action_file() -> Path:
    return Path(settings.data_dir) / "lsre-quick-action-last.json"


def _write_latest_quick_action_result(payload: dict[str, object]) -> Path:
    path = _latest_quick_action_file()
    _write_json_file(path, payload)
    return path


def _load_latest_quick_action_result(path: Path | None = None) -> dict[str, object]:
    candidate = path or _latest_quick_action_file()
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
            "posture": swarm_report.get("posture", {}) if isinstance(swarm_report, dict) else {},
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
        typer.echo(f"无法解析行动命令: {_safe_exception_text(exc)}")
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
            typer.echo(f"template action parse failed: {_safe_exception_text(exc)}")
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

    if subcommand == "brief":
        report = _build_overview_brief_report(
            target=_extract_ssh_target_from_text(" ".join(tokens[1:])),
            include_remote=True,
            include_logs="--logs" in " ".join(tokens[1:]).lower(),
            timeout_sec=5,
        )
        if _console:
            _render_overview_brief_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return True

    if subcommand == "remote":
        target = _resolve_ssh_target_arg(_extract_ssh_target_from_text(" ".join(tokens[1:])))
        if not target:
            typer.echo("remote action 缺少 SSH target。请先执行：lsre target set --ssh-target root@host")
            return False
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
        report = _collect_remote_docker_report(
            target=target,
            service_filter=service,
            include_logs=include_logs,
            tail=tail,
            timeout_sec=8,
        )
        if _console:
            _render_remote_docker_report(report)
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


def _find_quick_action_item(options: dict[str, object], action_id: int) -> dict[str, str] | None:
    if action_id <= 0:
        return None
    snapshot = _build_tui_dashboard_snapshot(options)
    items = snapshot.get("quick_action_items", [])
    if not isinstance(items, list):
        return None
    for raw in items:
        if not isinstance(raw, dict):
            continue
        try:
            current = int(raw.get("id", 0))
        except Exception:
            current = 0
        if current == action_id:
            return {str(k): str(v) for k, v in raw.items()}
    return None


def _run_suggested_command(command_text: str, *, options: dict[str, object], execute_mode: bool) -> tuple[bool, str]:
    command = str(command_text or "").strip()
    if not command:
        return False, "建议动作为空。"
    if command.startswith("/"):
        result = _handle_tui_input(command, {**options, "execute": execute_mode})
        return True, str(result).strip()
    state = {"ok": False}

    def _callback() -> None:
        state["ok"] = _run_action_command(command, options=options, execute_mode=execute_mode)

    output = _capture_plain_output(_callback)
    return bool(state["ok"]), output


def _run_quick_action_item(*, options: dict[str, object], action_id: int, execute_mode: bool) -> tuple[bool, str]:
    item = _find_quick_action_item(options, action_id)
    if not item:
        return False, f"Quick action not found: {action_id}"
    command = str(item.get("command", "")).strip()
    title = str(item.get("title", command)).strip() or command
    source = str(item.get("source", "suggested")).strip() or "suggested"
    ok, output = _run_suggested_command(command, options=options, execute_mode=execute_mode)
    output_lines = [line.strip() for line in str(output or "").splitlines() if line.strip()]
    payload = {
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "action_id": str(action_id),
        "title": title,
        "source": source,
        "command": command,
        "status": "ok" if ok else "fail",
        "output_preview": " | ".join(output_lines[:2])[:240],
    }
    _write_latest_quick_action_result(payload)
    snapshot = _build_tui_dashboard_snapshot(options)
    rendered = _render_quick_action_result(
        action_id=action_id,
        item={**item, "title": title, "source": source, "command": command},
        ok=ok,
        output=output,
        snapshot=snapshot,
    )
    return ok, rendered


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


def _run_remote_autopilot_cycle(
    *,
    goal: str,
    target: str,
    service_filter: str,
    include_logs: bool,
    timeout_sec: int,
) -> dict[str, object]:
    remote_report = _collect_remote_docker_report(
        target=target,
        service_filter=service_filter,
        include_logs=include_logs,
        tail=120 if include_logs else 80,
        timeout_sec=timeout_sec,
    )
    report = _build_remote_autopilot_report(goal=goal, remote_report=remote_report)
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


def _build_remote_autopilot_report(*, goal: str, remote_report: dict[str, object]) -> dict[str, object]:
    remote_summary = remote_report.get("summary", {})
    if not isinstance(remote_summary, dict):
        remote_summary = {}
    recommendations = remote_report.get("recommendations", [])
    commands = _dedupe_strings([str(x) for x in recommendations]) if isinstance(recommendations, list) else []
    target = str(remote_report.get("target", "")).strip()
    root_causes = remote_report.get("root_causes", [])
    if isinstance(root_causes, list) and root_causes and target:
        commands.append(f'lazysre fix "远程 {target} 的 Docker/Swarm 异常"')
    commands = _dedupe_strings(commands)[:8]
    action_inbox = _build_remote_action_inbox(remote_report, commands)
    warn_count = int(remote_summary.get("warn", 0) or 0)
    error_count = int(remote_summary.get("error", 0) or 0)
    unhealthy_count = len(remote_report.get("unhealthy_services", [])) if isinstance(remote_report.get("unhealthy_services", []), list) else 0
    root_cause_count = len(root_causes) if isinstance(root_causes, list) else 0
    needs_attention = bool((not bool(remote_report.get("ok", False))) or warn_count or error_count or unhealthy_count or root_cause_count)
    first_action = {}
    actions = action_inbox.get("actions", [])
    if isinstance(actions, list) and actions and isinstance(actions[0], dict):
        first_action = actions[0]
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "remote-autopilot",
        "goal": str(goal or "").strip() or "远程巡检并给出下一步行动",
        "status": "needs_attention" if needs_attention else "clear",
        "ok": not needs_attention,
        "summary": {
            "remote_warn": warn_count,
            "remote_error": error_count,
            "remote_unhealthy_services": unhealthy_count,
            "remote_root_causes": root_cause_count,
            "actions": int(action_inbox.get("summary", {}).get("total", 0)) if isinstance(action_inbox.get("summary", {}), dict) else 0,
        },
        "remote": remote_report,
        "action_inbox": action_inbox,
        "recommended_commands": commands,
        "next_step": _build_autopilot_next_step(needs_attention=needs_attention, first_action=first_action),
    }


def _build_remote_action_inbox(remote_report: dict[str, object], commands: list[str]) -> dict[str, object]:
    actions: list[dict[str, object]] = []
    seen: set[str] = set()
    target = str(remote_report.get("target", "")).strip()
    root_causes = remote_report.get("root_causes", [])
    if isinstance(root_causes, list):
        for cause in root_causes[:12]:
            if not isinstance(cause, dict):
                continue
            service = str(cause.get("service", "")).strip()
            category = str(cause.get("category", "remote_swarm_issue")).strip()
            severity = str(cause.get("severity", "medium")).strip() or "medium"
            command = f"lazysre remote {target} --service {service} --logs" if target and service else (commands[0] if commands else "")
            _append_action(
                actions,
                seen,
                {
                    "title": f"远程处理 {category}: {service or target or 'remote'}",
                    "source": "remote-root-cause",
                    "severity": "high" if severity == "high" else "medium",
                    "risk_level": "low",
                    "template": "",
                    "variables": {"target": target, "service": service},
                    "command": command,
                    "reason": str(cause.get("advice", "") or cause.get("evidence", ""))[:240],
                    "dedupe_key": f"remote:{target}:{category}:{service}:{command}",
                },
            )
    if not actions:
        for command in commands[:8]:
            _append_action(
                actions,
                seen,
                {
                    "title": "远程下一步建议",
                    "source": "remote-recommendation",
                    "severity": "medium",
                    "risk_level": "low",
                    "template": "",
                    "variables": {"target": target},
                    "command": command,
                    "reason": "remote report recommendation",
                    "dedupe_key": f"remote-command:{command}",
                },
            )
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
        "source": "remote-report",
        "watch_generated_at_utc": remote_report.get("generated_at_utc", ""),
        "ok": bool(actions),
        "summary": {"total": len(actions), **severity_counts},
        "actions": actions,
        "message": "" if actions else "No actionable remote findings.",
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
    raw = str(value or "").strip()
    if not raw:
        return 0
    try:
        return int(raw)
    except Exception:
        pass
    normalized = re.sub(r"\s+", "", raw).lower()
    prefixes = ("第", "#", "no.", "no")
    suffixes = (
        "个建议",
        "个动作",
        "个行动",
        "个推荐",
        "建议",
        "动作",
        "行动",
        "推荐",
        "步",
        "条",
        "项",
        "次",
        "个",
        "号",
    )
    for prefix in prefixes:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    changed = True
    while changed and normalized:
        changed = False
        for suffix in suffixes:
            if normalized.endswith(suffix):
                normalized = normalized[: -len(suffix)]
                changed = True
                break
    if not normalized:
        return 0
    if re.fullmatch(r"[0-9]+", normalized):
        try:
            return int(normalized)
        except Exception:
            return 0
    circled_map: dict[str, int] = {}
    for idx, ch in enumerate("①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳", 1):
        circled_map[ch] = idx
    for idx, ch in enumerate("❶❷❸❹❺❻❼❽❾❿", 1):
        circled_map[ch] = idx
    if normalized in circled_map:
        return circled_map[normalized]
    zh_digit = {
        "零": 0,
        "〇": 0,
        "一": 1,
        "二": 2,
        "两": 2,
        "三": 3,
        "四": 4,
        "五": 5,
        "六": 6,
        "七": 7,
        "八": 8,
        "九": 9,
    }
    if normalized == "十":
        return 10
    if "十" in normalized:
        parts = normalized.split("十")
        if len(parts) != 2:
            return 0
        left, right = parts
        if left == "":
            tens = 1
        elif left in zh_digit:
            tens = zh_digit[left]
        else:
            return 0
        if right == "":
            ones = 0
        elif right in zh_digit:
            ones = zh_digit[right]
        else:
            return 0
        return tens * 10 + ones
    if normalized in zh_digit:
        return zh_digit[normalized]
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


def _read_last_incident_session_summary(data_dir: Path) -> dict[str, object]:
    def _parse_time(raw: object, *, fallback: Path) -> float:
        text = str(raw or "").strip()
        if text:
            try:
                return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
            except Exception:
                pass
        try:
            return fallback.stat().st_mtime
        except Exception:
            return 0.0

    def _stage_line(name: str, payload: dict[str, object]) -> str:
        executed = int(payload.get("executed", 0) or 0)
        succeeded = int(payload.get("succeeded", 0) or 0)
        failed = int(payload.get("failed", 0) or 0)
        skipped = int(payload.get("skipped", payload.get("skipped_high_risk", 0)) or 0)
        if executed <= 0 and failed <= 0 and skipped <= 0:
            return ""
        line = f"{name}:{succeeded}/{executed}"
        if failed:
            line += f" fail={failed}"
        elif executed > 0:
            line += " ok"
        if skipped:
            line += f" skip={skipped}"
        return line

    fix_path = data_dir / "lsre-fix-last.json"
    remediation_path = data_dir / "lsre-remediation-last.json"
    candidates: list[tuple[float, dict[str, object]]] = []

    if fix_path.exists():
        try:
            payload = json.loads(fix_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        if isinstance(payload, dict):
            plan = payload.get("plan", {})
            apply_commands = [str(x).strip() for x in list(plan.get("apply_commands", [])) if str(x).strip()] if isinstance(plan, dict) else []
            rollback_commands = [str(x).strip() for x in list(plan.get("rollback_commands", [])) if str(x).strip()] if isinstance(plan, dict) else []
            instruction = str(payload.get("instruction", "")).strip()
            candidates.append(
                (
                    _parse_time(payload.get("generated_at"), fallback=fix_path),
                    {
                        "exists": True,
                        "source": "fix-plan",
                        "status": "plan-ready",
                        "headline": instruction[:120] or "最近一次修复计划已生成，等待执行。",
                        "objective": instruction[:180],
                        "mode": "plan",
                        "stage_flow": f"plan apply={len(apply_commands)} rollback={len(rollback_commands)}",
                        "next_step": "可先 /approve 分步执行，或用 lazysre remediate --from-last-plan --apply --verify 进入闭环执行。",
                        "commands": [
                            "/approve",
                            "/undo",
                            "lazysre remediate --from-last-plan --apply --verify",
                        ],
                        "generated_at": str(payload.get("generated_at", "")),
                        "remote_target": "",
                    },
                )
            )

    if remediation_path.exists():
        try:
            payload = json.loads(remediation_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        if isinstance(payload, dict):
            execution = payload.get("execution", {})
            execution = execution if isinstance(execution, dict) else {}
            stage_parts = [
                _stage_line("diagnose", execution.get("diagnose", {}) if isinstance(execution.get("diagnose", {}), dict) else {}),
                _stage_line("apply", execution.get("apply", {}) if isinstance(execution.get("apply", {}), dict) else {}),
                _stage_line("verify", execution.get("verify", {}) if isinstance(execution.get("verify", {}), dict) else {}),
                _stage_line("rollback", execution.get("rollback", {}) if isinstance(execution.get("rollback", {}), dict) else {}),
            ]
            objective = str(payload.get("objective", "")).strip()
            ok = bool(payload.get("ok", False))
            candidates.append(
                (
                    _parse_time(payload.get("generated_at_utc"), fallback=remediation_path),
                    {
                        "exists": True,
                        "source": "closed-loop-remediation",
                        "status": "monitoring" if ok else "attention",
                        "headline": objective[:120] or "最近一次闭环修复已执行。",
                        "objective": objective[:180],
                        "mode": str(payload.get("mode", "")).strip() or "-",
                        "stage_flow": " -> ".join(part for part in stage_parts if part) or "closed-loop",
                        "next_step": str(payload.get("next_step", "")).strip(),
                        "commands": ["/trace", "/timeline", "/activity"] if ok else ["/trace", "/timeline", "lazysre undo"],
                        "generated_at": str(payload.get("generated_at_utc", "")),
                        "remote_target": str(payload.get("remote_target", "")).strip(),
                    },
                )
            )

    if not candidates:
        return {"exists": False}
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _read_recent_audit_events(path: Path, *, limit: int = 4) -> list[str]:
    if limit <= 0 or not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    events: list[str] = []
    for raw in reversed(lines):
        text = raw.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        timestamp = str(payload.get("timestamp", "")).strip()
        stamp = ""
        if "T" in timestamp:
            stamp = timestamp.split("T", 1)[1][:5]
        elif timestamp:
            stamp = timestamp[:16]
        status = str(
            payload.get("status")
            or payload.get("result")
            or ("ok" if payload.get("ok") is True else "error" if payload.get("ok") is False else "")
        ).strip()
        command = payload.get("command")
        command_text = ""
        if isinstance(command, list):
            command_text = " ".join(str(part).strip() for part in command if str(part).strip())
        elif command is not None:
            command_text = str(command).strip()
        action = str(payload.get("action") or payload.get("tool") or payload.get("event") or "").strip()
        summary = command_text or action or str(payload.get("message", "")).strip()
        if not summary:
            continue
        parts = [part for part in [stamp, status, summary[:96]] if part]
        events.append(" | ".join(parts))
        if len(events) >= limit:
            break
    return list(reversed(events))


def _read_recent_audit_timeline(path: Path, *, limit: int = 5) -> list[dict[str, str]]:
    if limit <= 0 or not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    items: list[dict[str, str]] = []
    for raw in reversed(lines):
        text = raw.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        timestamp = str(payload.get("timestamp", "")).strip()
        time_label = ""
        if "T" in timestamp:
            time_label = timestamp.split("T", 1)[1][:5]
        elif timestamp:
            time_label = timestamp[:16]
        command = payload.get("command")
        if isinstance(command, list):
            command_text = " ".join(str(part).strip() for part in command if str(part).strip())
        else:
            command_text = str(command or payload.get("action") or payload.get("tool") or payload.get("event") or "").strip()
        if not command_text:
            continue
        ok_flag = payload.get("ok")
        status = "ok" if ok_flag is True else "fail" if ok_flag is False else str(payload.get("status", "")).strip() or "info"
        mode = "dry-run" if bool(payload.get("dry_run")) else "exec"
        target = str(payload.get("remote_target", "")).strip()
        summary = command_text[:96]
        if target:
            summary = f"{target} :: {summary}"[:110]
        stage = _infer_trace_stage(summary)
        items.append(
            {
                "time": time_label or "--:--",
                "status": status,
                "mode": mode,
                "stage": stage,
                "summary": summary,
            }
        )
        if len(items) >= limit:
            break
    return list(reversed(items))


def _build_recent_trace_summary(timeline: list[dict[str, str]]) -> list[str]:
    if not timeline:
        return ["暂无 trace，先运行 /scan、/timeline 或一次自然语言操作。"]
    ok_count = 0
    fail_count = 0
    dry_run_count = 0
    exec_count = 0
    tool_counts: dict[str, int] = {}
    stage_counts: dict[str, int] = {}
    for item in timeline:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "")).strip().lower()
        mode = str(item.get("mode", "")).strip().lower()
        summary = str(item.get("summary", "")).strip()
        stage = str(item.get("stage", "")).strip().lower() or _infer_trace_stage(summary)
        if status == "ok":
            ok_count += 1
        elif status == "fail":
            fail_count += 1
        if mode == "dry-run":
            dry_run_count += 1
        elif mode == "exec":
            exec_count += 1
        first = summary.split("::")[-1].strip().split(" ", 1)[0].strip().lower() if summary else ""
        if first:
            tool_counts[first] = tool_counts.get(first, 0) + 1
        if stage:
            stage_counts[stage] = stage_counts.get(stage, 0) + 1
    top_tools = sorted(tool_counts.items(), key=lambda item: (-item[1], item[0]))[:3]
    latest = timeline[-1]
    latest_summary = str(latest.get("summary", "")).strip()
    latest_status = str(latest.get("status", "info")).strip()
    latest_mode = str(latest.get("mode", "-")).strip()
    lines = [
        f"steps={len(timeline)} ok={ok_count} fail={fail_count} dry-run={dry_run_count} exec={exec_count}",
        f"latest=[{latest_status}/{latest_mode}] {latest_summary[:96]}",
    ]
    if top_tools:
        lines.append("top-tools=" + ", ".join(f"{name}x{count}" for name, count in top_tools))
    if stage_counts:
        ordered_stages = ["observe", "plan", "apply", "verify", "other"]
        parts = [f"{name}x{stage_counts[name]}" for name in ordered_stages if stage_counts.get(name)]
        if parts:
            lines.append("stage-flow=" + " -> ".join(parts))
    return lines


def _build_tui_focus_card(
    *,
    recent_activity: list[str],
    recent_activity_commands: list[str],
    provider_report: dict[str, object],
    timeline: list[dict[str, str]],
    environment_drift: dict[str, object] | None = None,
    incident_session: dict[str, object] | None = None,
    watch_snapshot: dict[str, object] | None = None,
) -> dict[str, object]:
    latest_failure = next(
        (
            item
            for item in reversed(timeline)
            if isinstance(item, dict) and str(item.get("status", "")).strip().lower() == "fail"
        ),
        None,
    )
    if isinstance(latest_failure, dict):
        return {
            "title": "Recent Failure",
            "body": (
                f"{latest_failure.get('time', '--:--')} "
                f"[{latest_failure.get('stage', 'other')}/{latest_failure.get('mode', '-')}] "
                f"{str(latest_failure.get('summary', ''))[:120]}"
            ).strip(),
            "actions": ["/trace", "/timeline"],
        }
    posture = (
        ((watch_snapshot or {}).get("swarm", {}) if isinstance((watch_snapshot or {}).get("swarm", {}), dict) else {}).get("posture", {})
        if isinstance(watch_snapshot, dict)
        else {}
    )
    if isinstance(posture, dict) and str(posture.get("headline", "")).strip():
        actions = posture.get("top_actions", [])
        normalized_actions = [
            str(item).strip()
            for item in actions
            if str(item).strip() and _looks_like_shell_command(str(item).strip())
        ] if isinstance(actions, list) else []
        return {
            "title": "Swarm Posture",
            "body": (
                f"{str(posture.get('headline', '')).strip()} "
                f"{str(posture.get('summary', '')).strip()}"
            ).strip()[:140],
            "actions": normalized_actions[:2] or ["/activity", "/swarm --logs"],
        }
    if isinstance(environment_drift, dict) and str(environment_drift.get("status", "")).strip() in {"changed", "stale"}:
        actions = environment_drift.get("top_actions", [])
        normalized_actions = [str(item).strip() for item in actions if str(item).strip()] if isinstance(actions, list) else []
        return {
            "title": "Environment Drift",
            "body": str(environment_drift.get("headline", "")).strip()[:140],
            "actions": normalized_actions[:2] or ["/drift", "/scan"],
        }
    if isinstance(incident_session, dict) and bool(incident_session.get("exists")):
        headline = str(incident_session.get("headline", "")).strip()
        stage_flow = str(incident_session.get("stage_flow", "")).strip()
        commands = incident_session.get("commands", [])
        normalized_commands = [str(item).strip() for item in commands if str(item).strip()] if isinstance(commands, list) else []
        if headline or stage_flow:
            return {
                "title": "Incident Session",
                "body": f"{headline} {stage_flow}".strip()[:140],
                "actions": normalized_commands[:2] or ["/trace", "/timeline"],
            }
    alert = next((item for item in recent_activity if "attention" in str(item).lower()), "")
    if str(alert).strip():
        actions = [cmd for cmd in recent_activity_commands[:2] if str(cmd).strip()] or ["/activity", "/scan"]
        return {
            "title": "Active Alert",
            "body": str(alert).strip()[:140],
            "actions": actions,
        }
    if isinstance(provider_report, dict) and not bool(provider_report.get("active_ready")):
        detail = str(provider_report.get("active_detail", "") or provider_report.get("active_hint", "")).strip()
        return {
            "title": "Provider Needs Setup",
            "body": detail[:140] or "当前 active provider 尚未就绪，先检查 provider/runtime 配置。",
            "actions": ["/providers", "/provider auto"],
        }
    return {
        "title": "Ready",
        "body": "当前没有明显阻塞，建议从 /brief、/scan 或 /activity 开始下一轮检查。",
        "actions": ["/brief", "/scan"],
    }


def _build_quick_action_catalog(
    *,
    focus_title: str,
    focus_actions: list[str],
    recent_activity_commands: list[str],
    recommended_commands: list[str],
    watch_snapshot: dict[str, object],
) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    seen: set[str] = set()

    def _add(command: str, *, title: str, source: str) -> None:
        cmd = str(command or "").strip()
        if not cmd:
            return
        key = cmd.lower()
        if key in seen:
            return
        seen.add(key)
        items.append(
            {
                "id": str(len(items) + 1),
                "title": str(title or cmd).strip()[:80],
                "source": str(source or "suggested").strip(),
                "command": cmd,
            }
        )

    for cmd in focus_actions[:3]:
        _add(str(cmd), title=f"{focus_title or 'Focus'}", source="focus")

    watch_inbox = _build_action_inbox_from_watch(watch_snapshot if isinstance(watch_snapshot, dict) else {})
    actions = watch_inbox.get("actions", [])
    if isinstance(actions, list):
        for raw in actions[:3]:
            if not isinstance(raw, dict):
                continue
            _add(
                str(raw.get("command", "")),
                title=str(raw.get("title", "Watch action")).strip() or "Watch action",
                source=f"watch/{str(raw.get('severity', 'info')).strip() or 'info'}",
            )

    for cmd in recent_activity_commands[:4]:
        _add(str(cmd), title="Recent Activity", source="activity")

    for cmd in recommended_commands[:6]:
        _add(str(cmd), title="Recommended", source="recommended")

    return items[:8]


def _annotate_quick_action_catalog(
    items: list[dict[str, str]],
    *,
    latest_result: dict[str, object],
) -> list[dict[str, str]]:
    annotated: list[dict[str, str]] = []
    latest_command = str(latest_result.get("command", "")).strip()
    latest_status = str(latest_result.get("status", "")).strip()
    latest_summary = str(latest_result.get("output_preview", "")).strip()
    latest_when = str(latest_result.get("executed_at_utc", "")).strip()
    for raw in items:
        item = dict(raw)
        command = str(item.get("command", "")).strip()
        if latest_command and command == latest_command:
            if latest_status:
                item["last_status"] = latest_status
            if latest_summary:
                item["last_output_preview"] = latest_summary[:120]
            if latest_when:
                item["last_executed_at_utc"] = latest_when
        item["kind"] = _classify_quick_action_kind(command)
        item["risk"] = _classify_quick_action_risk(command)
        item["confidence"] = _classify_quick_action_confidence(item)
        annotated.append({str(k): str(v) for k, v in item.items()})
    return annotated


def _sort_quick_action_catalog(
    items: list[dict[str, str]],
    *,
    latest_result: dict[str, object],
) -> list[dict[str, str]]:
    latest_failed = str(latest_result.get("status", "")).strip().lower() == "fail"
    latest_succeeded = str(latest_result.get("status", "")).strip().lower() == "ok"
    latest_command = str(latest_result.get("command", "")).strip()

    def _rank(item: dict[str, str]) -> tuple[int, int, str, str]:
        command = str(item.get("command", "")).strip()
        source = str(item.get("source", "")).strip()
        kind = str(item.get("kind", "")).strip() or _classify_quick_action_kind(command)
        risk = str(item.get("risk", "")).strip() or _classify_quick_action_risk(command)
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3, "unknown": 4}
        repeated_success_penalty = 1 if latest_succeeded and latest_command and command == latest_command else 0
        bucket = 5

        if latest_failed:
            if command == "/trace":
                bucket = 0
                return (bucket, 0, source, command)
            if command == "/timeline":
                bucket = 1
                return (bucket, 0, source, command)
            if kind == "inspect" and risk == "low":
                bucket = 2
            elif source == "focus":
                bucket = 3
            elif risk in {"medium"}:
                bucket = 4
            elif risk in {"high", "critical"}:
                bucket = 6
            else:
                bucket = 5
            return (bucket, risk_order.get(risk, 4), source, command)

        if source == "focus" and risk == "low":
            bucket = 0
        elif kind == "inspect" and risk == "low":
            bucket = 1
        elif source == "activity":
            bucket = 2
        elif risk == "medium":
            bucket = 3
        elif kind == "remote" and risk == "low":
            bucket = 4
        elif risk in {"high", "critical"}:
            bucket = 6
        else:
            bucket = 5
        if repeated_success_penalty:
            bucket += 2
        return (bucket, risk_order.get(risk, 4), source, command)

    ordered = sorted(items, key=_rank)
    normalized: list[dict[str, str]] = []
    for index, raw in enumerate(ordered, 1):
        item = dict(raw)
        item["id"] = str(index)
        normalized.append({str(k): str(v) for k, v in item.items()})
    return normalized


def _infer_trace_stage(summary: str) -> str:
    text = str(summary or "").strip().lower()
    command = text.split("::")[-1].strip()
    if not command:
        return "other"
    if any(token in command for token in ["fix plan", "runbook", "template ", "report ", "brief"]):
        return "plan"
    if any(
        token in command
        for token in [
            " apply ",
            " patch ",
            " delete ",
            " scale ",
            " update ",
            " rollout restart",
            " rollout undo",
            " service update",
            " service rollback",
            " restart ",
            " remediate",
        ]
    ):
        return "apply"
    if any(token in command for token in [" wait ", " rollout status", " health", "/health", " verify", " status "]):
        return "verify"
    if any(
        token in command
        for token in [
            " get ",
            " describe ",
            " logs",
            " top ",
            " service ls",
            " service ps",
            " service inspect",
            " node ls",
            " docker info",
            " kubectl ",
            " curl ",
            " journalctl",
            " tail ",
        ]
    ):
        return "observe"
    return "other"


def _build_tui_recent_activity_context(options: dict[str, object]) -> dict[str, object]:
    items: list[str] = []
    commands: list[str] = []
    watch_snapshot = _load_latest_watch_snapshot(None)
    posture: dict[str, object] = {}
    incident_session = _read_last_incident_session_summary(Path(settings.data_dir))
    if watch_snapshot:
        alerts = watch_snapshot.get("alerts", [])
        alert_count = len(alerts) if isinstance(alerts, list) else 0
        items.append(
            "watch "
            + (
                f"attention alerts={alert_count} cycle={watch_snapshot.get('cycle', '-')}"
                if alert_count
                else f"healthy cycle={watch_snapshot.get('cycle', '-')}"
            )
        )
        if alert_count:
            commands.append("/activity")
            first_alert = alerts[0] if isinstance(alerts, list) and alerts else {}
            if isinstance(first_alert, dict):
                alert_name = str(first_alert.get("name", "")).strip()
                alert_source = str(first_alert.get("source", "")).strip()
                if alert_source.startswith("swarm") and alert_name:
                    commands.append(f"/swarm --service {alert_name} --logs")
        swarm = watch_snapshot.get("swarm", {})
        if isinstance(swarm, dict):
            posture = swarm.get("posture", {})
            if isinstance(posture, dict) and str(posture.get("headline", "")).strip():
                items.append(
                    f"swarm posture | {str(posture.get('headline', '')).strip()[:92]}"
                )
                top_actions = posture.get("top_actions", [])
                if isinstance(top_actions, list):
                    commands.extend(str(item).strip() for item in top_actions[:2] if str(item).strip())
    last_fix_path = Path(str(options.get("fix_plan_file", Path(settings.data_dir) / "lsre-fix-last.json"))).expanduser()
    last_fix = _read_last_fix_plan_summary(last_fix_path)
    if bool(last_fix.get("exists")):
        instruction = str(last_fix.get("instruction", "")).strip() or "最近一次修复计划"
        items.append(f"fix plan | cmds={last_fix.get('apply_commands', 0)} | {instruction[:72]}")
        commands.extend(["/activity", "/undo", "/approve"])
    if bool(incident_session.get("exists")):
        headline = str(incident_session.get("headline", "")).strip() or "最近一次 incident session"
        status = str(incident_session.get("status", "")).strip() or "unknown"
        items.append(f"incident {status} | {headline[:72]}")
        incident_commands = incident_session.get("commands", [])
        if isinstance(incident_commands, list):
            commands.extend(str(item).strip() for item in incident_commands[:2] if str(item).strip())
    audit_log = Path(str(options.get("audit_log", ".data/lsre-audit.jsonl"))).expanduser()
    items.extend(_read_recent_audit_events(audit_log, limit=3))
    if not items:
        items = ["还没有最近活动，先运行 /scan、/brief 或一次自然语言诊断。"]
        commands.append("/scan")
    return {
        "items": _dedupe_strings([str(item).strip() for item in items if str(item).strip()])[:5],
        "commands": _dedupe_strings([str(item).strip() for item in commands if str(item).strip()])[:4],
        "watch": watch_snapshot if isinstance(watch_snapshot, dict) else {},
        "swarm_posture": posture if isinstance(posture, dict) else {},
        "last_fix": last_fix,
        "incident_session": incident_session if isinstance(incident_session, dict) else {},
        "audit_log": str(audit_log),
    }


def _render_recent_activity_text(options: dict[str, object]) -> str:
    context = _build_tui_recent_activity_context(options)
    items = context.get("items", [])
    if not isinstance(items, list):
        items = []
    commands = context.get("commands", [])
    if not isinstance(commands, list):
        commands = []
    lines = ["Recent Activity", *[f"- {item}" for item in items]]
    if commands:
        lines.extend(["", "Suggested Next Commands", *[f"- {item}" for item in commands]])
    return "\n".join(lines)


def _render_focus_text(options: dict[str, object]) -> str:
    snapshot = _build_tui_dashboard_snapshot(options)
    focus_title = str(snapshot.get("focus_title", "")).strip() or "Focus"
    focus_body = str(snapshot.get("focus_body", "")).strip() or "当前没有明显阻塞。"
    focus_actions = snapshot.get("focus_actions", [])
    if not isinstance(focus_actions, list):
        focus_actions = []
    lines = ["Focus", f"- {focus_title}: {focus_body}"]
    if focus_actions:
        lines.extend(["", "Suggested Next Commands", *[f"- {item}" for item in focus_actions]])
    return "\n".join(lines)


def _render_environment_drift_text(options: dict[str, object]) -> str:
    snapshot = _build_tui_dashboard_snapshot(options)
    drift = snapshot.get("environment_drift", {})
    if not isinstance(drift, dict) or not bool(drift.get("exists")):
        return "Environment Drift\n- 暂无基线信息。先运行 /scan 或 /brief 建立环境基线。"
    lines = [
        "Environment Drift",
        f"- Status: {drift.get('status', '-')}",
        f"- Headline: {drift.get('headline', '-')}",
    ]
    signals = drift.get("signals", [])
    if isinstance(signals, list) and signals:
        lines.extend(["", "Signals", *[f"- {str(item)}" for item in signals[:5]]])
    actions = drift.get("top_actions", [])
    if isinstance(actions, list) and actions:
        lines.extend(["", "Suggested Next Commands", *[f"- {str(item)}" for item in actions[:4]]])
    return "\n".join(lines)


def _render_quick_actions_text(options: dict[str, object]) -> str:
    snapshot = _build_tui_dashboard_snapshot(options)
    items = snapshot.get("quick_action_items", [])
    if not isinstance(items, list):
        items = []
    if not items:
        return "Quick Actions\n- 暂无快捷建议，先运行 /focus、/activity 或 /scan。"
    lines = ["Quick Actions"]
    for raw in items[:8]:
        item = raw if isinstance(raw, dict) else {}
        lines.append(f"- {_format_quick_action_line(item)}")
        lines.append(f"  {_format_quick_action_command(item)}")
        output_preview = str(item.get("last_output_preview", "")).strip()
        if output_preview:
            lines.append(f"  last-output: {output_preview}")
    latest = snapshot.get("latest_quick_action", {})
    if isinstance(latest, dict) and str(latest.get("command", "")).strip():
        lines.extend(
            [
                "",
                "Last Run",
                f"- {latest.get('status', 'unknown')}: {latest.get('command', '')}",
            ]
        )
    lines.extend(["", "Usage", "- /do 1", "- /do 2"])
    return "\n".join(lines)


def _render_tui_history_text(options: dict[str, object], *, query: str = "") -> str:
    snapshot = _build_tui_dashboard_snapshot(options)
    rows = _collect_snapshot_recent_commands(snapshot, limit=12)
    return _render_history_text(rows, query=query)


def _render_history_text(rows: list[str], *, query: str = "") -> str:
    clean_rows = [str(item).strip() for item in rows if str(item).strip()]
    if not clean_rows:
        return "History\n- 暂无历史输入。先输入一句话或执行 /scan。"
    needle = str(query or "").strip().lower()
    if needle:
        filtered = [item for item in clean_rows if needle in item.lower()]
        if not filtered:
            return f"History Search: {query}\n- 没有匹配结果。可先输入 /history 查看全部历史。"
        lines = [f"History Search: {query} (latest first)"]
        for idx, command in enumerate(reversed(filtered), 1):
            lines.append(f"- {idx}. {command}")
        lines.extend(["", "Usage", "- /history", f"- /history {query}", "- /history 1", "- /retry"])
        return "\n".join(lines)
    lines = ["History (latest first)"]
    for idx, command in enumerate(reversed(clean_rows), 1):
        lines.append(f"- {idx}. {command}")
    lines.extend(["", "Usage", "- /history", "- /history <keyword>", "- /history 1", "- /retry"])
    return "\n".join(lines)


def _collect_snapshot_recent_commands(snapshot: dict[str, object], *, limit: int = 12) -> list[str]:
    cap = max(1, min(int(limit), 100))
    recent_commands_full = snapshot.get("recent_commands_full", [])
    if not isinstance(recent_commands_full, list):
        recent_commands_full = []
    recent_commands = snapshot.get("recent_commands", [])
    if not isinstance(recent_commands, list):
        recent_commands = []
    source = recent_commands_full or recent_commands
    rows = [str(item).strip() for item in source if str(item).strip()]
    return rows[-cap:]


def _render_quick_action_result(
    *,
    action_id: int,
    item: dict[str, str],
    ok: bool,
    output: str,
    snapshot: dict[str, object],
) -> str:
    title = str(item.get("title", item.get("command", ""))).strip() or str(item.get("command", "")).strip()
    source = str(item.get("source", "suggested")).strip() or "suggested"
    command = str(item.get("command", "")).strip()
    lines = [
        "Quick Action Result",
        f"- Action: {action_id}. [{source}] {title}",
        f"- Command: {command or '-'}",
        f"- Status: {'success' if ok else 'failed'}",
    ]
    output_lines = [line for line in str(output or "").splitlines() if str(line).strip()]
    if output_lines:
        lines.extend(["", "Output"])
        preview = output_lines[:10]
        lines.extend(f"- {line}" for line in preview)
        if len(output_lines) > len(preview):
            lines.append(f"- ... ({len(output_lines) - len(preview)} more lines)")
    focus_title = str(snapshot.get("focus_title", "")).strip()
    focus_body = str(snapshot.get("focus_body", "")).strip()
    if focus_title or focus_body:
        lines.extend(["", "Focus Now", f"- {focus_title or 'Focus'}: {focus_body or '-'}"])
    items = snapshot.get("quick_action_items", [])
    if isinstance(items, list) and items:
        lines.extend(["", "Next Quick Actions"])
        if not ok:
            lines.append("- /trace: 查看最近执行链路")
            lines.append("- /timeline: 查看完整时间线")
        for raw in items[:3]:
            if not isinstance(raw, dict):
                continue
            command_text = str(raw.get("command", "")).strip()
            if (not ok) and command_text in {"/trace", "/timeline"}:
                continue
            lines.append(f"- /do {raw.get('id', '?')}: {command_text}")
    return "\n".join(lines)


def _build_tui_state_card(snapshot: dict[str, object]) -> dict[str, str]:
    focus_title = str(snapshot.get("focus_title", "")).strip() or "Focus"
    focus_body = str(snapshot.get("focus_body", "")).strip() or "-"
    incident_session = snapshot.get("incident_session", {})
    if not isinstance(incident_session, dict):
        incident_session = {}
    environment_drift = snapshot.get("environment_drift", {})
    if not isinstance(environment_drift, dict):
        environment_drift = {}
    latest = snapshot.get("latest_quick_action", {})
    if not isinstance(latest, dict):
        latest = {}
    latest_status = str(latest.get("status", "")).strip() or "idle"
    latest_command = str(latest.get("command", "")).strip() or "-"
    quick_line = f"{latest_status}: {latest_command[:72]}"

    next_line = "-"
    if latest_status == "fail":
        next_line = "/trace -> /timeline -> /do 1"
    elif bool(incident_session.get("exists")):
        incident_commands = incident_session.get("commands", [])
        if isinstance(incident_commands, list) and incident_commands:
            next_line = str(incident_commands[0])[:72]
        else:
            next_line = str(incident_session.get("next_step", "")).strip()[:72] or "-"
    elif str(environment_drift.get("status", "")).strip() in {"changed", "stale"}:
        drift_actions = environment_drift.get("top_actions", [])
        if isinstance(drift_actions, list) and drift_actions:
            next_line = str(drift_actions[0])[:72]
        else:
            next_line = "/drift"
    else:
        quick_actions = snapshot.get("quick_action_items", [])
        if isinstance(quick_actions, list):
            for raw in quick_actions:
                if not isinstance(raw, dict):
                    continue
                command = str(raw.get("command", "")).strip()
                action_id = str(raw.get("id", "")).strip()
                if command and action_id:
                    if latest_status == "ok" and command == latest_command:
                        continue
                    next_line = f"/do {action_id} -> {command[:56]}"
                    break
        if next_line == "-":
            focus_actions = snapshot.get("focus_actions", [])
            if isinstance(focus_actions, list) and focus_actions:
                next_line = str(focus_actions[0])[:64]
    return {
        "focus": f"{focus_title}: {focus_body[:96]}",
        "quick": quick_line,
        "next": next_line,
    }


def _classify_quick_action_kind(command_text: str) -> str:
    command = str(command_text or "").strip()
    if not command:
        return "other"
    lowered = command.lower()
    if command.startswith("/"):
        if any(lowered.startswith(prefix) for prefix in ["/trace", "/timeline", "/activity", "/focus", "/scan", "/brief", "/providers"]):
            return "inspect"
        if any(lowered.startswith(prefix) for prefix in ["/do", "/actions"]):
            return "dispatch"
        return "command"
    if lowered.startswith("lazysre template run") or lowered.startswith("lsre template run"):
        return "template"
    if lowered.startswith("lazysre remote") or lowered.startswith("lsre remote"):
        return "remote"
    if lowered.startswith("lazysre fix") or lowered.startswith("lsre fix") or lowered.startswith("lazysre remediate") or lowered.startswith("lsre remediate"):
        return "repair"
    if lowered.startswith("lazysre swarm") or lowered.startswith("lsre swarm") or lowered.startswith("lazysre scan") or lowered.startswith("lsre scan") or lowered.startswith("lazysre brief") or lowered.startswith("lsre brief"):
        return "inspect"
    try:
        tokens = shlex.split(command)
    except Exception:
        return "other"
    if not tokens:
        return "other"
    decision = assess_command(tokens)
    if decision.risk_level in {"high", "critical"}:
        return "write"
    if tokens[0] in {"ssh", "scp"}:
        return "remote"
    return "inspect"


def _classify_quick_action_risk(command_text: str) -> str:
    command = str(command_text or "").strip()
    if not command:
        return "unknown"
    lowered = command.lower()
    if command.startswith("/"):
        if any(lowered.startswith(prefix) for prefix in ["/trace", "/timeline", "/activity", "/focus", "/scan", "/brief", "/providers", "/do", "/actions"]):
            return "low"
        return "medium"
    if lowered.startswith("lazysre template run") or lowered.startswith("lsre template run"):
        return "high" if "--apply" in lowered else "medium"
    if lowered.startswith("lazysre fix") or lowered.startswith("lsre fix") or lowered.startswith("lazysre remediate") or lowered.startswith("lsre remediate"):
        return "high"
    if lowered.startswith("lazysre remote") or lowered.startswith("lsre remote"):
        return "low" if ("--logs" in lowered or "--service" in lowered) else "medium"
    if lowered.startswith("lazysre swarm") or lowered.startswith("lsre swarm") or lowered.startswith("lazysre scan") or lowered.startswith("lsre scan") or lowered.startswith("lazysre brief") or lowered.startswith("lsre brief"):
        return "low"
    try:
        tokens = shlex.split(command)
    except Exception:
        return "unknown"
    if not tokens:
        return "unknown"
    return str(assess_command(tokens).risk_level or "unknown")


def _classify_quick_action_confidence(item: dict[str, object]) -> str:
    source = str(item.get("source", "")).strip().lower()
    kind = str(item.get("kind", "")).strip().lower()
    risk = str(item.get("risk", "")).strip().lower()
    command = str(item.get("command", "")).strip().lower()
    if risk in {"high", "critical"}:
        return "low"
    if source.startswith("watch/") and risk == "low":
        return "high"
    if source == "focus" and risk == "low":
        return "high"
    if kind == "inspect" and risk == "low":
        return "high"
    if kind in {"inspect", "remote"} and risk in {"medium"}:
        return "medium"
    if command.startswith("/do"):
        return "medium"
    if risk in {"unknown"}:
        return "low"
    return "medium"


def _format_quick_action_line(item: dict[str, object]) -> str:
    action_id = str(item.get("id", "?")).strip() or "?"
    command = str(item.get("command", "")).strip() or "-"
    title = str(item.get("title", command)).strip() or command
    source = str(item.get("source", "suggested")).strip() or "suggested"
    kind = str(item.get("kind", "")).strip() or _classify_quick_action_kind(command)
    risk = str(item.get("risk", "")).strip() or _classify_quick_action_risk(command)
    confidence = str(item.get("confidence", "")).strip() or _classify_quick_action_confidence(item)
    status = str(item.get("last_status", "")).strip()
    suffix = f" [last={status}]" if status else ""
    return f"{action_id}. [{kind}][{risk}][{source}] {title}{suffix} [conf={confidence}]"


def _format_quick_action_command(item: dict[str, object]) -> str:
    command = str(item.get("command", "")).strip() or "-"
    return f"cmd: {command}"


def _render_timeline_text(options: dict[str, object]) -> str:
    audit_log = Path(str(options.get("audit_log", ".data/lsre-audit.jsonl"))).expanduser()
    timeline = _read_recent_audit_timeline(audit_log, limit=6)
    if not timeline:
        return "Execution Timeline\n- 还没有执行轨迹，先运行 /scan、/brief、/remediate 或其它命令。"
    lines = ["Execution Timeline", "", "Trace Summary"]
    lines.extend(f"- {line}" for line in _build_recent_trace_summary(timeline))
    lines.append("")
    lines.append("Entries")
    for item in timeline:
        lines.append(
            f"- {item.get('time', '--:--')} [{item.get('stage', 'other')}/{item.get('status', 'info')}/{item.get('mode', '-')}] {item.get('summary', '')}"
        )
    return "\n".join(lines)


def _render_trace_text(options: dict[str, object]) -> str:
    audit_log = Path(str(options.get("audit_log", ".data/lsre-audit.jsonl"))).expanduser()
    timeline = _read_recent_audit_timeline(audit_log, limit=8)
    return "Operation Trace\n" + "\n".join(f"- {line}" for line in _build_recent_trace_summary(timeline))


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
    table.add_row("SSH Target", str(target_payload.get("ssh_target", "-") or "-"))
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
                "detail": _safe_exception_text(exc)[:220],
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

    checks.extend(_collect_proxy_runtime_checks())
    checks.extend(_collect_workspace_secret_checks())

    summary = _summarize_doctor_checks(checks)
    return {
        "checks": checks,
        "summary": summary,
    }


def _collect_preflight_report(
    *,
    profile_file: Path,
    timeout_sec: int,
    dry_run_probe: bool,
    strict: bool,
    staged: bool,
    max_findings: int,
    audit_log: Path,
) -> dict[str, object]:
    install_report = _collect_install_doctor_report()
    target_store = TargetEnvStore(profile_file)
    target = target_store.load()
    doctor_report = _collect_doctor_report(
        target=target,
        timeout_sec=timeout_sec,
        dry_run_probe=dry_run_probe,
        audit_log=audit_log,
    )
    secret_report = _collect_secret_scan_report(
        staged=staged,
        max_findings=max_findings,
    )
    checks: list[dict[str, object]] = []
    for report in (install_report, doctor_report, secret_report):
        rows = report.get("checks", [])
        if isinstance(rows, list):
            checks.extend([item for item in rows if isinstance(item, dict)])
    summary = _summarize_doctor_checks(checks)
    summary["strict_mode"] = strict
    summary["strict_healthy"] = _doctor_is_healthy(summary, strict=strict)
    result = {
        "kind": "preflight",
        "scope": {
            "secret_scan": "staged" if staged else "all_files",
            "dry_run_probe": dry_run_probe,
            "strict": strict,
        },
        "checks": checks,
        "summary": summary,
        "sections": {
            "install_doctor": install_report.get("summary", {}),
            "doctor": doctor_report.get("summary", {}),
            "secret_scan": secret_report.get("summary", {}),
        },
    }
    result["gate"] = _build_doctor_gate(result, strict=strict)
    return result


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
        return {"ok": False, "stdout": "", "stderr": _safe_exception_text(exc), "exit_code": -1}
    return {
        "ok": completed.returncode == 0,
        "stdout": (completed.stdout or "").strip(),
        "stderr": (completed.stderr or "").strip(),
        "exit_code": int(completed.returncode),
    }


def _collect_proxy_runtime_checks() -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    proxy_values = _read_proxy_env_values()
    if not proxy_values:
        checks.append(
            {
                "name": "runtime.proxy_env",
                "ok": True,
                "severity": "pass",
                "detail": "(unset)",
                "hint": "",
            }
        )
        return checks

    merged = ", ".join(f"{name}={_sanitize_tui_secret_tokens(value)}" for name, value in proxy_values.items())
    checks.append(
        {
            "name": "runtime.proxy_env",
            "ok": True,
            "severity": "pass",
            "detail": merged[:240],
            "hint": "",
        }
    )

    has_socks_proxy = any(_looks_like_socks_proxy(value) for value in proxy_values.values())
    socksio_ok = _is_socksio_available()
    if has_socks_proxy:
        checks.append(
            {
                "name": "runtime.proxy_socksio",
                "ok": socksio_ok,
                "severity": "pass" if socksio_ok else "error",
                "detail": "socksio installed" if socksio_ok else "socksio missing",
                "hint": "" if socksio_ok else "检测到 SOCKS 代理，请执行 python3 -m pip install \"httpx[socks]\"",
            }
        )
    else:
        checks.append(
            {
                "name": "runtime.proxy_socksio",
                "ok": True,
                "severity": "pass",
                "detail": "not required (no socks proxy)",
                "hint": "",
            }
        )
    return checks


def _collect_secret_scan_report(
    *,
    root: Path | None = None,
    max_findings: int = 8,
    staged: bool = False,
) -> dict[str, object]:
    workspace = (root or Path.cwd()).resolve()
    scan_paths: list[Path] | None = None
    scope_detail = "scope=workspace"
    if staged:
        staged_paths = _resolve_staged_secret_scan_paths(workspace)
        scope_detail = f"scope=staged files ({len(staged_paths)})"
        scan_paths = staged_paths
    checks = _collect_workspace_secret_checks(
        root=workspace,
        max_findings=max_findings,
        paths=scan_paths,
    )
    checks.insert(
        0,
        {
            "name": "runtime.workspace_secret_scan_scope",
            "ok": True,
            "severity": "pass",
            "detail": scope_detail,
            "hint": "",
        },
    )
    return {"checks": checks, "summary": _summarize_doctor_checks(checks)}


def _resolve_staged_secret_scan_paths(workspace: Path) -> list[Path]:
    git_path = shutil.which("git")
    if not git_path:
        return []
    probe = _safe_run_command(
        [
            git_path,
            "-C",
            str(workspace),
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMRTUXB",
        ],
        timeout_sec=6,
    )
    if not bool(probe.get("ok")):
        return []
    rows = [str(item).strip() for item in str(probe.get("stdout", "")).splitlines() if str(item).strip()]
    resolved: list[Path] = []
    for item in rows:
        path = (workspace / item).resolve()
        if (not path.exists()) or (not path.is_file()):
            continue
        try:
            path.relative_to(workspace)
        except Exception:
            continue
        if path in resolved:
            continue
        resolved.append(path)
    return resolved


def _collect_workspace_secret_checks(
    *,
    root: Path | None = None,
    max_findings: int = 8,
    paths: list[Path] | None = None,
) -> list[dict[str, object]]:
    workspace = (root or Path.cwd()).resolve()
    findings = _scan_workspace_for_secrets(workspace=workspace, limit=max_findings, paths=paths)
    if not findings:
        return [
            {
                "name": "runtime.workspace_secret_scan",
                "ok": True,
                "severity": "pass",
                "detail": "no suspicious secrets found",
                "hint": "",
            }
        ]
    preview = "; ".join(f"{item['file']}:{item['line']}" for item in findings[:3])
    return [
        {
            "name": "runtime.workspace_secret_scan",
            "ok": False,
            "severity": "error",
            "detail": f"detected {len(findings)} suspicious token(s): {preview}",
            "hint": "发现疑似密钥，请立即轮换并清理 Git 历史后再发布。",
            "findings": findings,
        }
    ]


def _scan_workspace_for_secrets(
    *,
    workspace: Path,
    limit: int = 8,
    paths: list[Path] | None = None,
) -> list[dict[str, object]]:
    root = Path(workspace).resolve()
    if (not root.exists()) or (not root.is_dir()):
        return []
    ignore_dirs = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".data",
        "dist",
        "build",
    }
    patterns = {
        "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
        "openai_api_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        "anthropic_api_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    }
    false_positive_markers = (
        "redacted",
        "example",
        "sample",
        "dummy",
        "placeholder",
        "fake",
        "test-",
        "test_",
        "demo-",
        "-demo",
        " demo",
        "xxxx",
        "***",
    )
    findings: list[dict[str, object]] = []
    files_to_scan: list[Path] = []
    if paths is not None:
        for raw in paths:
            path = Path(raw).resolve()
            if (not path.exists()) or (not path.is_file()):
                continue
            try:
                path.relative_to(root)
            except Exception:
                continue
            files_to_scan.append(path)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [item for item in dirnames if item not in ignore_dirs]
            for filename in filenames:
                files_to_scan.append(Path(dirpath) / filename)
    for path in files_to_scan:
        if len(findings) >= max(1, int(limit)):
            break
        if (paths is None) and any(part in ignore_dirs for part in path.parts):
            continue
        try:
            if path.stat().st_size > 1024 * 1024:
                continue
        except Exception:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if not text.strip():
            continue
        rel = str(path.relative_to(root))
        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            if len(findings) >= max(1, int(limit)):
                break
            line = str(raw_line or "")
            if not line.strip():
                continue
            lowered = line.lower()
            if any(marker in lowered for marker in false_positive_markers):
                continue
            matched_type = ""
            matched_value = ""
            for token_type, pattern in patterns.items():
                found = pattern.search(line)
                if found:
                    matched_type = token_type
                    matched_value = found.group(0)
                    break
            if not matched_type:
                continue
            findings.append(
                {
                    "type": matched_type,
                    "file": rel,
                    "line": line_no,
                    "token": _sanitize_tui_secret_tokens(matched_value),
                }
            )
    return findings


def _read_proxy_env_values() -> dict[str, str]:
    values: dict[str, str] = {}
    for upper, lower in (
        ("ALL_PROXY", "all_proxy"),
        ("HTTPS_PROXY", "https_proxy"),
        ("HTTP_PROXY", "http_proxy"),
    ):
        raw = str(os.getenv(upper, "") or os.getenv(lower, "")).strip()
        if raw:
            values[upper] = raw
    return values


def _looks_like_socks_proxy(value: str) -> bool:
    raw = str(value or "").strip().lower()
    return raw.startswith("socks://") or raw.startswith("socks5://") or raw.startswith("socks4://")


def _is_socksio_available() -> bool:
    try:
        import socksio  # noqa: F401

        return True
    except Exception:
        return False


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
    discovery_report = _collect_environment_discovery(
        timeout_sec=max(2, min(timeout_sec, 6)),
        secrets_file=secrets_file,
    )
    if apply_defaults:
        updates = _compute_setup_default_updates(target)
        discovery_updates = _build_discovery_target_updates(target, discovery_report)
        merged_updates = {**updates, **discovery_updates}
        if merged_updates:
            target = store.update(**merged_updates)
            setup_actions.extend(_format_target_update_actions(merged_updates, source="autofill"))

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
        "discovery": discovery_report,
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


def _build_discovery_target_updates(target, discovery_report: dict[str, object]) -> dict[str, object]:
    discoveries = discovery_report.get("discoveries", {})
    if not isinstance(discoveries, dict):
        discoveries = {}
    updates: dict[str, object] = {}

    prometheus = discoveries.get("prometheus", {})
    if isinstance(prometheus, dict):
        prom_url = str(prometheus.get("url", "")).strip()
        if prom_url and (not str(getattr(target, "prometheus_url", "") or "").strip()):
            updates["prometheus_url"] = prom_url

    kubernetes = discoveries.get("kubernetes", {})
    if isinstance(kubernetes, dict):
        context_name = str(kubernetes.get("context", "")).strip()
        server = str(kubernetes.get("server", "")).strip()
        namespace = str(kubernetes.get("namespace", "")).strip()
        current_context = str(getattr(target, "k8s_context", "") or "").strip()
        current_server = str(getattr(target, "k8s_api_url", "") or "").strip()
        current_namespace = str(getattr(target, "k8s_namespace", "") or "").strip()
        if context_name and (not current_context):
            updates["k8s_context"] = context_name
        if server and (not current_server):
            updates["k8s_api_url"] = server
        if namespace and ((not current_namespace) or (current_namespace == "default" and namespace != "default")):
            updates["k8s_namespace"] = namespace
    return updates


def _format_target_update_actions(updates: dict[str, object], *, source: str) -> list[str]:
    actions: list[str] = []
    for key, value in updates.items():
        if key == "k8s_bearer_token":
            actions.append(f"{source}: set {key}=(hidden)")
        else:
            actions.append(f"{source}: set {key}={value}")
    return actions


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
        elif provider == "compatible":
            env_present = bool(str(os.getenv("OPENAI_COMPATIBLE_API_KEY", "")).strip())
        source = "env" if env_present else ("secrets" if raw else "unset")
        extras: list[str] = []
        base_url = _resolve_provider_base_url(provider, secrets_file=secrets_file)
        default_model = _resolve_provider_default_model(provider, secrets_file=secrets_file)
        if base_url:
            extras.append(f"base_url={base_url}")
        if default_model:
            extras.append(f"model={default_model}")
        detail = f"{masked or '(unset)'} ({source})"
        if extras:
            detail = detail + "; " + "; ".join(extras)
        provider_ready = bool(raw)
        hint = f"执行 lsre login --provider {provider} 保存 API Key（或设置 {' / '.join(spec.env_names)}）"
        if provider == "compatible":
            provider_ready = bool(raw and base_url)
            if raw and (not base_url):
                hint = "compatible provider 还缺少 base_url，请执行 lsre login --provider compatible --base-url <url>"
        checks[provider] = {
            "name": f"runtime.{spec.secret_key}",
            "provider": provider,
            "label": spec.label,
            "ok": provider_ready,
            "severity": "pass" if provider_ready else "error",
            "detail": detail,
            "hint": "" if provider_ready else hint,
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
    scan_report = report.get("scan", report)
    if not isinstance(scan_report, dict):
        scan_report = report
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "ready": False,
        "first_scan_done": True,
        "source": str(report.get("source", "environment-scan")),
        "briefing": report.get("briefing", {}),
        "landscape": scan_report.get("landscape", {}),
        "scan_summary": scan_report.get("summary", {}),
        "usable_targets": scan_report.get("usable_targets", []),
        "issues": scan_report.get("issues", [])[:8] if isinstance(scan_report.get("issues", []), list) else [],
        "suggestions": scan_report.get("suggestions", [])[:5] if isinstance(scan_report.get("suggestions", []), list) else [],
        "next_actions": scan_report.get("next_actions", [])[:8] if isinstance(scan_report.get("next_actions", []), list) else [],
    }
    marker.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return marker


def _load_onboarding_marker() -> dict[str, object]:
    marker = Path(settings.data_dir) / "lsre-onboarding.json"
    if not marker.exists():
        return {}
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _show_first_run_setup_hint_once() -> None:
    marker = Path(settings.data_dir) / "lsre-onboarding.json"
    if marker.exists():
        return
    typer.echo("首次使用可先运行 /scan 自动体检；需要补齐配置时再用 /quickstart 或 /init。")


def _chat_state_file() -> Path:
    return Path(settings.data_dir) / "lsre-chat-state.json"


def _tui_state_file() -> Path:
    return Path(settings.data_dir) / "lsre-tui-state.json"


def _load_tui_runtime_state() -> dict[str, str]:
    path = _tui_state_file()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    panel = _normalize_tui_panel_name(str(payload.get("panel", "")).strip())
    ui_mode = _normalize_tui_ui_mode(str(payload.get("ui_mode", "")).strip())
    result: dict[str, str] = {}
    if panel:
        result["panel"] = panel
    if ui_mode:
        result["ui_mode"] = ui_mode
    return result


def _save_tui_runtime_state(*, panel: str, ui_mode: str) -> None:
    path = _tui_state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "panel": _normalize_tui_panel_name(panel),
        "ui_mode": _normalize_tui_ui_mode(ui_mode),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _persist_tui_runtime_state(options: dict[str, object]) -> None:
    _save_tui_runtime_state(
        panel=str(options.get("tui_panel", "overview")),
        ui_mode=str(options.get("tui_ui_mode", "simple")),
    )


def _apply_saved_tui_runtime_state(options: dict[str, object]) -> None:
    state = _load_tui_runtime_state()
    panel = str(state.get("panel", "")).strip()
    ui_mode = str(state.get("ui_mode", "")).strip()
    if panel:
        options["tui_panel"] = panel
    if ui_mode:
        options["tui_ui_mode"] = ui_mode


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
        _render_cached_startup_brief(_load_onboarding_marker())
        return
    typer.echo("首次启动：正在生成总览简报（只读，不需要 K8s token；如已保存远程目标会一并检查）...")
    report = _build_overview_brief_report(
        target="",
        include_remote=True,
        include_logs=False,
        timeout_sec=5,
    )
    _write_first_scan_marker(report)
    if _console:
        _render_overview_brief_report(report)
    else:
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
    typer.echo("你可以直接复制上面的建议来问我；需要交互式配置时再输入 /init，想刷新总览可输入 /brief。")


def _maybe_auto_bootstrap_for_tui(options: dict[str, object]) -> dict[str, object]:
    marker = Path(settings.data_dir) / "lsre-onboarding.json"
    if marker.exists():
        return {"triggered": False, "reason": "marker-exists"}
    if not bool(options.get("tui_auto_bootstrap", True)):
        return {"triggered": False, "reason": "disabled"}
    timeout_raw = options.get("startup_scan_timeout_sec", 4)
    try:
        timeout_sec = int(timeout_raw)
    except Exception:
        timeout_sec = 4
    timeout_sec = max(2, min(timeout_sec, 12))
    try:
        report = _collect_environment_discovery(timeout_sec=timeout_sec, secrets_file=None)
        _write_first_scan_marker(report)
    except Exception as exc:
        return {"triggered": True, "written": False, "error": _safe_exception_text(exc)[:180]}
    return {"triggered": True, "written": True, "timeout_sec": timeout_sec}


def _render_cached_startup_brief(marker: dict[str, object]) -> None:
    briefing = marker.get("briefing", {})
    if not isinstance(briefing, dict) or not briefing:
        typer.echo("输入 /brief 可刷新当前环境总览，输入 /help 查看快捷命令。")
        return
    status = str(briefing.get("status", "-"))
    headline = str(briefing.get("headline", "")).strip()
    next_step = str(briefing.get("next", "")).strip()
    generated = str(marker.get("generated_at_utc", "")).strip()
    lines = [f"上次总览: {status}"]
    if headline:
        lines.append(headline)
    if next_step:
        lines.append(f"下一步: {next_step}")
    if generated:
        lines.append(f"生成时间: {generated}")
    lines.append("输入 /brief 刷新总览，输入 /help 查看快捷命令。")
    if _console and Panel:
        _console.print(Panel("\n".join(lines), title="Startup Brief", border_style="cyan"))
    else:
        typer.echo("\n".join(lines))


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
    if normalized == "compatible":
        env_key = str(os.getenv("OPENAI_COMPATIBLE_API_KEY", "")).strip()
        if env_key:
            return env_key
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


def _resolve_provider_base_url(provider: str, *, secrets_file: Path | None = None) -> str:
    normalized = str(provider or "").strip().lower()
    if normalized == "openai":
        env_url = str(os.getenv("OPENAI_BASE_URL", "")).strip()
        if env_url:
            return env_url
    env_url = str(os.getenv(f"LAZYSRE_{normalized.upper()}_BASE_URL", "")).strip()
    if env_url:
        return env_url
    if normalized == "compatible":
        compat_env = str(os.getenv("OPENAI_COMPATIBLE_BASE_URL", "")).strip()
        if compat_env:
            return compat_env
    if normalized not in PROVIDER_SPECS:
        return ""
    stored = SecretStore(secrets_file).get_provider_base_url(normalized)
    if stored:
        return stored
    spec = PROVIDER_SPECS[normalized]
    return str(spec.base_url or "").strip()


def _resolve_provider_default_model(provider: str, *, secrets_file: Path | None = None) -> str:
    normalized = str(provider or "").strip().lower()
    env_model = str(os.getenv(f"LAZYSRE_{normalized.upper()}_MODEL", "")).strip()
    if env_model:
        return env_model
    if normalized == "compatible":
        compat_model = str(os.getenv("OPENAI_COMPATIBLE_MODEL", "")).strip()
        if compat_model:
            return compat_model
    if normalized not in PROVIDER_SPECS:
        return ""
    return SecretStore(secrets_file).get_provider_model(normalized)


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

    stored_model = _resolve_provider_default_model(mode, secrets_file=secrets_file)
    requested_model = str(model or "").strip()
    if stored_model and ((not requested_model) or (requested_model == settings.model_name)):
        resolved_model = stored_model
    else:
        resolved_model = resolve_model_name(mode, model)
    if mode == "openai":
        base_url = _resolve_provider_base_url(mode, secrets_file=secrets_file)
        if base_url:
            return (
                mode,
                resolved_model,
                OpenAICompatibleFunctionCallingLLM(
                    api_key=api_key,
                    provider=mode,
                    base_url=base_url,
                ),
            )
        return mode, resolved_model, OpenAIResponsesLLM(api_key)
    if mode == "anthropic":
        return mode, resolved_model, AnthropicMessagesLLM(api_key)
    if mode == "gemini":
        return mode, resolved_model, GeminiFunctionCallingLLM(api_key)
    spec = get_provider_spec(mode)
    if spec.compatible:
        base_url = _resolve_provider_base_url(mode, secrets_file=secrets_file)
        if not base_url:
            raise typer.BadParameter(
                f"{spec.label} 缺少 base_url。请执行：lsre login --provider {mode} --base-url <url>"
            )
        return (
            mode,
            resolved_model,
            OpenAICompatibleFunctionCallingLLM(
                api_key=api_key,
                provider=mode,
                base_url=base_url,
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

    discovery = report.get("discovery", {})
    if isinstance(discovery, dict):
        discovery_summary = discovery.get("summary", {})
        usable_targets = discovery.get("usable_targets", [])
        if not isinstance(discovery_summary, dict):
            discovery_summary = {}
        if not isinstance(usable_targets, list):
            usable_targets = []
        discovery_lines = [
            f"Usable Targets: {', '.join(str(x) for x in usable_targets) or 'none'}",
            (
                "Discovery Summary: "
                f"pass={discovery_summary.get('pass', 0)} "
                f"warn={discovery_summary.get('warn', 0)} "
                f"error={discovery_summary.get('error', 0)}"
            ),
        ]
        issues = discovery.get("issues", [])
        if isinstance(issues, list):
            for item in issues[:4]:
                if not isinstance(item, dict):
                    continue
                discovery_lines.append(
                    f"- {item.get('severity', 'warn')}: {item.get('name', '-')} {str(item.get('detail', ''))[:120]}"
                )
        _console.print(Panel("\n".join(discovery_lines), title="Auto Discovery", border_style="cyan"))

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
    ssh_target = str(getattr(target, "ssh_target", "") or "").strip()
    checks.append(
        {
            "name": "target.ssh_target",
            "ok": bool(ssh_target),
            "severity": "pass" if ssh_target else "warn",
            "detail": ssh_target or "(unset)",
            "hint": "" if ssh_target else "使用 lsre target set --ssh-target root@host 配置远程 Docker/Swarm 诊断目标",
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
    elif not str(target.prometheus_url or "").strip():
        detected_prometheus = _detect_prometheus_ready_url()
        if detected_prometheus:
            updates["prometheus_url"] = detected_prometheus
            actions.append(f"set prometheus_url={detected_prometheus}")
    if not str(target.k8s_api_url or "").strip() and settings.target_k8s_api_url.strip():
        updates["k8s_api_url"] = settings.target_k8s_api_url.strip()
        actions.append("set k8s_api_url from default settings")
    elif not str(target.k8s_api_url or "").strip():
        detected_server = _detect_kubectl_server()
        if detected_server:
            updates["k8s_api_url"] = detected_server
            actions.append(f"set k8s_api_url={detected_server}")
    if not str(target.k8s_context or "").strip():
        detected = _detect_kubectl_current_context()
        if detected:
            updates["k8s_context"] = detected
            actions.append(f"set k8s_context={detected}")
    detected_namespace = _detect_kubectl_default_namespace()
    current_namespace = str(target.k8s_namespace or "").strip()
    if detected_namespace and ((not current_namespace) or (current_namespace == "default" and detected_namespace != "default")):
        updates["k8s_namespace"] = detected_namespace
        actions.append(f"set k8s_namespace={detected_namespace}")
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


def _detect_kubectl_default_namespace() -> str:
    return _detect_kubectl_minified_jsonpath("{.contexts[0].context.namespace}") or "default"


def _detect_kubectl_server() -> str:
    return _detect_kubectl_minified_jsonpath("{.clusters[0].cluster.server}")


def _detect_kubectl_minified_jsonpath(path_expr: str) -> str:
    if not shutil.which("kubectl"):
        return ""
    try:
        completed = subprocess.run(
            ["kubectl", "config", "view", "--minify", "-o", f"jsonpath={path_expr}"],
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


def _detect_prometheus_ready_url(timeout_sec: int = 2) -> str:
    curl_path = shutil.which("curl")
    if not curl_path:
        return ""
    for url in _prometheus_candidate_urls():
        probe = _safe_run_command(
            [curl_path, "-fsS", "--max-time", str(max(1, timeout_sec)), f"{url.rstrip('/')}/-/ready"],
            timeout_sec=max(2, timeout_sec + 1),
        )
        if bool(probe.get("ok")):
            return url
    return ""


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
    kind = str(report.get("kind", "doctor")).strip().lower()
    title_prefix = "Preflight Gate" if kind == "preflight" else "Doctor Summary"
    if Panel:
        _console.print(Panel(summary_text, title=title_prefix, border_style="cyan"))
    sections = report.get("sections", {})
    if isinstance(sections, dict) and sections and Panel:
        lines: list[str] = []
        for name, section in sections.items():
            if not isinstance(section, dict):
                continue
            lines.append(
                f"{name}: pass={section.get('pass', 0)} warn={section.get('warn', 0)} "
                f"error={section.get('error', 0)} healthy={section.get('healthy', False)}"
            )
        if lines:
            _console.print(Panel("\n".join(lines), title="Preflight Sections", border_style="blue"))
    if isinstance(gate, dict) and int(gate.get("blocking_count", 0) or 0) > 0 and Panel:
        blocking = gate.get("blocking_checks", [])
        if isinstance(blocking, list):
            lines = []
            for raw in blocking[:8]:
                item = raw if isinstance(raw, dict) else {}
                hint = str(item.get("hint", "")).strip()
                suffix = f" - {hint}" if hint else ""
                lines.append(f"{item.get('severity', '-')}: {item.get('name', '-')}{suffix}")
            if lines:
                _console.print(Panel("\n".join(lines), title="Blocking Checks", border_style="red"))
    checks = report.get("checks", [])
    table = Table(title="Preflight Checks" if kind == "preflight" else "Doctor Checks")
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
    stripped = str(text or "").strip()
    normalized = stripped
    while normalized.lower().startswith("sudo "):
        normalized = normalized[5:].lstrip()
    lowered = normalized.lower()
    if (
        re.search(r"[\u4e00-\u9fff]", normalized)
        and not lowered.startswith(("lazysre ", "lsre ", "python -m lazysre"))
    ):
        return False
    prefixes = (
        "kubectl ",
        "docker ",
        "curl ",
        "helm ",
        "systemctl ",
        "journalctl ",
        "ssh ",
        "lazysre ",
        "lsre ",
        "python ",
        "python3 ",
        "bash ",
        "sh ",
    )
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
        "- /activity: 查看最近巡检、修复计划和审计轨迹，并给出建议下一步",
        "- /focus: 查看当前最值得关注的异常/阻塞与建议动作",
        "- /do [n]: 查看快捷建议；/do 1 直接执行第1条建议",
        "- 数字快捷：直接输入 1/2/3...，若存在对应动作则等价于 /do n（无动作时 1-4 等价 /go n）",
        "- /timeline: 查看最近执行时间线（命令、状态、dry-run/exec）",
        "- /trace: 查看最近一次操作链路的摘要（成功/失败、dry-run/exec、top tools）",
        "- /history [关键词|n]: 查看最近输入；/history 关键字 可筛选；/history 1 重放；/retry 直接重试上一条",
        "- 口语快捷：直接输入 继续/重试/历史/帮助/扫描/简报，也会自动映射到对应命令",
        "- /panel [overview|activity|timeline|providers|next|1-4]: 切换 TUI 左侧面板",
        "- /brief [user@host]: 汇总本机 scan 和可选远程目标，直接给一份 AI 总览简报",
        "- /scan: 零配置自动扫描本机 Docker/Swarm/K8s/Prometheus（不需要 K8s token）",
        "- /swarm [--logs]: 检查 Docker Swarm 服务、副本、任务失败证据",
        "- /watch [--count N]: 持续巡检并输出异常摘要",
        "- /actions [id]: 兼容旧入口，等价于 /do 或 /do 1",
        "- /autopilot [目标]: 自动扫描 -> 巡检 -> 行动清单，可加 --fix 生成修复计划",
        "- /connect [user@host]: 远程连接体检；SSH 连通后自动保存为默认远程目标",
        "- /remote [user@host] [--logs]: 通过 SSH 只读诊断远程 Docker/Swarm；已保存 ssh_target 时可省略主机",
        "- /remediate <目标>: 生产闭环修复（Observe -> Plan -> Apply -> Verify -> Rollback Advice）",
        "- /tui: 启动全屏 TUI（也可直接运行 lazysre tui）",
        "- /refresh: 刷新当前总览简报并更新 TUI/启动页摘要",
        "- /mode: 查看当前执行模式（dry-run/execute）",
        "- /mode execute|dry-run: 切换执行模式",
        "- /context: 查看会话记忆（最近 pod/service/namespace）",
        "- 输入容错：/quikstart /stauts /templete 会自动纠正",
        "- 自然语言目标配置：把 namespace 设成 prod / 把 prometheus 设成 http://x:9090 / 把远程服务器设成 root@host",
        "- 自然语言多集群：保存当前为 prod 并切换 / 切到 prod 集群 / 看看当前profile",
        "- 自然语言档案管理：导出profile到 .data/p.json / 从 .data/p.json 导入profile / 删除profile prod（需确认）",
        "- /reset: 重置引导与聊天模式记忆",
        "- /undo: 回滚最近一次修复计划",
        "- /init: 交互式初始化（API Key + 目标环境 + 探测）",
        "- /quickstart: 一键自动修复环境并完成快速就绪",
        f"- /login [--provider {provider_mode_help_text()}]: 保存对应 Provider API Key",
        "- /providers: 查看当前 Provider 就绪状态、base_url 和默认模型",
        "- /provider <name>: 切换当前会话使用的 Provider（auto/mock/openai/.../compatible）",
        "- /setup [--dry-run-probe]: 首次启动向导（安装检查+目标探测+LLM Key）",
        "- /status: 查看当前会话、目标配置、最近修复计划",
        "- /status probe: 追加目标探测摘要（dry-run）",
        "- /doctor: 运行环境预检（依赖/配置/连通性）",
        "- /doctor install: 安装环境自检（python/node/npm/gh）",
        "- /doctor fix: 执行安全自动修复后再预检",
        "- /doctor strict: 严格模式（warn 也视为不健康）",
        "- /preflight: 发布前一键体检（install-doctor + doctor + secret-scan）",
        "- /preflight --strict: 严格门禁（warn/error 触发失败）",
        "- /preflight --all-files: 扫描全仓库（默认仅扫描暂存区）",
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
        "- /incident status|open|note|assign|severity|timeline|close|list|export: 事故生命周期管理",
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
        "- TUI 里可用 Up/Down 浏览输入历史（支持前缀筛选），Ctrl-L 或 /clear 清空屏幕，1-4/F2 切换面板，F3 切换 UI",
        "- exit / quit: 退出",
    ]
    text = "\n".join(lines)
    if _console and Panel:
        _console.print(Panel(text, border_style="cyan"))
    else:
        typer.echo(text)


def _build_tui_dashboard_snapshot(options: dict[str, object]) -> dict[str, object]:
    target = TargetEnvStore().load()
    marker = _load_onboarding_marker()
    runtime_targets = _infer_runtime_targets(target)
    environment_drift = _build_environment_drift(marker if isinstance(marker, dict) else {}, runtime_targets)
    briefing = marker.get("briefing", {}) if isinstance(marker, dict) else {}
    if not isinstance(briefing, dict):
        briefing = {}
    landscape = marker.get("landscape", {}) if isinstance(marker, dict) else {}
    if not isinstance(landscape, dict):
        landscape = {}
    session_store = SessionStore(Path(str(options.get("session_file", ".data/lsre-session.json"))))
    session_turns = session_store.recent_turns(limit=30)
    last_user = ""
    if session_turns:
        tail = session_turns[-1]
        if isinstance(tail, dict):
            last_user = _sanitize_tui_secret_tokens(str(tail.get("user", "")).strip())
    recent_commands_full = [
        _sanitize_tui_secret_tokens(str(turn.get("user", "")).strip())
        for turn in session_turns[-12:]
        if isinstance(turn, dict) and str(turn.get("user", "")).strip()
    ]
    recent_commands = recent_commands_full[-3:]
    provider_checks = _build_provider_setup_checks(secrets_file=None)
    configured_providers = [
        str(row.get("provider", name))
        for name, row in provider_checks.items()
        if isinstance(row, dict) and bool(row.get("ok"))
    ]
    usable_targets = marker.get("usable_targets", []) if isinstance(marker, dict) else []
    if not isinstance(usable_targets, list):
        usable_targets = []
    if (not landscape) and usable_targets:
        landscape = _build_environment_landscape(
            {
                "usable_targets": usable_targets,
                "discoveries": marker.get("discoveries", {}) if isinstance(marker, dict) else {},
            }
        )
    if not usable_targets:
        usable_targets = list(runtime_targets)
    recommended_commands = []
    next_step = str(briefing.get("next", "")).strip()
    if next_step:
        recommended_commands.append(next_step)
    marker_actions = marker.get("next_actions", []) if isinstance(marker, dict) else []
    if isinstance(marker_actions, list):
        recommended_commands.extend(str(item).strip() for item in marker_actions[:4] if str(item).strip())
    recent_activity_context = _build_tui_recent_activity_context(options)
    recommended_commands.extend(
        cmd
        for cmd in [
            *[
                str(item)
                for item in recent_activity_context.get("commands", [])
                if str(item).strip()
            ],
            "lazysre brief",
            "lazysre scan",
            "lazysre autopilot",
        ]
        if cmd not in recommended_commands
    )
    recent_activity = recent_activity_context.get("items", [])
    if not isinstance(recent_activity, list):
        recent_activity = []
    recent_activity_commands = recent_activity_context.get("commands", [])
    if not isinstance(recent_activity_commands, list):
        recent_activity_commands = []
    if str(environment_drift.get("status", "")).strip() in {"changed", "stale"}:
        drift_headline = str(environment_drift.get("headline", "")).strip()
        if drift_headline:
            recent_activity = [f"env drift | {drift_headline[:92]}", *recent_activity]
        drift_actions = environment_drift.get("top_actions", [])
        if isinstance(drift_actions, list):
            recent_activity_commands = _dedupe_strings(
                [str(item).strip() for item in drift_actions if str(item).strip()] + [str(item).strip() for item in recent_activity_commands if str(item).strip()]
            )[:4]
            recommended_commands.extend(str(item).strip() for item in drift_actions if str(item).strip())
    incident_session = recent_activity_context.get("incident_session", {})
    if not isinstance(incident_session, dict):
        incident_session = {}
    provider_report = _build_provider_runtime_report(options)
    timeline_entries_raw = _read_recent_audit_timeline(
        Path(str(options.get("audit_log", ".data/lsre-audit.jsonl"))).expanduser(),
        limit=4,
    )
    focus_card = _build_tui_focus_card(
        recent_activity=recent_activity,
        recent_activity_commands=recent_activity_commands,
        provider_report=provider_report,
        timeline=timeline_entries_raw,
        environment_drift=environment_drift,
        incident_session=incident_session,
        watch_snapshot=recent_activity_context.get("watch", {}) if isinstance(recent_activity_context.get("watch", {}), dict) else {},
    )
    quick_action_items = _build_quick_action_catalog(
        focus_title=str(focus_card.get("title", "")),
        focus_actions=list(focus_card.get("actions", [])) if isinstance(focus_card.get("actions", []), list) else [],
        recent_activity_commands=recent_activity_commands,
        recommended_commands=[str(item) for item in recommended_commands if str(item).strip()],
        watch_snapshot=recent_activity_context.get("watch", {}) if isinstance(recent_activity_context.get("watch", {}), dict) else {},
    )
    latest_quick_action = _load_latest_quick_action_result()
    quick_action_items = _annotate_quick_action_catalog(
        quick_action_items,
        latest_result=latest_quick_action,
    )
    quick_action_items = _sort_quick_action_catalog(
        quick_action_items,
        latest_result=latest_quick_action,
    )
    timeline_entries = [
        f"{item.get('time', '--:--')} [{item.get('stage', 'other')}/{item.get('status', 'info')}/{item.get('mode', '-')}] {item.get('summary', '')}"
        for item in timeline_entries_raw
        if isinstance(item, dict)
    ]
    trace_summary = _build_recent_trace_summary(timeline_entries_raw)
    return {
        "title": "LazySRE TUI",
        "version": __version__,
        "ui_mode": _normalize_tui_ui_mode(str(options.get("tui_ui_mode", "simple"))),
        "mode": "execute" if bool(options.get("execute", False)) else "dry-run",
        "provider": str(options.get("provider", "auto")),
        "model": str(provider_report.get("resolved_model", options.get("model", settings.model_name))),
        "status": str(briefing.get("status", "cold-start")),
        "headline": str(briefing.get("headline", "")).strip() or "输入 /scan 或 /brief，LazySRE 会先给你一份现场总览。",
        "environment_profile": str(briefing.get("profile_label", landscape.get("label", ""))).strip(),
        "environment_summary": str(briefing.get("summary", landscape.get("summary", ""))).strip(),
        "environment_signals": (
            [str(item).strip() for item in briefing.get("signals", []) if str(item).strip()]
            if isinstance(briefing.get("signals", []), list)
            else [str(item).strip() for item in landscape.get("signals", []) if str(item).strip()]
        )[:5],
        "generated_at": str(marker.get("generated_at_utc", "")).strip() if isinstance(marker, dict) else "",
        "usable_targets": _dedupe_strings([str(item) for item in usable_targets if str(item).strip()]),
        "configured_providers": configured_providers,
        "provider_ready": bool(provider_report.get("active_ready", False)),
        "namespace": str(target.k8s_namespace or "default"),
        "ssh_target": str(target.ssh_target or settings.target_ssh_target or ""),
        "prometheus_url": str(target.prometheus_url or settings.target_prometheus_url or ""),
        "session_turns": len(session_turns),
        "last_user": last_user[:120],
        "recent_commands": recent_commands[-3:],
        "recent_commands_full": recent_commands_full[-12:],
        "recent_activity": recent_activity,
        "recent_activity_commands": recent_activity_commands,
        "swarm_posture": recent_activity_context.get("swarm_posture", {}) if isinstance(recent_activity_context.get("swarm_posture", {}), dict) else {},
        "incident_session": incident_session,
        "environment_drift": environment_drift,
        "sidebar_panel": _normalize_tui_panel_name(str(options.get("tui_panel", "overview"))),
        "panel_hint": _build_tui_panel_hint(_normalize_tui_panel_name(str(options.get("tui_panel", "overview")))),
        "provider_report": provider_report,
        "timeline_entries": timeline_entries,
        "trace_summary": trace_summary,
        "focus_title": str(focus_card.get("title", "")),
        "focus_body": str(focus_card.get("body", "")),
        "focus_actions": list(focus_card.get("actions", []))[:3] if isinstance(focus_card.get("actions", []), list) else [],
        "quick_action_items": quick_action_items,
        "latest_quick_action": latest_quick_action,
        "recommended_commands": _dedupe_strings([item for item in recommended_commands if item])[:6],
        "active_provider": _resolve_runtime_provider_label(str(options.get("provider", "auto"))),
        "shortcuts": [
            "/brief",
            "/scan",
            "/drift",
            "/activity",
            "/focus",
            "/do 1",
            "/timeline",
            "/trace",
            "/history",
            "/retry",
            "/panel next",
            "/refresh",
            "/providers",
            "/swarm --logs",
            "/remote root@host --logs",
            "/autopilot",
            "/remediate <目标>",
            "/mode execute",
            "exit",
        ],
    }


def _render_tui_demo_text(snapshot: dict[str, object]) -> str:
    shortcuts = snapshot.get("shortcuts", [])
    if not isinstance(shortcuts, list):
        shortcuts = []
    recommended = snapshot.get("recommended_commands", [])
    if not isinstance(recommended, list):
        recommended = []
    usable_targets = snapshot.get("usable_targets", [])
    if not isinstance(usable_targets, list):
        usable_targets = []
    configured_providers = snapshot.get("configured_providers", [])
    if not isinstance(configured_providers, list):
        configured_providers = []
    recent_activity = snapshot.get("recent_activity", [])
    if not isinstance(recent_activity, list):
        recent_activity = []
    recent_activity_commands = snapshot.get("recent_activity_commands", [])
    if not isinstance(recent_activity_commands, list):
        recent_activity_commands = []
    focus_actions = snapshot.get("focus_actions", [])
    if not isinstance(focus_actions, list):
        focus_actions = []
    quick_action_items = snapshot.get("quick_action_items", [])
    if not isinstance(quick_action_items, list):
        quick_action_items = []
    latest_quick_action = snapshot.get("latest_quick_action", {})
    if not isinstance(latest_quick_action, dict):
        latest_quick_action = {}
    timeline_entries = snapshot.get("timeline_entries", [])
    if not isinstance(timeline_entries, list):
        timeline_entries = []
    trace_summary = snapshot.get("trace_summary", [])
    if not isinstance(trace_summary, list):
        trace_summary = []
    recent_commands = snapshot.get("recent_commands", [])
    if not isinstance(recent_commands, list):
        recent_commands = []
    environment_signals = snapshot.get("environment_signals", [])
    if not isinstance(environment_signals, list):
        environment_signals = []
    swarm_posture = snapshot.get("swarm_posture", {})
    if not isinstance(swarm_posture, dict):
        swarm_posture = {}
    environment_drift = snapshot.get("environment_drift", {})
    if not isinstance(environment_drift, dict):
        environment_drift = {}
    incident_session = snapshot.get("incident_session", {})
    if not isinstance(incident_session, dict):
        incident_session = {}
    starter_prompts = _build_tui_starter_prompts(snapshot)
    action_bar = _build_tui_action_bar(snapshot)
    panel_hint = str(snapshot.get("panel_hint", "")).strip()
    state_card = _build_tui_state_card(snapshot)
    coach = _build_tui_start_coach(snapshot)
    boot_actions = _build_tui_boot_actions(snapshot)
    logo_lines = _build_tui_logo_lines()
    lines = [
        "╭─ ◉ LazySRE Fullscreen TUI ───────────────────────────────────────╮",
        "├─ Brand ──────────────────────────────────────────────────────────┤",
        *[f"│ {line}" for line in logo_lines],
        f"│ version={snapshot.get('version', '-')} mode={snapshot.get('mode', '-')} provider={snapshot.get('provider', '-')} model={snapshot.get('model', '-')}",
        f"│ panel={snapshot.get('sidebar_panel', 'overview')} hint={panel_hint or '-'}",
        f"│ action_bar={action_bar}",
        f"│ quick_state={_build_latest_quick_action_badge(snapshot)}",
        "├─ State Card ────────────────────────────────────────────────────┤",
        f"│ focus={state_card.get('focus', '-')}",
        f"│ quick={state_card.get('quick', '-')}",
        f"│ next={state_card.get('next', '-')}",
        "├─ Start Coach ───────────────────────────────────────────────────┤",
        f"│ phase={coach.get('phase_label', '-')}",
        f"│ headline={coach.get('headline', '-')}",
        f"│ primary={coach.get('primary', '/next')}",
        *[f"│ action: {item}" for item in boot_actions[:4]],
        "├─ Environment ───────────────────────────────────────────────────┤",
        f"│ profile={snapshot.get('environment_profile', '-') or '-'}",
        f"│ summary={snapshot.get('environment_summary', '-') or '-'}",
        *[f"│ signal: {item}" for item in environment_signals[:3]],
        "├─ Brief ─────────────────────────────────────────────────────────┤",
        f"│ status={snapshot.get('status', '-')}",
        f"│ headline={snapshot.get('headline', '-')}",
        "├─ Focus ─────────────────────────────────────────────────────────┤",
        f"│ {snapshot.get('focus_title', 'Focus')}: {snapshot.get('focus_body', '-')}",
        *(
            ["├─ Swarm Posture ───────────────────────────────────────────────┤"]
            + [f"│ {str(swarm_posture.get('headline', '')).strip()}"]
            + [f"│ {str(item)}" for item in list(swarm_posture.get("signals", []))[:3]]
            if str(swarm_posture.get("headline", "")).strip()
            else []
        ),
        *(
            ["├─ Incident Session ────────────────────────────────────────────┤"]
            + [f"│ status={incident_session.get('status', '-')}", f"│ {incident_session.get('headline', '-')}"]
            + ([f"│ {incident_session.get('stage_flow', '')}"] if str(incident_session.get("stage_flow", "")).strip() else [])
            + ([f"│ next={incident_session.get('next_step', '')}"] if str(incident_session.get("next_step", "")).strip() else [])
            if bool(incident_session.get("exists"))
            else []
        ),
        *(
            ["├─ Environment Drift ───────────────────────────────────────────┤"]
            + [f"│ status={environment_drift.get('status', '-')}", f"│ {environment_drift.get('headline', '-')}"]
            + [f"│ {str(item)}" for item in list(environment_drift.get("signals", []))[:3]]
            if str(environment_drift.get("status", "")).strip() in {"changed", "stale"}
            else []
        ),
        "├─ Target ────────────────────────────────────────────────────────┤",
        f"│ active_provider={snapshot.get('active_provider', '-')}",
        f"│ usable_targets={', '.join(str(x) for x in usable_targets) or '(none)'}",
        f"│ providers={', '.join(str(x) for x in configured_providers) or '(unset)'}",
        f"│ namespace={snapshot.get('namespace', '-')}",
        f"│ ssh_target={snapshot.get('ssh_target', '-') or '(not set)'}",
        f"│ prometheus={snapshot.get('prometheus_url', '-') or '(not set)'}",
        f"│ session_turns={snapshot.get('session_turns', 0)}",
        f"│ last_user={snapshot.get('last_user', '-') or '-'}",
        "├─ Recent Activity ───────────────────────────────────────────────┤",
        *[f"│ {item}" for item in recent_activity[:4]],
        *([ "├─ Focus Actions ────────────────────────────────────────────────┤"] + [f"│ {item}" for item in focus_actions[:2]] if focus_actions else []),
        *([ "├─ Activity Actions ──────────────────────────────────────────────┤"] + [f"│ {item}" for item in recent_activity_commands[:3]] if recent_activity_commands else []),
        *(
            ["├─ Quick Actions ───────────────────────────────────────────────┤"]
            + [
                line
                for item in quick_action_items[:3]
                if isinstance(item, dict)
                for line in [
                    f"│ {_format_quick_action_line(item)}",
                    f"│   {_format_quick_action_command(item)}",
                ]
            ]
            if quick_action_items
            else []
        ),
        *(
            ["├─ Last Quick Action ───────────────────────────────────────────┤"]
            + [
                f"│ {latest_quick_action.get('status', 'unknown')}: {latest_quick_action.get('command', '')}",
                f"│ {latest_quick_action.get('output_preview', '')}",
            ]
            if str(latest_quick_action.get("command", "")).strip()
            else []
        ),
        "├─ Recommended ───────────────────────────────────────────────────┤",
        *[f"│ {item}" for item in recommended[:4]],
        *([ "├─ Command Trail ─────────────────────────────────────────────────┤"] + [f"│ {item}" for item in recent_commands[-3:]] if recent_commands else []),
        *([ "├─ Trace Summary ────────────────────────────────────────────────┤"] + [f"│ {item}" for item in trace_summary[:3]] if trace_summary else []),
        *([ "├─ Execution Timeline ────────────────────────────────────────────┤"] + [f"│ {item}" for item in timeline_entries[:3]] if timeline_entries else []),
        *([ "├─ Starter Prompts ──────────────────────────────────────────────┤"] + [f"│ {item}" for item in starter_prompts[:4]] if starter_prompts else []),
        "├─ Shortcuts ─────────────────────────────────────────────────────┤",
        *[f"│ {item}" for item in shortcuts],
        "├─ Conversation ──────────────────────────────────────────────────┤",
        "│ 直接输入自然语言，例如：检查当前服务器 / 修复 swarm 副本不足",
        "│ Tab 自动补全命令，Up/Down 浏览历史（前缀筛选），Ctrl-L 清屏，F1/? 帮助，F3 切换 UI。",
        "╰─────────────────────────────────────────────────────────────────╯",
    ]
    return "\n".join(lines)


def _run_tui(options: dict[str, object], *, demo: bool) -> None:
    _maybe_auto_bootstrap_for_tui(options)
    _apply_saved_tui_runtime_state(options)
    snapshot = _build_tui_dashboard_snapshot(options)
    term = str(os.getenv("TERM", "")).strip().lower()
    if term in {"dumb", "unknown", ""}:
        typer.echo("终端能力受限，已切换简洁文本模式（可正常使用）。")
        typer.echo(_render_tui_demo_text(snapshot))
        return
    if demo or (not sys.stdin.isatty()) or (not sys.stdout.isatty()):
        typer.echo(_render_tui_demo_text(snapshot))
        return
    try:
        import curses
    except Exception:
        typer.echo("当前 Python 环境不支持 curses，使用预览模式：")
        typer.echo(_render_tui_demo_text(snapshot))
        return
    curses.wrapper(lambda stdscr: _run_curses_tui(stdscr, options, snapshot))


def _run_tui_request_with_progress(
    stdscr,
    *,
    snapshot: dict[str, object],
    history: list[tuple[str, str]],
    input_text: str,
    cursor_index: int,
    phase: str,
    raw_text: str,
    options: dict[str, object],
) -> tuple[str, int]:
    outcome: dict[str, str] = {"output": "", "error": ""}
    done = threading.Event()

    def _worker() -> None:
        try:
            outcome["output"] = _handle_tui_input(raw_text, options)
        except Exception as exc:  # pragma: no cover - defensive fallback
            outcome["error"] = _normalize_runtime_exception_message(exc)
        finally:
            done.set()

    worker = threading.Thread(target=_worker, daemon=True, name="lazysre-tui-runner")
    worker.start()
    spinner = ["|", "/", "-", "\\"]
    spin_index = 0
    started_at = time.monotonic()
    while not done.is_set():
        status = f"running:{phase} {spinner[spin_index % len(spinner)]}"
        _draw_tui(
            stdscr,
            snapshot=snapshot,
            history=history,
            input_text=input_text,
            cursor_index=cursor_index,
            status=status,
        )
        spin_index += 1
        time.sleep(0.08)
    worker.join(timeout=0.01)
    elapsed_ms = int((time.monotonic() - started_at) * 1000)
    if outcome["error"].strip():
        return f"error: {outcome['error']}", elapsed_ms
    return str(outcome["output"]), elapsed_ms


def _execute_tui_turn(
    stdscr,
    *,
    raw_text: str,
    options: dict[str, object],
    snapshot: dict[str, object],
    history: list[tuple[str, str]],
    input_history: list[str],
    input_text: str = "",
    cursor_index: int = 0,
) -> None:
    safe_text = _sanitize_tui_secret_tokens(raw_text)
    options["tui_last_input"] = safe_text
    if (not input_history) or (input_history[-1] != safe_text):
        input_history.append(safe_text)
    _save_tui_input_history(input_history)
    history.append(("You", safe_text))
    phase = _infer_tui_phase_from_input(raw_text)
    output, elapsed_ms = _run_tui_request_with_progress(
        stdscr,
        snapshot=snapshot,
        history=history,
        input_text=input_text,
        cursor_index=cursor_index,
        phase=phase,
        raw_text=raw_text,
        options=options,
    )
    fallback_note = _maybe_apply_tui_provider_fallback(options, output)
    display_output = _format_tui_output_for_display(output)
    display_output = _render_tui_completion_card(
        display_output,
        request=safe_text,
        duration_ms=elapsed_ms,
        ui_mode=_normalize_tui_ui_mode(str(options.get("tui_ui_mode", snapshot.get("ui_mode", "simple")))),
    )
    history.append(("LazySRE", display_output.strip() or "(no output)"))
    if fallback_note:
        history.append(("System", fallback_note))
    snapshot.update(_build_tui_dashboard_snapshot(options))


def _run_curses_tui(stdscr, options: dict[str, object], snapshot: dict[str, object]) -> None:
    import curses

    curses.curs_set(1)
    stdscr.keypad(True)
    try:
        curses.start_color()
        curses.use_default_colors()
    except Exception:
        pass
    stdscr.attrset(curses.A_NORMAL)
    stdscr.bkgd(" ", curses.A_NORMAL)
    history: list[tuple[str, str]] = [("LazySRE", _tui_welcome_message(snapshot))]
    input_text = ""
    cursor_index = 0
    status = "ready"
    completion_index = -1
    completion_seed = ""
    input_history = _merge_tui_input_history(
        _build_tui_bootstrap_input_history(snapshot),
        _load_tui_input_history(),
    )
    history_index = -1
    history_seed = ""
    overlay = ""
    while True:
        _draw_tui(
            stdscr,
            snapshot=snapshot,
            history=history,
            input_text=input_text,
            cursor_index=cursor_index,
            status=status,
            overlay=overlay,
        )
        key = stdscr.get_wch()
        if isinstance(key, str):
            if key in {"\x10", "\x0e"}:
                # Ctrl+P / Ctrl+N fallback for terminals that don't map arrow keys.
                direction = "up" if key == "\x10" else "down"
                input_text, history_index, history_seed = _cycle_tui_input_history(
                    input_text,
                    input_history=input_history,
                    history_index=history_index,
                    history_seed=history_seed,
                    direction=direction,
                )
                cursor_index = len(input_text)
                completion_index = -1
                completion_seed = ""
                continue
            if key == "\x1b":
                escape_key = _read_tui_escape_key(stdscr)
                if escape_key is not None:
                    key = escape_key
            key = _normalize_tui_key_alias(key)
            input_text, cursor_index, ctrl_handled = _apply_tui_ctrl_edit_key(
                key=key,
                input_text=input_text,
                cursor_index=cursor_index,
            )
            if ctrl_handled:
                overlay = ""
                completion_index = -1
                completion_seed = ""
                history_index = -1
                history_seed = ""
                continue
            if (not input_text) and key == "?":
                overlay = "" if overlay == "help" else "help"
                status = "help" if overlay else "ready"
                continue
            if key in {"\n", "\r"}:
                if overlay:
                    overlay = ""
                    status = "ready"
                    continue
                raw_text = input_text.strip()
                input_text = ""
                cursor_index = 0
                if not raw_text:
                    auto_cmd = _resolve_tui_empty_submit_command(snapshot=snapshot, history=history)
                    if auto_cmd:
                        _execute_tui_turn(
                            stdscr,
                            raw_text=auto_cmd,
                            options=options,
                            snapshot=snapshot,
                            history=history,
                            input_history=input_history,
                            input_text=input_text,
                            cursor_index=cursor_index,
                        )
                        status = "ready"
                        overlay = ""
                        completion_index = -1
                        completion_seed = ""
                        history_index = -1
                        history_seed = ""
                        cursor_index = 0
                    continue
                if raw_text.lower() in {"exit", "quit", ":q", "/exit", "/quit"}:
                    break
                if raw_text.lower() in {"/clear", "/cls"}:
                    history = [("LazySRE", "已清空当前屏幕内容。输入 /help /providers /brief 继续。")]
                    status = "ready"
                    history_index = -1
                    history_seed = ""
                    completion_index = -1
                    completion_seed = ""
                    cursor_index = 0
                    continue
                _execute_tui_turn(
                    stdscr,
                    raw_text=raw_text,
                    options=options,
                    snapshot=snapshot,
                    history=history,
                    input_history=input_history,
                    input_text=input_text,
                    cursor_index=cursor_index,
                )
                status = "ready"
                overlay = ""
                completion_index = -1
                completion_seed = ""
                history_index = -1
                history_seed = ""
                cursor_index = 0
                continue
            if key == "\t":
                input_text, completion_index, completion_seed = _cycle_tui_completion(
                    input_text,
                    snapshot=snapshot,
                    completion_index=completion_index,
                    completion_seed=completion_seed,
                )
                cursor_index = len(input_text)
                continue
            if key == "\x0c":
                history = [("LazySRE", "已清空当前屏幕内容。输入 /help /providers /brief 继续。")]
                input_text = ""
                cursor_index = 0
                status = "ready"
                overlay = ""
                completion_index = -1
                completion_seed = ""
                history_index = -1
                history_seed = ""
                continue
            if key in {"\x7f", "\b"}:
                if cursor_index > 0:
                    input_text = input_text[: cursor_index - 1] + input_text[cursor_index:]
                    cursor_index -= 1
                completion_index = -1
                completion_seed = ""
                history_index = -1
                history_seed = ""
                continue
            if key == "\x1b":
                if overlay:
                    overlay = ""
                    status = "ready"
                    continue
                break
            if key in {"<UP>", "<DOWN>"}:
                direction = "up" if key == "<UP>" else "down"
                input_text, history_index, history_seed = _cycle_tui_input_history(
                    input_text,
                    input_history=input_history,
                    history_index=history_index,
                    history_seed=history_seed,
                    direction=direction,
                )
                cursor_index = len(input_text)
                completion_index = -1
                completion_seed = ""
                continue
            if key in {"<LEFT>", "<RIGHT>", "<HOME>", "<END>", "<DELETE>"}:
                if key == "<LEFT>":
                    cursor_index = max(0, cursor_index - 1)
                elif key == "<RIGHT>":
                    cursor_index = min(len(input_text), cursor_index + 1)
                elif key == "<HOME>":
                    cursor_index = 0
                elif key == "<END>":
                    cursor_index = len(input_text)
                else:  # <DELETE>
                    if cursor_index < len(input_text):
                        input_text = input_text[:cursor_index] + input_text[cursor_index + 1 :]
                completion_index = -1
                completion_seed = ""
                history_index = -1
                history_seed = ""
                continue
            if (not input_text) and key in {"1", "2", "3", "4"}:
                ui_mode = _normalize_tui_ui_mode(str(options.get("tui_ui_mode", "simple")))
                if ui_mode == "expert":
                    options["tui_panel"] = _panel_name_from_shortcut(key)
                    _persist_tui_runtime_state(options)
                    snapshot.update(_build_tui_dashboard_snapshot(options))
                    history.append(("LazySRE", f"左侧面板已切换到 {snapshot.get('sidebar_panel', 'overview')}。"))
                    status = f"panel:{snapshot.get('sidebar_panel', 'overview')}"
                    overlay = ""
                    continue
            if (not input_text) and key in {"N", "T", "U", "R"}:
                quick_map = {"N": "/next", "T": "/trace", "U": "/undo", "R": "/retry"}
                quick_cmd = quick_map.get(key, "")
                if quick_cmd:
                    _execute_tui_turn(
                        stdscr,
                        raw_text=quick_cmd,
                        options=options,
                        snapshot=snapshot,
                        history=history,
                        input_history=input_history,
                        input_text="",
                        cursor_index=0,
                    )
                    status = "ready"
                    overlay = ""
                    completion_index = -1
                    completion_seed = ""
                    history_index = -1
                    history_seed = ""
                    cursor_index = 0
                    continue
            if key.isprintable():
                overlay = ""
                input_text = input_text[:cursor_index] + key + input_text[cursor_index:]
                cursor_index += 1
                completion_index = -1
                completion_seed = ""
                history_index = -1
                history_seed = ""
                continue
        elif key == curses.KEY_UP:
            input_text, history_index, history_seed = _cycle_tui_input_history(
                input_text,
                input_history=input_history,
                history_index=history_index,
                history_seed=history_seed,
                direction="up",
            )
            cursor_index = len(input_text)
        elif key == curses.KEY_DOWN:
            input_text, history_index, history_seed = _cycle_tui_input_history(
                input_text,
                input_history=input_history,
                history_index=history_index,
                history_seed=history_seed,
                direction="down",
            )
            cursor_index = len(input_text)
        elif key == curses.KEY_LEFT:
            cursor_index = max(0, cursor_index - 1)
            completion_index = -1
            completion_seed = ""
        elif key == curses.KEY_RIGHT:
            cursor_index = min(len(input_text), cursor_index + 1)
            completion_index = -1
            completion_seed = ""
        elif key == curses.KEY_HOME:
            cursor_index = 0
            completion_index = -1
            completion_seed = ""
        elif key == curses.KEY_END:
            cursor_index = len(input_text)
            completion_index = -1
            completion_seed = ""
        elif key == curses.KEY_F1:
            overlay = "" if overlay == "help" else "help"
            status = "help" if overlay else "ready"
        elif key == curses.KEY_F2:
            options["tui_panel"] = _next_tui_panel(str(options.get("tui_panel", snapshot.get("sidebar_panel", "overview"))))
            _persist_tui_runtime_state(options)
            snapshot.update(_build_tui_dashboard_snapshot(options))
            history.append(("LazySRE", f"左侧面板已切换到 {snapshot.get('sidebar_panel', 'overview')}。"))
            status = f"panel:{snapshot.get('sidebar_panel', 'overview')}"
            overlay = ""
        elif key == curses.KEY_F3:
            options["tui_ui_mode"] = _toggle_tui_ui_mode(str(options.get("tui_ui_mode", snapshot.get("ui_mode", "simple"))))
            _persist_tui_runtime_state(options)
            snapshot.update(_build_tui_dashboard_snapshot(options))
            history.append(("LazySRE", f"UI 模式已切换到 {snapshot.get('ui_mode', 'simple')}。"))
            status = f"ui:{snapshot.get('ui_mode', 'simple')}"
            overlay = ""
        elif key == curses.KEY_BACKSPACE:
            if cursor_index > 0:
                input_text = input_text[: cursor_index - 1] + input_text[cursor_index:]
                cursor_index -= 1
            overlay = ""
            completion_index = -1
            completion_seed = ""
            history_index = -1
            history_seed = ""
        elif key == curses.KEY_DC:
            if cursor_index < len(input_text):
                input_text = input_text[:cursor_index] + input_text[cursor_index + 1 :]
            overlay = ""
            completion_index = -1
            completion_seed = ""
            history_index = -1
            history_seed = ""


def _draw_tui(
    stdscr,
    *,
    snapshot: dict[str, object],
    history: list[tuple[str, str]],
    input_text: str,
    cursor_index: int,
    status: str,
    overlay: str = "",
) -> None:
    import curses

    height, width = stdscr.getmaxyx()
    if width < 86 or height < 20:
        _draw_tui_low_fidelity(
            stdscr,
            snapshot=snapshot,
            history=history,
            input_text=input_text,
            cursor_index=cursor_index,
            status=status,
            width=width,
            height=height,
        )
        return
    stdscr.attrset(curses.A_NORMAL)
    stdscr.bkgd(" ", curses.A_NORMAL)
    stdscr.erase()
    ui_mode = _normalize_tui_ui_mode(str(snapshot.get("ui_mode", "simple")))
    sidebar_w = min(max(30, width // 3), 44) if ui_mode == "simple" else min(max(28, width // 3), 46)
    logo = _build_tui_logo_lines(compact=True)[0]
    active_provider = str(snapshot.get("active_provider", snapshot.get("provider", "-"))).strip() or "-"
    mode = str(snapshot.get("mode", "-")).strip() or "-"
    title = (
        f" {logo} | {status} | {mode}/{active_provider} | ui={ui_mode} | F1 help | F2 panel | F3 ui | Tab complete | Esc quit "
    )
    _tui_addnstr(stdscr, 0, 0, title.ljust(width), width - 1)
    for y in range(1, height - 2):
        if sidebar_w < width:
            stdscr.addch(y, sidebar_w, "|")
    side_width = max(12, sidebar_w - 2)
    if ui_mode == "simple":
        side_lines = _build_tui_compact_sidebar_lines(snapshot, width=side_width)
    else:
        side_lines = _build_tui_sidebar_lines(snapshot, width=side_width)
    for idx, line in enumerate(side_lines[: max(0, height - 7)], 1):
        _tui_addnstr(stdscr, idx, 1, line, side_width)

    content_w = max(10, width - sidebar_w - 3)
    rows: list[str] = []
    if (not input_text.strip()) and (not _has_tui_user_history(history)):
        if ui_mode == "simple":
            rows.extend(_build_tui_compact_welcome_rows(snapshot, width=content_w))
        else:
            rows.extend(_build_tui_idle_content_rows(snapshot, width=content_w))
        rows.append("")
    history_limit = 18 if ui_mode == "simple" else 28
    for speaker, text in history[-history_limit:]:
        rows.append(f"{speaker}:")
        for raw in str(text).splitlines() or [""]:
            rows.extend(textwrap.wrap(raw, width=content_w) or [""])
        rows.append("")
    visible = rows[-max(1, height - 8) :]
    for idx, line in enumerate(visible, 1):
        _tui_addnstr(stdscr, idx, sidebar_w + 2, line, content_w)
    action_line = _build_tui_compact_action_bar(snapshot) if ui_mode == "simple" else _build_tui_action_bar(snapshot)
    _tui_addnstr(stdscr, height - 5, 0, action_line.ljust(width), width - 1)
    hint_line = _build_tui_compact_hint_line(snapshot) if ui_mode == "simple" else _build_tui_status_hint_line(snapshot)
    _tui_addnstr(stdscr, height - 4, 0, hint_line.ljust(width), width - 1)
    if ui_mode == "simple":
        footer = _build_tui_compact_footer_line(snapshot=snapshot, status=status)
    else:
        footer = _build_tui_footer_line(snapshot=snapshot, status=status, history=history)
    _tui_addnstr(stdscr, height - 3, 0, footer.ljust(width), width - 1)
    prompt, cursor_x = _build_tui_prompt_line_and_cursor(input_text=input_text, cursor_index=cursor_index, width=width)
    _tui_addnstr(stdscr, height - 2, 0, "-" * max(1, width - 1), width - 1)
    _tui_addnstr(stdscr, height - 1, 0, prompt, width - 1)
    if overlay == "help":
        _draw_tui_help_overlay(stdscr, snapshot=snapshot, width=width, height=height)
    stdscr.move(height - 1, cursor_x)
    stdscr.refresh()


def _draw_tui_low_fidelity(
    stdscr,
    *,
    snapshot: dict[str, object],
    history: list[tuple[str, str]],
    input_text: str,
    cursor_index: int,
    status: str,
    width: int,
    height: int,
) -> None:
    stdscr.erase()
    coach = _build_tui_start_coach(snapshot)
    provider = str(snapshot.get("active_provider", snapshot.get("provider", "-"))).strip() or "-"
    rows = [
        f"◉ LazySRE [{status}] {snapshot.get('mode', '-')}/{provider} (low-fidelity)",
        f"阶段: {coach.get('phase_label', '-')}",
        f"下一步: {coach.get('primary', '/next')}",
        "输入自然语言，或 /next /start /ui expert /help",
        "-" * max(1, width - 1),
    ]
    if history:
        speaker, text = history[-1]
        rows.append(f"{speaker}:")
        rows.extend(textwrap.wrap(str(text).strip(), width=max(12, width - 1))[: max(1, height - 9)])
    for idx, line in enumerate(rows[: max(1, height - 3)]):
        _tui_addnstr(stdscr, idx, 0, line, max(1, width - 1))
    prompt, cursor_x = _build_tui_prompt_line_and_cursor(input_text=input_text, cursor_index=cursor_index, width=width)
    _tui_addnstr(stdscr, height - 2, 0, "-" * max(1, width - 1), width - 1)
    _tui_addnstr(stdscr, height - 1, 0, prompt, width - 1)
    stdscr.move(height - 1, cursor_x)
    stdscr.refresh()


def _build_tui_compact_sidebar_lines(snapshot: dict[str, object], *, width: int) -> list[str]:
    state_card = _build_tui_state_card(snapshot)
    coach = _build_tui_start_coach(snapshot)
    boot_actions = _build_tui_boot_actions(snapshot)
    provider = str(snapshot.get("active_provider", snapshot.get("provider", "-"))).strip() or "-"
    targets = snapshot.get("usable_targets", [])
    target_list = [str(item).strip() for item in targets if str(item).strip()] if isinstance(targets, list) else []
    lines: list[str] = [
        *_build_tui_logo_lines(),
        "",
        "Now",
        f"- {state_card.get('focus', '-')}",
        "",
        "Next",
        f"- {state_card.get('next', '/do 1')}",
        "",
        "Guide",
        f"- {coach.get('headline', '-')}",
        *[f"- {item}" for item in list(coach.get("steps", []))[:2]],
        "",
        "Start",
        "- 直接输入自然语言",
        *[f"- {item}" for item in boot_actions[:3]],
        "- Shift+N/T/U/R 快速闭环",
        "- F3 切换 simple/expert",
        "",
        "Runtime",
        f"- provider: {provider}",
        f"- targets: {', '.join(target_list[:3]) if target_list else '-'}",
    ]
    rows: list[str] = []
    for item in lines:
        if not item:
            rows.append("")
            continue
        if item in {"Now", "Next", "Guide", "Start", "Runtime"}:
            rows.append(item)
            continue
        rows.extend(textwrap.wrap(item, width=max(10, width)) or [item])
    return rows


def _build_tui_compact_welcome_rows(snapshot: dict[str, object], *, width: int) -> list[str]:
    state_card = _build_tui_state_card(snapshot)
    coach = _build_tui_start_coach(snapshot)
    boot_actions = _build_tui_boot_actions(snapshot)
    prompts = _build_tui_starter_prompts(snapshot)[:4]
    sections = [
        "Start",
        f"- 当前: {state_card.get('focus', '-')}",
        f"- 下一步: {state_card.get('next', '/do 1')}",
        f"- 阶段: {coach.get('phase_label', '快速开始')}",
        "",
        "One Minute",
        *[f"- {item}" for item in boot_actions[:3]],
        "",
        "Quick Keys",
        "- Shift+N = /next",
        "- Shift+T = /trace",
        "- Shift+U = /undo",
        "- Shift+R = /retry",
        "",
        "Try",
        *[f"- {item}" for item in prompts],
    ]
    rows: list[str] = []
    for item in sections:
        if not item:
            rows.append("")
            continue
        if item in {"Start", "One Minute", "Quick Keys", "Try"}:
            rows.append(item)
            continue
        rows.extend(textwrap.wrap(item, width=max(10, width)) or [item])
    return rows


def _build_tui_compact_action_bar(snapshot: dict[str, object]) -> str:
    next_hint = str(_build_tui_state_card(snapshot).get("next", "")).strip() or "/do 1"
    return (
        "actions> Enter(空)=下一步 · 数字=动作 · ↑/↓ 历史(前缀筛选) · Tab 补全 · "
        "Shift+N/T/U/R · F3切UI · /history · /doctor · /preflight · /secret-scan · /ui expert · "
        f"{next_hint}"
    )


def _build_tui_compact_hint_line(snapshot: dict[str, object]) -> str:
    coach = _build_tui_start_coach(snapshot)
    coach_hint = str(coach.get("hint", "")).strip()
    if coach_hint:
        if len(coach_hint) > 96:
            return coach_hint[:93] + "..."
        return coach_hint
    hint = _build_tui_status_hint_line(snapshot)
    if len(hint) > 96:
        return hint[:93] + "..."
    return hint


def _build_tui_compact_footer_line(*, snapshot: dict[str, object], status: str) -> str:
    targets = snapshot.get("usable_targets", [])
    target_count = len(targets) if isinstance(targets, list) else 0
    provider = str(snapshot.get("active_provider", snapshot.get("provider", "-"))).strip() or "-"
    mode = str(snapshot.get("mode", "-")).strip() or "-"
    ui_mode = _normalize_tui_ui_mode(str(snapshot.get("ui_mode", "simple")))
    return f"{status} · {mode} · provider={provider} · targets={target_count} · ui={ui_mode} · /next"


def _build_tui_start_coach(snapshot: dict[str, object]) -> dict[str, object]:
    provider_ready = bool(snapshot.get("provider_ready"))
    targets = snapshot.get("usable_targets", [])
    target_count = len(targets) if isinstance(targets, list) else 0
    status = str(snapshot.get("status", "")).strip().lower()
    latest = snapshot.get("latest_quick_action", {})
    latest_status = str(latest.get("status", "")).strip().lower() if isinstance(latest, dict) else ""
    state_card = _build_tui_state_card(snapshot)

    if not provider_ready:
        return {
            "phase": "connect_llm",
            "phase_label": "连接模型",
            "headline": "先跑一键就绪，再连接模型",
            "primary": "/go 1",
            "hint": "hint> 先执行 /quickstart 自动补齐环境；完成后再 /providers 或 /provider gemini。",
            "steps": ["/go 1", "/go 3", "/providers"],
        }
    if target_count == 0:
        return {
            "phase": "scan_env",
            "phase_label": "自动探测环境",
            "headline": "先做一次全局扫描",
            "primary": "/go 1",
            "hint": "hint> 先执行 /scan，LazySRE 会自动识别 Docker/Swarm/K8s/Prometheus。",
            "steps": ["/go 1", "/go 2"],
        }
    if latest_status == "fail":
        return {
            "phase": "recover",
            "phase_label": "处理失败链路",
            "headline": "先看失败链路再决定重试",
            "primary": "/trace",
            "hint": "hint> 最近动作失败。先 /trace，再 /timeline，最后 /do 1。",
            "steps": ["/trace", "/timeline", "/next"],
        }
    if status in {"cold-start", "unknown"}:
        return {
            "phase": "triage",
            "phase_label": "建立现场认知",
            "headline": "先拿一份总览简报",
            "primary": "/go 2",
            "hint": "hint> 先执行 /brief，确认当前最优先问题，再 /do 1。",
            "steps": ["/go 2", "/next"],
        }
    return {
        "phase": "act",
        "phase_label": "执行下一步",
        "headline": "按当前建议继续推进",
        "primary": str(state_card.get("next", "/do 1")).strip() or "/do 1",
        "hint": "hint> 输入 /next 自动执行建议动作，或直接说你的目标。",
        "steps": [str(state_card.get("next", "/do 1")).strip() or "/do 1"],
    }


def _pick_tui_next_command(snapshot: dict[str, object]) -> str:
    coach = _build_tui_start_coach(snapshot)
    primary = str(coach.get("primary", "")).strip()
    resolved_primary = _resolve_tui_coach_primary_command(snapshot, primary)
    if resolved_primary:
        return resolved_primary
    candidates = [
        resolved_primary,
        primary,
        str(_build_tui_state_card(snapshot).get("next", "")).strip(),
        "/do 1",
        "/scan",
    ]
    tokens = [
        "/do 1",
        "/scan",
        "/brief",
        "/trace",
        "/timeline",
        "/drift",
        "/providers",
        "/provider mock",
        "/provider gemini",
        "/quickstart",
        "/doctor strict",
        "/activity",
        "/focus",
    ]
    for raw in candidates:
        if not raw:
            continue
        lowered = raw.lower()
        for token in tokens:
            if token in lowered:
                return token
    return "/do 1"


def _resolve_tui_coach_primary_command(snapshot: dict[str, object], primary: str) -> str:
    value = str(primary or "").strip()
    if not value:
        return ""
    lowered = value.lower()
    if lowered.startswith("/go "):
        action_id = _safe_int(lowered[len("/go ") :].strip())
        if action_id > 0:
            return _resolve_tui_boot_action_command(snapshot, action_id)
    if lowered in {"/provider mock", "/provider gemini", "/providers", "/quickstart", "/scan", "/brief", "/trace", "/timeline", "/doctor strict", "/do 1"}:
        return lowered
    return ""


def _build_tui_boot_actions(snapshot: dict[str, object]) -> list[str]:
    coach = _build_tui_start_coach(snapshot)
    phase = str(coach.get("phase", "")).strip()
    provider_ready = bool(snapshot.get("provider_ready"))
    if (not provider_ready) or phase == "connect_llm":
        return [
            "1) /quickstart（一键补齐基础环境）",
            "2) /provider mock（先可用）",
            "3) /providers（看就绪状态）",
            "4) /provider gemini（切到 Gemini）",
        ]
    return [
        "1) /scan（自动探测环境）",
        "2) /brief（生成总览简报）",
        "3) /next（执行建议动作）",
        "4) /doctor strict（严格体检）",
    ]


def _resolve_tui_boot_action_command(snapshot: dict[str, object], action_id: int) -> str:
    if action_id not in {1, 2, 3, 4}:
        return ""
    coach = _build_tui_start_coach(snapshot)
    phase = str(coach.get("phase", "")).strip()
    provider_ready = bool(snapshot.get("provider_ready"))
    if (not provider_ready) or phase == "connect_llm":
        return {1: "/quickstart", 2: "/provider mock", 3: "/providers", 4: "/provider gemini"}.get(action_id, "")
    return {1: "/scan", 2: "/brief", 3: "/next", 4: "/doctor strict"}.get(action_id, "")


def _render_tui_start_card(options: dict[str, object]) -> str:
    snapshot = _build_tui_dashboard_snapshot(options)
    coach = _build_tui_start_coach(snapshot)
    steps = list(coach.get("steps", [])) if isinstance(coach.get("steps", []), list) else []
    actions = _build_tui_boot_actions(snapshot)
    return "\n".join(
        [
            "Start Coach",
            f"- 阶段: {coach.get('phase_label', '-')}",
            f"- 目标: {coach.get('headline', '-')}",
            f"- 优先动作: {coach.get('primary', '/next')}",
            *(["- 下一步:"] + [f"  - {item}" for item in steps[:3]] if steps else []),
            "",
            "One Minute Setup",
            *[f"- {item}" for item in actions[:4]],
            "",
            "输入 /next 自动执行优先动作，或直接说你的需求。",
            "也可输入 /go 1|2|3|4 快速执行引导动作。",
            "高级用户可输入 /ui expert 切换专家视图。",
        ]
    )


def _render_tui_quick_help_text(snapshot: dict[str, object]) -> str:
    state_card = _build_tui_state_card(snapshot)
    coach = _build_tui_start_coach(snapshot)
    provider = str(snapshot.get("active_provider", snapshot.get("provider", "-"))).strip() or "-"
    mode = str(snapshot.get("mode", "-")).strip() or "-"
    return "\n".join(
        [
            "Quick Help",
            f"- 当前: mode={mode} provider={provider}",
            f"- 阶段: {coach.get('phase_label', '-')}",
            f"- 建议下一步: {state_card.get('next', '/next')}",
            "",
            "Core Commands",
            "- /next: 执行当前建议下一步",
            "- /scan: 自动探测环境",
            "- /brief: 生成总览简报",
            "- /do 1: 执行第1条建议动作",
            "- /trace /timeline: 看执行链路",
            "- /providers: 查看模型就绪状态",
            "- /doctor: 运行环境体检（支持 /doctor strict /doctor install）",
            "- /preflight: 发布前一键体检（install-doctor + doctor + secret-scan）",
            "- /preflight --strict: 严格门禁",
            "- /secret-scan: 检查当前工作区是否存在疑似密钥泄漏",
            "- /secret-scan --staged: 仅扫描当前 git 暂存区文件",
            "",
            "Input Shortcuts",
            "- 直接输入自然语言",
            "- 口语短句：继续/重试/历史/帮助/扫描/简报",
            "- ↑/↓ 历史（支持前缀筛选）",
            "- Tab 补全，Ctrl-A/E/U/K/W 编辑",
            "- Shift+N/T/U/R 快捷闭环，F2 切面板，F3 切 UI",
            "",
            "Tip",
            "- 按 F1 或 ? 可打开全屏帮助面板。",
        ]
    )


def _format_tui_output_for_display(text: str) -> str:
    lines = str(text or "").splitlines()
    internal_prefixes = ("[llm_turn]", "[lm_turn]", "[tool_call]", "[tool_output]", "[llm.turn]")
    cleaned: list[str] = []
    in_code = False
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            continue
        if (not in_code) and any(stripped.startswith(prefix) for prefix in internal_prefixes):
            continue
        if stripped.startswith("## "):
            cleaned.append(stripped[3:] + ":")
            continue
        if stripped.startswith("# "):
            cleaned.append(stripped[2:] + ":")
            continue
        cleaned.append(raw)
    compressed: list[str] = []
    blank_count = 0
    for line in cleaned:
        if line.strip():
            blank_count = 0
            compressed.append(line)
            continue
        blank_count += 1
        if blank_count <= 1:
            compressed.append("")
    result = "\n".join(compressed).strip() or str(text or "").strip()
    normalized = _sanitize_tui_secret_tokens(result)
    if _looks_like_tui_degraded_output(normalized):
        return _render_tui_degraded_card(normalized)
    if _looks_like_tui_error_output(normalized):
        return _render_tui_error_card(normalized)
    return normalized


def _infer_tui_phase_from_input(text: str) -> str:
    lowered = str(text or "").strip().lower()
    if any(token in lowered for token in ["/scan", "/brief", "/status", "/provider", "/providers"]):
        return "observe"
    if any(token in lowered for token in ["/trace", "/timeline", "/focus", "/activity", "/drift"]):
        return "diagnose"
    if any(token in lowered for token in ["/do", "/next", "/remediate", "/fix", "/apply", "/undo"]):
        return "act"
    return "thinking"


def _render_tui_completion_card(text: str, *, request: str, duration_ms: int, ui_mode: str = "simple") -> str:
    content = str(text or "").strip() or "(no output)"
    if content.lower().startswith("result: failed"):
        body = content
    elif _looks_like_tui_error_output(content):
        body = content
    elif _normalize_tui_ui_mode(ui_mode) == "simple":
        body = _render_tui_simple_result_card(content, request=request)
    else:
        body = _render_tui_success_card(content, request=request)
    return "\n".join(
        [
            "Result",
            f"- Request: {request[:96]}",
            f"- Duration: {max(0, int(duration_ms))} ms",
            "",
            body,
        ]
    )


def _looks_like_tui_error_output(text: str) -> bool:
    lowered = str(text or "").strip().lower()
    return (
        lowered.startswith("error:")
        or ("\nerror:" in lowered)
        or lowered.startswith("result: failed")
        or ("traceback" in lowered)
        or ("exception:" in lowered)
    )


def _looks_like_tui_degraded_output(text: str) -> bool:
    lowered = str(text or "").strip().lower()
    return "[auto-fallback]" in lowered or "provider_fallback" in lowered


def _render_tui_degraded_card(text: str) -> str:
    message = str(text or "").strip()
    detail = message.replace("[auto-fallback]", "").strip()
    lines = [line.strip() for line in detail.splitlines() if line.strip()]
    reason = "-"
    for line in lines:
        if "原因:" in line:
            reason = line.split("原因:", 1)[-1].strip() or "-"
            break
    if reason == "-" and lines:
        reason = lines[0]
    return "\n".join(
        [
            "Result: Degraded",
            "Reason: 当前 provider 调用失败，已自动降级到 mock 继续执行。",
            f"Detail: {reason[:220]}",
            "Do Now:",
            "- /providers（检查 provider 就绪状态）",
            "- /login --provider <openai|anthropic|gemini|deepseek|qwen|kimi>",
            "Fallback:",
            "- /provider mock（继续排障）",
            "- /next",
        ]
    )


def _maybe_apply_tui_provider_fallback(options: dict[str, object], output_text: str) -> str:
    if not _looks_like_tui_degraded_output(output_text):
        return ""
    current = str(options.get("provider", "auto")).strip().lower() or "auto"
    if current == "mock":
        return ""
    options["provider"] = "mock"
    options["model"] = resolve_model_name("openai", settings.model_name)
    return "已将当前会话 provider 自动切换为 mock，避免后续重复降级。可随时用 /provider <name> 切回真实模型。"


def _maybe_apply_runtime_provider_fallback(options: dict[str, object], result: DispatchResult) -> str:
    fallback_event: DispatchEvent | None = None
    for event in list(result.events or []):
        if str(event.message or "").strip().lower() == "provider_fallback":
            fallback_event = event
            break
    if fallback_event is None:
        return ""
    current = str(options.get("provider", "auto")).strip().lower() or "auto"
    target = "mock"
    reason = ""
    if isinstance(fallback_event.data, dict):
        target = str(fallback_event.data.get("to", "mock")).strip().lower() or "mock"
        reason = _sanitize_tui_secret_tokens(str(fallback_event.data.get("reason", "")).strip())
    if current == target:
        return ""
    options["provider"] = target
    if target == "mock":
        options["model"] = resolve_model_name("openai", settings.model_name)
    else:
        options["model"] = resolve_model_name(target, str(options.get("model", settings.model_name)))
    reason_text = f" 原因: {reason[:180]}" if reason else ""
    return (
        f"检测到 provider 自动降级，已将当前会话切换到 `{target}`，避免后续重复失败。"
        "可随时用 `/provider <name>` 切回真实模型。"
        f"{reason_text}"
    )


def _render_tui_simple_result_card(text: str, *, request: str) -> str:
    content = str(text or "").strip()
    status = _extract_named_field(content, ["status", "状态"]) or "Completed"
    risk = _extract_named_field(content, ["risk level", "风险等级"])
    summary = _extract_named_field(content, ["reasoning", "诊断", "结论", "summary", "摘要"])
    commands: list[str] = []
    seen_commands: set[str] = set()
    for item in _extract_command_candidates(content, max_items=8):
        if (not _looks_like_shell_command(item)) or (item in seen_commands):
            continue
        seen_commands.add(item)
        commands.append(item)
        if len(commands) >= 3:
            break
    if len(commands) < 3:
        for raw in content.splitlines():
            line = raw.strip().strip("`")
            if (not _looks_like_shell_command(line)) or (line in seen_commands):
                continue
            seen_commands.add(line)
            commands.append(line)
            if len(commands) >= 3:
                break
    if not summary:
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        for line in lines:
            lowered = line.lower()
            if lowered.startswith(("result:", "status:", "reason:", "impact:", "do now:", "fallback:")):
                continue
            if line.endswith(":"):
                continue
            if line.startswith("- "):
                continue
            summary = line
            break
    summary_text = _truncate_tui_status_text(summary or "已完成。", max_chars=160)
    next_actions = _infer_tui_next_actions_from_text(content, request=request)[:2]
    rows = [
        "Result: Success",
        f"Status: {status[:64]}",
        f"Summary: {summary_text}",
    ]
    if risk:
        rows.append(f"Risk: {_truncate_tui_status_text(risk, max_chars=96)}")
    if commands:
        rows.extend(["Commands:", *[f"- {item}" for item in commands]])
    rows.extend(["Next:", *[f"- {item}" for item in next_actions]])
    return "\n".join(rows)


def _render_tui_error_card(text: str) -> str:
    message = str(text or "").strip()
    detail = message.split("error:", 1)[-1].strip() if "error:" in message.lower() else message
    impact = "当前请求未完成，未执行任何高风险变更。"
    now_actions = ["/provider mock（先验证流程）", "/providers（检查 provider 就绪）"]
    fallback_actions = ["/trace", "/timeline"]
    lowered = detail.lower()
    if "http 400" in lowered or "api key" in lowered:
        now_actions = ["/providers（检查 key/模型）", "/provider mock（临时可用）"]
        fallback_actions = ["/start", "/next"]
    elif "socks" in lowered or "proxy" in lowered:
        now_actions = ['python3 -m pip install "httpx[socks]"', "检查/清理 ALL_PROXY HTTPS_PROXY HTTP_PROXY"]
        fallback_actions = ["/provider mock", "/providers"]
    return "\n".join(
        [
            "Result: Failed",
            f"Reason: {detail[:220]}",
            f"Impact: {impact}",
            "Do Now:",
            *[f"- {item}" for item in now_actions],
            "Fallback:",
            *[f"- {item}" for item in fallback_actions],
        ]
    )


def _render_tui_success_card(text: str, *, request: str) -> str:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    conclusion = lines[0] if lines else "已完成。"
    evidence = [line for line in lines[1:] if (line.startswith("-") or ":" in line)][:3]
    if not evidence and len(lines) > 1:
        evidence = [f"- {line}" for line in lines[1:4]]
    next_actions = _infer_tui_next_actions_from_text(text, request=request)[:2]
    return "\n".join(
        [
            "Result: Success",
            f"Conclusion: {conclusion[:220]}",
            "Evidence:",
            *(evidence or ["- (no structured evidence)"]),
            "Next:",
            *[f"- {item}" for item in next_actions],
        ]
    )


def _infer_tui_next_actions_from_text(text: str, *, request: str) -> list[str]:
    lowered = str(text or "").lower()
    if "trace" in lowered:
        return ["/timeline", "/next"]
    if "scan" in lowered:
        return ["/brief", "/next"]
    if "provider" in lowered:
        return ["/providers", "/next"]
    req = str(request or "").lower()
    if "/scan" in req:
        return ["/brief", "/next"]
    if "/brief" in req:
        return ["/next", "/trace"]
    return ["/next", "/trace"]


def _sanitize_tui_secret_tokens(text: str) -> str:
    value = str(text or "")
    value = re.sub(r"AIza[0-9A-Za-z_-]{10,}", "AIza***REDACTED***", value)
    value = re.sub(r"([?&]key=)[^&\s]+", r"\1***REDACTED***", value, flags=re.IGNORECASE)
    value = re.sub(r"([?&]token=)[^&\s]+", r"\1***REDACTED***", value, flags=re.IGNORECASE)
    value = re.sub(r"(\bkey=)[^\s,;]+", r"\1***REDACTED***", value, flags=re.IGNORECASE)
    value = re.sub(r"(\btoken=)[^\s,;]+", r"\1***REDACTED***", value, flags=re.IGNORECASE)
    value = re.sub(r"(://)([^/@:\s]+):([^/@\s]+)@", r"\1***:***@", value)
    value = re.sub(
        r"(?i)\b(password|passwd|pwd|api[_-]?key|secret)\b\s*[:=]?\s*([^\s,;]+)",
        lambda m: f"{m.group(1)}=***REDACTED***",
        value,
    )
    value = re.sub(r"密码\s*[是为:=]?\s*([^\s,;]+)", "密码=***REDACTED***", value)
    return value


def _normalize_tui_ui_mode(raw: str) -> str:
    value = str(raw or "").strip().lower()
    if value in {"expert", "pro", "advanced"}:
        return "expert"
    return "simple"


def _toggle_tui_ui_mode(current: str) -> str:
    mode = _normalize_tui_ui_mode(current)
    return "expert" if mode == "simple" else "simple"


def _tui_char_display_width(value: str) -> int:
    if not value:
        return 0
    if unicodedata.combining(value):
        return 0
    if unicodedata.category(value).startswith("C"):
        return 0
    return 2 if unicodedata.east_asian_width(value) in {"W", "F"} else 1


def _tui_text_display_width(text: str) -> int:
    return sum(_tui_char_display_width(ch) for ch in str(text))


def _build_tui_prompt_line_and_cursor(*, input_text: str, cursor_index: int, width: int) -> tuple[str, int]:
    prefix = "lsre> "
    max_width = max(1, int(width) - 1)
    prefix_width = _tui_text_display_width(prefix)
    if prefix_width >= max_width:
        return prefix[:max_width], max(0, max_width - 1)

    chars = list(str(input_text))
    cursor = max(0, min(int(cursor_index), len(chars)))
    char_widths = [_tui_char_display_width(ch) for ch in chars]
    width_prefix = [0]
    for w in char_widths:
        width_prefix.append(width_prefix[-1] + w)

    budget = max(0, max_width - prefix_width)

    def _segment_width(start: int, end: int) -> int:
        return width_prefix[end] - width_prefix[start]

    start = 0
    while start < cursor and _segment_width(start, cursor) > budget:
        start += 1

    end = start
    while end < len(chars) and _segment_width(start, end + 1) <= budget:
        end += 1

    visible = "".join(chars[start:end])
    cursor_x = prefix_width + _segment_width(start, cursor)
    cursor_x = max(0, min(max_width - 1, cursor_x))
    return f"{prefix}{visible}", cursor_x


def _build_tui_help_overlay_lines(snapshot: dict[str, object], *, width: int) -> list[str]:
    panel = _normalize_tui_panel_name(str(snapshot.get("sidebar_panel", "overview")))
    state_card = _build_tui_state_card(snapshot)
    active_provider = str(snapshot.get("active_provider", snapshot.get("provider", "-"))).strip() or "-"
    starter_prompts = _build_tui_starter_prompts(snapshot)
    panel_examples = {
        "overview": [
            "检查当前环境有什么异常",
            "/focus",
            "/brief",
        ],
        "activity": [
            "/activity",
            "列出最近失败的 Swarm service",
            "/do 1",
        ],
        "timeline": [
            "/trace",
            "/timeline",
            "解释最近一次修复为什么失败",
        ],
        "providers": [
            "/providers",
            "/provider openai",
            "检查当前 provider 是否就绪",
        ],
    }
    sections = [
        "LazySRE Help",
        f"当前面板: {panel}",
        f"当前 provider: {active_provider}",
        f"建议下一步: {state_card.get('next', '-')}",
        "",
        "Core",
        "- 直接输入自然语言，例如：检查当前服务器 / 修复 swarm 副本不足",
        "- /start 查看当前阶段与建议动作，/next 自动执行下一步",
        "- /go 1|2|3|4 执行开机即用引导动作（扫描/总览/连接模型/一键修环境）",
        "- /do 1 执行当前最优先建议，/focus /activity /trace /timeline 查看上下文",
        "- /retry 重试上一条输入；/history 查看并重放历史输入",
        "- 数字快捷：直接输入 1/2/3... 可执行对应 /do n（无动作时 1-4 走 /go n）",
        "- 首屏输入框留空直接按 Enter，会自动执行当前建议下一步",
        "- /scan 零配置探测本机 Docker/Swarm/K8s/Prometheus",
        "- /drift 查看环境基线漂移（新增/缺失目标、基线过期）",
        "",
        "Keys",
        "- Tab 自动补全，Up/Down 浏览输入历史（输入前缀可筛选）",
        "- 终端若不识别方向键，可用 Ctrl+P / Ctrl+N 浏览历史",
        "- Ctrl+A/E 光标跳到行首/行尾；Ctrl+U/K 删除左侧/右侧；Ctrl+W 删除前一个词",
        "- Left/Right/Home/End 移动光标，Delete 删除光标后字符",
        "- 1-4 或 F2 切换左侧面板，F3 切换 simple/expert",
        "- Shift+R 直接重试上一条输入",
        "- F1 或 ? 打开/关闭帮助",
        "- Ctrl-L 清屏，Esc 关闭帮助或退出 TUI",
        "",
        "Panel Examples",
        *[f"- {item}" for item in panel_examples.get(panel, panel_examples["overview"])],
        "",
        "High Value Commands",
        "- /do 1",
        "- /focus",
        "- /activity",
        "- /trace",
        "- /timeline",
        "- /drift",
        "- /doctor",
        "- /doctor install",
        "- /preflight",
        "- /secret-scan",
        "- /providers",
        "- /scan",
        "- /ui simple|expert",
        "",
        "Try Asking",
        *[f"- {item}" for item in starter_prompts[:4]],
    ]
    lines: list[str] = []
    for entry in sections:
        if not entry:
            lines.append("")
            continue
        if entry.startswith("- "):
            lines.extend(_wrap_tui_text_lines(entry, width=width))
            continue
        if entry in {"LazySRE Help", "Core", "Keys", "Panel Examples", "High Value Commands", "Try Asking"}:
            lines.append(entry)
            continue
        lines.extend(_wrap_tui_text_lines(entry, width=width))
    return lines


def _draw_tui_help_overlay(stdscr, *, snapshot: dict[str, object], width: int, height: int) -> None:
    overlay_width = min(max(52, width - 10), 92)
    content_width = max(20, overlay_width - 4)
    content_lines = _build_tui_help_overlay_lines(snapshot, width=content_width)
    overlay_height = min(height - 4, len(content_lines) + 4)
    top = max(1, (height - overlay_height) // 2)
    left = max(1, (width - overlay_width) // 2)
    bottom = min(height - 2, top + overlay_height - 1)
    right = min(width - 2, left + overlay_width - 1)

    for y in range(top, bottom + 1):
        for x in range(left, right + 1):
            char = " "
            if y in {top, bottom} and x in {left, right}:
                char = "+"
            elif y in {top, bottom}:
                char = "-"
            elif x in {left, right}:
                char = "|"
            stdscr.addch(y, x, char)

    visible_lines = content_lines[: max(0, overlay_height - 4)]
    for idx, line in enumerate(visible_lines, top + 1):
        _tui_addnstr(stdscr, idx, left + 2, line, content_width)
    footer = "F1/? close · F3 ui"
    _tui_addnstr(stdscr, bottom - 1, left + 2, footer, content_width)


def _tui_addnstr(stdscr, y: int, x: int, text: str, max_width: int) -> None:
    import curses

    try:
        stdscr.addnstr(y, x, text, max_width, curses.A_NORMAL)
    except TypeError:
        stdscr.addnstr(y, x, text, max_width)


def _read_tui_escape_key(stdscr) -> str | None:
    import curses

    # Some terminals send arrow/home/end/delete as ESC sequences (e.g. "\x1b[A").
    seq_chars: list[str] = []
    stdscr.nodelay(True)
    try:
        deadline = time.monotonic() + 0.04
        while time.monotonic() < deadline and len(seq_chars) < 6:
            try:
                nxt = stdscr.get_wch()
            except curses.error:
                continue
            if isinstance(nxt, int):
                if nxt == curses.KEY_UP:
                    return "<UP>"
                if nxt == curses.KEY_DOWN:
                    return "<DOWN>"
                if nxt == curses.KEY_LEFT:
                    return "<LEFT>"
                if nxt == curses.KEY_RIGHT:
                    return "<RIGHT>"
                if nxt == curses.KEY_HOME:
                    return "<HOME>"
                if nxt == curses.KEY_END:
                    return "<END>"
                if nxt == curses.KEY_DC:
                    return "<DELETE>"
                return None
            seq_chars.append(nxt)
            parsed = _parse_tui_escape_sequence("".join(seq_chars))
            if parsed is not None:
                return parsed
    finally:
        stdscr.nodelay(False)
    return None


def _parse_tui_escape_sequence(raw: str) -> str | None:
    seq = str(raw or "")
    if seq.startswith("\x1b"):
        seq = seq[1:]
    # Normalize modifier forms like "[1;5A" -> "[A" (Ctrl/Alt/Shift arrows).
    seq = re.sub(r"^\[(?:\d+;)+\d+([A-Za-z])$", r"[\1", seq)
    mapping = {
        "[A": "<UP>",
        "OA": "<UP>",
        "[B": "<DOWN>",
        "OB": "<DOWN>",
        "[C": "<RIGHT>",
        "OC": "<RIGHT>",
        "[D": "<LEFT>",
        "OD": "<LEFT>",
        "[H": "<HOME>",
        "OH": "<HOME>",
        "[F": "<END>",
        "OF": "<END>",
        "[1~": "<HOME>",
        "[4~": "<END>",
        "[3~": "<DELETE>",
    }
    if seq in mapping:
        return mapping[seq]
    for key, value in mapping.items():
        if seq.endswith(key):
            return value
    return None


def _normalize_tui_key_alias(raw: str) -> str:
    key = str(raw or "")
    parsed = _parse_tui_escape_sequence(key)
    if parsed:
        return parsed
    named_key_alias = {
        "KEY_UP": "<UP>",
        "KEY_DOWN": "<DOWN>",
        "KEY_LEFT": "<LEFT>",
        "KEY_RIGHT": "<RIGHT>",
        "KEY_HOME": "<HOME>",
        "KEY_END": "<END>",
        "KEY_DC": "<DELETE>",
        "KEY_BACKSPACE": "\x7f",
    }
    if key in named_key_alias:
        return named_key_alias[key]
    # Ignore common IME/system modifier glyphs that can leak into curses input.
    if key in {"⇧", "⌥", "⌘", "⌃"}:
        return ""
    alias = {
        "↑": "<UP>",
        "↓": "<DOWN>",
        "←": "<LEFT>",
        "→": "<RIGHT>",
        "⬆": "<UP>",
        "⬇": "<DOWN>",
        "⬅": "<LEFT>",
        "➡": "<RIGHT>",
        "↖": "<HOME>",
        "↘": "<END>",
        "⌫": "\x7f",
        "⌦": "<DELETE>",
    }
    return alias.get(key, key)


def _build_tui_sidebar_lines(snapshot: dict[str, object], *, width: int) -> list[str]:
    recommended = snapshot.get("recommended_commands", [])
    if not isinstance(recommended, list):
        recommended = []
    shortcuts = snapshot.get("shortcuts", [])
    if not isinstance(shortcuts, list):
        shortcuts = []
    usable_targets = snapshot.get("usable_targets", [])
    if not isinstance(usable_targets, list):
        usable_targets = []
    configured = snapshot.get("configured_providers", [])
    if not isinstance(configured, list):
        configured = []
    recent_activity = snapshot.get("recent_activity", [])
    if not isinstance(recent_activity, list):
        recent_activity = []
    recent_activity_commands = snapshot.get("recent_activity_commands", [])
    if not isinstance(recent_activity_commands, list):
        recent_activity_commands = []
    focus_actions = snapshot.get("focus_actions", [])
    if not isinstance(focus_actions, list):
        focus_actions = []
    quick_action_items = snapshot.get("quick_action_items", [])
    if not isinstance(quick_action_items, list):
        quick_action_items = []
    latest_quick_action = snapshot.get("latest_quick_action", {})
    if not isinstance(latest_quick_action, dict):
        latest_quick_action = {}
    timeline_entries = snapshot.get("timeline_entries", [])
    if not isinstance(timeline_entries, list):
        timeline_entries = []
    trace_summary = snapshot.get("trace_summary", [])
    if not isinstance(trace_summary, list):
        trace_summary = []
    environment_signals = snapshot.get("environment_signals", [])
    if not isinstance(environment_signals, list):
        environment_signals = []
    recent_commands = snapshot.get("recent_commands", [])
    if not isinstance(recent_commands, list):
        recent_commands = []
    swarm_posture = snapshot.get("swarm_posture", {})
    if not isinstance(swarm_posture, dict):
        swarm_posture = {}
    environment_drift = snapshot.get("environment_drift", {})
    if not isinstance(environment_drift, dict):
        environment_drift = {}
    incident_session = snapshot.get("incident_session", {})
    if not isinstance(incident_session, dict):
        incident_session = {}
    panel = _normalize_tui_panel_name(str(snapshot.get("sidebar_panel", "overview")))
    state_card = _build_tui_state_card(snapshot)
    logo_lines = _build_tui_logo_lines()
    side_brand = (
        f"v{snapshot.get('version', '-')} {snapshot.get('mode', '-')}/{snapshot.get('provider', '-')}"
    )
    lines = [
        logo_lines[0],
        logo_lines[1],
        side_brand,
        "",
        *_build_tui_panel_tabs(panel, width=width, snapshot=snapshot),
        "",
        f"panel: {panel}",
        f"hint: {snapshot.get('panel_hint', '-')}",
        f"status: {snapshot.get('status', '-')}",
        f"env: {snapshot.get('environment_profile', '-') or '-'}",
        f"focus: {snapshot.get('focus_title', '-')}",
        f"quick: {_build_latest_quick_action_badge(snapshot)}",
        f"next: {state_card.get('next', '-')}",
        f"mode: {snapshot.get('mode', '-')}",
        f"provider: {snapshot.get('provider', '-')}",
        f"model: {snapshot.get('model', '-')}",
        f"targets: {', '.join(str(x) for x in usable_targets) or 'none'}",
        f"providers: {', '.join(str(x) for x in configured) or 'unset'}",
        f"ns: {snapshot.get('namespace', '-')}",
        f"ssh: {snapshot.get('ssh_target', '-') or 'not set'}",
        f"prom: {snapshot.get('prometheus_url', '-') or 'not set'}",
        f"turns: {snapshot.get('session_turns', 0)}",
    ]
    if panel == "activity":
        if not recent_activity and not recent_activity_commands:
            lines.extend(["", "Recent Activity:", "- 暂无活动，先运行 /scan、/brief 或 /activity"])
        if recent_activity:
            lines.extend(["", "Recent Activity:"])
            for item in recent_activity[:5]:
                lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
        if recent_activity_commands:
            lines.extend(["", "Activity Actions:"])
            for item in recent_activity_commands[:4]:
                lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
        if recommended:
            lines.extend(["", "Recommended:"])
            for item in recommended[:4]:
                lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
        lines.extend(["", "1-4/F2: switch panel", "F3: toggle ui mode"])
        return lines
    if panel == "timeline":
        if not recent_commands and not timeline_entries:
            lines.extend(["", "Execution Timeline:", "- 暂无执行轨迹，先运行 /timeline、/scan 或 /remediate"])
        if trace_summary:
            lines.extend(["", "Trace Summary:"])
            for item in trace_summary[:3]:
                lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
        if recent_commands:
            lines.extend(["", "Command Trail:"])
            for item in recent_commands[-4:]:
                lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
        if timeline_entries:
            lines.extend(["", "Execution Timeline:"])
            for item in timeline_entries[:5]:
                lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
        lines.extend(["", "Commands:", "- /trace", "- /timeline", "- /activity", "- /panel next", "- 1-4/F2 切换", "- F3 切换UI"])
        return lines
    if panel == "providers":
        report = snapshot.get("provider_report", {})
        if not configured:
            lines.extend(["", "Providers:", "- 暂无可用 provider，先运行 /providers 或 /login --provider openai"])
        if isinstance(report, dict):
            lines.extend(
                [
                    "",
                    f"requested: {report.get('requested_provider', '-')}",
                    f"active: {report.get('active_provider', '-')}",
                    f"resolved: {report.get('resolved_model', '-')}",
                    f"ready: {'yes' if bool(report.get('active_ready')) else 'no'}",
                ]
            )
            detail = str(report.get("active_detail", "")).strip()
            if detail:
                lines.extend(["", "Active Detail:"])
                lines.extend(_wrap_tui_text_lines(detail, width=width))
            providers = report.get("providers", {})
            if isinstance(providers, dict):
                lines.extend(["", "Configured Providers:"])
                for name in list(PROVIDER_SPECS.keys())[:8]:
                    row = providers.get(name, {})
                    if not isinstance(row, dict):
                        continue
                    label = str(row.get("label", name))
                    ready = "PASS" if bool(row.get("ok")) else "FAIL"
                    lines.extend(_wrap_tui_text_lines(f"- {label}: {ready}", width=width))
        lines.extend(["", "Commands:", "- /providers", "- /provider <name>", "- /panel next", "- 1-4/F2 切换", "- F3 切换UI"])
        return lines
    headline = str(snapshot.get("headline", "")).strip()
    if headline:
        lines.extend(["", "Brief:"])
        lines.extend(_wrap_tui_text_lines(headline, width=width))
    environment_summary = str(snapshot.get("environment_summary", "")).strip()
    if environment_summary:
        lines.extend(["", "Environment:"])
        lines.extend(_wrap_tui_text_lines(environment_summary, width=width))
    if environment_signals:
        lines.extend(["", "Signals:"])
        for item in environment_signals[:3]:
            lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
    if str(environment_drift.get("status", "")).strip() in {"changed", "stale"}:
        lines.extend(["", "Environment Drift:"])
        lines.extend(_wrap_tui_text_lines(str(environment_drift.get("headline", "")).strip(), width=width))
        for item in list(environment_drift.get("signals", []))[:3]:
            lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
        for item in list(environment_drift.get("top_actions", []))[:2]:
            lines.extend(_wrap_tui_text_lines(f"- action: {item}", width=width))
    if str(swarm_posture.get("headline", "")).strip():
        lines.extend(["", "Swarm Posture:"])
        lines.extend(_wrap_tui_text_lines(str(swarm_posture.get("headline", "")).strip(), width=width))
        for item in list(swarm_posture.get("signals", []))[:3]:
            lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
    if bool(incident_session.get("exists")):
        lines.extend(["", "Incident Session:"])
        lines.extend(
            _wrap_tui_text_lines(
                f"{incident_session.get('status', '-')}: {incident_session.get('headline', '-')}",
                width=width,
            )
        )
        stage_flow = str(incident_session.get("stage_flow", "")).strip()
        if stage_flow:
            lines.extend(_wrap_tui_text_lines(stage_flow, width=width))
        next_step = str(incident_session.get("next_step", "")).strip()
        if next_step:
            lines.extend(_wrap_tui_text_lines(f"next: {next_step}", width=width))
    focus_body = str(snapshot.get("focus_body", "")).strip()
    if focus_body:
        lines.extend(["", "Focus:"])
        lines.extend(_wrap_tui_text_lines(focus_body, width=width))
    if focus_actions:
        lines.extend(["", "Focus Actions:"])
        for item in focus_actions[:3]:
            lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
    if quick_action_items:
        lines.extend(["", "Quick Actions:"])
        for raw in quick_action_items[:3]:
            if not isinstance(raw, dict):
                continue
            lines.extend(
                _wrap_tui_text_lines(
                    f"- {_format_quick_action_line(raw)}",
                    width=width,
                )
            )
            lines.extend(
                _wrap_tui_text_lines(
                    f"  {_format_quick_action_command(raw)}",
                    width=width,
                )
            )
    if str(latest_quick_action.get("command", "")).strip():
        lines.extend(["", "Last Quick Action:"])
        lines.extend(
            _wrap_tui_text_lines(
                f"{latest_quick_action.get('status', 'unknown')}: {latest_quick_action.get('command', '')}",
                width=width,
            )
        )
        preview = str(latest_quick_action.get("output_preview", "")).strip()
        if preview:
            lines.extend(_wrap_tui_text_lines(preview, width=width))
    last_user = str(snapshot.get("last_user", "")).strip()
    if last_user:
        lines.extend(["", "Last Input:"])
        lines.extend(_wrap_tui_text_lines(last_user, width=width))
    if recent_activity:
        lines.extend(["", "Recent Activity:"])
        for item in recent_activity[:4]:
            lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
    if recent_activity_commands:
        lines.extend(["", "Activity Actions:"])
        for item in recent_activity_commands[:3]:
            lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
    if recommended:
        lines.extend(["", "Recommended:"])
        for item in recommended[:4]:
            lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
    if recent_commands:
        lines.extend(["", "Command Trail:"])
        for item in recent_commands[-3:]:
            lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
    if timeline_entries:
        lines.extend(["", "Execution Timeline:"])
        for item in timeline_entries[:3]:
            lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
    if trace_summary:
        lines.extend(["", "Trace Summary:"])
        for item in trace_summary[:2]:
            lines.extend(_wrap_tui_text_lines(f"- {item}", width=width))
    lines.extend(["", "Shortcuts:"])
    for item in shortcuts[:6]:
        lines.extend(_wrap_tui_text_lines(str(item), width=width))
    lines.extend(["", "Tab: autocomplete", "1-4/F2: switch panel", "F3: toggle ui"])
    return lines


def _build_tui_starter_prompts(snapshot: dict[str, object]) -> list[str]:
    panel = _normalize_tui_panel_name(str(snapshot.get("sidebar_panel", "overview")))
    targets = snapshot.get("usable_targets", [])
    if not isinstance(targets, list):
        targets = []
    target_set = {str(item).strip().lower() for item in targets if str(item).strip()}
    swarm_posture = snapshot.get("swarm_posture", {})
    if not isinstance(swarm_posture, dict):
        swarm_posture = {}
    focus_service = str(swarm_posture.get("focus_service", "")).strip()
    provider = str(snapshot.get("active_provider", snapshot.get("provider", "auto"))).strip() or "auto"
    prompts: list[str] = [
        "检查当前环境有什么异常",
        "总结目前最值得优先处理的问题",
    ]
    if target_set.intersection({"swarm", "docker-swarm"}):
        prompts.extend(
            [
                "列出 Swarm 当前不健康的 service",
                "分析最近失败的 Swarm task 并给出修复建议",
            ]
        )
        if focus_service:
            prompts.append(f"为什么 {focus_service} 副本不足")
    if "docker" in target_set:
        prompts.append("看看 Docker 容器里有没有异常重启")
    if target_set.intersection({"k8s", "kubernetes"}):
        prompts.append("找出当前集群里异常 Pod 和最近 Events")
    panel_prompts = {
        "overview": ["给我一份当前平台总览简报"],
        "activity": ["把最近活动里最危险的动作挑出来"],
        "timeline": ["解释最近一次操作链路发生了什么"],
        "providers": [f"检查 {provider} provider 当前是否可用"],
    }
    prompts.extend(panel_prompts.get(panel, []))
    seen: set[str] = set()
    ordered: list[str] = []
    for item in prompts:
        text = str(item).strip()
        if (not text) or (text in seen):
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def _has_tui_user_history(history: list[tuple[str, str]]) -> bool:
    return any(str(speaker) == "You" and str(text).strip() for speaker, text in history)


def _resolve_tui_empty_submit_command(
    *,
    snapshot: dict[str, object],
    history: list[tuple[str, str]],
) -> str:
    if _has_tui_user_history(history):
        return ""
    return _pick_tui_next_command(snapshot)


def _build_tui_idle_content_rows(snapshot: dict[str, object], *, width: int) -> list[str]:
    prompts = _build_tui_starter_prompts(snapshot)
    quick_state = _build_latest_quick_action_badge(snapshot)
    state_card = _build_tui_state_card(snapshot)
    profile = str(snapshot.get("environment_profile", "")).strip() or "-"
    summary = str(snapshot.get("environment_summary", "")).strip() or "-"
    swarm_posture = snapshot.get("swarm_posture", {})
    if not isinstance(swarm_posture, dict):
        swarm_posture = {}
    environment_drift = snapshot.get("environment_drift", {})
    if not isinstance(environment_drift, dict):
        environment_drift = {}
    incident_session = snapshot.get("incident_session", {})
    if not isinstance(incident_session, dict):
        incident_session = {}
    logo_lines = _build_tui_logo_lines()
    sections = [
        "Brand",
        *[f"- {line}" for line in logo_lines],
        "",
        "Start Here",
        f"- profile: {profile}",
        f"- summary: {summary}",
        *([f"- swarm: {str(swarm_posture.get('headline', '')).strip()}"] if str(swarm_posture.get("headline", "")).strip() else []),
        *([f"- drift: {str(environment_drift.get('headline', '')).strip()}"] if str(environment_drift.get("status", "")).strip() in {"changed", "stale"} else []),
        *([f"- incident: {str(incident_session.get('headline', '')).strip()}"] if bool(incident_session.get("exists")) and str(incident_session.get("headline", "")).strip() else []),
        f"- next: {state_card.get('next', '-')}",
        f"- quick: {quick_state}",
        f"- hint: {snapshot.get('panel_hint', '-')}",
        "",
        "Try Asking",
        *[f"- {item}" for item in prompts[:5]],
        "",
        "Direct Commands",
        "- /do 1",
        "- /focus",
        "- /activity",
        "- /trace",
        "- /history",
        "- /retry",
    ]
    rows: list[str] = []
    for entry in sections:
        if not entry:
            rows.append("")
            continue
        if entry in {"Brand", "Start Here", "Try Asking", "Direct Commands"}:
            rows.append(entry)
            continue
        rows.extend(textwrap.wrap(entry, width=max(10, width)) or [entry])
    return rows


def _build_tui_footer_line(*, snapshot: dict[str, object], status: str, history: list[tuple[str, str]]) -> str:
    recent_activity = snapshot.get("recent_activity", [])
    activity_count = len(recent_activity) if isinstance(recent_activity, list) else 0
    timeline_entries = snapshot.get("timeline_entries", [])
    timeline_count = len(timeline_entries) if isinstance(timeline_entries, list) else 0
    targets = snapshot.get("usable_targets", [])
    target_count = len(targets) if isinstance(targets, list) else 0
    incident_session = snapshot.get("incident_session", {})
    incident_status = str(incident_session.get("status", "")).strip() if isinstance(incident_session, dict) else ""
    environment_drift = snapshot.get("environment_drift", {})
    drift_status = str(environment_drift.get("status", "")).strip() if isinstance(environment_drift, dict) else ""
    last_you = ""
    for speaker, text in reversed(history):
        if speaker == "You":
            last_you = str(text).strip()
            break
    parts = [
        f"status={status}",
        f"panel={snapshot.get('sidebar_panel', 'overview')}",
        f"mode={snapshot.get('mode', '-')}",
        f"provider={snapshot.get('active_provider', snapshot.get('provider', '-'))}",
        f"targets={target_count}",
        f"activity={activity_count}",
        f"timeline={timeline_count}",
    ]
    if incident_status:
        parts.append(f"incident={incident_status}")
    if drift_status in {"changed", "stale"}:
        parts.append(f"drift={drift_status}")
    if last_you:
        safe_last = _sanitize_tui_secret_tokens(last_you)
        parts.append(f"last={_truncate_tui_status_text(safe_last, max_chars=22)}")
    return " | ".join(parts)


def _truncate_tui_status_text(text: str, *, max_chars: int = 22) -> str:
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    limit = max(6, int(max_chars))
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def _build_tui_panel_hint(panel: str) -> str:
    normalized = _normalize_tui_panel_name(panel)
    hints = {
        "overview": "总览环境与下一步，试试 /brief /scan /drift /panel activity",
        "activity": "聚焦异常与建议动作，试试 /activity /remediate /panel timeline",
        "timeline": "聚焦执行轨迹，试试 /timeline /panel providers",
        "providers": "聚焦模型与网关状态，试试 /providers /provider <name>",
    }
    return hints.get(normalized, hints["overview"])


def _build_latest_quick_action_badge(snapshot: dict[str, object]) -> str:
    latest = snapshot.get("latest_quick_action", {})
    if not isinstance(latest, dict):
        return "-"
    command = str(latest.get("command", "")).strip()
    status = str(latest.get("status", "")).strip()
    if not command:
        return "-"
    short = command[:36]
    return f"{status or 'unknown'}:{short}"


def _build_tui_status_hint_line(snapshot: dict[str, object]) -> str:
    latest = snapshot.get("latest_quick_action", {})
    if isinstance(latest, dict):
        status = str(latest.get("status", "")).strip().lower()
        command = str(latest.get("command", "")).strip()
        if status == "fail" and command:
            return f"hint> 最近 quick action 失败，先看 /trace /timeline，再决定是否重试 {command[:36]}"
        if status == "ok" and command:
            return f"hint> 最近 quick action 成功，可继续 /focus、/activity 或重跑 {command[:36]}"
    incident_session = snapshot.get("incident_session", {})
    if isinstance(incident_session, dict) and bool(incident_session.get("exists")):
        stage_flow = str(incident_session.get("stage_flow", "")).strip()
        next_step = str(incident_session.get("next_step", "")).strip()
        if str(incident_session.get("status", "")).strip() == "attention":
            return f"hint> 最近闭环会话仍需处理，先看 /trace /timeline。{stage_flow[:72]}"
        if next_step:
            return f"hint> 最近闭环会话下一步: {next_step[:72]}"
    environment_drift = snapshot.get("environment_drift", {})
    if isinstance(environment_drift, dict):
        drift_status = str(environment_drift.get("status", "")).strip()
        if drift_status in {"changed", "stale"}:
            return f"hint> 检测到环境基线漂移，先看 /drift。{str(environment_drift.get('headline', ''))[:72]}"
    panel = _normalize_tui_panel_name(str(snapshot.get("sidebar_panel", "overview")))
    return f"hint> {_build_tui_panel_hint(panel)}"


def _build_tui_action_bar(snapshot: dict[str, object]) -> str:
    panel = _normalize_tui_panel_name(str(snapshot.get("sidebar_panel", "overview")))
    base = "actions> [1]overview [2]activity [3]timeline [4]providers"
    latest = snapshot.get("latest_quick_action", {})
    latest_status = str(latest.get("status", "")).strip().lower() if isinstance(latest, dict) else ""
    if latest_status == "fail":
        return f"{base} · /trace · /timeline · /do 1"
    panel_actions = {
        "overview": "/do 1 | /focus | /drift | /doctor",
        "activity": "/do 1 | /activity | /swarm --logs",
        "timeline": "/trace | /timeline | /panel next",
        "providers": "/providers | /provider <name> | /preflight",
    }
    return f"{base} · {panel_actions.get(panel, panel_actions['overview'])}"


def _build_tui_panel_tabs(active_panel: str, *, width: int, snapshot: dict[str, object] | None = None) -> list[str]:
    normalized = _normalize_tui_panel_name(active_panel)
    counts = _build_tui_panel_counts(snapshot or {})
    labels = []
    ordered = ["overview", "activity", "timeline", "providers"]
    for index, name in enumerate(ordered, 1):
        badge = counts.get(name, "")
        suffix = f"({badge})" if badge else ""
        label = f"{index}:{name}{suffix}"
        labels.append(f"[{label}]" if name == normalized else label)
    return textwrap.wrap("Panels: " + " | ".join(labels), width=max(20, width)) or ["Panels: " + " | ".join(labels)]


def _wrap_tui_text_lines(text: str, *, width: int) -> list[str]:
    value = str(text or "").strip()
    if not value:
        return [""]
    return textwrap.wrap(value, width=max(12, width)) or [value]


def _normalize_tui_panel_name(value: str) -> str:
    raw = str(value or "").strip().lower()
    aliases = {
        "overview": "overview",
        "summary": "overview",
        "home": "overview",
        "activity": "activity",
        "actions": "activity",
        "timeline": "timeline",
        "logs": "timeline",
        "providers": "providers",
        "provider": "providers",
    }
    return aliases.get(raw, "overview")


def _panel_name_from_shortcut(value: str) -> str:
    return {
        "1": "overview",
        "2": "activity",
        "3": "timeline",
        "4": "providers",
    }.get(str(value or "").strip(), "overview")


def _build_tui_panel_counts(snapshot: dict[str, object]) -> dict[str, str]:
    recent_activity = snapshot.get("recent_activity", [])
    timeline_entries = snapshot.get("timeline_entries", [])
    recommended = snapshot.get("recommended_commands", [])
    configured = snapshot.get("configured_providers", [])
    provider_report = snapshot.get("provider_report", {})
    provider_total = 0
    if isinstance(provider_report, dict):
        providers = provider_report.get("providers", {})
        if isinstance(providers, dict):
            provider_total = len(providers)
    return {
        "overview": str(len(recommended)) if isinstance(recommended, list) and recommended else "",
        "activity": str(len(recent_activity)) if isinstance(recent_activity, list) and recent_activity else "",
        "timeline": str(len(timeline_entries)) if isinstance(timeline_entries, list) and timeline_entries else "",
        "providers": (
            f"{len(configured)}/{provider_total or len(configured)}"
            if isinstance(configured, list) and configured
            else ""
        ),
    }


def _next_tui_panel(current: str) -> str:
    ordered = ["overview", "activity", "timeline", "providers"]
    panel = _normalize_tui_panel_name(current)
    try:
        idx = ordered.index(panel)
    except ValueError:
        idx = 0
    return ordered[(idx + 1) % len(ordered)]


def _switch_tui_panel(options: dict[str, object], requested: str) -> str:
    raw = str(requested or "").strip().lower()
    if not raw or raw in {"show", "current"}:
        panel = _normalize_tui_panel_name(str(options.get("tui_panel", "overview")))
        return f"当前左侧面板: {panel}"
    if raw in {"next", "cycle"}:
        options["tui_panel"] = _next_tui_panel(str(options.get("tui_panel", "overview")))
        _persist_tui_runtime_state(options)
        return f"已切换左侧面板: {options['tui_panel']}"
    if raw in {"1", "2", "3", "4"}:
        options["tui_panel"] = _panel_name_from_shortcut(raw)
        _persist_tui_runtime_state(options)
        return f"已切换左侧面板: {options['tui_panel']}"
    panel = _normalize_tui_panel_name(raw)
    if panel == "overview" and raw not in {"overview", "summary", "home"}:
        return "用法：/panel overview|activity|timeline|providers|next"
    options["tui_panel"] = panel
    _persist_tui_runtime_state(options)
    return f"已切换左侧面板: {panel}"


def _tui_welcome_message(snapshot: dict[str, object] | None = None) -> str:
    logo = "\n".join(_build_tui_logo_lines())
    coach_primary = "/next"
    coach_headline = "先拿到当前环境总览"
    actions: list[str] = []
    focus = "-"
    if isinstance(snapshot, dict):
        coach = _build_tui_start_coach(snapshot)
        coach_primary = str(coach.get("primary", "/next")).strip() or "/next"
        coach_headline = str(coach.get("headline", coach_headline)).strip() or coach_headline
        actions = _build_tui_boot_actions(snapshot)[:4]
        state = _build_tui_state_card(snapshot)
        focus = str(state.get("focus", "-")).strip() or "-"
    lines = [
        logo,
        f"目标: {coach_headline}",
        f"焦点: {focus}",
        "One Minute Setup:",
        *[f"- {item}" for item in actions],
        f"输入一句话描述问题，或输入 {coach_primary} 自动执行当前建议动作。",
        "也可输入 /go 1|2|3|4 快速执行引导动作，按 F1 查看帮助。",
    ]
    return "\n".join(lines)


def _build_tui_logo_lines(*, compact: bool = False) -> list[str]:
    if compact:
        return ["◉ LazySRE"]
    return [
        "◉ LazySRE",
        "AI-native Ops CLI",
    ]


def _cycle_tui_input_history(
    input_text: str,
    *,
    input_history: list[str],
    history_index: int,
    history_seed: str,
    direction: str,
) -> tuple[str, int, str]:
    if not input_history:
        return input_text, -1, ""
    seed = history_seed
    if history_index == -1:
        seed = input_text
    prefix = str(seed or "").strip().lower()

    def _matches(row: str) -> bool:
        value = str(row or "").strip().lower()
        if not prefix:
            return True
        return value.startswith(prefix)

    if direction == "up":
        start = len(input_history) if history_index == -1 else max(0, history_index)
        for idx in range(start - 1, -1, -1):
            if _matches(input_history[idx]):
                return input_history[idx], idx, seed
        return input_text, -1, seed

    if history_index == -1:
        return input_text, history_index, seed
    for idx in range(history_index + 1, len(input_history)):
        if _matches(input_history[idx]):
            return input_history[idx], idx, seed
    return seed, -1, seed


def _build_tui_bootstrap_input_history(snapshot: dict[str, object]) -> list[str]:
    recent_commands = _collect_snapshot_recent_commands(snapshot, limit=20)
    recommended = snapshot.get("recommended_commands", [])
    if not isinstance(recommended, list):
        recommended = []
    seeds = [
        *[str(item).strip() for item in recent_commands if str(item).strip()],
        *[str(item).strip() for item in recommended if str(item).strip()],
        "/quickstart",
        "/scan",
        "/brief",
        "/next",
        "/providers",
        "/history",
        "/retry",
    ]
    cleaned: list[str] = []
    for item in seeds:
        safe_item = _sanitize_tui_secret_tokens(item)
        if not safe_item or safe_item in cleaned:
            continue
        cleaned.append(safe_item)
    return cleaned[-20:]


def _tui_input_history_file() -> Path:
    return Path(settings.data_dir) / "lsre-tui-input-history.txt"


def _merge_tui_input_history(*sources: list[str], max_entries: int = 220) -> list[str]:
    rows: list[str] = []
    limit = max(20, int(max_entries))
    for source in sources:
        for item in source:
            safe = _sanitize_tui_secret_tokens(str(item or "").strip())
            if not safe:
                continue
            if safe in rows:
                rows.remove(safe)
            rows.append(safe)
    return rows[-limit:]


def _load_tui_input_history(*, max_entries: int = 220) -> list[str]:
    path = _tui_input_history_file()
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    return _merge_tui_input_history(lines, max_entries=max_entries)


def _save_tui_input_history(input_history: list[str], *, max_entries: int = 220) -> None:
    rows = _merge_tui_input_history(input_history, max_entries=max_entries)
    path = _tui_input_history_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = "\n".join(rows).strip()
        path.write_text((payload + "\n") if payload else "", encoding="utf-8")
    except Exception:
        return


def _delete_tui_word_left(input_text: str, cursor_index: int) -> tuple[str, int]:
    text = str(input_text or "")
    cursor = max(0, min(int(cursor_index), len(text)))
    idx = cursor
    while idx > 0 and text[idx - 1].isspace():
        idx -= 1
    while idx > 0 and (not text[idx - 1].isspace()):
        idx -= 1
    return text[:idx] + text[cursor:], idx


def _apply_tui_ctrl_edit_key(*, key: str, input_text: str, cursor_index: int) -> tuple[str, int, bool]:
    text = str(input_text or "")
    cursor = max(0, min(int(cursor_index), len(text)))
    if key == "\x01":  # Ctrl+A
        return text, 0, True
    if key == "\x05":  # Ctrl+E
        return text, len(text), True
    if key == "\x15":  # Ctrl+U (kill left)
        return text[cursor:], 0, True
    if key == "\x0b":  # Ctrl+K (kill right)
        return text[:cursor], cursor, True
    if key == "\x17":  # Ctrl+W (delete word left)
        next_text, next_cursor = _delete_tui_word_left(text, cursor)
        return next_text, next_cursor, True
    return text, cursor, False


def _cycle_tui_completion(
    input_text: str,
    *,
    snapshot: dict[str, object],
    completion_index: int,
    completion_seed: str,
) -> tuple[str, int, str]:
    seed = input_text.strip()
    if completion_seed:
        existing_candidates = _tui_completion_candidates(completion_seed, snapshot)
        if seed in existing_candidates:
            seed = completion_seed
    if seed != completion_seed:
        completion_index = -1
        completion_seed = seed
    candidates = _tui_completion_candidates(seed, snapshot)
    if not candidates:
        return input_text, -1, seed
    next_index = (completion_index + 1) % len(candidates)
    return candidates[next_index], next_index, completion_seed


def _tui_completion_candidates(prefix: str, snapshot: dict[str, object]) -> list[str]:
    shortcuts = snapshot.get("shortcuts", [])
    if not isinstance(shortcuts, list):
        shortcuts = []
    recommended = snapshot.get("recommended_commands", [])
    if not isinstance(recommended, list):
        recommended = []
    candidates = _dedupe_strings(
        [
            *[str(item) for item in shortcuts if str(item).strip()],
            *[str(item) for item in recommended if str(item).strip()],
            "/providers",
            "/provider auto",
            "/provider mock",
            "/start",
            "/go 1",
            "/go 2",
            "/go 3",
            "/go 4",
            "/next",
            "/ui simple",
            "/ui expert",
            "/activity",
            "/focus",
            "/do",
            "/do 1",
            "/timeline",
            "/trace",
            "/drift",
            "/panel overview",
            "/panel activity",
            "/panel timeline",
            "/panel providers",
            "/panel next",
            "/doctor fix",
            "/doctor",
            "/doctor strict",
            "/doctor install",
            "/preflight",
            "/preflight --strict",
            "/preflight --all-files",
            "/secret-scan",
            "/secret-scan --staged",
            "/quickstart",
            "/status probe",
            "/refresh",
            "/incident status",
            "/incident open 支付服务延迟",
            "/incident note 已切换流量",
            "/incident timeline",
            "/incident close 已恢复",
        ]
    )
    seed = str(prefix or "").strip().lower()
    if not seed:
        return candidates
    return [item for item in candidates if item.lower().startswith(seed)]


def _parse_preflight_inline_options(tail: str) -> dict[str, object]:
    raw = str(tail or "").strip()
    lowered = raw.lower()
    strict_mode = (" strict" in f" {lowered}") or ("--strict" in lowered) or ("严格" in raw)
    staged = True
    if "--all-files" in lowered:
        staged = False
    if "--staged" in lowered:
        staged = True
    dry_run_probe = True
    if ("--execute-probe" in lowered) or ("--no-dry-run-probe" in lowered):
        dry_run_probe = False
    timeout_sec = 6
    timeout_match = re.search(r"--timeout-sec(?:=|\s+)(\d+)", lowered, flags=re.IGNORECASE)
    if timeout_match:
        timeout_sec = max(1, min(60, _safe_int(timeout_match.group(1))))
    max_findings = 8
    findings_match = re.search(r"--max-findings(?:=|\s+)(\d+)", lowered, flags=re.IGNORECASE)
    if findings_match:
        max_findings = max(1, min(30, _safe_int(findings_match.group(1))))
    return {
        "strict": strict_mode,
        "staged": staged,
        "dry_run_probe": dry_run_probe,
        "timeout_sec": timeout_sec,
        "max_findings": max_findings,
    }


def _capture_plain_output(callback) -> str:
    global _console
    old_console = _console
    out = io.StringIO()
    err = io.StringIO()
    try:
        _console = None
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            callback()
    except Exception as exc:
        print(f"error: {_normalize_runtime_exception_message(exc)}", file=out)
    finally:
        _console = old_console
    return "\n".join(x for x in [out.getvalue().strip(), err.getvalue().strip()] if x)


def _normalize_runtime_exception_message(exc: Exception) -> str:
    message = _sanitize_tui_secret_tokens(str(exc).strip() or exc.__class__.__name__)
    lower = message.lower()
    if ("using socks proxy" in lower) and ("socksio" in lower):
        return (
            f"{message}\n"
            "fix: 当前 Python 环境缺少 SOCKS 依赖。执行 "
            "`python3 -m pip install \"httpx[socks]\"`。\n"
            "如你不需要代理，清理环境变量 `ALL_PROXY/HTTPS_PROXY/HTTP_PROXY` 后重试。"
        )
    if ("generativelanguage.googleapis.com" in lower) and ("400 bad request" in lower or "http 400" in lower):
        return (
            f"{message}\n"
            "fix: Gemini 返回 400。请依次检查："
            "1) API Key 是否属于当前项目并已启用 Gemini API；"
            "2) 当前网络/代理是否可访问 Google API；"
            "3) 先执行 `/provider mock` 保持流程可用。"
        )
    if ("http 401" in lower) or ("http 403" in lower) or ("unauthorized" in lower) or ("forbidden" in lower):
        return (
            f"{message}\n"
            "fix: 认证或权限失败。请检查 API Key 权限、配额/计费状态、IP/区域限制。"
        )
    return message


def _safe_exception_text(exc: Exception) -> str:
    return _sanitize_tui_secret_tokens(str(exc).strip() or exc.__class__.__name__)


def _should_auto_fallback_to_mock(*, provider_mode: str, error: Exception) -> bool:
    if str(os.getenv("LAZYSRE_DISABLE_MOCK_FALLBACK", "")).strip() == "1":
        return False
    mode = str(provider_mode or "").strip().lower()
    if mode == "mock":
        return False
    if isinstance(error, typer.BadParameter):
        return False
    message = _normalize_runtime_exception_message(error).lower()
    tokens = (
        "api key",
        "http 400",
        "http 401",
        "http 403",
        "unauthorized",
        "forbidden",
        "quota",
        "rate limit",
        "using socks proxy",
        "proxy",
        "socks",
        "connection",
        "name or service not known",
        "temporary failure",
        "dns",
        "ssl",
        "tls",
        "timed out",
        "timeout",
    )
    return any(token in message for token in tokens)


def _resolve_runtime_provider_label(provider: str, *, secrets_file: Path | None = None) -> str:
    mode = str(provider or "auto").strip().lower() or "auto"
    if mode == "auto":
        resolved = _resolve_default_provider(secrets_file=secrets_file)
        return f"auto->{resolved}"
    return mode


def _build_provider_runtime_report(options: dict[str, object], *, secrets_file: Path | None = None) -> dict[str, object]:
    requested_provider = str(options.get("provider", "auto") or "auto").strip().lower() or "auto"
    checks = _build_provider_setup_checks(secrets_file=secrets_file)
    active_provider = _resolve_default_provider(secrets_file=secrets_file) if requested_provider == "auto" else requested_provider
    active_check = checks.get(active_provider, {}) if active_provider in checks else {}
    active_ready = bool(active_check.get("ok", False))
    active_detail = str(active_check.get("detail", ""))
    active_hint = str(active_check.get("hint", ""))
    if active_provider == "mock":
        active_ready = True
        if not active_detail.strip():
            active_detail = "Mock provider 可用（无需 API Key）。"
        active_hint = ""
    return {
        "requested_provider": requested_provider,
        "active_provider": active_provider,
        "requested_model": str(options.get("model", settings.model_name)),
        "resolved_model": _resolve_provider_default_model(active_provider, secrets_file=secrets_file)
        or resolve_model_name(active_provider, str(options.get("model", settings.model_name))),
        "providers": checks,
        "active_ready": active_ready,
        "active_hint": active_hint,
        "active_detail": active_detail,
    }


def _render_provider_runtime_report(report: dict[str, object]) -> None:
    if not (_console and Table and Panel):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    summary = Table(title="Provider Runtime")
    summary.add_column("Item", style="cyan")
    summary.add_column("Value", style="white")
    summary.add_row("Requested", str(report.get("requested_provider", "-")))
    summary.add_row("Active", str(report.get("active_provider", "-")))
    summary.add_row("Model", str(report.get("resolved_model", "-")))
    summary.add_row("Ready", "yes" if bool(report.get("active_ready")) else "no")
    _console.print(summary)

    providers = report.get("providers", {})
    if isinstance(providers, dict):
        table = Table(title="Configured Providers")
        table.add_column("Provider", style="cyan")
        table.add_column("Ready", style="white")
        table.add_column("Detail", style="white")
        for name in PROVIDER_SPECS:
            row = providers.get(name, {})
            if not isinstance(row, dict):
                continue
            table.add_row(
                str(row.get("label", name)),
                "PASS" if bool(row.get("ok")) else "FAIL",
                str(row.get("detail", ""))[:180],
            )
        _console.print(table)
    if (not bool(report.get("active_ready"))) and str(report.get("active_hint", "")).strip():
        _console.print(Panel(str(report.get("active_hint", "")), border_style="yellow"))


def _switch_runtime_provider(options: dict[str, object], provider_name: str, *, secrets_file: Path | None = None) -> str:
    requested = str(provider_name or "").strip().lower()
    if not requested:
        report = _build_provider_runtime_report(options, secrets_file=secrets_file)
        return json.dumps(report, ensure_ascii=False, indent=2) if not _console else _capture_plain_output(
            lambda: _render_provider_runtime_report(report)
        )
    if requested not in {"auto", "mock", *PROVIDER_SPECS.keys()}:
        return provider_mode_error_text()
    if requested not in {"auto", "mock"}:
        checks = _build_provider_setup_checks(secrets_file=secrets_file)
        row = checks.get(requested, {})
        if isinstance(row, dict) and (not bool(row.get("ok"))):
            hint = str(row.get("hint", "")).strip()
            if hint:
                return f"Provider {requested} 尚未就绪。{hint}"
            return f"Provider {requested} 尚未就绪。"
    options["provider"] = requested
    if requested == "auto":
        options["model"] = settings.model_name
    elif requested == "mock":
        options["model"] = resolve_model_name("openai", settings.model_name)
    else:
        options["model"] = _resolve_provider_default_model(requested, secrets_file=secrets_file) or resolve_model_name(
            requested,
            str(options.get("model", settings.model_name)),
        )
    return (
        f"已切换 Provider: {_resolve_runtime_provider_label(requested, secrets_file=secrets_file)} "
        f"(model={options.get('model', settings.model_name)})"
    )


def _handle_tui_input(text: str, options: dict[str, object]) -> str:
    normalized = _normalize_chat_input_text(text)
    quick_command = _rewrite_simple_quick_phrase_to_command(normalized)
    if quick_command:
        normalized = quick_command
    lowered = normalized.lower()
    numeric_shortcut = _resolve_tui_numeric_shortcut_command(lowered, options=options)
    if numeric_shortcut:
        normalized = numeric_shortcut
        lowered = numeric_shortcut
    if normalized.startswith("/") and (not _extract_slash_command_name(normalized) in _KNOWN_SLASH_COMMANDS):
        return _render_unknown_slash_command_message(normalized)
    if lowered in {"/start", "/guide"}:
        return _render_tui_start_card(options)
    if lowered in {"/go", "/go show"}:
        snapshot = _build_tui_dashboard_snapshot(options)
        actions = _build_tui_boot_actions(snapshot)
        return "\n".join(["One Minute Setup", *[f"- {item}" for item in actions[:4]], "用法：/go 1|2|3|4"])
    if lowered.startswith("/go "):
        raw = lowered[len("/go ") :].strip()
        action_id = _safe_int(raw)
        if action_id <= 0:
            return "用法：/go 1|2|3|4"
        snapshot = _build_tui_dashboard_snapshot(options)
        command = _resolve_tui_boot_action_command(snapshot, action_id)
        if not command:
            return "用法：/go 1|2|3|4"
        rendered = _handle_tui_input(command, options)
        return f"执行引导动作: {command}\n\n{rendered}"
    if lowered in {"/next", "/continue"}:
        snapshot = _build_tui_dashboard_snapshot(options)
        command = _pick_tui_next_command(snapshot)
        rendered = _handle_tui_input(command, options)
        return f"自动执行下一步: {command}\n\n{rendered}"
    if lowered in {"/ui", "/ui show"}:
        ui_mode = _normalize_tui_ui_mode(str(options.get("tui_ui_mode", "simple")))
        return f"当前 UI 模式: {ui_mode}（可用: /ui simple | /ui expert）"
    if lowered.startswith("/ui "):
        raw = lowered[len("/ui ") :].strip()
        mode = _normalize_tui_ui_mode(raw)
        if raw not in {"simple", "expert", "pro", "advanced"}:
            return "用法：/ui simple 或 /ui expert"
        options["tui_ui_mode"] = mode
        _persist_tui_runtime_state(options)
        return f"已切换 UI 模式: {mode}"
    if lowered in {"/help", "help", "?"}:
        return _render_tui_quick_help_text(_build_tui_dashboard_snapshot(options))
    if lowered in {"/help full", "/help all", "/h full"}:
        return _render_tui_demo_text(_build_tui_dashboard_snapshot(options))
    if lowered in {"/history", "/history show"}:
        return _render_tui_history_text(options)
    if lowered.startswith("/history "):
        history_arg = normalized[len("/history ") :].strip()
        index = _safe_int(history_arg)
        if index <= 0:
            return _render_tui_history_text(options, query=history_arg)
        snapshot = _build_tui_dashboard_snapshot(options)
        rows = _collect_snapshot_recent_commands(snapshot, limit=12)
        replay_rows = list(reversed(rows))
        if index > len(replay_rows):
            return f"历史序号超出范围（当前 {len(replay_rows)} 条）。"
        command = replay_rows[index - 1]
        if (not command) or command.startswith("/history"):
            return "该历史项不可重放，请选择其他序号。"
        rendered = _handle_tui_input(command, options)
        return f"重放历史[{index}]: {command}\n\n{rendered}"
    if lowered in {"/retry", "/r"}:
        last_input = str(options.get("tui_last_input", "")).strip()
        if not last_input:
            snapshot = _build_tui_dashboard_snapshot(options)
            rows = _collect_snapshot_recent_commands(snapshot, limit=12)
            if rows:
                last_input = rows[-1]
        if (not last_input) or (last_input.lower() in {"/retry", "/r"}):
            return "没有可重试的上一条输入。先输入一句话，或执行 /history 查看历史。"
        rendered = _handle_tui_input(last_input, options)
        return f"重试上一条: {last_input}\n\n{rendered}"
    if lowered.startswith("/incident"):
        return _handle_incident_inline_command(normalized, path=_resolve_incident_inline_path(options))
    if lowered in {"/actions", "/actions show"}:
        return _render_quick_actions_text(options)
    if lowered.startswith("/actions "):
        action_id = _safe_int(normalized[len("/actions ") :].strip())
        if action_id <= 0:
            return "用法：/actions 1"
        _, rendered = _run_quick_action_item(options=options, action_id=action_id, execute_mode=bool(options.get("execute", False)))
        return rendered
    if lowered in {"/do", "/do show"}:
        return _render_quick_actions_text(options)
    if lowered.startswith("/do "):
        action_id = _safe_int(normalized[len("/do ") :].strip())
        if action_id <= 0:
            return "用法：/do 1"
        _, rendered = _run_quick_action_item(options=options, action_id=action_id, execute_mode=bool(options.get("execute", False)))
        return rendered
    if lowered.startswith("/activity"):
        return _render_recent_activity_text(options)
    if lowered.startswith("/focus"):
        return _render_focus_text(options)
    if lowered.startswith("/timeline"):
        return _render_timeline_text(options)
    if lowered.startswith("/trace"):
        return _render_trace_text(options)
    if lowered.startswith("/drift"):
        return _render_environment_drift_text(options)
    if lowered in {"/panel", "/panel show"}:
        return _switch_tui_panel(options, "show")
    if lowered.startswith("/panel "):
        return _switch_tui_panel(options, normalized[len("/panel ") :].strip())
    if lowered.startswith("/secret-scan") or lowered in {"/secrets", "/doctor secrets", "/doctor secret"}:
        tail = normalized[len("/secret-scan") :].strip() if lowered.startswith("/secret-scan") else ""
        staged = "--staged" in tail.lower() if tail else False
        max_findings = 8
        if tail:
            match = re.search(r"--max-findings(?:=|\s+)(\d+)", tail, flags=re.IGNORECASE)
            if match:
                max_findings = max(1, min(30, _safe_int(match.group(1))))

        def _render_secret_scan() -> None:
            report = _collect_secret_scan_report(staged=staged, max_findings=max_findings)
            report["gate"] = _build_doctor_gate(report, strict=False)
            _render_doctor_report(report)

        return _capture_plain_output(_render_secret_scan)
    if lowered.startswith("/doctor"):
        doctor_text = lowered

        def _render_install_doctor() -> None:
            report = _collect_install_doctor_report()
            report["gate"] = _build_doctor_gate(report, strict=False)
            _render_doctor_report(report)

        if (" install" in doctor_text) or ("--install" in doctor_text):
            return _capture_plain_output(_render_install_doctor)

        auto_fix = (" fix" in doctor_text) or ("--auto-fix" in doctor_text)
        strict_mode = (" strict" in doctor_text) or ("--strict" in doctor_text)
        write_backup = (" backup" in doctor_text) or ("--write-backup" in doctor_text)

        def _render_doctor() -> None:
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
                audit_log=Path(str(options.get("audit_log", ".data/lsre-audit.jsonl"))),
            )
            if autofix_payload is not None:
                report["autofix"] = autofix_payload
            summary_obj = report.get("summary", {})
            if isinstance(summary_obj, dict):
                summary_obj["strict_mode"] = strict_mode
                summary_obj["strict_healthy"] = _doctor_is_healthy(summary_obj, strict=strict_mode)
            report["gate"] = _build_doctor_gate(report, strict=strict_mode)
            _render_doctor_report(report)

        return _capture_plain_output(_render_doctor)
    if lowered.startswith("/preflight"):
        tail = normalized[len("/preflight") :].strip()
        preflight_options = _parse_preflight_inline_options(tail)

        def _render_preflight() -> None:
            report = _collect_preflight_report(
                profile_file=Path(settings.target_profile_file),
                timeout_sec=int(preflight_options["timeout_sec"]),
                dry_run_probe=bool(preflight_options["dry_run_probe"]),
                strict=bool(preflight_options["strict"]),
                staged=bool(preflight_options["staged"]),
                max_findings=int(preflight_options["max_findings"]),
                audit_log=Path(str(options.get("audit_log", ".data/lsre-audit.jsonl"))),
            )
            _render_doctor_report(report)

        return _capture_plain_output(_render_preflight)
    if lowered in {"/providers", "/provider", "/provider show"}:
        return _capture_plain_output(lambda: _render_provider_runtime_report(_build_provider_runtime_report(options)))
    if lowered.startswith("/provider "):
        return _switch_runtime_provider(options, normalized[len("/provider ") :].strip())
    if lowered in {"/mode", "/mode show"}:
        return f"当前模式: {'execute' if bool(options.get('execute', False)) else 'dry-run'}"
    if lowered.startswith("/mode "):
        tail = lowered[len("/mode ") :].strip()
        if tail in {"execute", "exec", "on", "real"}:
            options["execute"] = True
            _save_chat_runtime_state(True)
            return "已切换到 execute 模式。写操作仍会经过风险评估和确认。"
        if tail in {"dry-run", "dryrun", "preview", "off"}:
            options["execute"] = False
            _save_chat_runtime_state(False)
            return "已切换到 dry-run 模式。"
        return "用法：/mode execute 或 /mode dry-run"
    if lowered.startswith("/brief"):
        tail = normalized[len("/brief") :].strip()
        def _render_brief() -> None:
            report = _build_overview_brief_report(
                target=tail,
                include_remote=True,
                include_logs="--logs" in lowered,
                timeout_sec=5,
            )
            _write_first_scan_marker(report)
            _render_overview_brief_report(report)

        return _capture_plain_output(_render_brief)
    if lowered.startswith("/refresh"):
        def _refresh_brief() -> None:
            report = _build_overview_brief_report(
                target="",
                include_remote=True,
                include_logs="--logs" in lowered,
                timeout_sec=5,
            )
            _write_first_scan_marker(report)
            _render_overview_brief_report(report)

        return _capture_plain_output(_refresh_brief)
    if lowered.startswith("/scan"):
        def _render_scan() -> None:
            report = _collect_environment_discovery(timeout_sec=5, secrets_file=None)
            _write_first_scan_marker(report)
            _render_environment_discovery(report)

        return _capture_plain_output(_render_scan)
    if lowered.startswith("/swarm"):
        return _capture_plain_output(lambda: _render_swarm_health_report(_collect_swarm_health_report(service_filter=_extract_swarm_service_name(normalized), include_logs="--logs" in lowered, tail=120, timeout_sec=6)))
    if lowered.startswith("/autopilot"):
        goal = normalized[len("/autopilot") :].strip() or "巡检当前环境并给出下一步行动"
        return _capture_plain_output(lambda: _render_autopilot_report(_run_autopilot_cycle(goal=goal, include_swarm=True, include_logs="--logs" in lowered, remember=True, timeout_sec=5)))
    if lowered.startswith("/remote"):
        tail = normalized[len("/remote") :].strip()
        target = _resolve_ssh_target_arg(_extract_ssh_target_from_text(tail))
        if not target:
            return "用法：/remote [root@host] [--logs] [--service name]；或先 /connect root@host"
        service_text = tail.replace(target, " ")
        return _capture_plain_output(
            lambda: _render_remote_docker_report(
                _collect_remote_docker_report(
                    target=target,
                    service_filter=_extract_swarm_service_name(service_text),
                    include_logs="--logs" in lowered or "日志" in normalized,
                    tail=120,
                    timeout_sec=8,
                )
            )
        )
    if lowered.startswith("/connect"):
        tail = normalized[len("/connect") :].strip()
        return _capture_plain_output(
            lambda: _render_remote_docker_report(
                _run_remote_connect_flow(
                    target=_extract_ssh_target_from_text(tail),
                    save_target=True,
                    include_logs="--logs" in lowered or "日志" in normalized,
                    tail=80,
                    timeout_sec=8,
                )
            )
        )
    if lowered.startswith("/remediate"):
        objective = normalized[len("/remediate") :].strip() or "修复当前巡检发现的问题"
        return _capture_plain_output(
            lambda: _render_closed_loop_report(
                _run_closed_loop_remediation(
                    objective=objective,
                    remote_target=_extract_ssh_target_from_text(normalized),
                    service_filter=_extract_swarm_service_name(normalized),
                    include_logs="--logs" in lowered,
                    apply="--apply" in lowered,
                    verify=True,
                    rollback_on_failure="--rollback-on-failure" in lowered,
                    from_last_plan=False,
                    max_apply_steps=6,
                    execute=bool(options.get("execute", False)),
                    approval_mode=str(options.get("approval_mode", "balanced")),
                    audit_log=str(options.get("audit_log", ".data/lsre-audit.jsonl")),
                    allow_high_risk=False,
                    auto_approve_low_risk=True,
                    model=str(options.get("model", settings.model_name)),
                    provider=str(options.get("provider", "auto")),
                )
            )
        )
    return _capture_plain_output(
        lambda: _run_once(
            instruction=normalized,
            execute=bool(options.get("execute", False)),
            approve=bool(options.get("approve", False)),
            interactive_approval=bool(options.get("interactive_approval", True)),
            stream_output=False,
            verbose_reasoning=False,
            approval_mode=str(options.get("approval_mode", "balanced")),
            audit_log=str(options.get("audit_log", ".data/lsre-audit.jsonl")),
            lock_file=str(options.get("lock_file", ".data/lsre-tool-lock.json")),
            session_file=str(options.get("session_file", ".data/lsre-session.json")),
            deny_tool=list(options.get("deny_tool", [])),
            deny_prefix=list(options.get("deny_prefix", [])),
            tool_pack=list(options.get("tool_pack", ["builtin"])),
            remote_gateway=list(options.get("remote_gateway", [])),
            model=str(options.get("model", settings.model_name)),
            provider=str(options.get("provider", "auto")),
            max_steps=int(options.get("max_steps", 6)),
        )
    )


def _resolve_tui_numeric_shortcut_command(text: str, *, options: dict[str, object]) -> str:
    raw = str(text or "").strip().lower()
    if (not raw) or (not _looks_like_ordinal_shortcut(raw)):
        return ""
    action_id = _safe_int(raw)
    if action_id <= 0:
        return ""
    snapshot = _build_tui_dashboard_snapshot(options)
    quick_items = snapshot.get("quick_action_items", [])
    if isinstance(quick_items, list):
        for item in quick_items:
            if not isinstance(item, dict):
                continue
            if _safe_int(str(item.get("id", "")).strip()) == action_id:
                return f"/do {action_id}"
    if action_id in {1, 2, 3, 4}:
        return f"/go {action_id}"
    return ""


def _looks_like_ordinal_shortcut(text: str) -> bool:
    raw = str(text or "").strip()
    if not raw:
        return False
    pattern = (
        r"^(?:#|no\.?|第)?\s*"
        r"[0-9零〇一二三四五六七八九十两①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳❶❷❸❹❺❻❼❽❾❿]+"
        r"\s*(?:步|条|项|号|个|建议|动作|行动|推荐)?$"
    )
    return bool(re.fullmatch(pattern, raw, flags=re.IGNORECASE))


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
        (r"\bconect\b", "connect"),
        (r"\bbrif\b", "brief"),
    ]
    for pattern, replacement in replacements:
        normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)
    normalized = normalized.replace("模版", "模板")
    return normalized


def _rewrite_simple_quick_phrase_to_command(text: str) -> str:
    raw = str(text or "").strip()
    if (not raw) or raw.startswith("/"):
        return ""
    lowered = raw.lower().strip()
    compact = re.sub(r"[\s，。,.!?！？:：;；]+", "", lowered)

    mapping: dict[str, str] = {
        "继续": "/next",
        "继续吧": "/next",
        "继续一下": "/next",
        "继续完善": "/next",
        "继续优化": "/next",
        "继续打磨": "/next",
        "继续排查": "/next",
        "继续处理": "/next",
        "继续执行": "/next",
        "下一步": "/next",
        "next": "/next",
        "continue": "/next",
        "goon": "/next",
        "重试": "/retry",
        "再试一次": "/retry",
        "retry": "/retry",
        "retrylast": "/retry",
        "历史": "/history",
        "输入历史": "/history",
        "最近输入": "/history",
        "history": "/history",
        "帮助": "/help",
        "help": "/help",
        "怎么用": "/help",
        "命令列表": "/help",
        "扫描": "/scan",
        "环境扫描": "/scan",
        "scan": "/scan",
        "总览": "/brief",
        "简报": "/brief",
        "brief": "/brief",
        "执行轨迹": "/trace",
        "trace": "/trace",
        "时间线": "/timeline",
        "timeline": "/timeline",
        "模型状态": "/providers",
        "provider状态": "/providers",
        "providers": "/providers",
        "体检": "/doctor",
        "健康检查": "/doctor",
        "doctor": "/doctor",
        "安装检查": "/doctor install",
        "安装体检": "/doctor install",
        "发布前检查": "/preflight",
        "上线前检查": "/preflight",
        "preflight": "/preflight",
        "密钥检查": "/secret-scan",
        "泄漏检查": "/secret-scan",
        "暂存区密钥检查": "/secret-scan --staged",
        "暂存区泄漏检查": "/secret-scan --staged",
        "secretcheck": "/secret-scan",
        "secretscan": "/secret-scan",
    }
    direct = mapping.get(compact, "")
    if direct:
        return direct

    next_prefixes = (
        "继续",
        "下一步",
        "再继续",
        "continue",
        "next",
    )
    retry_prefixes = (
        "重试",
        "再试",
        "再来一次",
        "retry",
    )
    history_prefixes = (
        "历史",
        "看历史",
        "看看历史",
        "输入历史",
        "最近输入",
        "history",
    )
    help_prefixes = (
        "帮助",
        "help",
        "怎么用",
        "怎么使用",
        "命令",
        "指令",
        "用法",
    )
    scan_prefixes = (
        "扫描",
        "环境扫描",
        "scan",
        "先扫描",
    )
    brief_prefixes = (
        "简报",
        "总览",
        "brief",
    )
    trace_prefixes = (
        "轨迹",
        "执行轨迹",
        "trace",
    )
    timeline_prefixes = (
        "时间线",
        "timeline",
    )
    provider_prefixes = (
        "模型状态",
        "provider状态",
        "providers",
        "provider",
    )
    doctor_prefixes = (
        "体检",
        "健康检查",
        "doctor",
        "安装检查",
        "安装体检",
    )
    preflight_prefixes = (
        "发布前检查",
        "上线前检查",
        "上线检查",
        "发版前检查",
        "preflight",
    )
    secret_scan_prefixes = (
        "密钥检查",
        "泄漏检查",
        "secretcheck",
        "secretscan",
    )
    secret_scan_staged_prefixes = (
        "暂存区密钥检查",
        "暂存区泄漏检查",
        "stagedsecretcheck",
        "stagedsecretscan",
    )
    if any(compact.startswith(prefix) for prefix in next_prefixes):
        return "/next"
    if any(compact.startswith(prefix) for prefix in retry_prefixes):
        return "/retry"
    if any(compact.startswith(prefix) for prefix in history_prefixes):
        return "/history"
    if any(compact.startswith(prefix) for prefix in help_prefixes):
        return "/help"
    if any(compact.startswith(prefix) for prefix in scan_prefixes):
        return "/scan"
    if any(compact.startswith(prefix) for prefix in brief_prefixes):
        return "/brief"
    if any(compact.startswith(prefix) for prefix in trace_prefixes):
        return "/trace"
    if any(compact.startswith(prefix) for prefix in timeline_prefixes):
        return "/timeline"
    if any(compact.startswith(prefix) for prefix in provider_prefixes):
        return "/providers"
    if any(compact.startswith(prefix) for prefix in preflight_prefixes):
        return "/preflight"
    if any(compact.startswith(prefix) for prefix in secret_scan_prefixes):
        return "/secret-scan"
    if any(compact.startswith(prefix) for prefix in secret_scan_staged_prefixes):
        return "/secret-scan --staged"
    if any(compact.startswith(prefix) for prefix in doctor_prefixes):
        if compact.startswith("安装"):
            return "/doctor install"
        return "/doctor"
    return ""


_KNOWN_SLASH_COMMANDS: tuple[str, ...] = (
    "help",
    "h",
    "mode",
    "context",
    "ctx",
    "reset",
    "login",
    "logout",
    "init",
    "quickstart",
    "brief",
    "scan",
    "swarm",
    "watch",
    "actions",
    "autopilot",
    "connect",
    "remote",
    "remediate",
    "tui",
    "setup",
    "status",
    "doctor",
    "preflight",
    "runbook",
    "report",
    "incident",
    "template",
    "fix",
    "approve",
    "undo",
    "memory",
    "apply",
    "activity",
    "focus",
    "do",
    "timeline",
    "trace",
    "drift",
    "ui",
    "start",
    "next",
    "go",
    "providers",
    "provider",
    "secret-scan",
    "refresh",
    "panel",
    "history",
    "retry",
    "r",
)


def _extract_slash_command_name(text: str) -> str:
    raw = str(text or "").strip()
    if (not raw) or (not raw.startswith("/")):
        return ""
    parts = raw.split(maxsplit=1)
    command = parts[0][1:].strip().lower()
    return command


def _suggest_unknown_slash_command(text: str) -> str:
    command = _extract_slash_command_name(text)
    if (not command) or (command in _KNOWN_SLASH_COMMANDS):
        return ""
    match = get_close_matches(command, list(_KNOWN_SLASH_COMMANDS), n=1, cutoff=0.72)
    if not match:
        return ""
    return f"/{match[0]}"


def _render_unknown_slash_command_message(text: str) -> str:
    command = _extract_slash_command_name(text)
    if not command:
        return ""
    suggestion = _suggest_unknown_slash_command(text)
    if suggestion:
        return f"未知命令: /{command}\n你是不是想输入: {suggestion}\n输入 /help 查看全部命令。"
    return f"未知命令: /{command}\n输入 /help 查看全部命令。"


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
        "conect": "connect",
        "brif": "brief",
        "remedate": "remediate",
        "remediatee": "remediate",
        "hepl": "help",
        "ux": "ui",
        "inc": "incident",
        "hist": "history",
        "his": "history",
        "rt": "retry",
        "secretscan": "secret-scan",
        "secretcheck": "secret-scan",
        "secret": "secret-scan",
        "preflght": "preflight",
        "preflite": "preflight",
        "pre-flight": "preflight",
    }
    known = list(_KNOWN_SLASH_COMMANDS)
    corrected = aliases.get(command, "")
    if not corrected:
        match = get_close_matches(command, known, n=1, cutoff=0.78)
        if match:
            corrected = match[0]
    if (not corrected) or (corrected == command):
        corrected = command
    if corrected == "secret-scan":
        normalized_tail = tail.strip().lower()
        if normalized_tail in {"", "scan", "check", "检查", "扫描"}:
            return "/secret-scan"
    if tail:
        return f"/{corrected} {tail}"
    return f"/{corrected}"


def _normalize_chat_input_text(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return raw
    if raw.startswith("/"):
        return _normalize_slash_command_text(raw)
    bare = _normalize_bare_command_text(raw)
    if bare.startswith("/"):
        return _normalize_slash_command_text(bare)
    return _normalize_natural_language_text(raw)


def _normalize_bare_command_text(text: str) -> str:
    raw = str(text or "").strip()
    if (not raw) or raw.startswith("/"):
        return raw
    parts = raw.split(maxsplit=1)
    head = parts[0].strip().lower()
    tail = parts[1].strip() if len(parts) > 1 else ""
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
        "conect": "connect",
        "brif": "brief",
        "remedate": "remediate",
        "remediatee": "remediate",
        "hepl": "help",
        "ux": "ui",
        "inc": "incident",
        "hist": "history",
        "his": "history",
        "rt": "retry",
        "secretscan": "secret-scan",
        "secretcheck": "secret-scan",
        "secret": "secret-scan",
        "preflght": "preflight",
        "preflite": "preflight",
        "pre-flight": "preflight",
    }
    command = aliases.get(head, head)
    if command not in _KNOWN_SLASH_COMMANDS:
        match = get_close_matches(command, list(_KNOWN_SLASH_COMMANDS), n=1, cutoff=0.82)
        if not match:
            return raw
        command = match[0]
    if command == "secret-scan":
        normalized_tail = tail.strip().lower()
        if normalized_tail in {"", "scan", "check", "检查", "扫描"}:
            return "/secret-scan"
    # Avoid hijacking natural language phrases like "help me ...".
    if command in {"help", "h"} and tail and tail.lower() not in {"full", "all"}:
        return raw
    return f"/{command}{(' ' + tail) if tail else ''}"


def _bootstrap_chat_input_history(options: dict[str, object], *, limit: int = 20) -> list[str]:
    cap = max(1, min(limit, 100))
    session_file = Path(str(options.get("session_file", ".data/lsre-session.json"))).expanduser()
    try:
        turns = SessionStore(session_file).recent_turns(limit=cap)
    except Exception:
        turns = []
    rows: list[str] = []
    for item in turns:
        if not isinstance(item, dict):
            continue
        user = _sanitize_tui_secret_tokens(str(item.get("user", "")).strip())
        if (not user) or (user in rows):
            continue
        rows.append(user)
    return rows[-cap:]


def _chat_readline_history_file() -> Path:
    return Path(settings.data_dir) / "lsre-readline-history.txt"


def _enable_chat_readline_history(*, max_entries: int = 300) -> None:
    try:
        import readline  # type: ignore
    except Exception:
        return
    path = _chat_readline_history_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        readline.read_history_file(str(path))
    except FileNotFoundError:
        pass
    except Exception:
        return
    try:
        readline.set_history_length(max(50, int(max_entries)))
    except Exception:
        pass


def _append_chat_readline_history(line: str) -> None:
    text = str(line or "").strip()
    if not text:
        return
    # Never persist potential secrets to local readline history.
    if _sanitize_tui_secret_tokens(text) != text:
        return
    try:
        import readline  # type: ignore
    except Exception:
        return
    try:
        count = int(readline.get_current_history_length())
        last = readline.get_history_item(count) if count > 0 else None
        if last != text:
            readline.add_history(text)
        readline.write_history_file(str(_chat_readline_history_file()))
    except Exception:
        return


def _assistant_chat_loop(options: dict[str, object]) -> None:
    typer.echo("LazySRE 已启动，直接说需求即可（输入 exit/quit 退出）。")
    typer.echo("示例：1) 帮我排查 payment 延迟 2) 一键修复 CrashLoopBackOff")
    typer.echo("不需要记命令，直接用自然语言说你想做什么。")
    typer.echo("快速上手：扫描环境 / 检查状态 / 修复环境 / 看审批队列 / 保存当前为 prod 并切换")
    _maybe_auto_bootstrap_on_first_chat(options)
    _maybe_offer_one_click_env_fix(options)
    runtime_execute = _load_chat_runtime_state(bool(options["execute"]))
    _render_mode_hint(runtime_execute)
    _enable_chat_readline_history()
    chat_input_history = _bootstrap_chat_input_history(options)
    while True:
        try:
            line = typer.prompt("lsre")
        except (EOFError, KeyboardInterrupt):
            typer.echo("")
            break
        text = line.strip()
        if not text:
            continue
        _append_chat_readline_history(text)
        normalized_text = _normalize_chat_input_text(text)
        if normalized_text != text:
            typer.echo(f"已自动纠正输入：{normalized_text}")
            text = normalized_text
        numeric_shortcut = _resolve_tui_numeric_shortcut_command(text, options=options)
        if numeric_shortcut:
            typer.echo(f"已识别数字快捷：{text} -> {numeric_shortcut}")
            text = numeric_shortcut
        quick_command = _rewrite_simple_quick_phrase_to_command(text)
        if quick_command:
            typer.echo(f"已识别快捷口语：{text} -> {quick_command}")
            text = quick_command
        if text.lower() in {"exit", "quit"}:
            break
        if text.startswith("/") and (not _extract_slash_command_name(text) in _KNOWN_SLASH_COMMANDS):
            typer.echo(_render_unknown_slash_command_message(text))
            continue
        if text.lower() in {"/history", "/history show"}:
            typer.echo(_render_history_text(chat_input_history[-12:]))
            continue
        if text.lower().startswith("/history "):
            history_arg = text[len("/history ") :].strip()
            index = _safe_int(history_arg)
            if index <= 0:
                typer.echo(_render_history_text(chat_input_history[-12:], query=history_arg))
                continue
            replay_rows = list(reversed(chat_input_history))
            if index > len(replay_rows):
                typer.echo(f"历史序号超出范围（当前 {len(replay_rows)} 条）。")
                continue
            command = replay_rows[index - 1]
            if (not command) or command.startswith("/history"):
                typer.echo("该历史项不可重放，请选择其他序号。")
                continue
            typer.echo(f"重放历史[{index}]: {command}")
            text = command
        if text.lower() in {"/retry", "/r"}:
            if not chat_input_history:
                typer.echo("没有可重试的上一条输入。先输入一句话，或执行 /history 查看历史。")
                continue
            text = chat_input_history[-1]
            typer.echo(f"重试上一条: {text}")
        safe_history_item = _sanitize_tui_secret_tokens(text)
        if safe_history_item and safe_history_item.lower() not in {"/retry", "/r"}:
            if (not chat_input_history) or (chat_input_history[-1] != safe_history_item):
                chat_input_history.append(safe_history_item)
                chat_input_history = chat_input_history[-30:]
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
        if text.lower().startswith("/incident"):
            typer.echo(_handle_incident_inline_command(text, path=_resolve_incident_inline_path(options)))
            continue
        if text.lower() in {"/actions", "/actions show"}:
            typer.echo(_render_quick_actions_text({**options, "execute": runtime_execute}))
            continue
        if text.lower().startswith("/actions "):
            action_id = _safe_int(text[len("/actions ") :].strip())
            if action_id <= 0:
                typer.echo("用法：/actions 1")
            else:
                _, rendered = _run_quick_action_item(
                    options={**options, "execute": runtime_execute},
                    action_id=action_id,
                    execute_mode=runtime_execute,
                )
                typer.echo(rendered)
            continue
        if text.lower() in {"/do", "/do show"}:
            typer.echo(_render_quick_actions_text({**options, "execute": runtime_execute}))
            continue
        if text.lower().startswith("/do "):
            action_id = _safe_int(text[len("/do ") :].strip())
            if action_id <= 0:
                typer.echo("用法：/do 1")
            else:
                _, rendered = _run_quick_action_item(
                    options={**options, "execute": runtime_execute},
                    action_id=action_id,
                    execute_mode=runtime_execute,
                )
                typer.echo(rendered)
            continue
        if text.lower().startswith("/activity"):
            typer.echo(_render_recent_activity_text({**options, "execute": runtime_execute}))
            continue
        if text.lower().startswith("/focus"):
            typer.echo(_render_focus_text({**options, "execute": runtime_execute}))
            continue
        if text.lower().startswith("/timeline"):
            typer.echo(_render_timeline_text({**options, "execute": runtime_execute}))
            continue
        if text.lower().startswith("/trace"):
            typer.echo(_render_trace_text({**options, "execute": runtime_execute}))
            continue
        if text.lower() in {"/panel", "/panel show"}:
            typer.echo(_switch_tui_panel(options, "show"))
            continue
        if text.lower().startswith("/panel "):
            typer.echo(_switch_tui_panel(options, text[len("/panel ") :].strip()))
            continue
        if text.lower() in {"/mode", "/mode show"}:
            _render_mode_hint(runtime_execute)
            continue
        if text.lower() in {"/context", "/ctx"}:
            _render_context_snapshot(options, execute_mode=runtime_execute)
            continue
        if text.lower() in {"/providers", "/provider", "/provider show"}:
            _render_provider_runtime_report(_build_provider_runtime_report(options))
            continue
        if text.lower().startswith("/provider "):
            typer.echo(_switch_runtime_provider(options, text[len("/provider ") :].strip()))
            continue
        if text.lower().startswith("/tui"):
            _run_tui({**options, "execute": runtime_execute}, demo=False)
            continue
        if text.lower().startswith("/scan"):
            report = _collect_environment_discovery(timeout_sec=5, secrets_file=None)
            if _console:
                _render_environment_discovery(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/brief"):
            tail = text[len("/brief") :].strip()
            report = _build_overview_brief_report(
                target=_extract_ssh_target_from_text(tail),
                include_remote=True,
                include_logs="--logs" in tail.lower() or "日志" in tail,
                timeout_sec=5,
            )
            if _console:
                _render_overview_brief_report(report)
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
                    runtime_options=options,
                )
            continue
        if text.lower().startswith("/remediate"):
            tail = text[len("/remediate") :].strip()
            apply_requested = "--apply" in tail.lower() or "执行" in tail
            rollback_requested = "--rollback-on-failure" in tail.lower() or "失败回滚" in tail
            objective = re.sub(r"--(?:apply|rollback-on-failure|logs)\b", "", tail, flags=re.IGNORECASE).strip()
            report = _run_closed_loop_remediation(
                objective=objective or "修复当前巡检发现的问题",
                remote_target=_extract_ssh_target_from_text(tail),
                service_filter=_extract_swarm_service_name(tail),
                include_logs="--logs" in tail.lower() or "日志" in tail,
                apply=apply_requested,
                verify=True,
                rollback_on_failure=rollback_requested,
                from_last_plan="last" in tail.lower() or "最近计划" in tail,
                max_apply_steps=6,
                execute=_resolve_execute_for_apply_request(
                    runtime_execute,
                    label="闭环修复执行",
                    apply=apply_requested,
                ),
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                allow_high_risk=False,
                auto_approve_low_risk=True,
                model=str(options["model"]),
                provider=str(options["provider"]),
            )
            if _console:
                _render_closed_loop_report(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/remote"):
            tail = text[len("/remote") :].strip()
            target = _resolve_ssh_target_arg(_extract_ssh_target_from_text(tail))
            if not target:
                typer.echo("用法：/remote [root@192.168.10.101] [--logs] [--service name]；或先 /connect root@host")
                continue
            service_text = tail.replace(target, " ")
            report = _collect_remote_docker_report(
                target=target,
                service_filter=_extract_swarm_service_name(service_text),
                include_logs="--logs" in tail.lower() or "日志" in tail,
                tail=120,
                timeout_sec=8,
            )
            if _console:
                _render_remote_docker_report(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            continue
        if text.lower().startswith("/connect"):
            tail = text[len("/connect") :].strip()
            report = _run_remote_connect_flow(
                target=_extract_ssh_target_from_text(tail),
                save_target=True,
                include_logs="--logs" in tail.lower() or "日志" in tail,
                tail=80,
                timeout_sec=8,
            )
            if _console:
                _render_remote_docker_report(report)
            else:
                typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
            save_payload = report.get("target_save", {})
            if isinstance(save_payload, dict):
                if bool(save_payload.get("saved")):
                    typer.echo(f"默认远程目标已保存: {save_payload.get('target', '')}")
                else:
                    typer.echo(f"未保存默认远程目标: {save_payload.get('reason', 'unknown')}")
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
        if text.lower().startswith("/preflight"):
            tail = text[len("/preflight") :].strip()
            preflight_options = _parse_preflight_inline_options(tail)
            report = _collect_preflight_report(
                profile_file=Path(settings.target_profile_file),
                timeout_sec=int(preflight_options["timeout_sec"]),
                dry_run_probe=bool(preflight_options["dry_run_probe"]),
                strict=bool(preflight_options["strict"]),
                staged=bool(preflight_options["staged"]),
                max_findings=int(preflight_options["max_findings"]),
                audit_log=Path(str(options["audit_log"])),
            )
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
                typer.echo(f"runbook 命令格式错误: {_safe_exception_text(exc)}")
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
                    typer.echo(f"runbook add failed: {_safe_exception_text(exc)}")
                continue
            if action == "remove":
                try:
                    runbook_remove(
                        name=str(command.get("name", "")),
                        runbook_file=str(command.get("runbook_file", settings.runbook_store_file)),
                        yes=bool(command.get("yes", False)),
                    )
                except typer.BadParameter as exc:
                    typer.echo(f"runbook remove failed: {_safe_exception_text(exc)}")
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
                    typer.echo(f"runbook export failed: {_safe_exception_text(exc)}")
                continue
            if action == "import":
                try:
                    runbook_import(
                        input_file=str(command.get("input_file", "")),
                        merge=bool(command.get("merge", True)),
                        runbook_file=str(command.get("runbook_file", settings.runbook_store_file)),
                    )
                except typer.BadParameter as exc:
                    typer.echo(f"runbook import failed: {_safe_exception_text(exc)}")
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
                typer.echo(_safe_exception_text(exc))
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
                typer.echo(f"report 命令格式错误: {_safe_exception_text(exc)}")
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
                typer.echo(f"report 生成失败: {_safe_exception_text(exc)}")
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
                typer.echo(f"template 命令格式错误: {_safe_exception_text(exc)}")
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
                    typer.echo(_safe_exception_text(exc))
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

        if _looks_like_remediate_request(text):
            _run_remediate_from_text(text, options, execute_mode=runtime_execute)
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
                runtime_options=options,
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
            runtime_options=options,
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
    if _looks_like_remote_connect_request(text):
        target = _extract_ssh_target_from_text(text)
        report = _run_remote_connect_flow(
            target=target,
            save_target=bool(target),
            include_logs=any(k in lowered for k in ("日志", "logs")),
            tail=80,
            timeout_sec=8,
        )
        if _console:
            _render_remote_docker_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        save_payload = report.get("target_save", {})
        if isinstance(save_payload, dict) and target:
            if bool(save_payload.get("saved")):
                typer.echo(f"默认远程目标已保存: {save_payload.get('target', '')}")
            else:
                typer.echo(f"未保存默认远程目标: {save_payload.get('reason', 'unknown')}")
        return True
    if _looks_like_remote_diagnose_request(text):
        target = _resolve_ssh_target_arg(_extract_ssh_target_from_text(text))
        if not target:
            typer.echo("请提供 SSH target，例如：远程诊断 root@192.168.10.101；或先执行 lsre target set --ssh-target root@host")
            return True
        service_text = text.replace(target, " ")
        report = _collect_remote_docker_report(
            target=target,
            service_filter=_extract_swarm_service_name(service_text),
            include_logs=any(k in lowered for k in ("日志", "logs")),
            tail=120,
            timeout_sec=8,
        )
        if _console:
            _render_remote_docker_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
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
                runtime_options=options,
            )
        return True
    if _looks_like_action_run_request(text):
        action_id = _extract_action_id_from_text(text)
        if action_id <= 0:
            typer.echo("请指定要执行的行动编号，例如：执行第1个建议")
            return True
        ok, rendered = _run_quick_action_item(options=options, action_id=action_id, execute_mode=execute_mode)
        if ok:
            typer.echo(rendered)
        else:
            snapshot = _load_latest_watch_snapshot(None)
            inbox = _build_action_inbox_from_watch(snapshot)
            _run_action_inbox_item(
                inbox=inbox,
                action_id=action_id,
                options=options,
                execute_mode=execute_mode,
            )
        return True
    if _looks_like_actions_request(text):
        typer.echo(_render_quick_actions_text({**options, "execute": execute_mode}))
        return True
    if _looks_like_brief_request(text):
        report = _build_overview_brief_report(
            target=_extract_ssh_target_from_text(text),
            include_remote=True,
            include_logs=any(k in lowered for k in ("日志", "logs")),
            timeout_sec=5,
        )
        if _console:
            _render_overview_brief_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
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
    if _looks_like_preflight_request(text):
        strict_mode = ("strict" in lowered) or ("严格" in lowered)
        staged = ("全仓" not in lowered) and ("all files" not in lowered)
        report = _collect_preflight_report(
            profile_file=Path(settings.target_profile_file),
            timeout_sec=6,
            dry_run_probe=True,
            strict=strict_mode,
            staged=staged,
            max_findings=8,
            audit_log=Path(str(options["audit_log"])),
        )
        if _console:
            _render_doctor_report(report)
        else:
            typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
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


def _run_closed_loop_remediation(
    *,
    objective: str,
    remote_target: str,
    service_filter: str,
    include_logs: bool,
    apply: bool,
    verify: bool,
    rollback_on_failure: bool,
    from_last_plan: bool,
    max_apply_steps: int,
    execute: bool,
    approval_mode: str,
    audit_log: str,
    allow_high_risk: bool,
    auto_approve_low_risk: bool,
    model: str,
    provider: str,
) -> dict[str, object]:
    resolved_remote_target = _resolve_ssh_target_arg(remote_target) if str(remote_target or "").strip() else ""
    observation = (
        _run_remote_autopilot_cycle(
            goal=objective,
            target=resolved_remote_target,
            service_filter=service_filter,
            include_logs=include_logs,
            timeout_sec=6,
        )
        if resolved_remote_target
        else _run_autopilot_cycle(
            goal=objective,
            include_swarm=True,
            include_logs=include_logs,
            remember=True,
            timeout_sec=5,
        )
    )
    plan_payload = _derive_closed_loop_plan(
        objective=objective,
        observation=observation,
        from_last_plan=from_last_plan,
    )
    plan = FixPlan(
        apply_commands=[str(x) for x in list(plan_payload.get("apply_commands", []))],
        rollback_commands=[str(x) for x in list(plan_payload.get("rollback_commands", []))],
    )
    diagnose_commands = [str(x) for x in list(plan_payload.get("diagnose_commands", []))]
    verify_commands = [str(x) for x in list(plan_payload.get("verify_commands", []))]
    execution = _run_closed_loop_execution(
        diagnose_commands=diagnose_commands,
        plan=plan,
        verify_commands=verify_commands,
        apply=apply,
        verify=verify,
        rollback_on_failure=rollback_on_failure,
        max_apply_steps=max_apply_steps,
        execute=execute,
        approval_mode=approval_mode,
        audit_log=audit_log,
        allow_high_risk=allow_high_risk,
        auto_approve_low_risk=auto_approve_low_risk,
        model=model,
        provider=provider,
        remote_target=resolved_remote_target,
    )
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "closed-loop-remediation",
        "objective": objective,
        "mode": "execute" if execute else "dry-run",
        "remote_target": resolved_remote_target,
        "apply_requested": apply,
        "observation": {
            "source": observation.get("source", ""),
            "status": observation.get("status", ""),
            "summary": observation.get("summary", {}),
            "next_step": observation.get("next_step", ""),
        },
        "plan": plan_payload,
        "execution": execution,
        "ok": bool(execution.get("ok", False)),
        "next_step": _closed_loop_next_step(execution),
    }
    _write_json_file(Path(".data/lsre-remediation-last.json"), report)
    return report


def _derive_closed_loop_plan(
    *,
    objective: str,
    observation: dict[str, object],
    from_last_plan: bool,
) -> dict[str, object]:
    if from_last_plan:
        loaded = _load_last_fix_plan()
        if loaded:
            return {
                "source": "last-fix-plan",
                "template": "",
                "diagnose_commands": _infer_verification_commands(loaded),
                "apply_commands": loaded.apply_commands,
                "rollback_commands": loaded.rollback_commands,
                "verify_commands": _infer_verification_commands(loaded),
            }
    template = match_template_for_text(objective)
    actions = (observation.get("action_inbox", {}) if isinstance(observation.get("action_inbox", {}), dict) else {}).get("actions", [])
    first_action = actions[0] if isinstance(actions, list) and actions and isinstance(actions[0], dict) else {}
    if not template:
        template_name = str(first_action.get("template", "")).strip()
        template = get_remediation_template(template_name) if template_name else None
    if template:
        variables = first_action.get("variables", {})
        overrides = {str(k): str(v) for k, v in variables.items()} if isinstance(variables, dict) else {}
        rendered = render_remediation_template(template=template, overrides=overrides)
        plan = FixPlan(
            apply_commands=[str(x) for x in list(rendered.get("apply_commands", []))],
            rollback_commands=[str(x) for x in list(rendered.get("rollback_commands", []))],
        )
        return {
            "source": "template",
            "template": template.name,
            "variables": rendered.get("variables", {}),
            "diagnose_commands": [str(x) for x in list(rendered.get("diagnose_commands", []))],
            "apply_commands": plan.apply_commands,
            "rollback_commands": plan.rollback_commands,
            "verify_commands": _infer_verification_commands(plan, diagnose_commands=[str(x) for x in list(rendered.get("diagnose_commands", []))]),
        }
    command = str(first_action.get("command", "")).strip()
    diagnose = [command] if command and _looks_like_shell_command(command) else []
    return {
        "source": "observation-action",
        "template": "",
        "variables": {},
        "diagnose_commands": diagnose,
        "apply_commands": [],
        "rollback_commands": [],
        "verify_commands": diagnose,
    }


def _run_closed_loop_execution(
    *,
    diagnose_commands: list[str],
    plan: FixPlan,
    verify_commands: list[str],
    apply: bool,
    verify: bool,
    rollback_on_failure: bool,
    max_apply_steps: int,
    execute: bool,
    approval_mode: str,
    audit_log: str,
    allow_high_risk: bool,
    auto_approve_low_risk: bool,
    model: str,
    provider: str,
    remote_target: str = "",
) -> dict[str, object]:
    diagnose_result = _execute_read_only_commands(
        diagnose_commands,
        stage="diagnose",
        approval_mode=approval_mode,
        audit_log=audit_log,
        remote_target=remote_target,
    )
    if apply and plan.apply_commands:
        if remote_target:
            apply_result = _execute_remote_fix_plan_steps(
                target=remote_target,
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
        else:
            apply_result = _execute_fix_plan_steps(
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
    else:
        apply_result = {
            "executed": 0,
            "succeeded": 0,
            "failed": 0,
            "skipped_high_risk": 0,
            "skipped_reason": "apply not requested" if not apply else "no apply commands",
        }
    verify_result = (
        _execute_read_only_commands(
            verify_commands,
            stage="verify",
            approval_mode=approval_mode,
            audit_log=audit_log,
            remote_target=remote_target,
        )
        if verify
        else {"executed": 0, "succeeded": 0, "failed": 0, "skipped": 0, "items": []}
    )
    failed = (
        int(diagnose_result.get("failed", 0) or 0)
        + int(apply_result.get("failed", 0) or 0)
        + int(verify_result.get("failed", 0) or 0)
    )
    rollback_result: dict[str, object] = {"executed": 0, "succeeded": 0, "failed": 0, "skipped": 0, "items": []}
    if rollback_on_failure and execute and failed and plan.rollback_commands:
        rollback_plan = FixPlan(apply_commands=plan.rollback_commands, rollback_commands=[])
        if remote_target:
            rollback_result = _execute_remote_fix_plan_steps(
                target=remote_target,
                plan=rollback_plan,
                max_apply_steps=len(plan.rollback_commands),
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
            rollback_result = _execute_fix_plan_steps(
                plan=rollback_plan,
                max_apply_steps=len(plan.rollback_commands),
                execute=True,
                approval_mode=approval_mode,
                audit_log=audit_log,
                allow_high_risk=True,
                auto_approve_low_risk=True,
                model=model,
                provider=provider,
                skip_confirm=True,
            )
    return {
        "ok": failed == 0,
        "diagnose": diagnose_result,
        "apply": apply_result,
        "verify": verify_result,
        "rollback": rollback_result,
    }


def _execute_read_only_commands(
    commands: list[str],
    *,
    stage: str,
    approval_mode: str,
    audit_log: str,
    remote_target: str = "",
) -> dict[str, object]:
    executor = SafeExecutor(
        dry_run=False,
        approval_mode=approval_mode,
        approval_granted=True,
        audit_logger=AuditLogger(Path(audit_log)),
    )
    items: list[dict[str, object]] = []
    executed = succeeded = failed = skipped = 0
    safe_remote_target = _normalize_ssh_target(remote_target)
    for command_text in _dedupe_strings(commands)[:12]:
        try:
            command = shlex.split(command_text)
        except ValueError as exc:
            skipped += 1
            items.append(
                {
                    "command": command_text,
                    "ok": False,
                    "skipped": True,
                    "reason": _safe_exception_text(exc),
                }
            )
            continue
        decision = assess_command(command, approval_mode=approval_mode)
        if decision.risk_level != "low":
            skipped += 1
            items.append(
                {
                    "command": command_text,
                    "ok": False,
                    "skipped": True,
                    "reason": f"{stage} only runs read-only commands; risk={decision.risk_level}",
                }
            )
            continue
        if safe_remote_target:
            raw = _safe_run_ssh_command(safe_remote_target, _remote_shell_command(command), timeout_sec=20)
            result = ExecResult(
                ok=bool(raw.get("ok", False)),
                command=["ssh", safe_remote_target, command_text],
                stdout=str(raw.get("stdout", "")),
                stderr=str(raw.get("stderr", "")),
                exit_code=int(raw.get("exit_code", 0) or 0),
                dry_run=False,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                risk_report=build_risk_report(command, decision),
                requires_approval=decision.requires_approval,
                approved=True,
            )
            AuditLogger(Path(audit_log)).write(
                {
                    "command": result.command,
                    "remote_target": safe_remote_target,
                    "remote_command": command,
                    "ok": result.ok,
                    "exit_code": result.exit_code,
                    "dry_run": result.dry_run,
                    "risk_level": result.risk_level,
                    "requires_approval": result.requires_approval,
                    "approved": result.approved,
                    "policy_reasons": result.policy_reasons,
                    "risk_report": result.risk_report,
                    "stderr": result.stderr[:500],
                    "stdout_preview": result.stdout[:300],
                }
            )
        else:
            result = asyncio.run(executor.run(command))
        executed += 1
        succeeded += 1 if result.ok else 0
        failed += 0 if result.ok else 1
        items.append(
            {
                "command": command_text,
                "ok": result.ok,
                "exit_code": result.exit_code,
                "stdout_preview": result.stdout[:500],
                "stderr_preview": result.stderr[:500],
            }
        )
    return {"executed": executed, "succeeded": succeeded, "failed": failed, "skipped": skipped, "items": items}


def _execute_remote_fix_plan_steps(
    *,
    target: str,
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
    safe_target = _normalize_ssh_target(target)
    if not safe_target:
        typer.echo("远程执行目标无效，已跳过。")
        return {"executed": 0, "succeeded": 0, "failed": 1, "skipped_high_risk": 0}
    selected = plan.apply_commands[:max_apply_steps]
    total = len(selected)
    skipped_high_risk = 0
    executed = 0
    succeeded = 0
    failed = 0
    audit = AuditLogger(Path(audit_log))
    for idx, command_text in enumerate(selected, 1):
        try:
            command = shlex.split(command_text)
        except ValueError as exc:
            typer.echo(
                f"[remote step {idx}/{total}] 无法解析命令，跳过: {command_text} "
                f"({_safe_exception_text(exc)})"
            )
            continue
        if not command:
            continue
        if command[0] not in {"docker", "kubectl", "curl", "tail"}:
            failed += 1
            typer.echo(f"[remote step {idx}/{total}] blocked command: {command[0]}")
            continue
        decision = assess_command(command, approval_mode=approval_mode)
        report = build_risk_report(command, decision)
        impact_statement = _generate_impact_statement(
            command_text=f"ssh {safe_target} {shlex.quote(command_text)}",
            report={**report, "impact_scope": f"remote:{safe_target}"},
            model=model,
            provider=provider,
        )
        _render_step_risk(
            idx,
            total,
            f"ssh {safe_target} {shlex.quote(command_text)}",
            report,
            impact_statement=impact_statement,
        )
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
            typer.echo(f"[remote step {idx}/{total}] 已跳过高风险步骤（如需执行请加 --allow-high-risk）")
            continue
        if (not skip_confirm) and need_confirm and (
            not typer.confirm(f"[remote step {idx}/{total}] 是否在 {safe_target} 执行该步骤？", default=False)
        ):
            continue
        if not execute:
            result_exec = ExecResult(
                ok=True,
                command=["ssh", safe_target, command_text],
                stdout=f"[dry-run] ssh {safe_target} {command_text}",
                exit_code=0,
                dry_run=True,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                risk_report=report,
                requires_approval=decision.requires_approval,
                approved=True,
            )
        else:
            raw = _safe_run_ssh_command(safe_target, _remote_shell_command(command), timeout_sec=30)
            result_exec = ExecResult(
                ok=bool(raw.get("ok", False)),
                command=["ssh", safe_target, command_text],
                stdout=str(raw.get("stdout", "")),
                stderr=str(raw.get("stderr", "")),
                exit_code=int(raw.get("exit_code", 0) or 0),
                dry_run=False,
                risk_level=decision.risk_level,
                policy_reasons=decision.reasons,
                risk_report=report,
                requires_approval=decision.requires_approval,
                approved=True,
            )
        audit.write(
            {
                "command": result_exec.command,
                "remote_target": safe_target,
                "remote_command": command,
                "ok": result_exec.ok,
                "exit_code": result_exec.exit_code,
                "dry_run": result_exec.dry_run,
                "risk_level": result_exec.risk_level,
                "requires_approval": result_exec.requires_approval,
                "approved": result_exec.approved,
                "policy_reasons": result_exec.policy_reasons,
                "risk_report": result_exec.risk_report,
                "stderr": result_exec.stderr[:500],
                "stdout_preview": result_exec.stdout[:300],
            }
        )
        executed += 1
        if result_exec.ok:
            succeeded += 1
        else:
            failed += 1
        _render_step_result(idx, total, result_exec)
        if (not result_exec.ok) and (not skip_confirm) and (
            not typer.confirm("远程步骤失败，是否继续后续步骤？", default=False)
        ):
            break
    if skipped_high_risk:
        typer.echo(f"共跳过 {skipped_high_risk} 个远程高风险步骤。")
    return {
        "executed": executed,
        "succeeded": succeeded,
        "failed": failed,
        "skipped_high_risk": skipped_high_risk,
    }


def _infer_verification_commands(plan: FixPlan, *, diagnose_commands: list[str] | None = None) -> list[str]:
    commands: list[str] = []
    if diagnose_commands:
        commands.extend(diagnose_commands[:4])
    for command_text in plan.apply_commands:
        text = str(command_text).strip()
        if not text:
            continue
        if "rollout status" in text:
            commands.append(text)
        if text.startswith("docker service update ") or text.startswith("docker service rollback "):
            parts = shlex.split(text)
            service = parts[-1] if parts else ""
            if service and not service.startswith("-"):
                commands.append(f"docker service ps {service} --no-trunc")
                commands.append("docker service ls --format '{{.Name}}\\t{{.Replicas}}\\t{{.Image}}'")
        if text.startswith("kubectl ") and (" scale " in text or " set image " in text or " rollout restart " in text):
            commands.append("kubectl get pods -A --field-selector=status.phase!=Running")
    return _dedupe_strings(commands)


def _closed_loop_next_step(execution: dict[str, object]) -> str:
    if bool(execution.get("ok", False)):
        return "闭环完成：诊断、执行/预演和验证阶段未发现失败。建议继续 watch 观察一个周期。"
    rollback = execution.get("rollback", {})
    if isinstance(rollback, dict) and int(rollback.get("executed", 0) or 0):
        return "闭环检测到失败并已触发回滚。建议立刻查看 verify 阶段输出并保留审计日志。"
    return "闭环检测到失败。建议先执行 lazysre undo 或带 --rollback-on-failure 重试，并查看 .data/lsre-remediation-last.json。"


def _render_closed_loop_report(report: dict[str, object]) -> None:
    if not (_console and Panel):
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return
    execution = report.get("execution", {})
    if not isinstance(execution, dict):
        execution = {}
    plan = report.get("plan", {})
    if not isinstance(plan, dict):
        plan = {}
    lines = [
        f"目标: {report.get('objective', '')}",
        f"模式: {report.get('mode', '-')}",
        f"计划来源: {plan.get('source', '-')}",
        f"模板: {plan.get('template', '-') or '-'}",
        f"诊断: {execution.get('diagnose', {}).get('succeeded', 0) if isinstance(execution.get('diagnose', {}), dict) else 0} ok",
        f"执行: {execution.get('apply', {}).get('succeeded', 0) if isinstance(execution.get('apply', {}), dict) else 0} ok",
        f"验证: {execution.get('verify', {}).get('succeeded', 0) if isinstance(execution.get('verify', {}), dict) else 0} ok",
        f"下一步: {report.get('next_step', '')}",
    ]
    _console.print(Panel("\n".join(lines), title="Closed Loop Remediation", border_style="green" if report.get("ok") else "yellow"))


def _render_closed_loop_report_markdown(report: dict[str, object]) -> str:
    observation = report.get("observation", {})
    if not isinstance(observation, dict):
        observation = {}
    plan = report.get("plan", {})
    if not isinstance(plan, dict):
        plan = {}
    execution = report.get("execution", {})
    if not isinstance(execution, dict):
        execution = {}
    lines = [
        "# LazySRE Closed-loop Remediation Report",
        "",
        f"- Generated: {report.get('generated_at_utc', '')}",
        f"- Objective: {report.get('objective', '')}",
        f"- Mode: `{report.get('mode', '-')}`",
        f"- Remote Target: `{report.get('remote_target', '') or '-'}`",
        f"- OK: `{report.get('ok', False)}`",
        f"- Next Step: {report.get('next_step', '')}",
        "",
        "## Observation",
        "",
        f"- Source: `{observation.get('source', '-')}`",
        f"- Status: `{observation.get('status', '-')}`",
        f"- Summary: `{json.dumps(observation.get('summary', {}), ensure_ascii=False)}`",
        f"- Suggested Next: {observation.get('next_step', '')}",
        "",
        "## Plan",
        "",
        f"- Source: `{plan.get('source', '-')}`",
        f"- Template: `{plan.get('template', '-') or '-'}`",
    ]
    for title, key in [
        ("Diagnose Commands", "diagnose_commands"),
        ("Apply Commands", "apply_commands"),
        ("Verify Commands", "verify_commands"),
        ("Rollback Commands", "rollback_commands"),
    ]:
        commands = [str(x) for x in list(plan.get(key, [])) if str(x).strip()]
        lines.extend(["", f"### {title}", ""])
        if commands:
            lines.extend(["```bash", *commands, "```"])
        else:
            lines.append("- None")
    lines.extend(["", "## Execution", ""])
    for stage in ["diagnose", "apply", "verify", "rollback"]:
        payload = execution.get(stage, {})
        if not isinstance(payload, dict):
            payload = {}
        lines.append(
            f"- {stage}: executed={payload.get('executed', 0)} "
            f"succeeded={payload.get('succeeded', 0)} failed={payload.get('failed', 0)}"
        )
    return "\n".join(lines)


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
    verify_commands = _infer_verification_commands(plan, diagnose_commands=diagnose_commands)
    exec_summary = _run_closed_loop_execution(
        diagnose_commands=diagnose_commands,
        plan=plan,
        verify_commands=verify_commands,
        apply=True,
        verify=True,
        rollback_on_failure=False,
        max_apply_steps=max_apply_steps,
        execute=execute,
        approval_mode=approval_mode,
        audit_log=audit_log,
        allow_high_risk=allow_high_risk,
        auto_approve_low_risk=auto_approve_low_risk,
        model=model,
        provider=provider,
    )
    if _console and Panel:
        _console.print(Panel(json.dumps(exec_summary, ensure_ascii=False, indent=2), title="Template Closed Loop", border_style="green" if exec_summary.get("ok") else "yellow"))
    else:
        typer.echo(json.dumps(exec_summary, ensure_ascii=False, indent=2))
    _persist_successful_fix_case(
        instruction=f"[template] {template.name}",
        final_text=json.dumps(payload, ensure_ascii=False),
        plan=plan,
        plan_md_path=Path(".data/lsre-template-last.md"),
        exec_summary={
            "executed": int(exec_summary.get("apply", {}).get("executed", 0)) if isinstance(exec_summary.get("apply", {}), dict) else 0,
            "succeeded": int(exec_summary.get("apply", {}).get("succeeded", 0)) if isinstance(exec_summary.get("apply", {}), dict) else 0,
            "failed": int(exec_summary.get("apply", {}).get("failed", 0)) if isinstance(exec_summary.get("apply", {}), dict) else 0,
            "skipped_high_risk": int(exec_summary.get("apply", {}).get("skipped_high_risk", 0)) if isinstance(exec_summary.get("apply", {}), dict) else 0,
        },
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
            typer.echo(
                f"[step {idx}/{total}] 无法解析命令，跳过: {command_text} "
                f"({_safe_exception_text(exc)})"
            )
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

    ssh_target = _first(
        [
            r"(?:ssh\s*target|ssh|远程(?:服务器|主机|目标)?|服务器|主机|remote(?:\s*host)?)[\s:=：]*(?:是|为|改成|设成|设置为|用|保存为|配置为)?\s*([A-Za-z0-9._-]+@[A-Za-z0-9._:-]+)",
        ]
    )
    if not ssh_target:
        maybe_target = _extract_ssh_target_from_text(raw)
        explicit_target_update = (
            "ssh target",
            "保存远程",
            "配置远程",
            "设置远程",
            "远程目标",
            "remote host",
        )
        if maybe_target and any(k in lowered for k in explicit_target_update):
            ssh_target = maybe_target
    if ssh_target:
        normalized_target = _normalize_ssh_target(ssh_target)
        if normalized_target:
            updates["ssh_target"] = normalized_target

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
            typer.echo(_safe_exception_text(exc))
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


def _looks_like_remediate_request(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(
        phrase in lowered
        for phrase in [
            "闭环修复",
            "生产修复",
            "修复并验证",
            "修复后验证",
            "自动回滚",
            "失败回滚",
            "remediate",
            "closed-loop",
        ]
    )


def _run_remediate_from_text(text: str, options: dict[str, object], *, execute_mode: bool) -> None:
    apply_requested = any(x in str(text).lower() for x in ["执行", "--apply", "apply", "真实修复"])
    rollback_requested = any(x in str(text).lower() for x in ["失败回滚", "自动回滚", "--rollback-on-failure"])
    report = _run_closed_loop_remediation(
        objective=str(text).strip() or "修复当前巡检发现的问题",
        remote_target=_extract_ssh_target_from_text(text),
        service_filter=_extract_swarm_service_name(text),
        include_logs="--logs" in str(text).lower() or "日志" in str(text),
        apply=apply_requested,
        verify=True,
        rollback_on_failure=rollback_requested,
        from_last_plan="最近计划" in str(text) or "last plan" in str(text).lower(),
        max_apply_steps=6,
        execute=_resolve_execute_for_apply_request(
            execute_mode,
            label="闭环修复执行",
            apply=apply_requested,
        ),
        approval_mode=str(options["approval_mode"]),
        audit_log=str(options["audit_log"]),
        allow_high_risk=False,
        auto_approve_low_risk=True,
        model=str(options["model"]),
        provider=str(options["provider"]),
    )
    if _console:
        _render_closed_loop_report(report)
    else:
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))


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
        "ssh",
        "远程",
        "服务器",
        "主机",
        "remote host",
        "ssh target",
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


def _looks_like_brief_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "简报",
        "总览",
        "总体情况",
        "整体情况",
        "一眼看",
        "给我总结",
        "给我一个摘要",
        "brief",
        "overview",
        "summary",
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


def _looks_like_remote_diagnose_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "远程",
        "ssh",
        "服务器",
        "remote",
        "host",
    )
    diagnose_words = (
        "诊断",
        "检查",
        "巡检",
        "排查",
        "看看",
        "scan",
        "diagnose",
        "check",
    )
    has_intent = any(k in lowered for k in keywords) and any(k in lowered for k in diagnose_words)
    if not has_intent:
        return False
    return bool(_extract_ssh_target_from_text(text) or _resolve_ssh_target_arg(""))


def _looks_like_remote_connect_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    has_target = bool(_extract_ssh_target_from_text(text))
    keywords = (
        "连接远程",
        "远程连接",
        "连接服务器",
        "测试ssh",
        "ssh连通",
        "ssh 连通",
        "连一下服务器",
        "ssh check",
    )
    if any(k in lowered for k in keywords):
        return True
    if "连接" in lowered and has_target:
        return True
    if "connect" in lowered:
        context_words = ("ssh", "remote", "server", "host", "服务器", "远程")
        return has_target or any(k in lowered for k in context_words)
    return False


def _extract_ssh_target_from_text(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    match = re.search(r"\b([A-Za-z0-9._-]+@[A-Za-z0-9._:-]+)\b", raw)
    if match:
        return _normalize_ssh_target(match.group(1))
    match = re.search(r"\bssh\s+([A-Za-z0-9._-]+@[A-Za-z0-9._:-]+)\b", raw, flags=re.IGNORECASE)
    if match:
        return _normalize_ssh_target(match.group(1))
    return ""


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
    number_token = r"[#0-9零〇一二三四五六七八九十两①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳❶❷❸❹❺❻❼❽❾❿]+"
    patterns = [
        rf"(?:执行|运行|处理|应用)\s*(?:第)?\s*({number_token})\s*(?:个|号)?\s*(?:建议|动作|行动|推荐|步骤?)",
        rf"(?:建议|动作|行动|推荐|步骤?)\s*(?:第)?\s*({number_token})(?:号)?",
        rf"(?:run|apply)\s+(?:action\s+)?({number_token})",
        rf"action\s+({number_token})",
        rf"^({number_token})$",
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


def _looks_like_preflight_request(text: str) -> bool:
    lowered = text.lower().strip()
    if not lowered:
        return False
    keywords = (
        "preflight",
        "发布前检查",
        "上线前检查",
        "上线检查",
        "发版前检查",
        "release check",
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
        typer.echo(f"长期记忆写入失败（已忽略）: {_safe_exception_text(exc)}")


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


def _version_info() -> dict[str, object]:
    return {
        "name": "lazysre",
        "version": __version__,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "executable": sys.executable,
    }


def _version_text(info: dict[str, object] | None = None) -> str:
    payload = info or _version_info()
    return (
        f"{payload.get('name', 'lazysre')} {payload.get('version', __version__)} "
        f"(python {payload.get('python', '-')})"
    )


def main() -> None:
    _rewrite_argv_for_default_run(sys.argv)
    app()


def _rewrite_argv_for_default_run(argv: list[str]) -> None:
    if len(argv) <= 1:
        return
    commands = {
        "run",
        "chat",
        "tui",
        "login",
        "logout",
        "init",
        "quickstart",
        "reset",
        "undo",
        "fix",
        "approve",
        "status",
        "brief",
        "scan",
        "swarm",
        "watch",
        "actions",
        "autopilot",
        "remediate",
        "connect",
        "remote",
        "doctor",
        "install-doctor",
        "preflight",
        "secret-scan",
        "setup",
        "report",
        "incident",
        "template",
        "runbook",
        "pack",
        "target",
        "history",
        "memory",
        "version",
        "--help",
        "--version",
        "-V",
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


def _should_launch_default_tui(tokens: list[str]) -> bool:
    if not tokens:
        return True
    commands = {
        "run",
        "chat",
        "tui",
        "login",
        "logout",
        "init",
        "quickstart",
        "reset",
        "undo",
        "fix",
        "approve",
        "status",
        "brief",
        "scan",
        "swarm",
        "watch",
        "actions",
        "autopilot",
        "remediate",
        "connect",
        "remote",
        "doctor",
        "install-doctor",
        "preflight",
        "secret-scan",
        "setup",
        "report",
        "incident",
        "template",
        "runbook",
        "pack",
        "target",
        "history",
        "memory",
        "version",
        "--help",
        "--version",
        "-V",
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


def _should_launch_assistant(tokens: list[str]) -> bool:
    if not tokens:
        return False
    commands = {
        "run",
        "chat",
        "tui",
        "login",
        "logout",
        "init",
        "quickstart",
        "reset",
        "undo",
        "fix",
        "approve",
        "status",
        "brief",
        "scan",
        "swarm",
        "watch",
        "actions",
        "autopilot",
        "remediate",
        "connect",
        "remote",
        "doctor",
        "install-doctor",
        "preflight",
        "secret-scan",
        "setup",
        "report",
        "incident",
        "template",
        "runbook",
        "pack",
        "target",
        "history",
        "memory",
        "version",
        "--help",
        "--version",
        "-V",
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
    return False


if __name__ == "__main__":
    main()
