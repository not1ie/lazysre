from __future__ import annotations

import asyncio
import json
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
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
from lazysre.cli.llm import MockFunctionCallingLLM, OpenAIResponsesLLM
from lazysre.cli.permissions import ToolPermissionContext
from lazysre.cli.policy import PolicyDecision, assess_command, build_risk_report
from lazysre.cli.session import SessionStore
from lazysre.cli.memory import IncidentMemoryStore, MemoryCase, format_memory_context
from lazysre.cli.runbook import (
    RunbookStore,
    RunbookTemplate,
    all_runbooks,
    find_runbook,
    parse_runbook_vars,
    render_runbook_instruction,
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
    provider: Annotated[str, typer.Option(help="LLM provider: auto|mock|openai")] = "auto",
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


@app.command("doctor")
def doctor(
    ctx: typer.Context,
    profile_file: Annotated[str, typer.Option("--profile-file", help="Target profile JSON path.")] = settings.target_profile_file,
    timeout_sec: Annotated[int, typer.Option("--timeout-sec", help="Probe timeout seconds.")] = 6,
    dry_run_probe: Annotated[bool, typer.Option("--dry-run-probe", help="Run probe checks in dry-run mode.")] = False,
    auto_fix: Annotated[bool, typer.Option("--auto-fix", help="Apply safe auto-fixes for doctor findings.")] = False,
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
    if auto_fix:
        autofix = _apply_doctor_autofix(target_store, target, write_backup=write_backup)
        target = target_store.load()
        report = _collect_doctor_report(
            target=target,
            timeout_sec=timeout_sec,
            dry_run_probe=dry_run_probe,
            audit_log=Path(str(options["audit_log"])),
        )
        report["autofix"] = autofix
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
    payload = _build_incident_report_payload(
        session_file=Path(str(options["session_file"])),
        target_profile_file=Path(settings.target_profile_file),
        include_doctor=include_doctor,
        include_memory=include_memory,
        memory_limit=5,
        turn_limit=limit,
        audit_log=Path(str(options["audit_log"])),
    )
    chosen = fmt.strip().lower()
    if chosen not in {"markdown", "json"}:
        raise typer.BadParameter("format must be markdown or json")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if not output.strip():
        output = _default_report_output_path(fmt=chosen, stamp=stamp, push_to_git=push_to_git)
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if chosen == "json":
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        out_path.write_text(_render_incident_report_markdown(payload), encoding="utf-8")
    typer.echo(f"Report exported: {out_path}")
    if push_to_git:
        archived_path = _archive_report_for_git(out_path, stamp=stamp)
        commit_message = git_message.strip() or f"chore(report): archive incident report {stamp}"
        pushed = _push_report_to_git(
            archived_path=archived_path,
            remote=git_remote.strip() or "origin",
            commit_message=commit_message,
        )
        if pushed:
            typer.echo(f"Report archived & pushed: {archived_path}")
        else:
            typer.echo(f"Report archived (no changes to push): {archived_path}")


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
    provider: Annotated[str | None, typer.Option(help="Override provider: auto|mock|openai")] = None,
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
    provider: Annotated[str | None, typer.Option(help="Override provider: auto|mock|openai")] = None,
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
    provider: Annotated[str | None, typer.Option(help="Override provider: auto|mock|openai")] = None,
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
    if mode not in {"auto", "mock", "openai"}:
        raise typer.BadParameter("provider must be one of auto/mock/openai")
    ap_mode = (approval_mode or "balanced").strip().lower()
    if ap_mode not in {"strict", "balanced", "permissive"}:
        raise typer.BadParameter("approval_mode must be one of strict/balanced/permissive")
    if mode == "openai" or (mode == "auto" and settings.openai_api_key):
        if not settings.openai_api_key:
            raise typer.BadParameter(
                "OPENAI_API_KEY is required when provider=openai",
            )
        llm = OpenAIResponsesLLM(settings.openai_api_key)
    else:
        llm = MockFunctionCallingLLM()

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
        model=model,
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
    provider: Annotated[str | None, typer.Option(help="Override provider: auto|mock|openai")] = None,
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
        vars_payload = parse_runbook_vars(var)
        instruction, resolved_vars = render_runbook_instruction(template, overrides=vars_payload)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if extra.strip():
        instruction = f"{instruction}\n\n[runbook-extra]\n{extra.strip()}"
    if resolved_vars:
        instruction = (
            f"{instruction}\n\n[runbook-vars]\n"
            + ", ".join(f"{k}={v}" for k, v in sorted(resolved_vars.items()))
        )
    _execute_runbook(
        template=template,
        instruction=instruction,
        apply=apply,
        options=options,
    )


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
        "- /status: 查看当前会话、目标配置、最近修复计划",
        "- /status probe: 追加目标探测摘要（dry-run）",
        "- /doctor: 运行环境预检（依赖/配置/连通性）",
        "- /doctor fix: 执行安全自动修复后再预检",
        "- /doctor strict: 严格模式（warn 也视为不健康）",
        "- /runbook list: 查看 runbook 模板",
        "- /runbook <name> [k=v]: 执行 runbook（支持变量覆盖）",
        "- /report: 导出复盘报告",
        "- /fix <问题>: 进入修复计划模式",
        "- /apply: 执行最近一次修复计划",
        "- /approve: 查看审批队列",
        "- /approve 1,3-4: 执行指定步骤",
        "- /memory: 查看最近故障记忆",
        "- /memory <query>: 检索相似历史案例",
        "- exit / quit: 退出",
    ]
    text = "\n".join(lines)
    if _console and Panel:
        _console.print(Panel(text, border_style="cyan"))
    else:
        typer.echo(text)


def _assistant_chat_loop(options: dict[str, object]) -> None:
    typer.echo("LazySRE 自然语言助手已启动。直接输入问题即可，输入 exit/quit 退出。")
    typer.echo("提示：说“修复 xxx”会自动生成修复计划；说“执行修复计划”会执行最近计划。")
    typer.echo(
        "快捷命令：/help /status [/status probe] /doctor [/doctor fix] "
        "/runbook [name] [k=v] /report /fix <问题> /apply /approve [steps] /memory [query]"
    )
    while True:
        try:
            line = typer.prompt("lsre")
        except (EOFError, KeyboardInterrupt):
            typer.echo("")
            break
        text = line.strip()
        if not text:
            continue
        if text.lower() in {"exit", "quit"}:
            break
        if text.lower() in {"/help", "/h"}:
            _render_chat_short_help()
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
            if (not tail) or (tail.lower() in {"list", "ls"}):
                runbook_list()
                continue
            parts = [p for p in tail.split(" ") if p.strip()]
            runbook_name = parts[0] if parts else ""
            runbook_var_items = [item for item in parts[1:] if "=" in item]
            runbook_extra = " ".join(item for item in parts[1:] if "=" not in item).strip()
            template = find_runbook(runbook_name, store=RunbookStore.default())
            if not template:
                typer.echo(f"runbook not found: {tail}")
                continue
            try:
                overrides = parse_runbook_vars(runbook_var_items)
                instruction, resolved_vars = render_runbook_instruction(template, overrides=overrides)
            except ValueError as exc:
                typer.echo(str(exc))
                continue
            if runbook_extra:
                instruction = f"{instruction}\n\n[runbook-extra]\n{runbook_extra}"
            if resolved_vars:
                instruction = (
                    f"{instruction}\n\n[runbook-vars]\n"
                    + ", ".join(f"{k}={v}" for k, v in sorted(resolved_vars.items()))
                )
            _execute_runbook(
                template=template,
                instruction=instruction,
                apply=False,
                options=options,
            )
            continue
        if text.lower().startswith("/report"):
            payload = _build_incident_report_payload(
                session_file=Path(str(options["session_file"])),
                target_profile_file=Path(settings.target_profile_file),
                include_doctor=True,
                include_memory=True,
                memory_limit=5,
                turn_limit=20,
                audit_log=Path(str(options["audit_log"])),
            )
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            out_path = Path(f".data/lsre-report-{stamp}.md")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(_render_incident_report_markdown(payload), encoding="utf-8")
            typer.echo(f"Report exported: {out_path}")
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
                execute=bool(options["execute"]),
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
                execute=bool(options["execute"]),
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                model=str(options["model"]),
                provider=str(options["provider"]),
            )
            continue

        if _looks_like_apply_request(text):
            _apply_last_fix_plan(
                max_apply_steps=6,
                execute=bool(options["execute"]),
                approval_mode=str(options["approval_mode"]),
                audit_log=str(options["audit_log"]),
                model=str(options["model"]),
                provider=str(options["provider"]),
            )
            continue

        if _looks_like_fix_request(text):
            _run_fix(
                instruction=text,
                apply=False,
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
            continue

        _run_once(
            instruction=text,
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
        allow_execute, need_confirm = evaluate_apply_guardrail(
            risk_level=str(report.get("risk_level", "low")),
            allow_high_risk=allow_high_risk,
            auto_approve_low_risk=auto_approve_low_risk,
        )
        if not allow_execute:
            skipped_high_risk += 1
            typer.echo(f"[step {idx}/{total}] 已跳过高风险步骤（如需执行请加 --allow-high-risk）")
            continue
        if (not skip_confirm) and need_confirm and (
            not typer.confirm(f"[step {idx}/{total}] 是否执行该步骤？", default=False)
        ):
            continue
        if (not need_confirm) and auto_approve_low_risk:
            typer.echo(f"[step {idx}/{total}] low-risk 自动通过确认")
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
        allow_high_risk=False,
        auto_approve_low_risk=False,
        model=model,
        provider=provider,
    )
    if plan.rollback_commands:
        typer.echo("\n可回滚命令：")
        for cmd in plan.rollback_commands:
            typer.echo(f"- {cmd}")


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
    return any(
        keyword in lowered
        for keyword in [
            "执行修复计划",
            "应用修复计划",
            "执行刚才修复",
            "执行计划",
            "apply plan",
            "apply fix",
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
    if mode not in {"openai"} or (not settings.openai_api_key):
        # deterministic fallback for local/mock mode
        scope = str(report.get("impact_scope", "service"))
        radius = str(report.get("blast_radius", "single target"))
        return f"该操作将影响 {scope}，潜在影响范围为 {radius}，请确认业务窗口与回滚条件。"
    try:
        llm = OpenAIResponsesLLM(settings.openai_api_key)
        turn = asyncio.run(
            llm.respond(
                model=model,
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
    commands = {"run", "chat", "fix", "approve", "status", "doctor", "report", "runbook", "pack", "target", "history", "memory", "--help", "-h"}
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
    commands = {"run", "chat", "fix", "approve", "status", "doctor", "report", "runbook", "pack", "target", "history", "memory", "--help", "-h"}
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
