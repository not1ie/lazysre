from __future__ import annotations

import asyncio
import json
import shlex
import sys
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
from lazysre.cli.memory import IncidentMemoryStore, format_memory_context
from lazysre.cli.target import TargetEnvStore, probe_target_environment
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
history_app = typer.Typer(help="Session history management.")


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    execute: Annotated[bool, typer.Option("--execute", help="Run commands for real. Default is dry-run.")] = False,
    approve: Annotated[bool, typer.Option("--approve", help="Acknowledge policy gate for high-risk commands.")] = False,
    interactive_approval: Annotated[bool, typer.Option("--interactive-approval/--no-interactive-approval", help="Prompt y/n confirmation for risky write actions in execute mode.")] = True,
    stream_output: Annotated[bool, typer.Option("--stream-output/--no-stream-output", help="Stream model tokens in terminal output.")] = True,
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


@app.command("chat")
def chat(
    ctx: typer.Context,
    execute: Annotated[bool | None, typer.Option("--execute", help="Override execution mode.")] = None,
    approve: Annotated[bool | None, typer.Option("--approve", help="Override approval gate acknowledgement.")] = None,
    interactive_approval: Annotated[bool | None, typer.Option("--interactive-approval/--no-interactive-approval", help="Override interactive approval prompt.")] = None,
    stream_output: Annotated[bool | None, typer.Option("--stream-output/--no-stream-output", help="Override token streaming mode.")] = None,
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
    stream_enabled = bool(_console and stream_output)

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
        if Markdown and (not streamed_chunks):
            _console.print(Panel(Markdown(result.final_text), title="LazySRE", border_style="blue"))
        elif (not streamed_chunks):
            _console.print(result.final_text)
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
    stream_enabled = bool(_console and stream_output)

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
        if Markdown and (not streamed_chunks):
            _console.print(Panel(Markdown(result.final_text), title="Fix Plan", border_style="magenta"))
        elif (not streamed_chunks):
            _console.print(result.final_text)
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


def _build_system_prompt(*, conversation_context: str = "", memory_context: str = "") -> str:
    env = TargetEnvStore().load()
    target_summary = (
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
app.add_typer(target_app, name="target")
app.add_typer(history_app, name="history")


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


def _assistant_chat_loop(options: dict[str, object]) -> None:
    typer.echo("LazySRE 自然语言助手已启动。直接输入问题即可，输入 exit/quit 退出。")
    typer.echo("提示：说“修复 xxx”会自动生成修复计划；说“执行修复计划”会执行最近计划。")
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
        if need_confirm and (not typer.confirm(f"[step {idx}/{total}] 是否执行该步骤？", default=False)):
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
        if (not result_exec.ok) and (not typer.confirm("步骤失败，是否继续后续步骤？", default=False)):
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
    path = Path(".data/lsre-fix-last.json")
    if not path.exists():
        typer.echo("未找到最近修复计划（.data/lsre-fix-last.json）。先说“修复 xxx”生成计划。")
        return
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        typer.echo("最近修复计划文件损坏，无法读取。")
        return
    if not isinstance(payload, dict):
        typer.echo("最近修复计划格式无效。")
        return
    plan_obj = payload.get("plan", {})
    if not isinstance(plan_obj, dict):
        typer.echo("最近修复计划缺少 plan 字段。")
        return
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
        store = IncidentMemoryStore()
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
        IncidentMemoryStore().add_case(
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
        typer.echo("已写入长期记忆库：~/.lazysre/history_db")
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
    commands = {"run", "chat", "fix", "pack", "target", "history", "--help", "-h"}
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
    commands = {"run", "chat", "fix", "pack", "target", "history", "--help", "-h"}
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
