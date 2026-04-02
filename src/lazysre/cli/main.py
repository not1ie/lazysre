from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer

from lazysre.cli.audit import AuditLogger
from lazysre.cli.dispatcher import Dispatcher
from lazysre.cli.executor import SafeExecutor
from lazysre.cli.llm import MockFunctionCallingLLM, OpenAIResponsesLLM
from lazysre.cli.tools import build_default_registry
from lazysre.config import settings

app = typer.Typer(
    name="lsre",
    help="LazySRE AI-native CLI for operations workflows.",
    add_completion=False,
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    instruction: Annotated[str | None, typer.Argument(help='Natural-language instruction, e.g. lsre "check k8s pods"')] = None,
    execute: Annotated[bool, typer.Option("--execute", help="Run commands for real. Default is dry-run.")] = False,
    approve: Annotated[bool, typer.Option("--approve", help="Acknowledge policy gate for high-risk commands.")] = False,
    approval_mode: Annotated[str, typer.Option(help="Policy level: strict|balanced|permissive")] = "balanced",
    audit_log: Annotated[str, typer.Option(help="Audit jsonl path for command execution records.")] = ".data/lsre-audit.jsonl",
    model: Annotated[str, typer.Option(help="Model name for LLM dispatcher.")] = settings.model_name,
    provider: Annotated[str, typer.Option(help="LLM provider: auto|mock|openai")] = "auto",
    max_steps: Annotated[int, typer.Option(help="Max function-calling iterations.")] = 6,
) -> None:
    ctx.obj = {
        "execute": execute,
        "approve": approve,
        "approval_mode": approval_mode,
        "audit_log": audit_log,
        "model": model,
        "provider": provider,
        "max_steps": max(1, min(max_steps, 12)),
    }
    if ctx.invoked_subcommand is None and instruction:
        _run_once(
            instruction=instruction,
            execute=execute,
            approve=approve,
            approval_mode=approval_mode,
            audit_log=audit_log,
            model=model,
            provider=provider,
            max_steps=max_steps,
        )


@app.command("chat")
def chat(
    ctx: typer.Context,
    execute: Annotated[bool | None, typer.Option("--execute", help="Override execution mode.")] = None,
    approve: Annotated[bool | None, typer.Option("--approve", help="Override approval gate acknowledgement.")] = None,
    approval_mode: Annotated[str | None, typer.Option(help="Override policy: strict|balanced|permissive")] = None,
    audit_log: Annotated[str | None, typer.Option(help="Override audit jsonl path.")] = None,
    model: Annotated[str | None, typer.Option(help="Override model.")] = None,
    provider: Annotated[str | None, typer.Option(help="Override provider: auto|mock|openai")] = None,
    max_steps: Annotated[int | None, typer.Option(help="Override max function-calling iterations.")] = None,
) -> None:
    options = _merged_options(
        ctx,
        execute=execute,
        approve=approve,
        approval_mode=approval_mode,
        audit_log=audit_log,
        model=model,
        provider=provider,
        max_steps=max_steps,
    )
    typer.echo("LazySRE chat started. Type 'exit' or 'quit' to leave.")
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
        _run_once(
            instruction=text,
            execute=bool(options["execute"]),
            approve=bool(options["approve"]),
            approval_mode=str(options["approval_mode"]),
            audit_log=str(options["audit_log"]),
            model=str(options["model"]),
            provider=str(options["provider"]),
            max_steps=int(options["max_steps"]),
        )


def _merged_options(
    ctx: typer.Context,
    *,
    execute: bool | None,
    approve: bool | None,
    approval_mode: str | None,
    audit_log: str | None,
    model: str | None,
    provider: str | None,
    max_steps: int | None,
) -> dict[str, object]:
    base = dict(ctx.obj or {})
    if execute is not None:
        base["execute"] = execute
    if approve is not None:
        base["approve"] = approve
    if approval_mode is not None:
        base["approval_mode"] = approval_mode
    if audit_log is not None:
        base["audit_log"] = audit_log
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
    if "approval_mode" not in base:
        base["approval_mode"] = "balanced"
    if "audit_log" not in base:
        base["audit_log"] = ".data/lsre-audit.jsonl"
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
    approval_mode: str,
    audit_log: str,
    model: str,
    provider: str,
    max_steps: int,
) -> None:
    result = asyncio.run(
        _dispatch(
            instruction=instruction,
            execute=execute,
            approve=approve,
            approval_mode=approval_mode,
            audit_log=audit_log,
            model=model,
            provider=provider,
            max_steps=max_steps,
        )
    )
    for event in result.events:
        if event.kind in {"tool_call", "tool_output"}:
            detail = json.dumps(event.data, ensure_ascii=False)
            typer.echo(f"[{event.kind}] {event.message} {detail}")
    typer.echo(result.final_text)


async def _dispatch(
    *,
    instruction: str,
    execute: bool,
    approve: bool,
    approval_mode: str,
    audit_log: str,
    model: str,
    provider: str,
    max_steps: int,
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
        registry=build_default_registry(),
        executor=SafeExecutor(
            dry_run=(not execute),
            approval_mode=ap_mode,
            approval_granted=approve,
            audit_logger=AuditLogger(Path(audit_log)),
        ),
        model=model,
        max_steps=max(1, min(max_steps, 12)),
    )
    return await dispatcher.run(instruction)


if __name__ == "__main__":
    app()
