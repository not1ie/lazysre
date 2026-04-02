from __future__ import annotations

import asyncio
import json
from typing import Annotated

import typer

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
    model: Annotated[str, typer.Option(help="Model name for LLM dispatcher.")] = settings.model_name,
    provider: Annotated[str, typer.Option(help="LLM provider: auto|mock|openai")] = "auto",
    max_steps: Annotated[int, typer.Option(help="Max function-calling iterations.")] = 6,
) -> None:
    ctx.obj = {
        "execute": execute,
        "model": model,
        "provider": provider,
        "max_steps": max(1, min(max_steps, 12)),
    }
    if ctx.invoked_subcommand is None and instruction:
        _run_once(
            instruction=instruction,
            execute=execute,
            model=model,
            provider=provider,
            max_steps=max_steps,
        )


@app.command("chat")
def chat(
    ctx: typer.Context,
    execute: Annotated[bool | None, typer.Option("--execute", help="Override execution mode.")] = None,
    model: Annotated[str | None, typer.Option(help="Override model.")] = None,
    provider: Annotated[str | None, typer.Option(help="Override provider: auto|mock|openai")] = None,
    max_steps: Annotated[int | None, typer.Option(help="Override max function-calling iterations.")] = None,
) -> None:
    options = _merged_options(ctx, execute=execute, model=model, provider=provider, max_steps=max_steps)
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
            model=str(options["model"]),
            provider=str(options["provider"]),
            max_steps=int(options["max_steps"]),
        )


def _merged_options(
    ctx: typer.Context,
    *,
    execute: bool | None,
    model: str | None,
    provider: str | None,
    max_steps: int | None,
) -> dict[str, object]:
    base = dict(ctx.obj or {})
    if execute is not None:
        base["execute"] = execute
    if model is not None:
        base["model"] = model
    if provider is not None:
        base["provider"] = provider
    if max_steps is not None:
        base["max_steps"] = max_steps
    if "execute" not in base:
        base["execute"] = False
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
    model: str,
    provider: str,
    max_steps: int,
) -> None:
    result = asyncio.run(
        _dispatch(
            instruction=instruction,
            execute=execute,
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
    model: str,
    provider: str,
    max_steps: int,
):
    mode = (provider or "auto").strip().lower()
    if mode not in {"auto", "mock", "openai"}:
        raise typer.BadParameter("provider must be one of auto/mock/openai")
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
        executor=SafeExecutor(dry_run=(not execute)),
        model=model,
        max_steps=max(1, min(max_steps, 12)),
    )
    return await dispatcher.run(instruction)


if __name__ == "__main__":
    app()

