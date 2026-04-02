from __future__ import annotations

import shlex

from lazysre.cli.executor import SafeExecutor
from lazysre.cli.registry import ToolDefinition
from lazysre.cli.types import ExecResult, ToolSpec


def builtin_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            spec=ToolSpec(
                name="kubectl",
                description="Run read-only or operational kubectl subcommands.",
                parameters={
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "kubectl subcommand body"},
                        "context": {"type": "string"},
                        "namespace": {"type": "string"},
                    },
                    "required": ["command"],
                    "additionalProperties": False,
                },
            ),
            handler=_run_kubectl,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="docker",
                description="Run docker subcommands for container/service diagnostics.",
                parameters={
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "docker subcommand body"}
                    },
                    "required": ["command"],
                    "additionalProperties": False,
                },
            ),
            handler=_run_docker,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="curl",
                description="Call HTTP endpoints for health checks or API diagnostics.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "GET"},
                        "headers": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "header lines like Key: Value",
                        },
                        "data": {"type": "string"},
                        "timeout_sec": {"type": "integer", "default": 10},
                    },
                    "required": ["url"],
                    "additionalProperties": False,
                },
            ),
            handler=_run_curl,
        ),
        ToolDefinition(
            spec=ToolSpec(
                name="logs",
                description="Read local log files with tail for troubleshooting.",
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "lines": {"type": "integer", "default": 100},
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            handler=_run_logs,
        ),
    ]


def tool_pack() -> list[ToolDefinition]:
    return builtin_tools()


async def _run_kubectl(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    command = str(args.get("command", "")).strip()
    if not command:
        return ExecResult(ok=False, command=["kubectl"], stderr="missing command", exit_code=2)
    cmd = ["kubectl"]
    context = str(args.get("context", "")).strip()
    namespace = str(args.get("namespace", "")).strip()
    if context:
        cmd.extend(["--context", context])
    if namespace:
        cmd.extend(["-n", namespace])
    cmd.extend(shlex.split(command))
    return await executor.run(cmd)


async def _run_docker(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    command = str(args.get("command", "")).strip()
    if not command:
        return ExecResult(ok=False, command=["docker"], stderr="missing command", exit_code=2)
    cmd = ["docker", *shlex.split(command)]
    return await executor.run(cmd)


async def _run_curl(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    url = str(args.get("url", "")).strip()
    if not url:
        return ExecResult(ok=False, command=["curl"], stderr="missing url", exit_code=2)
    method = str(args.get("method", "GET")).strip().upper() or "GET"
    timeout_sec = int(args.get("timeout_sec", 10) or 10)
    headers = args.get("headers", [])
    data = str(args.get("data", "")).strip()

    cmd = ["curl", "-sS", "--max-time", str(max(1, min(timeout_sec, 60)))]
    if method != "GET":
        cmd.extend(["-X", method])
    if isinstance(headers, list):
        for header in headers:
            line = str(header).strip()
            if line:
                cmd.extend(["-H", line])
    if data:
        cmd.extend(["--data", data])
    cmd.append(url)
    return await executor.run(cmd)


async def _run_logs(args: dict[str, object], executor: SafeExecutor) -> ExecResult:
    path = str(args.get("path", "")).strip()
    if not path:
        return ExecResult(ok=False, command=["tail"], stderr="missing path", exit_code=2)
    lines = int(args.get("lines", 100) or 100)
    lines = max(1, min(lines, 2000))
    cmd = ["tail", "-n", str(lines), path]
    return await executor.run(cmd)
