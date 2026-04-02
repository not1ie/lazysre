from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(slots=True)
class ToolCall:
    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass(slots=True)
class ToolOutput:
    call_id: str
    output: str


@dataclass(slots=True)
class LLMTurn:
    response_id: str | None = None
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass(slots=True)
class ExecResult:
    ok: bool
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    dry_run: bool = False
    blocked: bool = False


@dataclass(slots=True)
class DispatchEvent:
    kind: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DispatchResult:
    final_text: str
    events: list[DispatchEvent] = field(default_factory=list)

