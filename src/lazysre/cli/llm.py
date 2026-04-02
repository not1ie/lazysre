from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import httpx

from lazysre.cli.types import LLMTurn, ToolCall, ToolOutput, ToolSpec


class FunctionCallingLLM(ABC):
    @abstractmethod
    async def respond(
        self,
        *,
        model: str,
        tools: list[ToolSpec],
        system_prompt: str,
        user_input: str | None = None,
        previous_response_id: str | None = None,
        tool_outputs: list[ToolOutput] | None = None,
    ) -> LLMTurn:
        raise NotImplementedError


class OpenAIResponsesLLM(FunctionCallingLLM):
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def respond(
        self,
        *,
        model: str,
        tools: list[ToolSpec],
        system_prompt: str,
        user_input: str | None = None,
        previous_response_id: str | None = None,
        tool_outputs: list[ToolOutput] | None = None,
    ) -> LLMTurn:
        payload: dict[str, Any] = {"model": model}
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        if previous_response_id:
            payload["previous_response_id"] = previous_response_id
            payload["input"] = [
                {
                    "type": "function_call_output",
                    "call_id": x.call_id,
                    "output": x.output,
                }
                for x in (tool_outputs or [])
            ]
        else:
            payload["input"] = [
                {
                    "role": "system",
                    "content": [{"type": "input_text", "text": system_prompt}],
                },
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": user_input or ""}],
                },
            ]
            payload["tools"] = [
                {
                    "type": "function",
                    "name": x.name,
                    "description": x.description,
                    "parameters": x.parameters,
                }
                for x in tools
            ]
            payload["tool_choice"] = "auto"
        payload["max_output_tokens"] = 800

        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/responses",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        return _parse_openai_turn(data)


class MockFunctionCallingLLM(FunctionCallingLLM):
    async def respond(
        self,
        *,
        model: str,
        tools: list[ToolSpec],
        system_prompt: str,
        user_input: str | None = None,
        previous_response_id: str | None = None,
        tool_outputs: list[ToolOutput] | None = None,
    ) -> LLMTurn:
        if previous_response_id and tool_outputs:
            lines = [f"[mock:{model}] 工具执行结果汇总："]
            for item in tool_outputs:
                lines.append(f"- call={item.call_id}: {item.output[:220]}")
            lines.append("建议：先 dry-run 验证，再执行线上动作。")
            return LLMTurn(response_id="mock-final", text="\n".join(lines), tool_calls=[])

        text = (user_input or "").lower()
        if any(word in text for word in ("pod", "k8s", "kubectl", "节点", "集群")):
            return LLMTurn(
                response_id="mock-1",
                tool_calls=[
                    ToolCall(
                        call_id="mock-kubectl-1",
                        name="kubectl",
                        arguments={"command": "get pods -A"},
                    )
                ],
            )
        if any(word in text for word in ("docker", "容器", "service")):
            return LLMTurn(
                response_id="mock-1",
                tool_calls=[
                    ToolCall(
                        call_id="mock-docker-1",
                        name="docker",
                        arguments={"command": "ps -a --format '{{.ID}} {{.Status}} {{.Names}}'"},
                    )
                ],
            )
        if any(word in text for word in ("http", "curl", "接口", "探活", "health")):
            return LLMTurn(
                response_id="mock-1",
                tool_calls=[
                    ToolCall(
                        call_id="mock-curl-1",
                        name="curl",
                        arguments={"url": "http://127.0.0.1:32080/health", "method": "GET"},
                    )
                ],
            )
        if any(word in text for word in ("日志", "log", "报错")):
            return LLMTurn(
                response_id="mock-1",
                tool_calls=[
                    ToolCall(
                        call_id="mock-logs-1",
                        name="logs",
                        arguments={"path": "/var/log/system.log", "lines": 80},
                    )
                ],
            )
        return LLMTurn(
            response_id="mock-0",
            text=(
                f"[mock:{model}] 已收到指令。可尝试包含关键字 kubectl/docker/curl/log，"
                "我会自动触发对应工具。"
            ),
            tool_calls=[],
        )


def _parse_openai_turn(payload: dict[str, Any]) -> LLMTurn:
    response_id = payload.get("id")
    text = _extract_output_text(payload)
    calls: list[ToolCall] = []
    for item in payload.get("output", []):
        if item.get("type") != "function_call":
            continue
        name = str(item.get("name", "")).strip()
        call_id = str(item.get("call_id", "")).strip() or str(item.get("id", "")).strip()
        if not name or not call_id:
            continue
        args_raw = item.get("arguments", "{}")
        args = _safe_json_loads(args_raw)
        if not isinstance(args, dict):
            args = {}
        calls.append(ToolCall(call_id=call_id, name=name, arguments=args))

    return LLMTurn(response_id=response_id, text=text, tool_calls=calls)


def _extract_output_text(payload: dict[str, Any]) -> str:
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()

    chunks: list[str] = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            if content.get("type") == "output_text" and content.get("text"):
                chunks.append(str(content["text"]))
    return "\n".join(chunks).strip()


def _safe_json_loads(raw: Any) -> Any:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}

