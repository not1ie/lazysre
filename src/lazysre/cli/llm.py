from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any
from uuid import uuid4

import httpx

from lazysre.cli.types import LLMTurn, ToolCall, ToolOutput, ToolSpec
from lazysre.providers.registry import resolve_model_name


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
        text_stream: Callable[[str], None] | None = None,
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
        text_stream: Callable[[str], None] | None = None,
    ) -> LLMTurn:
        resolved_model = resolve_model_name("openai", model)
        payload: dict[str, Any] = {"model": resolved_model}
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
        if text_stream:
            payload["stream"] = True
            return await _stream_openai_turn(
                payload=payload,
                headers=headers,
                text_stream=text_stream,
            )

        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/responses",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        return _parse_openai_turn(data)


class AnthropicMessagesLLM(FunctionCallingLLM):
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._messages: list[dict[str, Any]] = []

    async def respond(
        self,
        *,
        model: str,
        tools: list[ToolSpec],
        system_prompt: str,
        user_input: str | None = None,
        previous_response_id: str | None = None,
        tool_outputs: list[ToolOutput] | None = None,
        text_stream: Callable[[str], None] | None = None,
    ) -> LLMTurn:
        messages = list(self._messages)
        resolved_model = resolve_model_name("anthropic", model)
        if previous_response_id:
            tool_blocks = [
                {
                    "type": "tool_result",
                    "tool_use_id": item.call_id,
                    "content": item.output,
                }
                for item in (tool_outputs or [])
            ]
            if tool_blocks:
                messages.append({"role": "user", "content": tool_blocks})
        else:
            messages.append({"role": "user", "content": user_input or ""})

        payload: dict[str, Any] = {
            "model": resolved_model,
            "system": system_prompt,
            "max_tokens": 800,
            "messages": messages,
        }
        if tools:
            payload["tools"] = [
                {
                    "name": item.name,
                    "description": item.description,
                    "input_schema": item.parameters,
                }
                for item in tools
            ]

        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

        self._messages = messages + [{"role": "assistant", "content": data.get("content", [])}]
        turn = _parse_anthropic_turn(data)
        if text_stream and turn.text:
            _emit_stream_from_text(turn.text, text_stream)
        return turn


class GeminiFunctionCallingLLM(FunctionCallingLLM):
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._contents: list[dict[str, Any]] = []
        self._pending_tool_names: dict[str, str] = {}

    async def respond(
        self,
        *,
        model: str,
        tools: list[ToolSpec],
        system_prompt: str,
        user_input: str | None = None,
        previous_response_id: str | None = None,
        tool_outputs: list[ToolOutput] | None = None,
        text_stream: Callable[[str], None] | None = None,
    ) -> LLMTurn:
        contents = list(self._contents)
        resolved_model = resolve_model_name("gemini", model)
        if previous_response_id:
            tool_response_parts = []
            for item in (tool_outputs or []):
                tool_name = self._pending_tool_names.get(item.call_id, "")
                if not tool_name:
                    continue
                tool_response_parts.append(
                    {
                        "functionResponse": {
                            "name": tool_name,
                            "response": _normalize_gemini_tool_response(item.output),
                        }
                    }
                )
            if tool_response_parts:
                contents.append({"role": "user", "parts": tool_response_parts})
        else:
            contents.append({"role": "user", "parts": [{"text": user_input or ""}]})

        payload: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": contents,
        }
        if tools:
            payload["tools"] = [
                {
                    "functionDeclarations": [
                        {
                            "name": item.name,
                            "description": item.description,
                            "parameters": item.parameters,
                        }
                        for item in tools
                    ]
                }
            ]
            payload["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}

        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{resolved_model}:generateContent",
                params={"key": self._api_key},
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        candidate_content = _extract_gemini_candidate_content(data)
        if candidate_content:
            contents.append(candidate_content)
        self._contents = contents
        turn = _parse_gemini_turn(data)
        self._pending_tool_names = {item.call_id: item.name for item in turn.tool_calls}
        if text_stream and turn.text:
            _emit_stream_from_text(turn.text, text_stream)
        return turn


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
        text_stream: Callable[[str], None] | None = None,
    ) -> LLMTurn:
        if previous_response_id == "mock-react-1":
            return LLMTurn(
                response_id="mock-react-2",
                tool_calls=[
                    ToolCall(
                        call_id="mock-logs-react-1",
                        name="fetch_service_logs",
                        arguments={
                            "namespace": "default",
                            "service": "payment",
                            "keyword": "error",
                            "since_minutes": 30,
                            "limit": 200,
                        },
                    )
                ],
            )

        if previous_response_id == "mock-react-2" and tool_outputs:
            lines = [f"[mock:{model}] 初步诊断完成：", "", "## Root Cause", "payment 服务实例可能出现抖动或资源争抢。", "", "## Fix Plan", "1. 重启 payment 部署滚动恢复。", "2. 持续观察 pods 与错误日志。", "", "## Apply Commands", "```bash"]
            for item in tool_outputs:
                lines.append(f"# call={item.call_id}: {item.output[:120]}")
            lines.append("kubectl -n default rollout restart deploy/payment")
            lines.append("kubectl -n default get pods -l app=payment -w")
            lines.append("```")
            lines.append("")
            lines.append("## Rollback Commands")
            lines.append("```bash")
            lines.append("kubectl -n default rollout undo deploy/payment")
            lines.append("```")
            rendered = "\n".join(lines)
            if text_stream:
                for token in _chunk_text(rendered):
                    text_stream(token)
            return LLMTurn(response_id="mock-final", text=rendered, tool_calls=[])

        if previous_response_id and tool_outputs:
            lines = [
                f"[mock:{model}] 工具执行结果汇总：",
                "",
                "## Root Cause",
                "需结合工具结果进一步确认。",
                "",
                "## Fix Plan",
                "1. 先按建议命令进行安全修复。",
                "",
                "## Apply Commands",
                "```bash",
            ]
            for item in tool_outputs:
                lines.append(f"# call={item.call_id}: {item.output[:120]}")
            lines.append("kubectl get pods -A")
            lines.append("```")
            lines.append("")
            lines.append("## Rollback Commands")
            lines.append("```bash")
            lines.append("# no-op")
            lines.append("```")
            lines.append("")
            lines.append("建议：先 dry-run 验证，再执行线上动作。")
            rendered = "\n".join(lines)
            if text_stream:
                for token in _chunk_text(rendered):
                    text_stream(token)
            return LLMTurn(response_id="mock-final", text=rendered, tool_calls=[])

        text = (user_input or "").lower()
        if any(word in text for word in ("变慢", "慢了", "latency", "延迟", "响应慢", "支付服务")):
            return LLMTurn(
                response_id="mock-react-1",
                tool_calls=[
                    ToolCall(
                        call_id="mock-metrics-1",
                        name="get_metrics",
                        arguments={
                            "query": 'histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{service="payment"}[5m])) by (le))',
                            "window_minutes": 15,
                            "step_sec": 30,
                            "timeout_sec": 8,
                        },
                    ),
                    ToolCall(
                        call_id="mock-cluster-1",
                        name="get_cluster_context",
                        arguments={"namespace": "default", "event_limit": 30},
                    ),
                ],
            )
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
        if any(word in text for word in ("重启", "restart", "reboot")):
            return LLMTurn(
                response_id="mock-1",
                tool_calls=[
                    ToolCall(
                        call_id="mock-docker-risk-1",
                        name="docker",
                        arguments={"command": "restart lazysre_lazysre.1.kdjvjz4qyxrhpsojsr3o7ye9q"},
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
        fallback = (
            f"[mock:{model}] 已收到指令。可尝试包含关键字 kubectl/docker/curl/log，"
            "我会自动触发对应工具。"
        )
        if text_stream:
            for token in _chunk_text(fallback):
                text_stream(token)
        return LLMTurn(
            response_id="mock-0",
            text=fallback,
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


def _parse_anthropic_turn(payload: dict[str, Any]) -> LLMTurn:
    text_parts: list[str] = []
    calls: list[ToolCall] = []
    for item in payload.get("content", []):
        item_type = str(item.get("type", "")).strip()
        if item_type == "text" and item.get("text"):
            text_parts.append(str(item["text"]))
            continue
        if item_type != "tool_use":
            continue
        call_id = str(item.get("id", "")).strip()
        name = str(item.get("name", "")).strip()
        args = item.get("input", {})
        if not isinstance(args, dict):
            args = {}
        if call_id and name:
            calls.append(ToolCall(call_id=call_id, name=name, arguments=args))
    return LLMTurn(
        response_id=str(payload.get("id", "")) or _new_response_id("anthropic"),
        text="\n".join(text_parts).strip(),
        tool_calls=calls,
    )


def _parse_gemini_turn(payload: dict[str, Any]) -> LLMTurn:
    text_parts: list[str] = []
    calls: list[ToolCall] = []
    for candidate in payload.get("candidates", []):
        content = candidate.get("content", {})
        for part in content.get("parts", []):
            if part.get("text"):
                text_parts.append(str(part["text"]))
            function_call = part.get("functionCall")
            if not isinstance(function_call, dict):
                continue
            name = str(function_call.get("name", "")).strip()
            call_id = str(function_call.get("id", "")).strip() or _new_response_id(f"gemini-{name or 'tool'}")
            args = function_call.get("args", {})
            if not isinstance(args, dict):
                args = {}
            if name:
                calls.append(ToolCall(call_id=call_id, name=name, arguments=args))
        if text_parts or calls:
            break
    return LLMTurn(
        response_id=_new_response_id("gemini-turn"),
        text="\n".join(text_parts).strip(),
        tool_calls=calls,
    )


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


def _extract_gemini_candidate_content(payload: dict[str, Any]) -> dict[str, Any] | None:
    for candidate in payload.get("candidates", []):
        content = candidate.get("content")
        if isinstance(content, dict):
            role = str(content.get("role", "")).strip() or "model"
            parts = content.get("parts", [])
            if isinstance(parts, list) and parts:
                return {"role": role, "parts": parts}
    return None


def _normalize_gemini_tool_response(output: str) -> dict[str, Any]:
    parsed = _safe_json_loads(output)
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        return {"items": parsed}
    return {"result": output}


def _new_response_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}"


def _emit_stream_from_text(text: str, text_stream: Callable[[str], None]) -> None:
    for token in _chunk_text(text):
        text_stream(token)


async def _stream_openai_turn(
    *,
    payload: dict[str, Any],
    headers: dict[str, str],
    text_stream: Callable[[str], None],
) -> LLMTurn:
    final_response: dict[str, Any] | None = None
    buffered_chunks: list[str] = []
    async with httpx.AsyncClient(timeout=60.0) as client:
        async with client.stream(
            "POST",
            "https://api.openai.com/v1/responses",
            json=payload,
            headers=headers,
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line:
                    continue
                if not line.startswith("data: "):
                    continue
                data = line[6:]
                if data == "[DONE]":
                    break
                try:
                    event = json.loads(data)
                except Exception:
                    continue
                event_type = str(event.get("type", ""))
                if event_type == "response.output_text.delta":
                    delta = str(event.get("delta", ""))
                    if delta:
                        buffered_chunks.append(delta)
                        text_stream(delta)
                elif event_type == "response.completed":
                    maybe_response = event.get("response")
                    if isinstance(maybe_response, dict):
                        final_response = maybe_response
    if final_response is not None:
        return _parse_openai_turn(final_response)
    return LLMTurn(response_id="stream-fallback", text="".join(buffered_chunks), tool_calls=[])


def _chunk_text(text: str, size: int = 18) -> list[str]:
    if not text:
        return []
    return [text[idx : idx + size] for idx in range(0, len(text), size)]
