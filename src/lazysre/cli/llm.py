from __future__ import annotations

import json
import re
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
            try:
                return await _stream_openai_turn(
                    payload=payload,
                    headers=headers,
                    text_stream=text_stream,
                )
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(_build_http_status_error(provider="OpenAI", exc=exc)) from exc
            except httpx.HTTPError as exc:
                raise RuntimeError(_build_provider_network_error(provider="OpenAI", exc=exc)) from exc

        async with httpx.AsyncClient(timeout=45.0) as client:
            try:
                resp = await client.post(
                    "https://api.openai.com/v1/responses",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(_build_http_status_error(provider="OpenAI", exc=exc)) from exc
            except httpx.HTTPError as exc:
                raise RuntimeError(_build_provider_network_error(provider="OpenAI", exc=exc)) from exc
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
            try:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(_build_http_status_error(provider="Anthropic", exc=exc)) from exc
            except httpx.HTTPError as exc:
                raise RuntimeError(_build_provider_network_error(provider="Anthropic", exc=exc)) from exc
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
            try:
                resp = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{resolved_model}:generateContent",
                    params={"key": self._api_key},
                    json=payload,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(_build_gemini_http_error(exc)) from exc
            except httpx.HTTPError as exc:
                raise RuntimeError(_build_provider_network_error(provider="Gemini", exc=exc)) from exc
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


class OpenAICompatibleFunctionCallingLLM(FunctionCallingLLM):
    def __init__(self, *, api_key: str, provider: str, base_url: str) -> None:
        self._api_key = api_key
        self._provider = provider
        self._base_url = base_url.rstrip("/")
        self._messages: list[dict[str, Any]] = []
        self._pending_tool_calls: dict[str, str] = {}

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
        resolved_model = resolve_model_name(self._provider, model)
        messages = list(self._messages)
        if previous_response_id:
            for item in (tool_outputs or []):
                tool_name = self._pending_tool_calls.get(item.call_id, "")
                if not tool_name:
                    continue
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": item.call_id,
                        "name": tool_name,
                        "content": item.output,
                    }
                )
        else:
            messages.extend(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_input or ""},
                ]
            )

        payload: dict[str, Any] = {
            "model": resolved_model,
            "messages": messages,
            "temperature": 0.2,
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": item.name,
                        "description": item.description,
                        "parameters": item.parameters,
                    },
                }
                for item in tools
            ]
            payload["tool_choice"] = "auto"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=45.0) as client:
            try:
                resp = await client.post(
                    f"{self._base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(_build_http_status_error(provider=self._provider, exc=exc)) from exc
            except httpx.HTTPError as exc:
                raise RuntimeError(_build_provider_network_error(provider=self._provider, exc=exc)) from exc
            data = resp.json()

        turn = _parse_openai_compatible_turn(data, provider=self._provider)
        assistant_message = _extract_openai_compatible_assistant_message(data)
        if assistant_message:
            messages.append(assistant_message)
        self._messages = messages
        self._pending_tool_calls = {item.call_id: item.name for item in turn.tool_calls}
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

        if previous_response_id == "mock-swarm-1" and tool_outputs:
            service_hint = "lazysre_lazysre"
            rendered = "\n".join(
                [
                    f"[mock:{model}] Swarm 诊断完成：",
                    "",
                    "## Status",
                    "Diagnosing",
                    "",
                    "## Reasoning",
                    "已优先采集 Docker Swarm service/node/task 证据，下一步应聚焦副本不足、任务拒绝或镜像拉取失败。",
                    "",
                    "## Evidence",
                    *[f"- call={item.call_id}: {item.output[:160]}" for item in tool_outputs],
                    "",
                    "## Apply Commands",
                    "```bash",
                    f"docker service ps {service_hint} --no-trunc",
                    f"docker service logs --tail 200 {service_hint}",
                    f"docker service update --force {service_hint}",
                    "```",
                    "",
                    "## Rollback Commands",
                    "```bash",
                    f"docker service rollback {service_hint}",
                    "```",
                    "",
                    "## Risk Level",
                    "High - service update 会滚动替换任务，可能造成短暂抖动，必须审批后执行。",
                ]
            )
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
        if any(word in text for word in ("swarm", "docker service", "副本不足", "服务副本", "服务有没有异常", "服务健康")):
            return LLMTurn(
                response_id="mock-swarm-1",
                tool_calls=[
                    ToolCall(
                        call_id="mock-swarm-context-1",
                        name="get_swarm_context",
                        arguments={"include_logs": False, "tail": 80},
                    )
                ],
            )
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


def _parse_openai_compatible_turn(payload: dict[str, Any], *, provider: str) -> LLMTurn:
    choices = payload.get("choices", [])
    if not isinstance(choices, list) or not choices:
        return LLMTurn(response_id=_new_response_id(f"{provider}-turn"), text="", tool_calls=[])

    message = choices[0].get("message", {})
    text = _extract_compatible_message_text(message)
    calls: list[ToolCall] = []
    for item in message.get("tool_calls", []):
        if not isinstance(item, dict):
            continue
        function = item.get("function", {})
        name = str(function.get("name", "")).strip()
        call_id = str(item.get("id", "")).strip() or _new_response_id(f"{provider}-{name or 'tool'}")
        args = _safe_json_loads(function.get("arguments", "{}"))
        if not isinstance(args, dict):
            args = {}
        if name:
            calls.append(ToolCall(call_id=call_id, name=name, arguments=args))
    return LLMTurn(
        response_id=str(payload.get("id", "")) or _new_response_id(f"{provider}-turn"),
        text=text,
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


def _extract_openai_compatible_assistant_message(payload: dict[str, Any]) -> dict[str, Any] | None:
    choices = payload.get("choices", [])
    if not isinstance(choices, list) or not choices:
        return None
    message = choices[0].get("message", {})
    if not isinstance(message, dict):
        return None
    assistant: dict[str, Any] = {"role": "assistant"}
    if "content" in message:
        assistant["content"] = message.get("content")
    if isinstance(message.get("tool_calls"), list):
        assistant["tool_calls"] = message["tool_calls"]
    return assistant


def _extract_compatible_message_text(message: dict[str, Any]) -> str:
    content = message.get("content", "")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        chunks: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("text"):
                chunks.append(str(item["text"]))
        return "\n".join(chunks).strip()
    return ""


def _normalize_gemini_tool_response(output: str) -> dict[str, Any]:
    parsed = _safe_json_loads(output)
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        return {"items": parsed}
    return {"result": output}


def _build_gemini_http_error(exc: httpx.HTTPStatusError) -> str:
    response = exc.response
    status = response.status_code if response is not None else "unknown"
    detail = _extract_gemini_error_detail(response)
    detail_lower = str(detail).lower()
    hints: list[str] = []
    if status == 400:
        if "api key not valid" in detail_lower or "invalid api key" in detail_lower:
            hints.append("API Key 无效或不属于当前项目，请在 AI Studio 重新生成并替换。")
        elif "permission denied" in detail_lower or "not enabled" in detail_lower:
            hints.append("当前项目可能未启用 Gemini API，请先在 GCP/AI Studio 打开 Gemini API。")
        else:
            hints.append("检查 API Key、Gemini API 开关、模型名与请求格式。")
        hints.append("可先切到 mock 保持流程可用：/provider mock")
    elif status in {401, 403}:
        hints.append("检查 API Key 权限、项目配额/计费、IP 限制和区域策略。")
        hints.append("若启用了代理，请确认代理允许访问 generativelanguage.googleapis.com。")
    elif status == 429:
        hints.append("请求过于频繁或配额不足，稍后重试。")
    elif status in {500, 502, 503, 504}:
        hints.append("Gemini 服务暂时不可用，建议稍后重试或临时切换到 mock。")
    hint_text = f" hint: {' '.join(hints)}" if hints else ""
    return f"Gemini API HTTP {status}: {detail}{hint_text}"


def _build_http_status_error(*, provider: str, exc: httpx.HTTPStatusError) -> str:
    response = exc.response
    status = response.status_code if response is not None else "unknown"
    detail = _extract_http_error_detail(response)
    provider_label = str(provider or "provider").strip()
    hints: list[str] = []
    if status in {400, 422}:
        hints.append("检查模型名、请求参数与 provider 配置是否匹配。")
    elif status in {401, 403}:
        hints.append("检查 API Key 权限、配额/计费与访问策略。")
    elif status == 404:
        hints.append("检查 base_url、路由路径与模型是否存在。")
    elif status == 429:
        hints.append("请求过于频繁或额度不足，请稍后重试。")
    elif status in {500, 502, 503, 504}:
        hints.append("上游服务暂不可用，请稍后重试或切换 provider。")
    hint_text = f" hint: {' '.join(hints)}" if hints else ""
    return f"{provider_label} API HTTP {status}: {detail}{hint_text}"


def _extract_http_error_detail(response: httpx.Response | None) -> str:
    if response is None:
        return "unknown error"
    try:
        payload = response.json()
    except Exception:
        return _sanitize_secret_text(response.text.strip() or "unknown error")[:300]
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            for key in ("message", "detail", "error"):
                text = str(error.get(key, "")).strip()
                if text:
                    return _sanitize_secret_text(text)[:300]
        for key in ("message", "detail", "error"):
            text = str(payload.get(key, "")).strip()
            if text:
                return _sanitize_secret_text(text)[:300]
    return _sanitize_secret_text(response.text.strip() or "unknown error")[:300]


def _build_provider_network_error(*, provider: str, exc: Exception) -> str:
    detail = _sanitize_secret_text(str(exc).strip() or exc.__class__.__name__)
    provider_label = str(provider or "provider").strip()
    detail_lower = detail.lower()
    hints: list[str] = []
    if "socksio" in detail_lower and "proxy" in detail_lower:
        hints.append("检测到 SOCKS 代理但缺少依赖，执行 `python3 -m pip install \"httpx[socks]\"`。")
    elif any(token in detail_lower for token in ("name or service not known", "dns", "temporary failure", "timed out", "timeout")):
        hints.append("检查网络连通性、DNS 与代理配置。")
    hint_text = f" hint: {' '.join(hints)}" if hints else ""
    return f"{provider_label} network error: {detail}{hint_text}"


def _extract_gemini_error_detail(response: httpx.Response | None) -> str:
    if response is None:
        return "unknown error"
    try:
        payload = response.json()
    except Exception:
        raw = response.text.strip() or "unknown error"
        return _sanitize_secret_text(raw)[:300]
    if isinstance(payload, dict):
        error = payload.get("error", {})
        if isinstance(error, dict):
            message = str(error.get("message", "")).strip()
            if message:
                return _sanitize_secret_text(message)
        message = str(payload.get("message", "")).strip()
        if message:
            return _sanitize_secret_text(message)
    return _sanitize_secret_text(response.text.strip() or "unknown error")[:300]


def _sanitize_secret_text(text: str) -> str:
    value = str(text or "")
    value = re.sub(r"AIza[0-9A-Za-z_-]{10,}", "AIza***REDACTED***", value)
    value = re.sub(r"([?&]key=)[^&\s]+", r"\1***REDACTED***", value, flags=re.IGNORECASE)
    value = re.sub(r"(\bkey=)[^\s,;]+", r"\1***REDACTED***", value, flags=re.IGNORECASE)
    value = re.sub(r"([?&]token=)[^&\s]+", r"\1***REDACTED***", value, flags=re.IGNORECASE)
    value = re.sub(r"(\btoken=)[^\s,;]+", r"\1***REDACTED***", value, flags=re.IGNORECASE)
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._-]{10,}", "Bearer ***REDACTED***", value)
    value = re.sub(r"(?i)\b(x-api-key|api-key|apikey)\b\s*[:=]\s*([^\s,;]+)", r"\1=***REDACTED***", value)
    value = re.sub(r"(://)([^/@:\s]+):([^/@\s]+)@", r"\1***:***@", value)
    return value


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
