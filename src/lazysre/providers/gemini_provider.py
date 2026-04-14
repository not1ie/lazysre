from __future__ import annotations

import re
from typing import Any

import httpx

from lazysre.providers.base import LLMProvider
from lazysre.providers.registry import resolve_model_name


class GeminiProvider(LLMProvider):
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def complete(self, system_prompt: str, user_prompt: str, model: str) -> str:
        resolved_model = resolve_model_name("gemini", model)
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
        }
        headers = {
            "x-goog-api-key": self._api_key,
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{resolved_model}:generateContent",
                json=payload,
                headers=headers,
            )
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(_build_gemini_http_error(exc)) from exc
            data = resp.json()
        return _extract_gemini_text(data)


def _extract_gemini_text(payload: dict[str, Any]) -> str:
    chunks: list[str] = []
    for candidate in payload.get("candidates", []):
        content = candidate.get("content", {})
        for part in content.get("parts", []):
            if part.get("text"):
                chunks.append(str(part["text"]))
    return "\n".join(chunks).strip()


def _build_gemini_http_error(exc: httpx.HTTPStatusError) -> str:
    response = exc.response
    status = response.status_code if response is not None else "unknown"
    detail = _extract_gemini_error_detail(response)
    hints: list[str] = []
    if status == 400:
        hints.append("检查 API Key 是否有效、项目是否已启用 Gemini API、模型名是否可用。")
    elif status in {401, 403}:
        hints.append("检查 API Key 权限、项目配额/计费与地域策略。")
    elif status == 429:
        hints.append("请求过于频繁或配额不足，稍后重试并检查配额。")
    hint_text = f" hint: {' '.join(hints)}" if hints else ""
    return f"Gemini API HTTP {status}: {detail}{hint_text}"


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
    return value
