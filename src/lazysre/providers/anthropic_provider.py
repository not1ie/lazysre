from __future__ import annotations

from typing import Any

import httpx

from lazysre.providers.base import LLMProvider
from lazysre.providers.registry import resolve_model_name


class AnthropicProvider(LLMProvider):
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def complete(self, system_prompt: str, user_prompt: str, model: str) -> str:
        resolved_model = resolve_model_name("anthropic", model)
        payload = {
            "model": resolved_model,
            "system": system_prompt,
            "max_tokens": 700,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        return _extract_anthropic_text(data)


def _extract_anthropic_text(payload: dict[str, Any]) -> str:
    chunks: list[str] = []
    for item in payload.get("content", []):
        if item.get("type") == "text" and item.get("text"):
            chunks.append(str(item["text"]))
    return "\n".join(chunks).strip()
