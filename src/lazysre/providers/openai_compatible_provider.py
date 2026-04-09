from __future__ import annotations

from typing import Any

import httpx

from lazysre.providers.base import LLMProvider
from lazysre.providers.registry import resolve_model_name


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, *, api_key: str, provider: str, base_url: str) -> None:
        self._api_key = api_key
        self._provider = provider
        self._base_url = base_url.rstrip("/")

    async def complete(self, system_prompt: str, user_prompt: str, model: str) -> str:
        resolved_model = resolve_model_name(self._provider, model)
        payload = {
            "model": resolved_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        return _extract_compatible_text(data)


def _extract_compatible_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices", [])
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message", {})
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
