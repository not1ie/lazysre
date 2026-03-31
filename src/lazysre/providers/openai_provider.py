from __future__ import annotations

from typing import Any

import httpx

from lazysre.providers.base import LLMProvider


class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def complete(self, system_prompt: str, user_prompt: str, model: str) -> str:
        payload = {
            "model": model,
            "input": [
                {
                    "role": "system",
                    "content": [{"type": "input_text", "text": system_prompt}],
                },
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": user_prompt}],
                },
            ],
            "max_output_tokens": 700,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/responses",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        return _extract_output_text(data)


def _extract_output_text(payload: dict[str, Any]) -> str:
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()

    chunks: list[str] = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            if content.get("type") == "output_text" and content.get("text"):
                chunks.append(content["text"])
    return "\n".join(chunks).strip()

