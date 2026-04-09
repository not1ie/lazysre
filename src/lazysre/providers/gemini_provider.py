from __future__ import annotations

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
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{resolved_model}:generateContent",
                params={"key": self._api_key},
                json=payload,
            )
            resp.raise_for_status()
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
