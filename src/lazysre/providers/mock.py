from __future__ import annotations

from lazysre.providers.base import LLMProvider


class MockProvider(LLMProvider):
    async def complete(self, system_prompt: str, user_prompt: str, model: str) -> str:
        return (
            f"[mock:{model}] "
            f"{system_prompt[:80].strip()} | {user_prompt[:220].strip()} | "
            "建议将该节点接入真实模型和工具链。"
        )

