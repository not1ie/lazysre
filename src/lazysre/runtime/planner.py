from __future__ import annotations

from typing import Any

import httpx

from lazysre.config import settings


class Planner:
    async def make_plan(self, objective: str, context: dict[str, Any]) -> list[str]:
        if settings.model_mode.lower() == "openai" and settings.openai_api_key:
            plan = await self._make_openai_plan(objective, context)
            if plan:
                return plan
        return self._make_heuristic_plan(objective, context)

    def _make_heuristic_plan(self, objective: str, context: dict[str, Any]) -> list[str]:
        service = context.get("service", "目标服务")
        return [
            f"收集 {service} 最近 30 分钟错误率、延迟和流量趋势",
            f"定位异常实例与关键日志，并提取最可能根因",
            f"给出可执行修复方案与回滚方案，明确验证步骤",
        ]

    async def _make_openai_plan(self, objective: str, context: dict[str, Any]) -> list[str]:
        system_prompt = (
            "你是 SRE 智能体规划器。请将目标拆解为最多 5 条可执行步骤。"
            "每行一条，不要额外解释。"
        )
        user_prompt = f"目标: {objective}\n上下文: {context}"

        payload = {
            "model": settings.model_name,
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
            "max_output_tokens": 300,
        }
        headers = {
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/responses", json=payload, headers=headers
                )
                resp.raise_for_status()
                data = resp.json()
            output_text = _extract_output_text(data)
            parsed = _parse_lines(output_text)
            return parsed[:5]
        except Exception:
            return []


def _extract_output_text(payload: dict[str, Any]) -> str:
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct

    texts: list[str] = []
    for output in payload.get("output", []):
        for part in output.get("content", []):
            if part.get("type") == "output_text" and part.get("text"):
                texts.append(part["text"])
    return "\n".join(texts).strip()


def _parse_lines(text: str) -> list[str]:
    lines = []
    for raw in text.splitlines():
        item = raw.strip().lstrip("-*0123456789. ")
        if item:
            lines.append(item)
    return lines

