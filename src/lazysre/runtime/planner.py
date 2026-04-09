from __future__ import annotations

from typing import Any

from lazysre.config import settings
from lazysre.providers.factory import build_provider_from_settings, resolve_provider_name_from_settings


class Planner:
    async def make_plan(self, objective: str, context: dict[str, Any]) -> list[str]:
        provider_name = resolve_provider_name_from_settings()
        if provider_name != "mock":
            plan = await self._make_model_plan(objective, context)
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

    async def _make_model_plan(self, objective: str, context: dict[str, Any]) -> list[str]:
        system_prompt = (
            "你是 SRE 智能体规划器。请将目标拆解为最多 5 条可执行步骤。"
            "每行一条，不要额外解释。"
        )
        user_prompt = f"目标: {objective}\n上下文: {context}"
        try:
            provider = build_provider_from_settings()
            output_text = await provider.complete(system_prompt, user_prompt, settings.model_name)
            parsed = _parse_lines(output_text)
            return parsed[:5]
        except Exception:
            return []


def _parse_lines(text: str) -> list[str]:
    lines = []
    for raw in text.splitlines():
        item = raw.strip().lstrip("-*0123456789. ")
        if item:
            lines.append(item)
    return lines
