from typing import Any

from lazysre.tools.base import Tool


class EchoTool(Tool):
    name = "echo"
    description = "Return a concise execution note for a step."

    async def run(self, instruction: str, context: dict[str, Any]) -> str:
        service = context.get("service", "unknown-service")
        cluster = context.get("cluster", "unknown-cluster")
        return (
            f"[{service}@{cluster}] 执行步骤：{instruction}. "
            "当前为 MVP 模拟执行，建议在此处接入真实观测与修复工具。"
        )

