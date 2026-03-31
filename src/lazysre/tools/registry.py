from collections.abc import Iterable

from lazysre.tools.base import Tool
from lazysre.tools.echo import EchoTool
from lazysre.tools.http_fetch import HTTPFetchTool


class ToolRegistry:
    def __init__(self, tools: Iterable[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        default_tools = tools or (EchoTool(), HTTPFetchTool())
        for tool in default_tools:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"tool not found: {name}")
        return self._tools[name]

    def choose_tool(self, step_text: str) -> Tool:
        lowered = step_text.lower()
        if "http://" in lowered or "https://" in lowered:
            return self.get("http_fetch")
        return self.get("echo")

