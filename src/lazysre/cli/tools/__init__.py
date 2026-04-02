from lazysre.cli.registry import ToolRegistry
from lazysre.cli.tools.builtin import builtin_tools


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for tool in builtin_tools():
        registry.register(tool)
    return registry

