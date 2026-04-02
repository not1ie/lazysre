from lazysre.cli.permissions import ToolPermissionContext
from lazysre.cli.registry import ToolRegistry
from lazysre.cli.tools.builtin import builtin_tools


def build_default_registry(
    permission_context: ToolPermissionContext | None = None,
) -> ToolRegistry:
    registry = ToolRegistry(permission_context=permission_context)
    for tool in builtin_tools():
        registry.register(tool)
    return registry
