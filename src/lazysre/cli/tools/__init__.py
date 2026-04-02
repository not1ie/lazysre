from lazysre.cli.permissions import ToolPermissionContext
from lazysre.cli.registry import ToolRegistry
from lazysre.cli.tools.packs import load_tool_packs


def build_default_registry(
    permission_context: ToolPermissionContext | None = None,
    tool_packs: list[str] | None = None,
    remote_gateways: list[str] | None = None,
) -> ToolRegistry:
    registry = ToolRegistry(permission_context=permission_context)
    for pack in load_tool_packs(pack_specs=tool_packs, remote_gateways=remote_gateways):
        for tool in pack.tools:
            registry.register(tool)
    return registry
