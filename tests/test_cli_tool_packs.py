import pytest

from lazysre.cli.permissions import ToolPermissionContext
from lazysre.cli.tools import build_default_registry
from lazysre.cli.tools.packs import load_tool_packs


def test_load_tool_packs_builtin_default() -> None:
    packs = load_tool_packs()
    assert packs
    first = packs[0]
    assert first.name == "builtin"
    names = {tool.spec.name for tool in first.tools}
    assert {"kubectl", "docker", "curl", "logs"} <= names


def test_load_tool_packs_module_factory() -> None:
    packs = load_tool_packs(pack_specs=["module:lazysre.cli.tools.builtin:tool_pack"])
    assert len(packs) == 1
    names = {tool.spec.name for tool in packs[0].tools}
    assert "kubectl" in names


def test_build_registry_with_remote_gateway_pack() -> None:
    registry = build_default_registry(
        tool_packs=["builtin"],
        remote_gateways=["edge=http://127.0.0.1:18080"],
    )
    names = {spec.name for spec in registry.specs()}
    assert "remote_edge" in names


def test_load_tool_packs_bad_remote_gateway() -> None:
    with pytest.raises(ValueError):
        load_tool_packs(remote_gateways=["bad-gateway-format"])


def test_permission_context_hides_denied_pack_tools() -> None:
    registry = build_default_registry(
        permission_context=ToolPermissionContext.from_iterables(deny_names=["remote_edge"]),
        tool_packs=["builtin"],
        remote_gateways=["edge=http://127.0.0.1:18080"],
    )
    names = {spec.name for spec in registry.specs()}
    assert "remote_edge" not in names

