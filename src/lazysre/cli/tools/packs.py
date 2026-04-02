from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from lazysre.cli.registry import ToolDefinition
from lazysre.cli.tools.builtin import builtin_tools
from lazysre.cli.tools.marketplace import ToolPackLockStore, compute_module_digest
from lazysre.cli.tools.remote_pack import remote_gateway_tool


@dataclass(slots=True)
class LoadedPack:
    name: str
    tools: list[ToolDefinition]


def load_tool_packs(
    pack_specs: list[str] | None = None,
    remote_gateways: list[str] | None = None,
    lock_file: Path | None = None,
) -> list[LoadedPack]:
    specs = pack_specs or ["builtin"]
    store = ToolPackLockStore(lock_file or Path(".data/lsre-tool-lock.json"))
    packs: list[LoadedPack] = []
    for spec in specs:
        normalized = spec.strip()
        if not normalized:
            continue
        if normalized == "builtin":
            packs.append(LoadedPack(name="builtin", tools=builtin_tools()))
            continue
        if normalized.startswith("module:"):
            module_spec = normalized[len("module:") :].strip()
            packs.append(_load_module_pack(module_spec))
            continue
        if normalized.startswith("locked:"):
            name = normalized[len("locked:") :].strip()
            packs.append(_load_locked_pack(store, name))
            continue
        raise ValueError(f"unknown tool pack spec: {normalized}")

    for gateway in remote_gateways or []:
        parsed = _parse_remote_gateway(gateway)
        packs.append(
            LoadedPack(
                name=f"remote:{parsed[0]}",
                tools=[remote_gateway_tool(name=parsed[0], base_url=parsed[1], token=parsed[2])],
            )
        )
    return packs


def _load_module_pack(spec: str) -> LoadedPack:
    # format: module:my_pkg.my_module[:factory_name]
    module_name, _, maybe_factory = spec.partition(":")
    if not module_name:
        raise ValueError("empty module pack name")
    factory_name = maybe_factory or "tool_pack"
    module = importlib.import_module(module_name)
    factory = getattr(module, factory_name, None)
    if not callable(factory):
        raise ValueError(f"module pack factory not found: {module_name}:{factory_name}")

    tool_list = _call_factory(factory)
    if not isinstance(tool_list, list):
        raise ValueError(f"module pack factory must return list[ToolDefinition]: {module_name}")
    return LoadedPack(name=f"module:{module_name}", tools=tool_list)


def _load_locked_pack(store: ToolPackLockStore, name: str) -> LoadedPack:
    if not name:
        raise ValueError("locked pack name is empty")
    locked = store.get(name)
    if not locked:
        raise ValueError(f"locked pack not found: {name}")
    expected = locked.digest_sha256.strip().lower()
    if expected:
        actual = compute_module_digest(locked.module)
        if actual != expected:
            raise ValueError(
                f"locked pack digest mismatch for {locked.name}: expected={expected}, actual={actual}"
            )
    loaded = _load_module_pack(locked.module)
    return LoadedPack(name=f"locked:{locked.name}@{locked.version}", tools=loaded.tools)


def _call_factory(factory: Callable[[], list[ToolDefinition]]) -> list[ToolDefinition]:
    return factory()


def _parse_remote_gateway(raw: str) -> tuple[str, str, str]:
    # format: <name>=<base_url>[#token]
    text = raw.strip()
    if "=" not in text:
        raise ValueError("remote gateway must be <name>=<base_url>[#token]")
    name, rest = text.split("=", 1)
    name = name.strip()
    if not name:
        raise ValueError("remote gateway name is empty")
    token = ""
    if "#" in rest:
        base_url, token = rest.split("#", 1)
    else:
        base_url = rest
    base_url = base_url.strip()
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("remote gateway base_url must start with http:// or https://")
    return name, base_url, token.strip()
