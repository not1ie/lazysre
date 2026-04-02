from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolPermissionContext:
    deny_names: frozenset[str] = field(default_factory=frozenset)
    deny_prefixes: tuple[str, ...] = ()

    @classmethod
    def from_iterables(
        cls,
        deny_names: list[str] | None = None,
        deny_prefixes: list[str] | None = None,
    ) -> "ToolPermissionContext":
        return cls(
            deny_names=frozenset(x.strip().lower() for x in (deny_names or []) if x.strip()),
            deny_prefixes=tuple(x.strip().lower() for x in (deny_prefixes or []) if x.strip()),
        )

    def blocks(self, tool_name: str) -> bool:
        lowered = tool_name.strip().lower()
        if not lowered:
            return True
        if lowered in self.deny_names:
            return True
        return any(lowered.startswith(prefix) for prefix in self.deny_prefixes)

