from __future__ import annotations

import json
from pathlib import Path

from lazysre.platform.models import AgentDefinition, WorkflowDefinition, WorkflowRun


class PlatformState:
    def __init__(
        self,
        agents: dict[str, AgentDefinition] | None = None,
        workflows: dict[str, WorkflowDefinition] | None = None,
        runs: dict[str, WorkflowRun] | None = None,
    ) -> None:
        self.agents = agents or {}
        self.workflows = workflows or {}
        self.runs = runs or {}


class FilePlatformStore:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> PlatformState:
        if not self._path.exists():
            return PlatformState()
        raw = self._path.read_text(encoding="utf-8").strip()
        if not raw:
            return PlatformState()

        payload = json.loads(raw)
        agents = {
            item["id"]: AgentDefinition.model_validate(item)
            for item in payload.get("agents", [])
        }
        workflows = {
            item["id"]: WorkflowDefinition.model_validate(item)
            for item in payload.get("workflows", [])
        }
        runs = {item["id"]: WorkflowRun.model_validate(item) for item in payload.get("runs", [])}
        return PlatformState(agents=agents, workflows=workflows, runs=runs)

    def save(self, state: PlatformState) -> None:
        payload = {
            "agents": [a.model_dump(mode="json") for a in state.agents.values()],
            "workflows": [w.model_dump(mode="json") for w in state.workflows.values()],
            "runs": [r.model_dump(mode="json") for r in state.runs.values()],
        }
        temp = self._path.with_suffix(self._path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self._path)

