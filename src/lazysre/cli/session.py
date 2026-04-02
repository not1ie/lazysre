from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lazysre.cli.context_window import compact_conversation
from lazysre.cli.types import DispatchResult


@dataclass(slots=True)
class SessionStore:
    path: Path

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"turns": [], "entities": {}}
        raw = self.path.read_text(encoding="utf-8").strip()
        if not raw:
            return {"turns": [], "entities": {}}
        try:
            payload = json.loads(raw)
        except Exception:
            return {"turns": [], "entities": {}}
        if not isinstance(payload, dict):
            return {"turns": [], "entities": {}}
        turns = payload.get("turns", [])
        entities = payload.get("entities", {})
        if not isinstance(turns, list):
            turns = []
        if not isinstance(entities, dict):
            entities = {}
        return {"turns": turns[-30:], "entities": entities}

    def append_turn(self, user_input: str, result: DispatchResult) -> None:
        payload = self.load()
        turns = payload["turns"]
        entities = payload["entities"]
        turns.append(
            {
                "user": user_input,
                "assistant": result.final_text[:2000],
                "trace": _extract_trace(result),
            }
        )
        _extract_entities(user_input, result, entities)
        payload["turns"] = turns[-30:]
        payload["entities"] = entities
        self._save(payload)

    def build_context_hint(self, user_input: str) -> str:
        payload = self.load()
        turns = payload.get("turns", [])
        entities = payload.get("entities", {})
        if not turns:
            return ""
        last_user = turns[-1].get("user", "")
        pronoun_hit = any(token in user_input.lower() for token in ["它", "他", "她", "it", "that", "this"])
        if not pronoun_hit:
            return ""
        hints: list[str] = []
        if entities.get("last_pod"):
            hints.append(f"last_pod={entities['last_pod']}")
        if entities.get("last_service"):
            hints.append(f"last_service={entities['last_service']}")
        if entities.get("last_namespace"):
            hints.append(f"last_namespace={entities['last_namespace']}")
        if not hints:
            return f"previous_user_request={last_user}"
        return "session_hint: " + ", ".join(hints)

    def recent_turns(self, limit: int = 10) -> list[dict[str, str]]:
        payload = self.load()
        turns = payload.get("turns", [])
        if not isinstance(turns, list):
            return []
        cap = max(1, min(limit, 100))
        rows: list[dict[str, str]] = []
        for item in turns[-cap:]:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "user": str(item.get("user", "")),
                    "assistant": str(item.get("assistant", "")),
                }
            )
        return rows

    def build_dialogue_context(self, *, max_chars: int = 2400) -> str:
        payload = self.load()
        turns = payload.get("turns", [])
        if not isinstance(turns, list):
            return ""
        return compact_conversation(turns, max_chars=max_chars)

    def clear(self) -> None:
        self._save({"turns": [], "entities": {}})

    def export_markdown(self, limit: int = 30) -> str:
        turns = self.recent_turns(limit=limit)
        if not turns:
            return "# LazySRE Session History\n\n(Empty)\n"
        lines = ["# LazySRE Session History", ""]
        for idx, item in enumerate(turns, 1):
            lines.append(f"## Turn {idx}")
            lines.append("")
            lines.append(f"### User")
            lines.append("")
            lines.append(item["user"])
            lines.append("")
            lines.append(f"### Assistant")
            lines.append("")
            lines.append(item["assistant"])
            lines.append("")
        return "\n".join(lines).strip() + "\n"

    def _save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.path)


def _extract_entities(user_input: str, result: DispatchResult, entities: dict[str, Any]) -> None:
    text = user_input.lower()
    ns_match = re.search(r"(?:-n|--namespace)\s+([a-z0-9-]+)", text)
    if ns_match:
        entities["last_namespace"] = ns_match.group(1)

    for evt in result.events:
        if evt.kind != "tool_call":
            continue
        args = evt.data.get("arguments", {})
        if not isinstance(args, dict):
            continue
        pod = str(args.get("pod", "")).strip()
        svc = str(args.get("service", "")).strip()
        ns = str(args.get("namespace", "")).strip()
        if pod:
            entities["last_pod"] = pod
        if svc:
            entities["last_service"] = svc
        if ns:
            entities["last_namespace"] = ns


def _extract_trace(result: DispatchResult) -> list[str]:
    trace: list[str] = []
    for evt in result.events:
        if evt.kind == "llm_turn":
            trace.append(f"Thought: {evt.message}")
        elif evt.kind == "tool_call":
            trace.append(f"Action: {evt.message}")
        elif evt.kind == "tool_output":
            trace.append(f"Observation: {evt.message}")
    return trace[:24]
