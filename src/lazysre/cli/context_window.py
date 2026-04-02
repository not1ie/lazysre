from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ContextWindowManager:
    max_chars: int = 12000
    max_tool_output_chars: int = 3500

    def fit_text(self, text: str, *, max_chars: int | None = None) -> str:
        cap = max_chars if max_chars is not None else self.max_chars
        if len(text) <= cap:
            return text
        summarized = self._smart_summarize(text, cap)
        if len(summarized) <= cap:
            return summarized
        return summarized[:cap]

    def fit_tool_output_json(self, raw_output: str) -> str:
        text = raw_output.strip()
        if not text:
            return raw_output
        try:
            payload = json.loads(text)
        except Exception:
            return self.fit_text(text, max_chars=self.max_tool_output_chars)
        if not isinstance(payload, dict):
            return self.fit_text(text, max_chars=self.max_tool_output_chars)

        stdout = str(payload.get("stdout", ""))
        stderr = str(payload.get("stderr", ""))
        payload["stdout"] = self.fit_text(stdout, max_chars=2200)
        payload["stderr"] = self.fit_text(stderr, max_chars=900)
        compact = json.dumps(payload, ensure_ascii=False)
        trimmed = self.fit_text(compact, max_chars=self.max_tool_output_chars)
        if len(trimmed) <= self.max_tool_output_chars:
            return trimmed
        return trimmed[: self.max_tool_output_chars]

    def _smart_summarize(self, text: str, cap: int) -> str:
        lines = text.splitlines()
        if not lines:
            return text[:cap]
        highlights = []
        pattern = re.compile(r"(error|warn|fail|timeout|exception|critical|oom|killed)", re.IGNORECASE)
        for line in lines:
            if pattern.search(line):
                highlights.append(line.strip())
        highlights = highlights[:40]
        head = lines[:40]
        tail = lines[-40:]
        merged = "\n".join(
            [
                "[summary]",
                f"total_lines={len(lines)}",
                "[highlights]",
                *highlights,
                "[head]",
                *head,
                "[tail]",
                *tail,
            ]
        )
        if len(merged) <= cap:
            return merged
        return merged[: cap // 2] + "\n...<snip>...\n" + merged[-cap // 2 :]


def compact_conversation(turns: list[dict[str, Any]], *, max_chars: int = 2400) -> str:
    if not turns:
        return ""
    lines: list[str] = []
    for idx, item in enumerate(turns[-8:], 1):
        user = str(item.get("user", "")).strip()
        assistant = str(item.get("assistant", "")).strip()
        trace = item.get("trace", [])
        lines.append(f"turn={idx} user={user[:180]}")
        lines.append(f"turn={idx} assistant={assistant[:220]}")
        if isinstance(trace, list) and trace:
            trace_preview = "; ".join(str(x)[:120] for x in trace[:6])
            lines.append(f"turn={idx} trace={trace_preview}")
    text = "\n".join(lines)
    if len(text) <= max_chars:
        return text
    return text[: max_chars // 2] + "\n...<snip>...\n" + text[-max_chars // 2 :]
