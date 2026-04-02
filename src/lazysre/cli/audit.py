from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AuditLogger:
    path: Path

    def write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = dict(payload)
        line["timestamp"] = datetime.now(timezone.utc).isoformat()
        with self.path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(line, ensure_ascii=False) + "\n")

