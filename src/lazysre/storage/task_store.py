from __future__ import annotations

import json
from pathlib import Path

from lazysre.models import TaskRecord


class FileTaskStore:
    def __init__(self, file_path: str) -> None:
        self._path = Path(file_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def load_all(self) -> dict[str, TaskRecord]:
        if not self._path.exists():
            return {}
        raw = self._path.read_text(encoding="utf-8").strip()
        if not raw:
            return {}

        payload = json.loads(raw)
        if not isinstance(payload, list):
            return {}

        tasks: dict[str, TaskRecord] = {}
        for item in payload:
            task = TaskRecord.model_validate(item)
            tasks[task.id] = task
        return tasks

    def save_all(self, tasks: dict[str, TaskRecord]) -> None:
        rows = [task.model_dump(mode="json") for task in tasks.values()]
        temp = self._path.with_suffix(self._path.suffix + ".tmp")
        temp.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self._path)

