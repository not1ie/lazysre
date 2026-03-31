from collections import defaultdict

from lazysre.models import StepResult


class MemoryStore:
    def __init__(self) -> None:
        self._short_term: dict[str, list[StepResult]] = defaultdict(list)
        self._long_term: list[str] = []

    def append_step(self, task_id: str, result: StepResult) -> None:
        self._short_term[task_id].append(result)

    def get_short_term(self, task_id: str) -> list[StepResult]:
        return list(self._short_term.get(task_id, []))

    def promote_summary(self, summary: str) -> None:
        if summary:
            self._long_term.append(summary)

    def search(self, query: str, limit: int = 5) -> list[str]:
        lowered = query.lower()
        hits = [x for x in self._long_term if lowered in x.lower()]
        return hits[:limit]

