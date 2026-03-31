from abc import ABC, abstractmethod
from typing import Any


class Tool(ABC):
    name: str
    description: str

    @abstractmethod
    async def run(self, instruction: str, context: dict[str, Any]) -> str:
        raise NotImplementedError

