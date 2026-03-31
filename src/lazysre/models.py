from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TaskStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    canceled = "canceled"


class TaskCreateRequest(BaseModel):
    objective: str = Field(min_length=3, max_length=2000)
    context: dict[str, Any] = Field(default_factory=dict)


class TaskEvent(BaseModel):
    timestamp: datetime = Field(default_factory=utcnow)
    kind: str
    message: str
    level: str = "info"


class StepResult(BaseModel):
    step: str
    tool: str
    output: str
    success: bool


class CriticResult(BaseModel):
    done: bool
    score: float
    feedback: str


class TaskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    objective: str
    context: dict[str, Any] = Field(default_factory=dict)
    parent_task_id: str | None = None
    status: TaskStatus = TaskStatus.pending
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    updated_at: datetime = Field(default_factory=utcnow)
    plan: list[str] = Field(default_factory=list)
    steps: list[StepResult] = Field(default_factory=list)
    reflections: int = 0
    events: list[TaskEvent] = Field(default_factory=list)
    critic: CriticResult | None = None
    summary: str | None = None
    error: str | None = None


class MemorySearchResponse(BaseModel):
    query: str
    hits: list[str]
