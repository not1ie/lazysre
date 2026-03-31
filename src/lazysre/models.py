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


class TaskCreateRequest(BaseModel):
    objective: str = Field(min_length=3, max_length=2000)
    context: dict[str, Any] = Field(default_factory=dict)


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
    status: TaskStatus = TaskStatus.pending
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    plan: list[str] = Field(default_factory=list)
    steps: list[StepResult] = Field(default_factory=list)
    critic: CriticResult | None = None
    summary: str | None = None
    error: str | None = None

