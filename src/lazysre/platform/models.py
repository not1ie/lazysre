from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AgentRole(str, Enum):
    planner = "planner"
    worker = "worker"
    critic = "critic"
    custom = "custom"


class AgentDefinition(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(min_length=2, max_length=128)
    role: AgentRole = AgentRole.custom
    system_prompt: str = Field(min_length=1, max_length=8000)
    model: str = "gpt-5.4-mini"
    created_at: datetime = Field(default_factory=utcnow)


class WorkflowNode(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    agent_id: str
    instruction: str = Field(min_length=1, max_length=4000)
    next_nodes: list[str] = Field(default_factory=list)


class WorkflowDefinition(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(min_length=2, max_length=128)
    objective: str = Field(min_length=3, max_length=2000)
    start_node: str
    nodes: list[WorkflowNode] = Field(min_length=1)
    created_at: datetime = Field(default_factory=utcnow)


class RunStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    canceled = "canceled"


class RunEvent(BaseModel):
    timestamp: datetime = Field(default_factory=utcnow)
    kind: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


class WorkflowRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    workflow_id: str
    input: dict[str, Any] = Field(default_factory=dict)
    status: RunStatus = RunStatus.pending
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    events: list[RunEvent] = Field(default_factory=list)
    outputs: dict[str, str] = Field(default_factory=dict)
    summary: str | None = None
    error: str | None = None


class AgentCreateRequest(BaseModel):
    name: str
    role: AgentRole = AgentRole.custom
    system_prompt: str
    model: str = "gpt-5.4-mini"


class WorkflowCreateRequest(BaseModel):
    name: str
    objective: str
    start_node: str
    nodes: list[WorkflowNode]


class RunCreateRequest(BaseModel):
    input: dict[str, Any] = Field(default_factory=dict)


class QuickstartRequest(BaseModel):
    name: str = "Default SRE Flow"
    objective: str = Field(min_length=3, max_length=2000)

