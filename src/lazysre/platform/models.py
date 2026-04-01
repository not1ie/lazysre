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
    tool_binding: str | None = None
    tool_query: str | None = None
    required_permission: str = "read"
    requires_approval: bool = False
    approval_reason: str | None = None
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
    waiting_approval = "waiting_approval"
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
    queue: list[str] = Field(default_factory=list)
    visited: list[str] = Field(default_factory=list)
    pending_node_id: str | None = None
    approvals: list["RunApprovalRecord"] = Field(default_factory=list)
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


class PlatformTemplate(BaseModel):
    slug: str
    name: str
    description: str
    recommended_objective: str
    stages: list[str] = Field(default_factory=list)


class AutoDesignRequest(BaseModel):
    objective: str = Field(min_length=3, max_length=2000)
    name: str | None = None
    template_slug: str | None = None


class PlatformOverview(BaseModel):
    total_agents: int
    total_workflows: int
    total_runs: int
    active_runs: int
    completed_runs: int
    failed_runs: int
    canceled_runs: int
    success_rate: float


class OpsToolKind(str, Enum):
    prometheus = "prometheus"
    kubernetes = "kubernetes"
    logs = "logs"
    generic_http = "generic_http"


class OpsToolDefinition(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(min_length=2, max_length=128)
    kind: OpsToolKind
    base_url: str = Field(min_length=4, max_length=2000)
    headers: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True
    default_query: str = ""
    required_permission: str = "read"
    created_at: datetime = Field(default_factory=utcnow)


class ToolCreateRequest(BaseModel):
    name: str
    kind: OpsToolKind
    base_url: str
    headers: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True
    default_query: str = ""
    required_permission: str = "read"


class ToolProbeRequest(BaseModel):
    query: str = ""
    timeout_sec: float = 8.0


class ToolProbeResult(BaseModel):
    ok: bool
    preview: str


class ToolHealthItem(BaseModel):
    tool_id: str
    name: str
    kind: OpsToolKind
    ok: bool
    latency_ms: int
    preview: str = ""
    error: str = ""


class EnvironmentBootstrapRequest(BaseModel):
    monitoring_ip: str = "92.168.69.176"
    monitoring_port: int = 9090
    k8s_api_url: str = "https://192.168.10.1:6443"
    k8s_verify_tls: bool = False
    k8s_bearer_token: str = ""
    create_mission_workflow: bool = True
    workflow_name: str = "Prod Autonomous Incident"


class EnvironmentBootstrapResult(BaseModel):
    tools: list[OpsToolDefinition] = Field(default_factory=list)
    primary_tool_id: str | None = None
    workflow: WorkflowDefinition | None = None
    probe_results: dict[str, str] = Field(default_factory=dict)


class IncidentBriefing(BaseModel):
    generated_at: datetime = Field(default_factory=utcnow)
    severity: str
    headline: str
    tool_snapshot: list[ToolHealthItem] = Field(default_factory=list)
    recent_runs: list[dict[str, str]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    artifact_path: str | None = None


class RunReport(BaseModel):
    run_id: str
    workflow_id: str
    workflow_name: str
    status: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    event_count: int
    approvals: list["RunApprovalRecord"] = Field(default_factory=list)
    outputs: dict[str, str] = Field(default_factory=dict)
    summary: str | None = None
    error: str | None = None


class RunApprovalRequest(BaseModel):
    action: str = Field(pattern="^(approve|reject)$")
    approver: str = Field(min_length=1, max_length=120)
    comment: str = ""


class RunApprovalRecord(BaseModel):
    node_id: str
    action: str
    approver: str
    comment: str = ""
    created_at: datetime = Field(default_factory=utcnow)


WorkflowRun.model_rebuild()
