"""Generated from agent-execution-v2.yaml; do not edit by hand.

由 agent-execution-v2.yaml 生成；禁止手工修改。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

PROTOCOL_VERSION = "agent-execution/v2"


@dataclass(frozen=True, slots=True)
class ScopeKey:
    tenant_id: str
    department_id: str
    application_id: str
    agent_instance_id: str
    agent_id: str
    agent_version_id: str
    principal_type: Literal["user", "service_principal"]
    principal_id: str
    session_id: str
    run_id: str
    authorization_epoch: int
    trace_id: str
    installation_id: str
    parent_run_id: str = ""
    delegation_depth: int = 0


@dataclass(frozen=True, slots=True)
class ExecuteRequest:
    protocol_version: str
    context_token: str
    scope: ScopeKey
    operation: Literal["invoke", "run", "resume", "cancel"]
    idempotency_key: str
    input_schema: str
    input: dict[str, Any]
    resume_input: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class AppError:
    code: str
    message: str
    retryable: bool
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ExecuteResponse:
    protocol_version: str
    run_id: str
    status: Literal[
        "accepted", "running", "waiting", "succeeded", "failed", "cancelled"
    ]
    output_schema: str = ""
    output: dict[str, Any] = field(default_factory=dict)
    error: AppError | None = None


@dataclass(frozen=True, slots=True)
class EventRequest:
    protocol_version: str
    context_token: str
    scope: ScopeKey
    after_seq: int
    policy_snapshot_hash: str


@dataclass(frozen=True, slots=True)
class ExecutionEvent:
    run_id: str
    seq: int
    event_type: Literal[
        "accepted",
        "started",
        "progress",
        "waiting",
        "artifact",
        "completed",
        "failed",
        "cancelled",
    ]
    occurred_at: datetime
    payload: dict[str, Any] = field(default_factory=dict)
