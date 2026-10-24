"""Strict Agent Execution v2 wire models.

严格的 Agent Execution v2 传输模型。SDK 只提供协议便利层，不包含业务分支。
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

MAX_SAFE_EVENT_SEQUENCE = (1 << 53) - 1
_AGENT_EDGE_WHITESPACE = " \t\n\r\v\f\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"


def validate_event_cursor(value: Any) -> int:
    """Require a JSON/JavaScript-safe event cursor; bool is not an integer here."""
    if type(value) is not int or not 0 <= value <= MAX_SAFE_EVENT_SEQUENCE:
        raise ValueError("event cursor is outside the safe integer range")
    return value


def validate_event_sequence(value: Any) -> int:
    """Require a positive JSON/JavaScript-safe SDK event sequence."""
    if type(value) is not int or not 1 <= value <= MAX_SAFE_EVENT_SEQUENCE:
        raise ValueError("event sequence is outside the safe integer range")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScopeKey(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    department_id: str = Field(min_length=1, max_length=128)
    application_id: str = Field(min_length=1, max_length=128)
    agent_instance_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    agent_version_id: str = Field(min_length=1, max_length=128)
    # Keep the wire value identical to the platform authorization model.
    # `service_principal` represents an OAuth client / machine identity;
    # accepting only the historical `service` alias made valid external
    # invocations fail Pydantic validation before an Agent could run.
    # 线上的协议值必须与中台授权模型一致。`service_principal` 表示 OAuth
    # 客户端/机器身份；旧版只接受 `service` 会让合法外部调用在进入 Agent 前
    # 就被 Pydantic 拒绝。
    principal_type: Literal["user", "service_principal"]
    principal_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    authorization_epoch: int = Field(ge=1)
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    parent_run_id: str = Field(default="", max_length=128)
    delegation_depth: int = Field(default=0, ge=0, le=8)
    # A durable Run is always bound to a platform-owned Agent installation.
    # 持久化 Run 必须绑定平台所有的 Agent 安装实例。
    installation_id: str = Field(min_length=1, max_length=128)


class ExecuteRequest(StrictModel):
    protocol_version: Literal["agent-execution/v2"]
    context_token: str = Field(min_length=32, max_length=8192)
    scope: ScopeKey
    operation: Literal["invoke", "run", "resume", "cancel"]
    idempotency_key: str = Field(min_length=8, max_length=128)
    input_schema: str = Field(pattern=r"^schema://")
    input: dict[str, Any]
    resume_input: dict[str, Any] | None = None


class EventRequest(StrictModel):
    """Run-scoped event subscription. / 运行作用域内的事件订阅请求。"""

    protocol_version: Literal["agent-execution/v2"]
    context_token: str = Field(min_length=32, max_length=8192)
    scope: ScopeKey
    after_seq: int = Field(ge=0, le=MAX_SAFE_EVENT_SEQUENCE, strict=True)
    policy_snapshot_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class AppError(StrictModel):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    message: str = Field(min_length=1, max_length=512)
    retryable: bool
    details: dict[str, Any] = Field(default_factory=dict, max_length=32)


class HandlerHandoff(StrictModel):
    """Metadata emitted by supervision after a particular handler exits."""

    version: Literal["sdk-handler-exit/v1"]
    run_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    execution_revision: int = Field(ge=1, lt=1 << 53, strict=True)
    body_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    lease_token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    origin_operation: Literal["invoke", "run"]
    harness_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    tool_name: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    call_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    last_event_seq: int = Field(ge=1, lt=1 << 53, strict=True)


class RecoveryCheckpointReference(StrictModel):
    """Public six-field reference to one current, bounded State checkpoint."""

    state_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: int = Field(ge=1, le=4096, strict=True)
    schema_id: Literal["schema://agentplug/agent-group/v1"]
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    execution_revision: int = Field(ge=1, lt=1 << 53, strict=True)
    expires_at: str = Field(min_length=20, max_length=64)

    @field_validator("expires_at")
    @classmethod
    def _valid_expiry(cls, value: str) -> str:
        try:
            expiry = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        except ValueError:
            raise ValueError("invalid checkpoint expiry") from None
        if expiry.tzinfo is None or expiry.utcoffset() is None or expiry <= datetime.now(timezone.utc):
            raise ValueError("checkpoint is expired or has no timezone")
        return value


class AgentGroupHandoff(StrictModel):
    """Actual supervised exit metadata for a durable child-group wait."""

    version: Literal["sdk-agent-group-exit/v1"]
    run_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    execution_revision: int = Field(ge=1, lt=1 << 53, strict=True)
    body_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    lease_token_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    origin_operation: Literal["invoke", "run"]
    group_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    operation_key: StrictStr = Field(min_length=1, max_length=128)
    last_event_seq: int = Field(ge=1, lt=1 << 53, strict=True)
    checkpoint: RecoveryCheckpointReference
    child_keys: list[StrictStr] = Field(min_length=1, max_length=16)

    @field_validator("operation_key")
    @classmethod
    def _valid_operation_key(cls, value: str) -> str:
        if (value.strip(_AGENT_EDGE_WHITESPACE) != value
                or any(character in value for character in "*\x00\r\n")):
            raise ValueError("invalid operation key")
        try:
            if len(value.encode("utf-8")) > 128:
                raise ValueError("invalid operation key")
        except UnicodeEncodeError:
            raise ValueError("invalid operation key") from None
        return value

    @field_validator("child_keys")
    @classmethod
    def _validate_child_keys(cls, value: list[str]) -> list[str]:
        if (len(value) > 16 or len(set(value)) != len(value)
                or any(not isinstance(key, str) or re.fullmatch(r"[a-f0-9]{64}", key) is None
                       for key in value)):
            raise ValueError("invalid fixed child keys")
        return value


class ExecuteResponse(StrictModel):
    protocol_version: Literal["agent-execution/v2"] = "agent-execution/v2"
    run_id: str
    status: Literal[
        "accepted", "running", "waiting", "succeeded", "failed", "cancelled"
    ]
    output_schema: str = ""
    output: dict[str, Any] = Field(default_factory=dict)
    error: AppError | None = None
    handoff: HandlerHandoff | None = None
    agent_group_handoff: AgentGroupHandoff | None = None


class ExecutionEvent(StrictModel):
    run_id: str
    seq: int = Field(ge=1, le=MAX_SAFE_EVENT_SEQUENCE, strict=True)
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
    payload: dict[str, Any] = Field(default_factory=dict)


def normalize_execution_event(value: Any) -> ExecutionEvent:
    """Revalidate Store output, including instances created with model_construct."""
    if isinstance(value, ExecutionEvent):
        value = value.model_dump(mode="python")
    if not isinstance(value, dict):
        raise ValueError("invalid execution event")
    event = ExecutionEvent.model_validate(value)
    validate_event_sequence(event.seq)
    return event
