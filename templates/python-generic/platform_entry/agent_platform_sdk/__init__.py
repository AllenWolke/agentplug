"""Language-neutral Agent Platform protocol helpers for Python."""

__version__ = "2.1.0"

from .checkpoint_cursor import CheckpointCursor

from .lifecycle import (
    EVENT_ACCEPTED,
    EVENT_ARTIFACT,
    EVENT_CANCELLED,
    EVENT_COMPLETED,
    EVENT_FAILED,
    EVENT_PROGRESS,
    EVENT_STARTED,
    EVENT_WAITING,
    MEMORY_RUN_STORE_LABEL,
    GenerationRunStore,
    RecoveryGenerationRunStore,
    IdempotencyConflictError,
    InvalidTransitionError,
    MemoryRunStore,
    RunRecord,
    RunUnknownError,
)
from .models import (AgentGroupHandoff, AppError, EventRequest, ExecuteRequest,
                     ExecuteResponse, ExecutionEvent, RecoveryCheckpointReference, ScopeKey)
from .security import (
    ContextVerifier,
    ContextVerificationError,
    TrustedContext,
    canonical_body_hash,
    canonical_event_hash,
    encode_internal_envelope,
    internal_signing_secret,
    internal_token,
    signed_internal_headers,
    verify_internal_signature,
)
from .server import ExecutionServer, RunHandler, ServerConfig, ServerConfigError
from .factory import AgentApp, create_agent_app
from .async_factory import AsyncAgentApp, AsyncAgentHooks, AsyncFactoryError, create_async_agent_app
from .fastapi_factory import create_fastapi_agent_app
from .execution_lifecycle import AgentGroupPause, ExecutionLifecycle, HarnessPause
from .recovery_context import (RecoveryCheckpointSelector, RecoveryCheckpointSnapshot,
                               RecoveryCheckpointStep, RecoveryPlan)
from .event_authority import EventAuthorityClient
from .run_gateway import NoopRunProvider, RunGateway, RunProvider
from .runtime_mode import RuntimeMode, RuntimeModeError, resolve_runtime_mode
from .platform_run import PlatformProjectionProvider, PlatformRunClient, PlatformRunError
from .checkpoint import PostgresCheckpointProvider, close_checkpointer, get_checkpointer, scoped_config
from .checkpoint_sync import SyncPostgresCheckpointProvider
from .conformance import validate_manifest
from .tracing import Attribute, NoopTracer, Tracer
from .telemetry import configure_telemetry
from .runtime import AgentRuntime, start_agent_runtime
from .capability_client import CapabilityGatewayClient, GatewayError
from .coordination import agent_group_plan_input_hash
from .run_models import ExecutionOutcome
from .cancellation import CancellationState, CancellationEvidenceError, read_cancellation_state
from .step_workflow import StepExecutor, StepRuntime, run_step_workflow
from .tool_client import (
    ToolGatewayError,
    invoke_tool,
)

__all__ = [
    "AgentGroupHandoff", "RecoveryCheckpointReference", "AppError", "EventRequest", "ExecuteRequest", "ExecuteResponse", "ExecutionEvent", "ScopeKey",
    "ContextVerifier", "ContextVerificationError", "TrustedContext", "canonical_body_hash", "canonical_event_hash",
    "internal_token", "internal_signing_secret", "signed_internal_headers", "verify_internal_signature", "encode_internal_envelope",
    "ExecutionServer", "RunHandler", "ServerConfig", "ServerConfigError",
    "AgentApp", "create_agent_app", "validate_manifest",
    "AsyncAgentApp", "AsyncAgentHooks", "AsyncFactoryError", "create_async_agent_app",
    "create_fastapi_agent_app",
    "ExecutionLifecycle", "HarnessPause", "AgentGroupPause",
    "RecoveryCheckpointStep", "RecoveryCheckpointSnapshot", "RecoveryCheckpointSelector", "RecoveryPlan",
    "EventAuthorityClient",
    "RunGateway", "RunProvider", "NoopRunProvider", "PlatformProjectionProvider", "PlatformRunClient", "PlatformRunError",
    "RuntimeMode", "RuntimeModeError", "resolve_runtime_mode",
    "PostgresCheckpointProvider", "SyncPostgresCheckpointProvider", "get_checkpointer", "close_checkpointer", "scoped_config",
    "MemoryRunStore", "GenerationRunStore", "RecoveryGenerationRunStore", "RunRecord", "RunUnknownError", "IdempotencyConflictError", "InvalidTransitionError",
    "MEMORY_RUN_STORE_LABEL",
    "EVENT_ACCEPTED", "EVENT_STARTED", "EVENT_PROGRESS", "EVENT_WAITING", "EVENT_ARTIFACT",
    "EVENT_COMPLETED", "EVENT_FAILED", "EVENT_CANCELLED",
    "Attribute", "Tracer", "NoopTracer",
    "configure_telemetry",
    "AgentRuntime", "start_agent_runtime",
    "CapabilityGatewayClient", "GatewayError",
    "agent_group_plan_input_hash",
    "ExecutionOutcome",
    "CancellationState", "CancellationEvidenceError", "read_cancellation_state",
    "StepExecutor", "StepRuntime", "run_step_workflow",
    "CheckpointCursor",
    "ToolGatewayError", "invoke_tool",
]
