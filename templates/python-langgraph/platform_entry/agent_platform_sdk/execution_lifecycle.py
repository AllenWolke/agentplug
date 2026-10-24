"""Execution v2 hooks over the existing RunStore and actual task supervision.

Only use these hooks behind verified SDK transport. The local generation map
cannot prove a former process stopped: restart recovery requires platform
handoff. Business handlers never create a second lifecycle state machine.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .errors import DomainExecutionError, classify_execution_error
from .capability_client import GatewayError
from .agent_group_resume import AgentGroupResumeBinding, current_agent_group_resume
from .lifecycle import (RunStore, RUNNING, WAITING, TERMINAL_STATUSES, InvalidTransitionError,
                        generation_sequence_range)
from .models import (AgentGroupHandoff, AppError, ExecuteRequest, ExecuteResponse, EventRequest,
                     HandlerHandoff, RecoveryCheckpointReference,
                     normalize_execution_event, validate_event_cursor,
                     validate_event_sequence)
from .recovery_context import (RecoveryCheckpointSelector, RecoveryCheckpointSnapshot,
                               RecoveryCheckpointStep, RecoveryPlan,
                               prepare_runtime_recovery_state, reset_runtime_recovery,
                               set_runtime_recovery)
from .security import canonical_body_hash
from .task_registry import ExecutionTaskRegistry

_HARNESS_STATE_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_HARNESS_PENDING_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_AGENT_EDGE_WHITESPACE = " \t\n\r\v\f\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"


def _safe_harness_identifier(value: Any) -> bool:
    # Match the platform's bounded pending-tool identifier/event allowlist.
    return isinstance(value, str) and _HARNESS_PENDING_IDENTIFIER.fullmatch(value) is not None


def _safe_agent_operation_key(value: Any) -> bool:
    if (not isinstance(value, str) or not value
            or value.strip(_AGENT_EDGE_WHITESPACE) != value
            or any(character in value for character in "*\x00\r\n")):
        return False
    try:
        return len(value.encode("utf-8")) <= 128
    except UnicodeEncodeError:
        return False


def _platform_json(value: Any) -> str:
    """Match Go encoding/json's compact HTML-safe encoding for State keys."""
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return (encoded.replace("&", "\\u0026").replace("<", "\\u003c")
            .replace(">", "\\u003e").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def _expected_agent_group_state_key(scope: Any, group_key: str) -> str:
    if not isinstance(group_key, str) or _HARNESS_STATE_KEY.fullmatch(group_key) is None:
        raise ValueError("invalid group key")
    scope_values = [getattr(scope, name, None) for name in (
        "tenant_id", "department_id", "application_id", "agent_id",
        "agent_instance_id", "principal_type", "principal_id", "installation_id",
        "agent_version_id", "session_id", "run_id",
    )]
    if any(not isinstance(value, str) for value in scope_values):
        raise ValueError("incomplete trusted State scope")
    prefix = hashlib.sha256(_platform_json(scope_values).encode("utf-8")).hexdigest()
    return hashlib.sha256(_platform_json([prefix, "coordination", group_key]).encode("utf-8")).hexdigest()


def _safe_group_schema(value: Any) -> bool:
    return (isinstance(value, str) and value.startswith("schema://")
            and len(value.encode("utf-8")) <= 256
            and not any(character in value for character in "\x00\r\n\t* "))


class HarnessPause(Exception):
    """Persist only safe tool identifiers, never arguments or confirmation tokens."""

    def __init__(self, key: str, tool_name: str, call_id: str):
        if (not isinstance(key, str) or _HARNESS_STATE_KEY.fullmatch(key) is None
                or not _safe_harness_identifier(tool_name)
                or not _safe_harness_identifier(call_id)):
            raise DomainExecutionError("INVALID_REQUEST")
        super().__init__("approval required")
        self._identifiers = (key, tool_name, call_id)

    @classmethod
    def from_result(cls, result: Any, key: str) -> dict[str, Any] | HarnessPause:
        """Return completed Harness output unchanged, or a safe approval pause.

        ``run_harness`` returns ``completed``/``incomplete`` results unchanged
        and exposes the FIFO approval operation as a single mapping. A bounded
        pending list is also accepted for callers that preserve the public
        loop queue; only its first operation may define the pause identity.
        Arguments, tokens, and all other pending fields are never copied.
        """
        if not isinstance(result, dict):
            raise DomainExecutionError("INVALID_REQUEST")
        status = result.get("status")
        if isinstance(status, str) and status in {"completed", "incomplete"}:
            return result
        if status != "approval_required" or not isinstance(key, str) or _HARNESS_STATE_KEY.fullmatch(key) is None:
            raise DomainExecutionError("INVALID_REQUEST")

        pending = result.get("pending")
        if isinstance(pending, list):
            if not 1 <= len(pending) <= 16:
                raise DomainExecutionError("INVALID_REQUEST")
            operations = pending
        elif isinstance(pending, dict):
            operations = [pending]
        else:
            raise DomainExecutionError("INVALID_REQUEST")

        allowed_fields = {"name", "call_id", "payload", "model_call_id", "run_id"}
        head: tuple[str, str] | None = None
        for operation in operations:
            if (not isinstance(operation, dict) or not {"name", "call_id"}.issubset(operation)
                    or set(operation) - allowed_fields):
                raise DomainExecutionError("INVALID_REQUEST")
            name, call_id = operation.get("name"), operation.get("call_id")
            if not _safe_harness_identifier(name) or not _safe_harness_identifier(call_id):
                raise DomainExecutionError("INVALID_REQUEST")
            if head is None:
                head = (name, call_id)
        if head is None:
            raise DomainExecutionError("INVALID_REQUEST")
        return cls(key, *head)

    @property
    def metadata(self) -> dict[str, str]:
        # Construct a fresh allowlisted view; a caller cannot inject arbitrary
        # arguments or tokens by mutating a previously returned dictionary.
        key, tool_name, call_id = self._identifiers
        if (not isinstance(key, str) or _HARNESS_STATE_KEY.fullmatch(key) is None
                or not _safe_harness_identifier(tool_name)
                or not _safe_harness_identifier(call_id)):
            raise DomainExecutionError("INVALID_REQUEST")
        return {"reason": "approval_required", "harness_key": key,
                "tool_name": tool_name, "call_id": call_id}


class AgentGroupPause(Exception):
    """Safe signal that a persisted fixed child group is still nonterminal."""

    def __init__(self, group_key: str, operation_key: str,
                 checkpoint: RecoveryCheckpointReference | dict[str, Any],
                 child_keys: list[str] | tuple[str, ...]):
        try:
            reference = (checkpoint if isinstance(checkpoint, RecoveryCheckpointReference)
                         else RecoveryCheckpointReference.model_validate(checkpoint))
        except (TypeError, ValueError):
            raise DomainExecutionError("AGENT_GROUP_REJECTED") from None
        keys = tuple(child_keys) if isinstance(child_keys, (list, tuple)) else ()
        if (not isinstance(group_key, str) or _HARNESS_STATE_KEY.fullmatch(group_key) is None
                or not _safe_agent_operation_key(operation_key)
                or not 1 <= len(keys) <= 16 or len(set(keys)) != len(keys)
                or any(not isinstance(key, str) or re.fullmatch(r"[a-f0-9]{64}", key) is None
                       for key in keys)
                or reference.schema_id != "schema://agentplug/agent-group/v1"):
            raise DomainExecutionError("AGENT_GROUP_REJECTED")
        super().__init__("agent group is waiting")
        self._group_key = group_key
        self._operation_key = operation_key
        self._checkpoint = reference
        self._child_keys = keys

    @property
    def metadata(self) -> dict[str, str]:
        return {"operation": "agent_group_wait", "reason": "agent_group_pending",
                "group_key": self._group_key, "operation_key": self._operation_key}

    @property
    def group_key(self) -> str:
        return self._group_key

    @property
    def operation_key(self) -> str:
        return self._operation_key

    @property
    def checkpoint(self) -> RecoveryCheckpointReference:
        return self._checkpoint

    @property
    def child_keys(self) -> tuple[str, ...]:
        return self._child_keys


@dataclass(frozen=True)
class _Generation:
    scope: str
    business_hash: str
    key: str
    body_hash: str


BusinessHook = Callable[[ExecuteRequest], Awaitable[dict[str, Any]]]
AuthorityHook = Callable[[ExecuteRequest], Awaitable[None]]
CheckpointHook = Callable[[ExecuteRequest, str, str, str], Awaitable[dict[str, Any]]]
RecoveryCheckpointHook = Callable[[ExecuteRequest, dict[str, Any]], Awaitable[dict[str, Any]]]


class ExecutionLifecycle:
    """Reusable invoke/run/resume/cancel hooks; events need a current read guard.

    RunStore owns status/output/events. This adapter retains only verified local
    identity/input fingerprints and exit-proof keys, bounded to 4096 runs.
    """

    def __init__(self, *, store: RunStore, registry: ExecutionTaskRegistry,
                 business: BusinessHook, authorize_current: AuthorityHook,
                 output_schema: str,
                 validate_input: Callable[[ExecuteRequest], Any] | None = None,
                 authorize_events: Callable[[EventRequest], Awaitable[None]] | None = None,
                 load_checkpoint: CheckpointHook | None = None,
                 load_recovery_checkpoint: RecoveryCheckpointHook | None = None,
                 recovery_checkpoint_selector: RecoveryCheckpointSelector | None = None,
                 load_recovery_reference_page=None, output_schema_selector=None):
        self.store, self.registry = store, registry
        self.business, self.authorize_current = business, authorize_current
        self.output_schema = output_schema
        self.output_schema_selector=output_schema_selector
        self.validate_input = validate_input
        self.authorize_events = authorize_events
        self.load_checkpoint = load_checkpoint
        self.load_recovery_checkpoint = load_recovery_checkpoint
        self.load_recovery_reference_page=load_recovery_reference_page
        self.recovery_checkpoint_selector = recovery_checkpoint_selector
        self._generations: dict[str, _Generation] = {}
        self._origins: dict[str, str] = {}
        self._pauses: dict[str, tuple[str, dict[str, str]]] = {}
        self._group_pauses: dict[str, tuple[str, dict[str, Any]]] = {}
        # Only a lifecycle-owned, post-authorization input validator can add
        # this marker. finalize_response rechecks it after Registry observes
        # the exact generation exit; a business exception cannot mint it.
        self._preflight_rejections: dict[str, _Generation] = {}
        # An explicit governed budget rejection is known; transport/receipt
        # uncertainty must never populate this lifecycle-owned marker.
        self._budget_rejections: dict[str, _Generation] = {}

    @staticmethod
    def _scope_identity(scope: Any) -> str:
        return json.dumps(scope.model_dump(exclude={"trace_id", "authorization_epoch"}),
                          sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _identity(request: ExecuteRequest) -> _Generation:
        scope = ExecutionLifecycle._scope_identity(request.scope)
        raw = json.dumps([request.input_schema, request.idempotency_key, request.input],
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode()
        return _Generation(scope, hashlib.sha256(raw).hexdigest(),
                           ExecutionTaskRegistry.key(request), canonical_body_hash(request))

    def _admit(self, request: ExecuteRequest) -> bool:
        run_id = request.scope.run_id
        identity = self._identity(request)
        previous = self._generations.get(run_id)
        if previous is not None:
            if previous != identity:
                raise DomainExecutionError("RUN_GENERATION_UNVERIFIED")
            return False
        if len(self._generations) >= 4096:
            raise DomainExecutionError("EXECUTION_CAPACITY_EXCEEDED")
        revision = json.loads(identity.key)[1]
        start_generation = getattr(self.store, "start_generation", None)
        resume_generation = getattr(self.store, "resume_generation", None)
        generation_spi = callable(start_generation) and callable(resume_generation)
        sequence_base = 0
        if revision > 0:
            # Validate even when an older custom RunStore is injected; an
            # oversized signed revision must never fall back to unbounded IDs.
            try:
                sequence_base, _ = generation_sequence_range(revision)
            except InvalidTransitionError:
                raise DomainExecutionError("INVALID_REQUEST") from None
        if revision > 0 and generation_spi:
            projection, created = start_generation(request.scope, request.idempotency_key, revision)
            if created and (projection is None or projection.run_id != run_id
                    or self._scope_identity(projection.scope) != identity.scope
                    or projection.idempotency_key != request.idempotency_key
                    or projection.status != RUNNING or projection.error is not None or projection.output
                    or not projection.events or projection.events[-1].run_id != run_id
                    or projection.events[-1].seq != sequence_base + 1
                    or projection.events[-1].event_type != "accepted"):
                raise DomainExecutionError("RUN_GENERATION_UNVERIFIED")
        else:
            _, created = self.store.start_run(request)
        if not created:
            # A durable row does not establish exit proof from another process.
            raise DomainExecutionError("RUN_GENERATION_UNVERIFIED")
        self._generations[run_id] = identity
        self._origins[run_id] = request.operation
        return True

    def finalize_response(self, request: ExecuteRequest, response: ExecuteResponse) -> ExecuteResponse:
        """Called by transport only after its registry has observed task exit.

        The business hook cannot supply this receipt. Ordinary waiting states,
        expired leases, and unknown generations never establish exit evidence.
        """
        response = response.model_copy(update={"handoff": None, "agent_group_handoff": None})
        if response.status == "failed":
            return self._finalize_preflight_rejection(request, response)
        if response.status != WAITING:
            return response
        run_id = request.scope.run_id
        identity = self._generations.get(run_id)
        pause = self._pauses.get(run_id)
        group_pause = self._group_pauses.get(run_id)
        record = self.store.get_run(run_id)
        if (response.run_id != run_id or identity is None or identity != self._identity(request)
                or (pause is None) == (group_pause is None) or record is None
                or record.status != WAITING or not self.registry.has_generation_exit_proof(identity.key)):
            raise DomainExecutionError("RUN_HANDOFF_UNCONFIRMED")
        if ((pause is not None and pause[0] != identity.key)
                or (group_pause is not None and group_pause[0] != identity.key)):
            raise DomainExecutionError("RUN_HANDOFF_UNCONFIRMED")
        record_scope = json.dumps(record.scope.model_dump(exclude={"trace_id", "authorization_epoch"}),
                                  sort_keys=True, separators=(",", ":"))
        if record_scope != identity.scope or record.idempotency_key != request.idempotency_key or not record.events:
            raise DomainExecutionError("RUN_HANDOFF_UNCONFIRMED")
        try:
            event = normalize_execution_event(record.events[-1])
            validate_event_sequence(event.seq)
        except (TypeError, ValueError):
            raise DomainExecutionError("RUN_HANDOFF_UNCONFIRMED") from None
        expected_event_payload = pause[1] if pause is not None else group_pause[1]["event"]
        if event.run_id != run_id or event.event_type != "waiting" or event.payload != expected_event_payload:
            raise DomainExecutionError("RUN_HANDOFF_UNCONFIRMED")
        if group_pause is not None:
            generation = json.loads(identity.key)
            if self._origins.get(run_id) not in {"invoke", "run"}:
                raise DomainExecutionError("RUN_HANDOFF_UNCONFIRMED")
            try:
                sequence_base, sequence_limit = generation_sequence_range(generation[1])
            except InvalidTransitionError:
                raise DomainExecutionError("RUN_HANDOFF_UNCONFIRMED") from None
            if not sequence_base < event.seq <= sequence_limit:
                raise DomainExecutionError("RUN_HANDOFF_UNCONFIRMED")
            try:
                receipt = AgentGroupHandoff(
                    version="sdk-agent-group-exit/v1", run_id=run_id,
                    execution_revision=generation[1], body_hash=identity.body_hash,
                    lease_token_hash=generation[2], input_fingerprint=identity.business_hash,
                    origin_operation=self._origins[run_id], group_key=group_pause[1]["group_key"],
                    operation_key=group_pause[1]["operation_key"], last_event_seq=event.seq,
                    checkpoint=group_pause[1]["checkpoint"], child_keys=list(group_pause[1]["child_keys"]),
                )
            except (TypeError, ValueError):
                raise DomainExecutionError("RUN_HANDOFF_UNCONFIRMED") from None
            return response.model_copy(update={"agent_group_handoff": receipt})
        generation = json.loads(identity.key)
        metadata = pause[1]
        receipt = HandlerHandoff(version="sdk-handler-exit/v1", run_id=run_id,
            execution_revision=generation[1], body_hash=identity.body_hash,
            lease_token_hash=generation[2], input_fingerprint=identity.business_hash,
            origin_operation=self._origins[run_id], harness_key=metadata["harness_key"],
            tool_name=metadata["tool_name"], call_id=metadata["call_id"], last_event_seq=event.seq)
        return response.model_copy(update={"handoff": receipt})

    def _finalize_preflight_rejection(
        self, request: ExecuteRequest, response: ExecuteResponse,
    ) -> ExecuteResponse:
        """Return a persisted input/budget rejection after exact generation exit."""
        run_id = request.scope.run_id
        identity = self._generations.get(run_id)
        record = self.store.get_run(run_id)
        error = response.error
        budget = error is not None and error.code == "MODEL_BUDGET_EXCEEDED"
        marker = self._budget_rejections if budget else self._preflight_rejections
        expected_error = (
            AppError(code="MODEL_BUDGET_EXCEEDED", message="governed model budget exhausted", retryable=False)
            if budget else AppError(code="INVALID_REQUEST", message="business request rejected", retryable=False)
        )
        if (identity is None or marker.get(run_id) != identity
                or identity != self._identity(request)
                or self._origins.get(run_id) not in {"invoke", "run"}
                or not self.registry.has_generation_exit_proof(identity.key)
                or response.run_id != run_id or response.status != "failed"
                or response.output_schema != self._output_schema(request) or response.output
                or error is None or error.model_dump() != expected_error.model_dump()):
            raise DomainExecutionError("RUN_RESULT_UNCONFIRMED")
        if (record is None or record.run_id != run_id or record.status != "failed"
                or record.error is None or record.error.model_dump() != error.model_dump()
                or self._scope_identity(record.scope) != identity.scope
                or record.idempotency_key != request.idempotency_key or not record.events):
            raise DomainExecutionError("RUN_RESULT_UNCONFIRMED")
        try:
            event = normalize_execution_event(record.events[-1])
            validate_event_sequence(event.seq)
        except (TypeError, ValueError):
            raise DomainExecutionError("RUN_RESULT_UNCONFIRMED") from None
        if (event.run_id != run_id or event.event_type != "failed"
                or event.payload != {"code": expected_error.code}):
            raise DomainExecutionError("RUN_RESULT_UNCONFIRMED")
        return response

    def _validate_input_for_admission(self, request: ExecuteRequest) -> bool:
        """Validate pure business input; only its exact rejection is terminalized."""
        if self.validate_input is None:
            return False
        try:
            self.validate_input(request)
            return False
        except DomainExecutionError as exc:
            if exc.code != "INVALID_REQUEST":
                raise
            return True

    def _record_preflight_rejection(self, request: ExecuteRequest) -> ExecuteResponse:
        """Persist the exact admitted generation's zero-side-effect input failure."""
        run_id = request.scope.run_id
        identity = self._generations.get(run_id)
        record = self.store.get_run(run_id)
        if (identity is None or identity != self._identity(request) or record is None
                or record.status != RUNNING or self._scope_identity(record.scope) != identity.scope
                or record.idempotency_key != request.idempotency_key):
            raise DomainExecutionError("RUN_GENERATION_UNVERIFIED")
        error = AppError(code="INVALID_REQUEST", message="business request rejected", retryable=False)
        self.store.fail(run_id, error)
        failed = self.store.get_run(run_id)
        if (failed is None or failed.status != "failed" or failed.error is None
                or failed.error.model_dump() != error.model_dump() or not failed.events):
            raise DomainExecutionError("RUN_RESULT_UNCONFIRMED")
        try:
            event = normalize_execution_event(failed.events[-1])
            validate_event_sequence(event.seq)
        except (TypeError, ValueError):
            raise DomainExecutionError("RUN_RESULT_UNCONFIRMED") from None
        if event.run_id != run_id or event.event_type != "failed" or event.payload != {"code": "INVALID_REQUEST"}:
            raise DomainExecutionError("RUN_RESULT_UNCONFIRMED")
        self._preflight_rejections[run_id] = identity
        return ExecuteResponse(run_id=run_id, status="failed", output_schema=self._output_schema(request),
                               error=error)

    def _response(self, request: ExecuteRequest) -> ExecuteResponse:
        record = self.store.get_run(request.scope.run_id)
        if record is None:
            raise DomainExecutionError("RUN_RESULT_UNCONFIRMED")
        if record.status != RUNNING and not self.registry.has_generation_exit_proof(
                self._generations[request.scope.run_id].key):
            raise DomainExecutionError("RUN_RESULT_UNCONFIRMED")
        return ExecuteResponse(run_id=record.run_id, status=record.status,
                               output_schema=self._output_schema(request),
                               output=record.output, error=record.error)

    async def invoke(self, request: ExecuteRequest) -> ExecuteResponse:
        await self.authorize_current(request)
        rejected = self._validate_input_for_admission(request)
        if not self._admit(request):
            return self._response(request)
        if rejected:
            return self._record_preflight_rejection(request)
        # The Factory supervises this hook; do not register it a second time.
        return await self._execute(request)

    async def run(self, request: ExecuteRequest) -> ExecuteResponse:
        await self.authorize_current(request)
        rejected = self._validate_input_for_admission(request)
        if not self._admit(request):
            return self._response(request)
        if rejected:
            async def record_rejection() -> ExecuteResponse:
                return self._record_preflight_rejection(request)
            # This route normally acknowledges background execution. A pure
            # input rejection is synchronous and uses the same real Registry
            # exit proof as invoke before returning a terminal response.
            return await self.registry.execute(request, record_rejection)
        try:
            await self.registry.start_background(request, lambda: self._execute(request))
        except Exception as exc:
            record = self.store.get_run(request.scope.run_id)
            if record is not None and record.status == RUNNING:
                self.store.fail(request.scope.run_id, classify_execution_error(exc)[1])
            raise
        return ExecuteResponse(run_id=request.scope.run_id, status="accepted")

    async def resume(self, run_id: str, request: ExecuteRequest,
                     verified: bool, resume_input: dict[str, Any]) -> ExecuteResponse:
        if (not verified or request.operation != "resume" or not isinstance(resume_input, dict)
                or request.resume_input != resume_input):
            raise DomainExecutionError("INVALID_REQUEST")
        await self.authorize_current(request)
        if self.validate_input is not None:
            self.validate_input(request)
        identity = self._identity(request)
        current_revision = json.loads(identity.key)[1]
        if current_revision > 0:
            try:
                generation_sequence_range(current_revision)
            except InvalidTransitionError:
                raise DomainExecutionError("RUN_RESUME_UNCONFIRMED") from None
        previous = self._generations.get(run_id)
        if run_id != request.scope.run_id:
            raise DomainExecutionError("RUN_GENERATION_UNVERIFIED")
        if resume_input.get("version") in ("runtime-recovery/v1","runtime-recovery/v2"):
            return await self._resume_runtime_recovery(
                request, identity, current_revision, previous, resume_input,
            )
        if resume_input.get("version") == "agent-group-resume/v1":
            return await self._resume_agent_group(
                request, identity, current_revision, previous, resume_input,
            )
        if previous is None:
            await self._restore_waiting(request, identity, resume_input)
            return await self._execute(request)
        if (previous.scope != identity.scope
            or previous.business_hash != identity.business_hash):
            raise DomainExecutionError("RUN_GENERATION_UNVERIFIED")
        if previous.key == identity.key:
            if previous.body_hash != identity.body_hash:
                raise DomainExecutionError("RUN_GENERATION_UNVERIFIED")
            return self._response(request)
        old_key, new_key = json.loads(previous.key), json.loads(identity.key)
        record = self.store.get_run(run_id)
        if (record is None or record.status != WAITING or new_key[1] <= old_key[1]
            or new_key[2] == old_key[2]
            or not self.registry.has_generation_exit_proof(previous.key)):
            raise DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        start_generation = getattr(self.store, "start_generation", None)
        resume_generation = getattr(self.store, "resume_generation", None)
        generation_spi = callable(start_generation) and callable(resume_generation)
        generation_base = 0
        if new_key[1] > 0:
            try:
                generation_base, _ = generation_sequence_range(new_key[1])
            except InvalidTransitionError:
                raise DomainExecutionError("RUN_RESUME_UNCONFIRMED") from None
        previous_last_seq = record.events[-1].seq if record.events else 0
        if new_key[1] > 0 and generation_spi:
            if generation_base < previous_last_seq:
                raise DomainExecutionError("RUN_RESUME_UNCONFIRMED")
            try:
                resume_generation(request.scope, request.idempotency_key, new_key[1])
            except Exception:
                raise DomainExecutionError("RUN_RESUME_UNCONFIRMED") from None
        else:
            self.store.resume(run_id, {"operation": "resume"})
        record = self.store.get_run(run_id)
        if (record is None or record.run_id != run_id
                or self._scope_identity(record.scope) != identity.scope
                or record.idempotency_key != request.idempotency_key or record.status != RUNNING):
            raise DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        if new_key[1] > 0 and generation_spi:
            expected_seq = max(generation_base, previous_last_seq) + 1
            if (not record.events or record.events[-1].run_id != run_id
                    or record.events[-1].seq != expected_seq
                    or record.events[-1].event_type != "started"):
                raise DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        self._generations[run_id] = identity
        self._pauses.pop(run_id, None)
        self._group_pauses.pop(run_id, None)
        return await self._execute(request)

    @staticmethod
    def _runtime_recovery_reference(
        request: ExecuteRequest, identity: _Generation, execution_revision: int,
        resume_input: dict[str, Any],
        *, maximum_checkpoints: int = 128,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], tuple[AgentGroupHandoff, list[dict[str, Any]]] | None]:
        deny = lambda: DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        required = {"version", "origin_operation", "reference"}
        allowed = required | {"confirmation_token", "group_resume", "business_review"}
        if (not required.issubset(resume_input) or set(resume_input) - allowed
                or resume_input.get("version") != "runtime-recovery/v1"
                or ("confirmation_token" in resume_input and "group_resume" in resume_input)):
            raise deny()
        origin_operation = resume_input.get("origin_operation")
        if (not isinstance(origin_operation, str)
                or ("group_resume" not in resume_input and origin_operation != "invoke")
                or ("group_resume" in resume_input and origin_operation not in {"invoke", "run"})):
            raise deny()
        if "confirmation_token" in resume_input:
            token = resume_input["confirmation_token"]
            if not isinstance(token, str) or not token or len(token.encode("utf-8")) > 8192:
                raise deny()

        ref = resume_input["reference"]
        fields = {
            "version", "run_id", "stopped_revision", "ready_revision", "operation",
            "body_hash", "policy_hash", "lease_token_hash", "request_hash",
            "resume_input_hash", "source", "checkpoints",
        }
        optional = {"proof_digest", "runtime_id"}
        if (not isinstance(ref, dict) or not fields.issubset(ref)
                or set(ref) - fields - optional
                or ref.get("version") != "runtime-recovery-stop/v1"
                or ref.get("run_id") != request.scope.run_id
                or not isinstance(ref.get("operation"), str)
                or ref.get("operation") not in {"invoke", "run", "resume"}):
            raise deny()
        if "business_review" in resume_input:
            review = resume_input["business_review"]
            if (ref.get("operation") != "resume" or "confirmation_token" in resume_input or "group_resume" in resume_input
                    or not isinstance(review, dict) or set(review) != {"decision", "reviewer_id"}
                    or review.get("decision") not in {"approve", "reject", "request_changes"}
                    or not isinstance(review.get("reviewer_id"), str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", review["reviewer_id"]) is None
                    or review["reviewer_id"] == request.scope.principal_id):
                raise deny()
        stopped, ready = ref.get("stopped_revision"), ref.get("ready_revision")
        if (type(stopped) is not int or type(ready) is not int
                or ready != stopped + 2 or execution_revision != ready + 1):
            raise deny()
        try:
            generation_sequence_range(stopped)
            generation_sequence_range(ready)
            generation_sequence_range(execution_revision)
        except InvalidTransitionError:
            raise deny() from None

        current = json.loads(identity.key)
        digests = ("body_hash", "policy_hash", "lease_token_hash", "request_hash", "resume_input_hash")
        if any(not isinstance(ref.get(key), str)
               or re.fullmatch(r"[a-f0-9]{64}", ref[key]) is None for key in digests):
            raise deny()
        if ref["lease_token_hash"] == current[2]:
            raise deny()
        policy = request.input.get("policy_snapshot")
        if (not isinstance(policy, dict)
                or not isinstance(policy.get("content_hash"), str)
                or re.fullmatch(r"[a-f0-9]{64}", policy["content_hash"]) is None
                or ref["policy_hash"] != policy["content_hash"]):
            raise deny()

        source = ref.get("source")
        if source == "sdk-cancel-exit/v1":
            if "proof_digest" in ref or "runtime_id" in ref:
                raise deny()
        elif source == "runtime-process-stop/v1":
            if any(not isinstance(ref.get(key), str)
                   or re.fullmatch(r"[a-f0-9]{64}", ref[key]) is None
                   for key in ("proof_digest", "runtime_id")):
                raise deny()
        else:
            raise deny()

        checkpoints = ref.get("checkpoints")
        if maximum_checkpoints not in {128, 8192} or not isinstance(checkpoints, list) or not 1 <= len(checkpoints) <= maximum_checkpoints:
            raise deny()
        checkpoint_fields = {
            "state_key", "revision", "schema_id", "content_hash",
            "execution_revision", "expires_at",
        }
        previous_key = ""
        now = datetime.now(timezone.utc)
        for checkpoint in checkpoints:
            if not isinstance(checkpoint, dict) or set(checkpoint) != checkpoint_fields:
                raise deny()
            state_key, content_hash = checkpoint.get("state_key"), checkpoint.get("content_hash")
            schema_id, expiry = checkpoint.get("schema_id"), checkpoint.get("expires_at")
            state_revision, state_execution_revision = checkpoint.get("revision"), checkpoint.get("execution_revision")
            if (not isinstance(state_key, str) or re.fullmatch(r"[a-f0-9]{64}", state_key) is None
                    or state_key <= previous_key
                    or not isinstance(content_hash, str) or re.fullmatch(r"[a-f0-9]{64}", content_hash) is None
                    or not _safe_group_schema(schema_id)
                    or type(state_revision) is not int or not 1 <= state_revision <= 4096
                    or type(state_execution_revision) is not int
                    or not 1 <= state_execution_revision <= stopped
                    or not isinstance(expiry, str)):
                raise deny()
            try:
                expires_at = datetime.fromisoformat(
                    expiry[:-1] + "+00:00" if expiry.endswith("Z") else expiry
                )
            except ValueError:
                raise deny() from None
            if expires_at.tzinfo is None or expires_at.utcoffset() is None or expires_at <= now:
                raise deny()
            previous_key = state_key
        group_resume = None
        if "group_resume" in resume_input:
            group_resume = ExecutionLifecycle._runtime_group_resume_parts(
                request, identity, ref, origin_operation,
                resume_input["group_resume"], checkpoints,
            )
        return ref, checkpoints, group_resume

    @staticmethod
    def _runtime_group_resume_parts(
        request: ExecuteRequest, identity: _Generation, runtime_reference: dict[str, Any],
        runtime_origin: str, value: Any, runtime_checkpoints: list[dict[str, Any]],
    ) -> tuple[AgentGroupHandoff, list[dict[str, Any]]]:
        """Validate an older committed group-wait reference without treating it as stop proof."""
        deny = lambda: DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        fields = {"version", "origin_operation", "waiting_revision", "handoff", "checkpoints"}
        if (not isinstance(value, dict) or set(value) != fields
                or value.get("version") != "agent-group-resume/v1"):
            raise deny()
        try:
            receipt = AgentGroupHandoff.model_validate(value["handoff"])
        except (TypeError, ValueError):
            raise deny() from None
        waiting_revision = value.get("waiting_revision")
        stopped_revision = runtime_reference.get("stopped_revision")
        if (receipt.run_id != request.scope.run_id
                or receipt.input_fingerprint != identity.business_hash
                or value.get("origin_operation") != runtime_origin
                or value.get("origin_operation") != receipt.origin_operation
                or type(waiting_revision) is not int
                or waiting_revision != receipt.execution_revision + 1
                or type(stopped_revision) is not int
                or waiting_revision + 2 > stopped_revision
                or receipt.checkpoint.execution_revision != receipt.execution_revision
                or receipt.checkpoint.schema_id != "schema://agentplug/agent-group/v1"):
            raise deny()
        current_key = json.loads(identity.key)
        try:
            old_base, old_limit = generation_sequence_range(receipt.execution_revision)
            group_resume_base, _ = generation_sequence_range(waiting_revision + 2)
            expected_state_key = _expected_agent_group_state_key(request.scope, receipt.group_key)
        except (InvalidTransitionError, TypeError, ValueError):
            raise deny() from None
        if (not old_base < receipt.last_event_seq <= old_limit
                or group_resume_base < receipt.last_event_seq
                or receipt.checkpoint.state_key != expected_state_key
                or receipt.lease_token_hash == current_key[2]):
            raise deny()

        historical_values = value.get("checkpoints")
        checkpoint_fields = {"state_key", "revision", "schema_id", "content_hash",
                             "execution_revision", "expires_at"}
        if not isinstance(historical_values, list) or not 1 <= len(historical_values) <= 128:
            raise deny()
        historical: list[dict[str, Any]] = []
        previous_key = ""
        for checkpoint in historical_values:
            if not isinstance(checkpoint, dict) or set(checkpoint) != checkpoint_fields:
                raise deny()
            state_key, schema_id = checkpoint.get("state_key"), checkpoint.get("schema_id")
            content_hash, expiry = checkpoint.get("content_hash"), checkpoint.get("expires_at")
            revision, state_execution_revision = checkpoint.get("revision"), checkpoint.get("execution_revision")
            if (not isinstance(state_key, str) or re.fullmatch(r"[a-f0-9]{64}", state_key) is None
                    or state_key <= previous_key
                    or not _safe_group_schema(schema_id)
                    or not isinstance(content_hash, str) or re.fullmatch(r"[a-f0-9]{64}", content_hash) is None
                    or type(revision) is not int or not 1 <= revision <= 4096
                    or type(state_execution_revision) is not int
                    or not 1 <= state_execution_revision <= receipt.execution_revision
                    or not isinstance(expiry, str)):
                raise deny()
            try:
                expires_at = datetime.fromisoformat(
                    expiry[:-1] + "+00:00" if expiry.endswith("Z") else expiry
                )
            except ValueError:
                raise deny() from None
            if expires_at.tzinfo is None or expires_at.utcoffset() is None:
                raise deny()
            historical.append(dict(checkpoint))
            previous_key = state_key

        group_reference = receipt.checkpoint.model_dump()
        if sum(checkpoint == group_reference for checkpoint in historical) != 1:
            raise deny()
        matching_current = [checkpoint for checkpoint in runtime_checkpoints
                            if checkpoint["state_key"] == receipt.checkpoint.state_key]
        if len(matching_current) != 1 or matching_current[0] != group_reference:
            raise deny()
        return receipt, historical

    @staticmethod
    def _verify_recovery_checkpoint_response(
        reference: dict[str, Any], result: Any,
    ) -> None:
        deny = lambda: DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        if (not isinstance(result, dict) or set(result) - {"checkpoint_history"} != {"state_key", "checkpoint"}
                or result.get("state_key") != reference["state_key"]):
            raise deny()
        checkpoint = result.get("checkpoint")
        expected_checkpoint_fields = {
            "revision", "schema_id", "value", "content_hash",
            "execution_revision", "expires_at",
        }
        if (not isinstance(checkpoint, dict) or set(checkpoint) != expected_checkpoint_fields
                or not isinstance(checkpoint.get("value"), dict)):
            raise deny()
        expected_fields = (
            "revision", "schema_id", "content_hash", "execution_revision", "expires_at",
        )
        if any(checkpoint.get(key) != reference[key] for key in expected_fields):
            raise deny()
        if (type(checkpoint.get("revision")) is not int
                or type(checkpoint.get("execution_revision")) is not int):
            raise deny()
        from .checkpoint_capacity import reply_limit
        if not 1 <= checkpoint["revision"] <= reply_limit(result):
            raise deny()
        # Compare instants as timestamps while retaining exact string type/shape
        # checks from the signed reference validator above.
        raw_expiry = checkpoint.get("expires_at")
        if not isinstance(raw_expiry, str):
            raise deny()
        try:
            expires_at = datetime.fromisoformat(
                raw_expiry[:-1] + "+00:00" if raw_expiry.endswith("Z") else raw_expiry
            )
            reference_expiry = datetime.fromisoformat(
                reference["expires_at"][:-1] + "+00:00"
                if reference["expires_at"].endswith("Z") else reference["expires_at"]
            )
        except ValueError:
            raise deny() from None
        if (expires_at.tzinfo is None or reference_expiry.tzinfo is None
                or expires_at.utcoffset() is None or reference_expiry.utcoffset() is None
                or expires_at != reference_expiry or expires_at <= datetime.now(timezone.utc)):
            raise deny()

    @staticmethod
    def _agent_group_resume_parts(
        request: ExecuteRequest, identity: _Generation, execution_revision: int,
        resume_input: dict[str, Any],
    ) -> tuple[AgentGroupHandoff, list[dict[str, Any]]]:
        deny = lambda: DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        if (set(resume_input) != {"version", "origin_operation", "waiting_revision", "handoff", "checkpoints"}
                or resume_input.get("version") != "agent-group-resume/v1"):
            raise deny()
        try:
            receipt = AgentGroupHandoff.model_validate(resume_input["handoff"])
        except (TypeError, ValueError):
            raise deny() from None
        waiting_revision = resume_input.get("waiting_revision")
        if (receipt.run_id != request.scope.run_id
                or receipt.input_fingerprint != identity.business_hash
                or resume_input.get("origin_operation") != receipt.origin_operation
                or type(waiting_revision) is not int
                or waiting_revision != receipt.execution_revision + 1
                or execution_revision != waiting_revision + 2
                or receipt.checkpoint.execution_revision != receipt.execution_revision
                or receipt.checkpoint.schema_id != "schema://agentplug/agent-group/v1"):
            raise deny()
        current_key = json.loads(identity.key)
        try:
            expected_state_key = _expected_agent_group_state_key(request.scope, receipt.group_key)
        except (TypeError, ValueError):
            raise deny() from None
        if receipt.lease_token_hash == current_key[2] or receipt.checkpoint.state_key != expected_state_key:
            raise deny()
        try:
            old_base, old_limit = generation_sequence_range(receipt.execution_revision)
            new_base, _ = generation_sequence_range(execution_revision)
        except InvalidTransitionError:
            raise deny() from None
        if (not old_base < receipt.last_event_seq <= old_limit
                or new_base < receipt.last_event_seq):
            raise deny()

        checkpoint_values = resume_input.get("checkpoints")
        fields = {"state_key", "revision", "schema_id", "content_hash",
                  "execution_revision", "expires_at"}
        if not isinstance(checkpoint_values, list) or not 1 <= len(checkpoint_values) <= 128:
            raise deny()
        checkpoints: list[dict[str, Any]] = []
        previous_key = ""
        now = datetime.now(timezone.utc)
        for item in checkpoint_values:
            if not isinstance(item, dict) or set(item) != fields:
                raise deny()
            state_key, schema_id = item.get("state_key"), item.get("schema_id")
            content_hash, expiry = item.get("content_hash"), item.get("expires_at")
            state_revision, state_execution_revision = item.get("revision"), item.get("execution_revision")
            if (not isinstance(state_key, str) or re.fullmatch(r"[a-f0-9]{64}", state_key) is None
                    or state_key <= previous_key
                    or not isinstance(schema_id, str) or not schema_id.startswith("schema://")
                    or len(schema_id) <= len("schema://") or len(schema_id) > 256
                    or any(character in schema_id for character in "\x00\r\n\t* ")
                    or not isinstance(content_hash, str) or re.fullmatch(r"[a-f0-9]{64}", content_hash) is None
                    or type(state_revision) is not int or not 1 <= state_revision <= 4096
                    or type(state_execution_revision) is not int
                    or not 1 <= state_execution_revision <= receipt.execution_revision
                    or not isinstance(expiry, str)):
                raise deny()
            try:
                expires_at = datetime.fromisoformat(
                    expiry[:-1] + "+00:00" if expiry.endswith("Z") else expiry
                )
            except ValueError:
                raise deny() from None
            if (expires_at.tzinfo is None or expires_at.utcoffset() is None
                    or expires_at <= now):
                raise deny()
            checkpoints.append(dict(item))
            previous_key = state_key
        group_ref = receipt.checkpoint.model_dump()
        if sum(item == group_ref for item in checkpoints) != 1:
            raise deny()
        return receipt, checkpoints

    @staticmethod
    def _agent_group_checkpoint_state(
        value: Any, group_key: str, operation_key: str, input_fingerprint: str,
        child_keys: tuple[str, ...] | list[str], parent_run_id: str,
    ) -> None:
        deny = lambda: DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        fields = {"version", "group_key", "operation_key", "parent_run_id", "input_hash",
                  "input_fingerprint", "phase", "ordinal", "targets", "bindings", "child_keys"}
        if (not isinstance(value, dict) or set(value) != fields
                or value.get("version") != "agent-group/v1"
                or value.get("group_key") != group_key
                or value.get("operation_key") != operation_key
                or value.get("parent_run_id") != parent_run_id
                or value.get("phase") != "gather"
                or value.get("input_fingerprint") != input_fingerprint
                or not isinstance(value.get("input_hash"), str)
                or re.fullmatch(r"[a-f0-9]{64}", value["input_hash"]) is None):
            raise deny()
        bindings, targets, state_child_keys = value.get("bindings"), value.get("targets"), value.get("child_keys")
        if (not isinstance(bindings, list) or not isinstance(targets, list)
                or not isinstance(state_child_keys, list)
                or type(value.get("ordinal")) is not int
                or value["ordinal"] != len(bindings)
                or len(bindings) != len(child_keys)
                or len(targets) != len(bindings) or state_child_keys != list(child_keys)):
            raise deny()
        seen: set[str] = set()
        for binding, target, child_key in zip(bindings, targets, child_keys):
            if (not isinstance(binding, dict) or set(binding) != {"child_key", "input_fingerprint", "output_schema"}
                    or not isinstance(target, dict) or set(target) != {"input_schema", "output_schema"}
                    or binding.get("child_key") != child_key or child_key in seen
                    or not isinstance(binding.get("input_fingerprint"), str)
                    or re.fullmatch(r"[a-f0-9]{64}", binding["input_fingerprint"]) is None
                    or binding.get("output_schema") != target.get("output_schema")
                    or not _safe_group_schema(target.get("input_schema"))
                    or not _safe_group_schema(target.get("output_schema"))
                    or not _safe_group_schema(binding.get("output_schema"))):
                raise deny()
            seen.add(child_key)

    async def _resume_agent_group(
        self, request: ExecuteRequest, identity: _Generation, execution_revision: int,
        previous: _Generation | None, resume_input: dict[str, Any],
    ) -> ExecuteResponse:
        deny = lambda: DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        receipt, checkpoints = self._agent_group_resume_parts(
            request, identity, execution_revision, resume_input,
        )
        replay = await self._same_generation_runtime_replay(
            request, identity, previous, receipt.origin_operation, (receipt, checkpoints),
        )
        if replay is not None:
            return replay
        if self.load_recovery_checkpoint is None:
            raise deny()

        group_state: Any = None
        try:
            for reference in checkpoints:
                loaded = await self.load_recovery_checkpoint(request, dict(reference))
                self._verify_recovery_checkpoint_response(reference, loaded)
                if reference["state_key"] == receipt.checkpoint.state_key:
                    checkpoint = loaded["checkpoint"]
                    if any(checkpoint.get(key) != value for key, value in receipt.checkpoint.model_dump().items()
                           if key != "state_key"):
                        raise deny()
                    group_state = checkpoint.get("value")
        except DomainExecutionError:
            raise
        except Exception:
            raise deny() from None
        if group_state is None:
            raise deny()
        self._agent_group_checkpoint_state(
            group_state, receipt.group_key, receipt.operation_key,
            receipt.input_fingerprint, receipt.child_keys, request.scope.run_id,
        )
        # Re-evaluate the signed caller's current authority after all current
        # public State reads and before returning or changing the local store.
        await self.authorize_current(request)

        run_id = request.scope.run_id
        if previous is not None and previous.key == identity.key:
            record = self.store.get_run(run_id)
            if (previous != identity or previous.body_hash != identity.body_hash
                    or self._origins.get(run_id) != receipt.origin_operation
                    or record is None or record.status == RUNNING
                    or not self.registry.has_generation_exit_proof(identity.key)):
                raise deny()
            # Exact same-generation command replay is read-only. A waiting
            # response receives a fresh supervised receipt in finalize_response.
            return self._response(request)

        if self.registry.has_other_active_generation(request):
            raise deny()
        prior = self.store.get_run(run_id)
        generation = json.loads(identity.key)
        start_generation = getattr(self.store, "start_generation", None)
        resume_generation = getattr(self.store, "resume_generation", None)
        adopt_waiting = getattr(self.store, "adopt_waiting", None)
        if not callable(start_generation) or not callable(resume_generation):
            raise deny()
        if previous is None:
            if prior is not None or not callable(adopt_waiting):
                raise deny()
            previous_events: tuple[Any, ...] = ()
        else:
            try:
                old_key = json.loads(previous.key)
            except (TypeError, ValueError):
                raise deny() from None
            local_pause = self._group_pauses.get(run_id)
            if (not isinstance(old_key, list) or len(old_key) != 3
                    or type(old_key[1]) is not int or not isinstance(old_key[2], str)
                    or previous.scope != identity.scope
                    or previous.business_hash != identity.business_hash
                    or previous.body_hash != receipt.body_hash
                    or old_key[1] != receipt.execution_revision
                    or old_key[2] != receipt.lease_token_hash
                    or self._origins.get(run_id) != receipt.origin_operation
                    or not self.registry.has_generation_exit_proof(previous.key)
                    or prior is None or prior.status != WAITING or local_pause is None
                    or local_pause[0] != previous.key):
                raise deny()
            local = local_pause[1]
            if (local.get("group_key") != receipt.group_key
                    or local.get("operation_key") != receipt.operation_key
                    or tuple(local.get("child_keys", ())) != tuple(receipt.child_keys)
                    or not isinstance(local.get("checkpoint"), RecoveryCheckpointReference)
                    or local["checkpoint"].model_dump() != receipt.checkpoint.model_dump()):
                raise deny()
            previous_events = tuple(prior.events)
            if not previous_events:
                raise deny()
            try:
                last = normalize_execution_event(previous_events[-1])
                validate_event_sequence(last.seq)
            except (TypeError, ValueError):
                raise deny() from None
            if (last.run_id != run_id or last.seq != receipt.last_event_seq
                    or last.event_type != "waiting"
                    or last.payload != local.get("event")):
                raise deny()
        if (prior is not None and (previous is None
                or prior.run_id != run_id
                or self._scope_identity(prior.scope) != identity.scope
                or prior.idempotency_key != request.idempotency_key
                or prior.status != WAITING or prior.output or prior.error is not None)):
            raise deny()
        try:
            base, limit = generation_sequence_range(generation[1])
        except InvalidTransitionError:
            raise deny() from None
        if base < receipt.last_event_seq:
            raise deny()

        # No await separates final conflict/exit checks, Store mutation and
        # registration. adopt_waiting imports no old events or result body.
        if (self._generations.get(run_id) is not previous
                or self.registry.has_other_active_generation(request)
                or (previous is not None and not self.registry.has_generation_exit_proof(previous.key))
                or (previous is None and self.store.get_run(run_id) is not None)):
            raise deny()
        if len(self._generations) >= 4096 and run_id not in self._generations:
            raise DomainExecutionError("EXECUTION_CAPACITY_EXCEEDED")
        if previous is None:
            try:
                projection = adopt_waiting(request.scope, request.idempotency_key, receipt.last_event_seq)
            except Exception:
                raise deny() from None
            if (projection is None or projection.run_id != run_id
                    or self._scope_identity(projection.scope) != identity.scope
                    or projection.idempotency_key != request.idempotency_key
                    or projection.status != WAITING or projection.output or projection.error is not None
                    or projection.events):
                raise deny()
            previous_events = tuple(projection.events)
        try:
            resume_generation(request.scope, request.idempotency_key, generation[1])
        except Exception:
            raise deny() from None
        projection = self.store.get_run(run_id)
        try:
            started = normalize_execution_event(projection.events[-1]) if projection and projection.events else None
            expected_sequence = max(base, receipt.last_event_seq) + 1
        except (TypeError, ValueError, InvalidTransitionError):
            raise deny() from None
        if (projection is None or projection.run_id != run_id
                or self._scope_identity(projection.scope) != identity.scope
                or projection.idempotency_key != request.idempotency_key
                or projection.status != RUNNING or projection.output or projection.error is not None
                or tuple(projection.events[:-1]) != previous_events
                or started is None or started.run_id != run_id or started.seq != expected_sequence
                or started.seq > limit or started.event_type != "started"
                or started.payload != {"operation": "resume"}):
            raise deny()
        self._generations[run_id] = identity
        self._origins[run_id] = receipt.origin_operation
        self._pauses.pop(run_id, None)
        self._group_pauses.pop(run_id, None)
        binding = AgentGroupResumeBinding(
            run_id=run_id, execution_revision=execution_revision,
            group_key=receipt.group_key, operation_key=receipt.operation_key,
            input_fingerprint=receipt.input_fingerprint,
            input_hash=group_state["input_hash"], child_keys=tuple(receipt.child_keys),
            checkpoint=receipt.checkpoint.model_dump(),
        )
        context_token = current_agent_group_resume.set(binding)
        try:
            response = await self._execute(request)
            if not binding.gathered or binding.pause_required:
                raise deny()
            return response
        finally:
            current_agent_group_resume.reset(context_token)

    def _output_schema(self,request):
        value=self.output_schema_selector(request) if self.output_schema_selector else self.output_schema
        if not isinstance(value,str) or not value.startswith("schema://") or len(value)>256:
            raise DomainExecutionError("OUTPUT_SCHEMA_INVALID")
        return value

    async def _runtime_parts(self,request,identity,revision,resume_input):
        maximum=128
        if resume_input.get("version")=="runtime-recovery/v2":
            if self.load_recovery_reference_page is None: raise DomainExecutionError("RUN_RESUME_UNCONFIRMED")
            await self.authorize_current(request)
            from .checkpoint_reference_set import expand_reference_set
            async def fetch(group,offset,limit):
                return await self.load_recovery_reference_page(request,group,offset,limit)
            resume_input=await expand_reference_set(resume_input,fetch)
            maximum=8192
        return self._runtime_recovery_reference(request,identity,revision,resume_input,maximum_checkpoints=maximum)

    async def _resume_runtime_recovery(
        self, request: ExecuteRequest, identity: _Generation, execution_revision: int,
        previous: _Generation | None, resume_input: dict[str, Any],
    ) -> ExecuteResponse:
        deny = lambda: DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        ref, checkpoints, group_resume = await self._runtime_parts(request,identity,execution_revision,resume_input)
        run_id = request.scope.run_id
        expected_origin = group_resume[0].origin_operation if group_resume is not None else "invoke"
        replay = await self._same_generation_runtime_replay(
            request, identity, previous, expected_origin, group_resume,
        )
        if replay is not None:
            return replay

        group_state: dict[str, Any] | None = None
        checkpoints_loaded = False
        checkpoint_snapshots: dict[str, RecoveryCheckpointSnapshot] = {}
        group_snapshot: RecoveryCheckpointSnapshot | None = None
        if group_resume is not None:
            if self.load_recovery_checkpoint is None:
                raise deny()
            group_receipt, _historical_group_checkpoints = group_resume
            try:
                for checkpoint_ref in checkpoints:
                    loaded = await self.load_recovery_checkpoint(request, dict(checkpoint_ref))
                    self._verify_recovery_checkpoint_response(checkpoint_ref, loaded)
                    snapshot = RecoveryCheckpointSnapshot(dict(checkpoint_ref), loaded)
                    checkpoint_snapshots[checkpoint_ref["state_key"]] = snapshot
                    if checkpoint_ref["state_key"] == group_receipt.checkpoint.state_key:
                        group_snapshot = snapshot
                        group_state = loaded["checkpoint"].get("value")
            except DomainExecutionError:
                raise
            except Exception:
                raise deny() from None
            if not isinstance(group_state, dict):
                raise deny()
            self._agent_group_checkpoint_state(
                group_state, group_receipt.group_key, group_receipt.operation_key,
                group_receipt.input_fingerprint, group_receipt.child_keys, run_id,
            )
            # The nested SDK handoff is only a frozen gather binding. Actual
            # old-generation stop proof remains the runtime reference/registry.
            await self.authorize_current(request)
            checkpoints_loaded = True
        if previous is not None and previous.key == identity.key:
            if group_resume is None:
                await self.authorize_current(request)
            record = self.store.get_run(run_id)
            if (previous != identity or self._origins.get(run_id) != expected_origin
                    or record is None or record.status == RUNNING
                    or not self.registry.has_generation_exit_proof(identity.key)):
                raise deny()
            # A duplicate signed command for this exact generation is a
            # permission-checked projection read; never invoke business again.
            return self._response(request)

        if self.load_recovery_checkpoint is None:
            raise deny()
        start_generation = getattr(self.store, "start_generation", None)
        resume_generation = getattr(self.store, "resume_generation", None)
        recover_generation = getattr(self.store, "recover_generation", None)
        if not all(callable(method) for method in
                   (start_generation, resume_generation, recover_generation)):
            raise deny()

        old_key: list[Any] | None = None
        if previous is not None:
            try:
                old_key = json.loads(previous.key)
            except (TypeError, ValueError):
                raise deny() from None
            if (not isinstance(old_key, list) or len(old_key) != 3
                    or type(old_key[1]) is not int or not isinstance(old_key[2], str)
                    or previous.scope != identity.scope
                    or previous.business_hash != identity.business_hash
                    or previous.body_hash != ref["body_hash"]
                    or old_key[1] != ref["stopped_revision"]
                    or old_key[2] != ref["lease_token_hash"]
                    or self._origins.get(run_id) != expected_origin
                    or not self.registry.has_generation_exit_proof(previous.key)):
                raise deny()
        if self.registry.has_other_active_generation(request):
            raise deny()

        prior = self.store.get_run(run_id)
        prior_events: tuple[Any, ...] = ()
        last_sequence = 0
        if prior is not None:
            if (previous is None or prior.run_id != run_id
                    or prior.status not in {"succeeded", "failed", "cancelled"}
                    or self._scope_identity(prior.scope) != identity.scope
                    or prior.idempotency_key != request.idempotency_key):
                raise deny()
            prior_events = prior.events
            if prior_events:
                try:
                    prior_last = normalize_execution_event(prior_events[-1])
                    validate_event_sequence(prior_last.seq)
                except (TypeError, ValueError):
                    raise deny() from None
                if prior_last.run_id != run_id:
                    raise deny()
                last_sequence = prior_last.seq
        elif previous is not None:
            raise deny()

        # State values remain in memory only for validation; they are never
        # copied into RunStore, events, logs, or a response by the adapter.
        if not checkpoints_loaded:
            for checkpoint_ref in checkpoints:
                try:
                    loaded = await self.load_recovery_checkpoint(request, dict(checkpoint_ref))
                except Exception:
                    raise deny() from None
                self._verify_recovery_checkpoint_response(checkpoint_ref, loaded)
                checkpoint_snapshots[checkpoint_ref["state_key"]] = RecoveryCheckpointSnapshot(
                    dict(checkpoint_ref), loaded,
                )

        if self.recovery_checkpoint_selector is None or self.load_checkpoint is None:
            raise deny()
        try:
            plan = self.recovery_checkpoint_selector(
                request, tuple(checkpoint_snapshots.values()), group_snapshot,
            )
            if group_resume is not None and (
                    not isinstance(plan, RecoveryPlan) or not plan.allow_group_resume
                    or plan.allowed_agent_group_key != group_resume[0].group_key):
                raise deny()
            recovery_state = await prepare_runtime_recovery_state(
                request, plan, tuple(checkpoint_snapshots.values()), execution_revision,
                self.load_checkpoint,
                group_identity=(("coordination", group_resume[0].group_key)
                                if group_resume is not None else None),
            )
        except DomainExecutionError:
            raise
        except Exception:
            raise deny() from None
        await self.authorize_current(request)

        # No await separates the final conflict/exit checks, the Store-owned
        # atomic projection replacement, and local generation registration.
        if (self._generations.get(run_id) is not previous
                or self.registry.has_other_active_generation(request)
                or (previous is not None and not self.registry.has_generation_exit_proof(previous.key))):
            raise deny()
        if len(self._generations) >= 4096 and run_id not in self._generations:
            raise DomainExecutionError("EXECUTION_CAPACITY_EXCEEDED")
        try:
            projection = recover_generation(
                request.scope, request.idempotency_key,
                ref["stopped_revision"], execution_revision,
            )
        except Exception:
            raise deny() from None
        try:
            started = normalize_execution_event(projection.events[-1]) if projection.events else None
            expected_sequence = max(generation_sequence_range(execution_revision)[0], last_sequence) + 1
        except (TypeError, ValueError, InvalidTransitionError):
            raise deny() from None
        if (projection.run_id != run_id
                or self._scope_identity(projection.scope) != identity.scope
                or projection.idempotency_key != request.idempotency_key
                or projection.status != RUNNING or projection.error is not None or projection.output
                or len(projection.events) != len(prior_events) + 1
                or tuple(projection.events[:-1]) != tuple(prior_events)
                or started is None or started.run_id != run_id
                or started.seq != expected_sequence or started.event_type != "started"
                or started.payload != {"operation": "resume", "reason": "runtime_recovery"}):
            raise deny()
        self._generations[run_id] = identity
        self._origins[run_id] = expected_origin
        self._pauses.pop(run_id, None)
        self._group_pauses.pop(run_id, None)
        if group_resume is None or group_state is None:
            runtime_token = set_runtime_recovery(recovery_state)
            try:
                return await self._execute(request)
            finally:
                reset_runtime_recovery(runtime_token)
        group_receipt, _historical_group_checkpoints = group_resume
        binding = AgentGroupResumeBinding(
            run_id=run_id, execution_revision=execution_revision,
            group_key=group_receipt.group_key, operation_key=group_receipt.operation_key,
            input_fingerprint=group_receipt.input_fingerprint,
            input_hash=group_state["input_hash"], child_keys=tuple(group_receipt.child_keys),
            checkpoint=group_receipt.checkpoint.model_dump(),
        )
        runtime_token = set_runtime_recovery(recovery_state)
        context_token = current_agent_group_resume.set(binding)
        try:
            return await self._execute(request)
        finally:
            current_agent_group_resume.reset(context_token)
            reset_runtime_recovery(runtime_token)

    async def replay_runtime_recovery(
        self, request: ExecuteRequest, verified: bool,
    ) -> ExecuteResponse:
        """Read the same already-admitted signed runtime/group generation only."""
        deny = lambda: DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        resume_input = request.resume_input
        if (not verified or request.operation != "resume"
                or not isinstance(resume_input, dict)
                or request.resume_input != resume_input):
            raise deny()
        if self.validate_input is not None:
            self.validate_input(request)
        identity = self._identity(request)
        try:
            current_revision = json.loads(identity.key)[1]
            if current_revision > 0:
                generation_sequence_range(current_revision)
        except (IndexError, TypeError, InvalidTransitionError):
            raise deny() from None
        previous = self._generations.get(request.scope.run_id)
        expected_origin = ""
        group_resume = None
        if resume_input.get("version") in ("runtime-recovery/v1","runtime-recovery/v2"):
            # Re-parse every signed stop/business binding, but do not reload old
            # State heads: the exact admitted handler may already have advanced them.
            _, _, group_resume = await self._runtime_parts(request,identity,current_revision,resume_input)
            expected_origin = group_resume[0].origin_operation if group_resume is not None else "invoke"
        elif resume_input.get("version") == "agent-group-resume/v1":
            group_resume = self._agent_group_resume_parts(
                request, identity, current_revision, resume_input,
            )
            expected_origin = group_resume[0].origin_operation
        else:
            raise deny()
        replay = await self._same_generation_runtime_replay(
            request, identity, previous, expected_origin, group_resume,
        )
        if replay is None:
            raise deny()
        return replay

    async def _same_generation_runtime_replay(
        self, request: ExecuteRequest, identity: _Generation,
        previous: _Generation | None, expected_origin: str,
        group_resume: tuple[AgentGroupHandoff, list[dict[str, Any]]] | None,
    ) -> ExecuteResponse | None:
        if previous is None or previous.key != identity.key:
            return None
        deny = lambda: DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        run_id = request.scope.run_id
        if (previous != identity or self._origins.get(run_id) != expected_origin
                or expected_origin not in {"invoke", "run"}
                or (group_resume is not None and (
                    group_resume[0].run_id != run_id
                    or group_resume[0].input_fingerprint != identity.business_hash
                    or group_resume[0].origin_operation != expected_origin))):
            raise deny()
        await self.authorize_current(request)
        replay_state = self.registry.generation_replay_state(identity.key)
        record = self.store.get_run(run_id)
        record_scope = (json.dumps(record.scope.model_dump(exclude={"trace_id", "authorization_epoch"}),
                                   sort_keys=True, separators=(",", ":"))
                        if record is not None else "")
        if (record is None or record.run_id != run_id
                or record_scope != identity.scope
                or record.idempotency_key != request.idempotency_key):
            raise deny()
        if replay_state == "active":
            # Do not reveal a result or attach a stop receipt before actual exit.
            return ExecuteResponse(run_id=run_id, status="running")
        if replay_state != "exited" or (
                record.status not in TERMINAL_STATUSES and record.status != WAITING):
            raise deny()
        # Waiting/terminal disclosure requires the Registry's actual-exit proof.
        return self._response(request)

    async def _restore_waiting(self, request: ExecuteRequest, identity: _Generation,
                               resume_input: dict[str, Any]) -> None:
        """Import only the original exit/checkpoint sealed by signed resume."""
        deny = lambda: DomainExecutionError("RUN_RESUME_UNCONFIRMED")
        adopt = getattr(self.store, "adopt_waiting", None)
        generation = json.loads(identity.key)
        generation_base = 0
        if generation[1] > 0:
            try:
                generation_base, _ = generation_sequence_range(generation[1])
            except InvalidTransitionError:
                raise deny() from None
        start_generation = getattr(self.store, "start_generation", None)
        resume_generation = getattr(self.store, "resume_generation", None)
        generation_spi = callable(start_generation) and callable(resume_generation)
        if (self.load_checkpoint is None or not callable(adopt)
                or self.registry.has_other_active_generation(request)
                or set(resume_input) != {"confirmation_token", "handoff", "checkpoint"}):
            raise deny()
        token = resume_input["confirmation_token"]
        if not isinstance(token, str) or not token or len(token.encode()) > 8192:
            raise deny()
        try:
            receipt = HandlerHandoff.model_validate(resume_input["handoff"])
        except (ValueError, TypeError):
            raise deny() from None
        if (receipt.run_id != request.scope.run_id or receipt.input_fingerprint != identity.business_hash
                or receipt.execution_revision >= generation[1] or receipt.lease_token_hash == generation[2]):
            raise deny()
        if generation_spi and generation_base < receipt.last_event_seq:
            # Check before importing the waiting projection, so an overlap
            # rejection cannot leave a partial local Run behind.
            raise deny()
        reference = resume_input["checkpoint"]
        fields = {"namespace", "key", "schema_id", "revision", "content_hash", "execution_revision"}
        if (not isinstance(reference, dict) or set(reference) != fields
                or reference["namespace"] != "harness" or reference["key"] != receipt.harness_key
                or reference["schema_id"] != "schema://agentplug/harness-loop/v1"
                or type(reference["revision"]) is not int or not 1 <= reference["revision"] <= 4096
                or type(reference["execution_revision"]) is not int
                or reference["execution_revision"] != receipt.execution_revision
                or not isinstance(reference["content_hash"], str)
                or re.fullmatch(r"[a-f0-9]{64}", reference["content_hash"]) is None):
            raise deny()
        # No local-generation lock is held while reading current public State.
        loaded = await self.load_checkpoint(request, "harness", receipt.harness_key, reference["schema_id"])
        checkpoint = loaded.get("checkpoint") if isinstance(loaded, dict) else None
        if (not isinstance(checkpoint, dict)
                or type(checkpoint.get("revision")) is not int or checkpoint["revision"] != reference["revision"]
                or checkpoint.get("schema_id") != reference["schema_id"]
                or checkpoint.get("content_hash") != reference["content_hash"]
                or type(checkpoint.get("execution_revision")) is not int
                or checkpoint["execution_revision"] != receipt.execution_revision):
            raise deny()
        state = checkpoint.get("value")
        pending = state.get("pending") if isinstance(state, dict) else None
        if (not isinstance(state, dict) or state.get("version") != "harness-loop/v1"
                or state.get("phase") != "approval_required" or not isinstance(pending, list)
                or not 1 <= len(pending) <= 16 or not isinstance(pending[0], dict)
                or pending[0].get("name") != receipt.tool_name or pending[0].get("call_id") != receipt.call_id):
            raise deny()
        await self.authorize_current(request)
        # Register without an intervening await; another resume cannot replace
        # a local execution admitted while the external reads were in progress.
        run_id = request.scope.run_id
        if (run_id in self._generations or self.registry.has_other_active_generation(request)
                or self.store.get_run(run_id) is not None):
            raise deny()
        if len(self._generations) >= 4096:
            raise DomainExecutionError("EXECUTION_CAPACITY_EXCEEDED")
        projection = adopt(request.scope, request.idempotency_key, receipt.last_event_seq)
        if (projection is None or projection.run_id != run_id
                or self._scope_identity(projection.scope) != identity.scope
                or projection.idempotency_key != request.idempotency_key or projection.status != WAITING
                or projection.error is not None or projection.output):
            raise deny()
        if projection.events:
            try:
                last = normalize_execution_event(projection.events[-1])
            except (TypeError, ValueError):
                raise deny() from None
            if (last.run_id != run_id or last.seq != receipt.last_event_seq or last.event_type != "waiting"
                    or last.payload.get("reason") != "approval_required"
                    or last.payload.get("harness_key") != receipt.harness_key
                    or last.payload.get("tool_name") != receipt.tool_name
                    or last.payload.get("call_id") != receipt.call_id):
                raise deny()
        if generation[1] > 0 and generation_spi:
            try:
                resume_generation(request.scope, request.idempotency_key, generation[1])
            except Exception:
                raise deny() from None
            next_after_seq = max(receipt.last_event_seq, generation_base)
        else:
            self.store.resume(run_id, {"operation": "resume", "reason": "platform_handoff"})
            next_after_seq = receipt.last_event_seq
        record = self.store.get_run(run_id)
        if (record is None or record.run_id != run_id
                or self._scope_identity(record.scope) != identity.scope
                or record.idempotency_key != request.idempotency_key or record.status != RUNNING):
            raise deny()
        events = self.store.events_after(run_id, next_after_seq)
        try:
            first_event = normalize_execution_event(events[0]) if events else None
        except (TypeError, ValueError):
            raise deny() from None
        if (first_event is None or first_event.run_id != run_id
                or first_event.seq != next_after_seq + 1):
            raise deny()
        self._generations[run_id] = identity
        self._origins[run_id] = receipt.origin_operation
        self._pauses.pop(run_id, None)
        self._group_pauses.pop(run_id, None)

    async def cancel(self, run_id: str, request: ExecuteRequest) -> ExecuteResponse:
        previous = self._generations.get(run_id)
        identity = self._identity(request)
        if (request.operation != "cancel" or run_id != request.scope.run_id or previous is None
            or previous.scope != identity.scope or previous.key != identity.key
            or not self.registry.has_exit_proof(request)):
            raise DomainExecutionError("CANCELLATION_NOT_CONFIRMED")
        # Factory has verified signed cancel and observed actual task exit.
        self.store.cancel(run_id, "platform_cancel")
        # This acknowledges stopping the exact generation, not a rewrite of
        # its business outcome. Preserve an already failed/succeeded RunStore
        # record while returning the stop protocol's required acknowledgment.
        return ExecuteResponse(run_id=run_id, status="cancelled")

    async def _execute(self, request: ExecuteRequest) -> ExecuteResponse:
        run_id = request.scope.run_id
        try:
            output = await self.business(request)
            resume_binding = current_agent_group_resume.get()
            if (resume_binding is not None
                    and (not resume_binding.gathered or resume_binding.pause_required)):
                raise DomainExecutionError("RUN_RESUME_UNCONFIRMED")
            if self.store.cancelled(run_id).is_set():
                raise asyncio.CancelledError
            self.store.complete(run_id, output)
            return ExecuteResponse(run_id=run_id, status="succeeded",
                                   output_schema=self._output_schema(request), output=output)
        except AgentGroupPause as pause:
            postprocess_token = None
            try:
                resume_binding = current_agent_group_resume.get()
                if (resume_binding is not None
                        and (not resume_binding.gathered or not resume_binding.pause_required
                             or pause.group_key != resume_binding.group_key
                             or pause.operation_key != resume_binding.operation_key
                             or pause.checkpoint.model_dump() != resume_binding.checkpoint
                             or tuple(pause.child_keys) != resume_binding.child_keys)):
                    raise DomainExecutionError("RUN_RESUME_UNCONFIRMED")
                if resume_binding is not None:
                    # The business handler has consumed the single permitted gather.
                    # Lifecycle-owned checkpoint and authorization checks now run
                    # outside the handler's restricted capability context.
                    postprocess_token = current_agent_group_resume.set(None)
                metadata = pause.metadata
                if self.load_recovery_checkpoint is None:
                    raise DomainExecutionError("AGENT_GROUP_REJECTED")
                reference = pause.checkpoint.model_dump()
                loaded = await self.load_recovery_checkpoint(request, reference)
                self._verify_recovery_checkpoint_response(reference, loaded)
                self._agent_group_checkpoint_state(
                    loaded["checkpoint"].get("value"), pause.group_key,
                    pause.operation_key, self._generations[run_id].business_hash,
                    pause.child_keys, run_id,
                )
                await self.authorize_current(request)
                if self.store.cancelled(run_id).is_set():
                    raise asyncio.CancelledError
                generation = self._generations[run_id]
                if self._origins.get(run_id) not in {"invoke", "run"}:
                    raise DomainExecutionError("AGENT_GROUP_REJECTED")
                self.store.mark_waiting(run_id, metadata)
                self._group_pauses[run_id] = (generation.key, {
                    "event": metadata, "group_key": pause.group_key,
                    "operation_key": pause.operation_key,
                    "child_keys": tuple(pause.child_keys), "checkpoint": pause.checkpoint,
                })
                self._pauses.pop(run_id, None)
                return ExecuteResponse(run_id=run_id, status="waiting")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                record = self.store.get_run(run_id)
                if record is not None and record.status == RUNNING:
                    self.store.fail(run_id, classify_execution_error(exc)[1])
                raise
            finally:
                if postprocess_token is not None:
                    current_agent_group_resume.reset(postprocess_token)
        except HarnessPause as pause:
            metadata = dict(pause.metadata)
            self.store.mark_waiting(run_id, metadata)
            self._pauses[run_id] = (self._generations[run_id].key, metadata)
            self._group_pauses.pop(run_id, None)
            return ExecuteResponse(run_id=run_id, status="waiting")
        except asyncio.CancelledError:
            # Signed cancel records terminal state only after exit proof. A
            # disconnect/shutdown without that command stays unconfirmed.
            raise
        except Exception as exc:
            record = self.store.get_run(run_id)
            error = classify_execution_error(exc)[1]
            if record is not None and record.status == RUNNING:
                self.store.fail(run_id, error)
            if isinstance(exc, GatewayError) and exc.code == "MODEL_BUDGET_EXCEEDED":
                failed = self.store.get_run(run_id)
                identity = self._generations.get(run_id)
                if (identity is None or identity != self._identity(request)
                        or failed is None or failed.status != "failed"
                        or failed.error is None or failed.error.model_dump() != error.model_dump()):
                    raise DomainExecutionError("RUN_RESULT_UNCONFIRMED") from None
                self._budget_rejections[run_id] = identity
                # Factory finalization still requires actual Registry exit,
                # exact event/scope/idempotency bindings and no output.
                return ExecuteResponse(run_id=run_id, status="failed",
                                       output_schema=self._output_schema(request), error=error)
            raise

    async def events(self, run_id: str, request: EventRequest, authorization: str) -> Any:
        from fastapi.responses import StreamingResponse
        try:
            validate_event_cursor(request.after_seq)
        except (TypeError, ValueError):
            raise DomainExecutionError("INVALID_REQUEST") from None
        if (run_id != request.scope.run_id or authorization != "Bearer " + request.context_token
            or self.authorize_events is None):
            raise PermissionError("event read unavailable")
        scope = json.dumps(request.scope.model_dump(exclude={"trace_id", "authorization_epoch"}),
                           sort_keys=True, separators=(",", ":"))
        previous = self._generations.get(run_id)
        if previous is None or previous.scope != scope:
            raise PermissionError("event scope unavailable")
        await self.authorize_events(request)
        try:
            raw_batch = self.store.events_after(run_id, request.after_seq)[:256]
            batch = []
            cursor = request.after_seq
            for raw_event in raw_batch:
                event = normalize_execution_event(raw_event)
                validate_event_sequence(event.seq)
                if event.run_id != run_id or event.seq <= cursor:
                    raise ValueError("invalid event order")
                batch.append(event)
                cursor = event.seq
        except (TypeError, ValueError):
            raise DomainExecutionError("RUN_RESULT_UNCONFIRMED") from None

        async def stream():
            try:
                cursor = request.after_seq
                for event in batch:
                    if self._generations.get(run_id) != previous or event.run_id != run_id or event.seq <= cursor:
                        raise DomainExecutionError("RUN_RESULT_UNCONFIRMED")
                    # Check current IAM, machine credentials, token expiry and
                    # policy immediately before disclosing each metadata event.
                    await self.authorize_events(request)
                    if event.event_type in {"completed", "failed", "waiting", "cancelled"} and not self.registry.has_generation_exit_proof(previous.key):
                        break
                    metadata = {key: value for key, value in event.payload.items()
                        if key in {"operation", "reason", "harness_key", "tool_name", "call_id", "code"}
                        and isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value)}
                    safe = event.model_copy(update={"payload": metadata})
                    raw = json.dumps(safe.model_dump(mode="json"), ensure_ascii=False,
                                     separators=(",", ":"), allow_nan=False)
                    yield f"id: {event.seq}\nevent: {event.event_type}\ndata: {raw}\n\n"
                    cursor = event.seq
            except Exception:
                # HTTP headers may already be sent. Only a stable, nonsensitive
                # failure code is emitted; reconnect needs fresh authorization.
                yield 'event: stream_error\ndata: {"code":"EVENT_READ_UNCONFIRMED"}\n\n'

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store"})
