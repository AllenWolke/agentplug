"""Bounded internal context for a signed AgentGroup resume."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any


@dataclass
class AgentGroupResumeBinding:
    run_id: str
    execution_revision: int
    group_key: str
    operation_key: str
    input_fingerprint: str
    input_hash: str
    child_keys: tuple[str, ...]
    checkpoint: dict[str, Any]
    runner_started: bool = False
    gather_authorized: bool = False
    gather_inflight: bool = False
    gather_request_used: bool = False
    gathered: bool = False
    pause_required: bool = False

    def begin_runner(self, run_id: str, group_key: str, operation_key: str,
                     input_fingerprint: str, input_hash: str,
                     child_keys: tuple[str, ...]) -> bool:
        if (self.runner_started or run_id != self.run_id or group_key != self.group_key
                or operation_key != self.operation_key
                or input_fingerprint != self.input_fingerprint
                or input_hash != self.input_hash or tuple(child_keys) != self.child_keys):
            return False
        self.runner_started = True
        return True

    def permit_gather(self) -> bool:
        if not self.runner_started or self.gather_authorized or self.gathered:
            return False
        self.gather_authorized = True
        return True

    def consume_gather_permission(self) -> bool:
        if not self.gather_authorized or self.gathered:
            return False
        self.gather_authorized = False
        self.gather_inflight = True
        self.gather_request_used = False
        return True

    def consume_gather_request(self, operation_key: str) -> bool:
        if (not self.gather_inflight or self.gather_request_used
                or operation_key != self.operation_key):
            return False
        self.gather_request_used = True
        return True

    def finish_gather(self, terminal: bool) -> bool:
        if (not self.runner_started or not self.gather_inflight or not self.gather_request_used
                or self.gathered or type(terminal) is not bool):
            return False
        self.gather_inflight = False
        self.gathered = True
        self.pause_required = not terminal
        return True


current_agent_group_resume: ContextVar[AgentGroupResumeBinding | None] = ContextVar(
    "agent_group_resume_binding", default=None,
)
