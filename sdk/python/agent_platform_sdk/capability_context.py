"""Platform capability context from an already verified execution request."""
from __future__ import annotations

import hashlib
import json
import re
from pydantic import BaseModel, ConfigDict, Field

from .capability_client import GatewayError
from .security import TrustedContext, canonical_body_hash


class CapabilityContext(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())
    tenant_id: str
    department_id: str
    application_id: str
    installation_id: str
    agent_instance_id: str
    agent_id: str
    agent_version_id: str
    principal_type: str
    actor_id: str
    request_id: str
    task_id: str
    parent_run_id: str = ""
    thread_id: str
    session_id: str
    trace_id: str
    authorization_epoch: int
    idempotency_key: str
    input_fingerprint: str = Field(default="", exclude=True, repr=False)
    execution_revision: int = Field(default=0, exclude=True, repr=False)
    execution_operation: str = Field(default="", exclude=True, repr=False)
    model_profile_id: str
    prompt_version_id: str
    tool_policy_id: str
    memory_policy_id: str
    knowledge_policy_id: str
    runtime_policy_id: str
    platform_context_token: str = Field(repr=False)
    # Used by the model client; not a field in the platform context envelope.
    prompt_template_hash: str = Field(default="", exclude=True)

    @classmethod
    def from_verified(cls, trusted: TrustedContext) -> "CapabilityContext":
        """Call only after ContextVerifier.verify; the platform rechecks live IAM.

        Detect accidental edits to the request after verification. Every resource
        comes from the signed published policy, never from business input/env.
        """
        request, claims = trusted.request, trusted.claims
        policy = request.input.get("policy_snapshot")
        revision = claims.get("execution_revision")
        lease = claims.get("lease_token_hash")
        if (
            claims.get("body_hash") != canonical_body_hash(request)
            or not isinstance(policy, dict)
            or not policy.get("content_hash")
            or claims.get("policy_snapshot_hash") != policy.get("content_hash")
            or type(revision) is not int or revision < 1
            or not isinstance(lease, str) or not re.fullmatch(r"[0-9a-f]{64}", lease)
        ):
            raise GatewayError("CAPABILITY_CONFIG_INVALID", "verified execution and lease required")
        keys = ("model_profile_id", "prompt_version_id", "tool_policy_id", "memory_policy_id", "knowledge_policy_id", "runtime_policy_id")
        if any(not isinstance(policy.get(key), str) or not policy[key].strip() or len(policy[key]) > 128 for key in keys):
            raise GatewayError("CAPABILITY_CONFIG_INVALID", "six published policy references required")
        scope = request.scope
        values = {key: getattr(scope, key) for key in (
            "tenant_id", "department_id", "application_id", "installation_id", "agent_instance_id", "agent_id", "agent_version_id", "principal_type", "session_id", "parent_run_id", "trace_id", "authorization_epoch")}
        values.update({key: policy[key] for key in keys})
        input_fingerprint = hashlib.sha256(json.dumps(
            [request.input_schema, request.idempotency_key, request.input],
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")).hexdigest()
        from .agent_group_resume import current_agent_group_resume
        resume_binding = current_agent_group_resume.get()
        if resume_binding is not None:
            if (request.operation != "resume" or scope.run_id != resume_binding.run_id
                    or revision != resume_binding.execution_revision
                    or input_fingerprint != resume_binding.input_fingerprint):
                raise GatewayError("RUN_RESUME_UNCONFIRMED", "resume context does not match the signed group")
        values.update(actor_id=scope.principal_id, request_id=request.idempotency_key,
                      task_id=scope.run_id, thread_id=scope.session_id,
                      idempotency_key=request.idempotency_key, platform_context_token=request.context_token,
                      input_fingerprint=input_fingerprint, execution_revision=revision,
                      execution_operation=request.operation)
        return cls(**values)
