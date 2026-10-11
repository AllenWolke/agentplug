"""Shared, domain-neutral bootstrap for independently deployed Python Agents.

独立 Python Agent 共用的无领域启动能力；业务图、Prompt 与状态不得放入此模块。
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import Header, HTTPException

from agent_platform_sdk import ContextVerifier, EventRequest, ExecuteRequest, TrustedContext
from contracts import HarnessContext


logger = logging.getLogger(__name__)


def build_verifier(audience: str | None = None) -> ContextVerifier:
    return ContextVerifier.from_environment(audience=audience)


def verify_request(
    verifier: ContextVerifier,
    request: ExecuteRequest,
    authorization: str,
) -> TrustedContext:
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        raise HTTPException(401, "Bearer capability is required")
    token = authorization[len(prefix):].strip()
    if token != request.context_token:
        raise HTTPException(401, "header and envelope capability mismatch")
    try:
        return verifier.verify(token, request)
    except ValueError as exc:
        # Keep the client response generic, but retain a safe diagnostic reason
        # for operators; no token or request payload is ever logged.
        # 对客户端仍返回通用错误，但保留不含令牌和正文的安全诊断原因。
        logger.warning("platform capability verification rejected: %s", exc)
        raise HTTPException(401, "platform capability is invalid") from exc


def harness_context(request: ExecuteRequest, *, require_rule_bundle: bool = False) -> HarnessContext:
    """Map a signed v2 scope and signed policy references to legacy domain ports.

    将已签名的 v2 作用域和策略引用映射到现有领域端口。字段受 BodyHash 保护，
    Agent 不接受未签名的客户端上下文覆盖。
    """

    policy = request.input.get("policy_snapshot")
    if not isinstance(policy, dict):
        raise HTTPException(422, "policy_snapshot is required")
    required = {
        "model_profile_id", "prompt_version_id", "tool_policy_id",
        "memory_policy_id", "knowledge_policy_id", "runtime_policy_id",
    }
    if not required.issubset(policy) or any(not str(policy[key]).strip() for key in required):
        raise HTTPException(422, "six immutable policy references are required")
    knowledge = policy.get("knowledge")
    if not isinstance(knowledge, dict):
        raise HTTPException(422, "materialized knowledge policy is required")
    allowed_scopes = knowledge.get("allowed_scopes")
    if not isinstance(allowed_scopes, list) or not all(isinstance(item, str) for item in allowed_scopes):
        raise HTTPException(422, "knowledge allowed_scopes is invalid")
    scope = request.scope
    knowledge_scope = str(request.input.get("knowledge_scope", ""))
    if knowledge_scope not in allowed_scopes:
        raise HTTPException(403, "knowledge scope is not allowed by the immutable policy")
    prompt = policy.get("prompt", {})
    if prompt and (not isinstance(prompt, dict) or not str(prompt.get("template_hash", "")).strip()):
        raise HTTPException(422, "prompt template hash is invalid")
    memory = policy.get("memory", {})
    if memory and (not isinstance(memory, dict) or int(memory.get("max_entries", 0)) < 1):
        raise HTTPException(422, "memory policy is invalid")
    rule = policy.get("rule_bundle", {})
    if require_rule_bundle and not rule:
        raise HTTPException(422, "approved rule bundle policy is required")
    if rule and (
        not isinstance(rule, dict)
        or not str(rule.get("version", "")).strip()
        or len(str(rule.get("checksum", "")).strip()) != 64
    ):
        raise HTTPException(422, "rule bundle policy is invalid")
    return HarnessContext(
        tenant_id=scope.tenant_id,
        department_id=scope.department_id,
        application_id=scope.application_id,
        agent_id=scope.agent_id,
        agent_instance_id=scope.agent_instance_id,
        installation_id=scope.installation_id,
        authorization_epoch=scope.authorization_epoch,
        principal_type=scope.principal_type,
        agent_version_id=scope.agent_version_id,
        actor_id=scope.principal_id,
        request_id=request.idempotency_key,
        trace_id=scope.trace_id,
        task_id=scope.run_id,
        parent_run_id=scope.parent_run_id,
        thread_id=scope.session_id,
        session_id=scope.session_id,
        knowledge_scope=knowledge_scope,
        idempotency_key=request.idempotency_key,
        model_profile_id=str(policy["model_profile_id"]),
        prompt_version_id=str(policy["prompt_version_id"]),
        tool_policy_id=str(policy["tool_policy_id"]),
        memory_policy_id=str(policy["memory_policy_id"]),
        knowledge_policy_id=str(policy["knowledge_policy_id"]),
        runtime_policy_id=str(policy["runtime_policy_id"]),
        rule_bundle_version=str(rule.get("version", "")),
        rule_bundle_checksum=str(rule.get("checksum", "")).strip().lower(),
        prompt_template_hash=str(prompt.get("template_hash", "")),
        memory_max_entries=int(memory.get("max_entries", 0) or 0),
        memory_working_ttl_seconds=int(memory.get("working_ttl_seconds", 0) or 0),
        memory_session_ttl_seconds=int(memory.get("session_ttl_seconds", 0) or 0),
        memory_task_ttl_seconds=int(memory.get("task_ttl_seconds", 0) or 0),
        platform_context_token=request.context_token,
    )


AuthorizationHeader = Header(default="", alias="Authorization")


def verify_event_request(verifier: ContextVerifier, request: EventRequest, authorization: str) -> None:
    """Verify the exact event scope and cursor. / 校验精确的事件作用域和游标。"""
    prefix = "Bearer "
    if not authorization.startswith(prefix) or authorization[len(prefix):].strip() != request.context_token:
        raise HTTPException(401, "event capability is required")
    try:
        verifier.verify_event(request.context_token, request)
    except ValueError as exc:
        raise HTTPException(401, "event capability is invalid") from exc
