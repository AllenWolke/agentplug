from __future__ import annotations

import pytest
import base64
import json
import httpx
from fastapi.testclient import TestClient

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.errors import DomainExecutionError
from agent_platform_sdk.tool_client import ToolGatewayError
from agent_platform_sdk.fastapi_factory import create_fastapi_agent_app


@pytest.mark.parametrize(
    "exception,status,code,retryable",
    [
        (GatewayError("MODEL_BUDGET_EXCEEDED", "secret-business-content"), 402, "MODEL_BUDGET_EXCEEDED", False),
        (GatewayError("TOOL_RESULT_UNKNOWN", "secret-business-content"), 409, "TOOL_RESULT_UNKNOWN", False),
        (GatewayError("TOOL_OBSERVATION_REJECTED", "secret-business-content"), 502, "TOOL_OBSERVATION_REJECTED", False),
        (
            ValueError("UNSUPPORTED_REPORT_TYPE: secret-business-content"),
            422,
            "UNSUPPORTED_REPORT_TYPE",
            False,
        ),
        (DomainExecutionError("RULE_BUNDLE_EMPTY"), 422, "RULE_BUNDLE_EMPTY", False),
        (GatewayError("KNOWLEDGE_SOURCES_DENIED", "secret-business-content"), 403, "KNOWLEDGE_SOURCES_DENIED", False),
        (GatewayError("KNOWLEDGE_DOCUMENTS_DENIED", "secret-business-content"), 403, "KNOWLEDGE_DOCUMENTS_DENIED", False),
        (GatewayError("MEMORY_POLICY_DENIED", "secret-business-content"), 403, "MEMORY_POLICY_DENIED", False),
        (GatewayError("MODEL_OUTPUT_INCOMPLETE", "secret-business-content"), 502, "MODEL_OUTPUT_INCOMPLETE", False),
        (
            GatewayError("POLICY_DENIED", "secret-business-content"),
            403,
            "POLICY_DENIED",
            False,
        ),
        (
            GatewayError("UPSTREAM_HTTP_ERROR", "secret-business-content"),
            503,
            "CAPABILITY_UNAVAILABLE",
            True,
        ),
        (TimeoutError("secret-business-content"), 504, "UPSTREAM_TIMEOUT", True),
        (
            GatewayError("CAPABILITY_RENEWAL_DENIED", "secret-business-content"),
            403,
            "CAPABILITY_RENEWAL_DENIED",
            False,
        ),
        (
            ToolGatewayError("CAPABILITY_RENEWAL_DENIED", "secret-business-content"),
            403,
            "CAPABILITY_RENEWAL_DENIED",
            False,
        ),
        (PermissionError("secret-business-content"), 403, "PERMISSION_DENIED", False),
        (
            GatewayError("REPORT_BATCH_NOT_FOUND", "secret-business-content"),
            422,
            "REPORT_BATCH_NOT_FOUND",
            False,
        ),
        (
            GatewayError("INVALID_GATEWAY_RESPONSE", "secret-business-content"),
            502,
            "UPSTREAM_PROTOCOL_ERROR",
            False,
        ),
        (
            ToolGatewayError("INVALID_TOOL_RESPONSE", "secret-business-content"),
            502,
            "UPSTREAM_PROTOCOL_ERROR",
            False,
        ),
        (httpx.ReadTimeout("secret-business-content"), 504, "UPSTREAM_TIMEOUT", True),
        (
            httpx.ConnectError("secret-business-content"),
            503,
            "CAPABILITY_UNAVAILABLE",
            True,
        ),
        (RuntimeError("secret-business-content"), 500, "INTERNAL_ERROR", False),
    ],
)
def test_factory_preserves_safe_error_class_and_no_side_effects(
    exception, status, code, retryable
):
    effects = []

    async def authorize(_request, _authorization):
        return None

    async def invoke(_request):
        # Business precondition checks reject before mutation. / 业务前置校验在写入前拒绝。
        raise exception
        effects.append("write")  # pragma: no cover

    app = create_fastapi_agent_app(
        title="errors",
        agent_id="agent",
        version="1",
        capabilities=["invoke"],
        authorize=authorize,
        invoke=invoke,
    )
    request = {
        "protocol_version": "agent-execution/v2",
        "context_token": "fixture."
        + base64.urlsafe_b64encode(
            json.dumps({"execution_revision": 2, "lease_token_hash": "a" * 64}).encode()
        )
        .decode()
        .rstrip("=")
        + ".fixture-signature",
        "operation": "invoke",
        "idempotency_key": "error-test",
        "input_schema": "schema://agent/input/v1",
        "input": {},
        "scope": {
            "tenant_id": "t",
            "department_id": "d",
            "application_id": "a",
            "agent_instance_id": "i",
            "installation_id": "install",
            "agent_id": "agent",
            "agent_version_id": "v1",
            "principal_type": "user",
            "principal_id": "u",
            "session_id": "s",
            "run_id": "r",
            "authorization_epoch": 1,
            "trace_id": "0" * 32,
        },
    }
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/internal/agent-execution/v2/invoke", json=request)
    assert response.status_code == status
    assert response.json()["code"] == code
    assert response.json()["retryable"] is retryable
    assert "secret-business-content" not in response.text
    assert effects == []
