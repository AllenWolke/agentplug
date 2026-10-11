from __future__ import annotations

import pytest
import base64
import json
from fastapi.testclient import TestClient

from .fastapi_factory import create_fastapi_agent_app

TOKEN = (
    "fixture."
    + base64.urlsafe_b64encode(
        json.dumps({"execution_revision": 2, "lease_token_hash": "a" * 64}).encode()
    )
    .decode()
    .rstrip("=")
    + ".fixture-signature"
)


def _app(manifest_extra=None):
    async def authorize(request, authorization):
        if authorization != "Bearer ok":
            raise PermissionError

    async def invoke(request):
        return {"echo": request.input}

    async def ready():
        return True

    return create_fastapi_agent_app(
        title="test-agent",
        agent_id="test-agent",
        version="1.0.0",
        capabilities=["invoke"],
        authorize=authorize,
        invoke=invoke,
        readiness=ready,
        manifest_extra=manifest_extra,
    )


def test_fastapi_factory_accepts_versioned_agent_bound_manifest_schemas() -> None:
    app = _app(manifest_extra={
        "schemas": {
            "input": "schema://test-agent/input/v2",
            "output": "schema://test-agent/output/v12",
        }
    })
    manifest = TestClient(app).get("/.well-known/agent-manifest.json").json()
    assert manifest["schemas"]["input"] == "schema://test-agent/input/v2"
    assert manifest["schemas"]["output"] == "schema://test-agent/output/v12"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("input", "schema://test-agent/input/v0"),
        ("input", "schema://test-agent/input/v01"),
        ("input", "schema://other-agent/input/v2"),
        ("input", "schema://test-agent/input/v2/extra"),
        ("input", "schema://test-agent/input/v2?mode=raw"),
        ("input", "schema://test-agent/input/v2#fragment"),
        ("output", "schema://test-agent/input/v2"),
    ],
)
def test_fastapi_factory_rejects_invalid_manifest_schema_declarations(
    name: str, value: str
) -> None:
    with pytest.raises(ValueError):
        _app(manifest_extra={"schemas": {name: value}})


def test_fastapi_factory_defaults_manifest_schema_versions_to_v1() -> None:
    manifest = TestClient(_app()).get("/.well-known/agent-manifest.json").json()
    assert manifest["schemas"]["input"] == "schema://test-agent/input/v1"
    assert manifest["schemas"]["output"] == "schema://test-agent/output/v1"


@pytest.mark.asyncio
async def test_fastapi_factory_owns_manifest_health_and_invoke() -> None:
    client = TestClient(_app())
    assert client.get("/health/ready").status_code == 200
    assert (
        client.get("/.well-known/agent-manifest.json").json()["agent_id"]
        == "test-agent"
    )
    payload = {
        "protocol_version": "agent-execution/v2",
        "context_token": TOKEN,
        "scope": {
            "run_id": "run-1",
            "tenant_id": "t",
            "department_id": "d",
            "application_id": "a",
            "agent_instance_id": "i",
            "installation_id": "installation-i",
            "agent_id": "test-agent",
            "agent_version_id": "v1",
            "principal_type": "user",
            "principal_id": "u",
            "session_id": "s",
            "authorization_epoch": 1,
            "trace_id": "0" * 32,
        },
        "operation": "invoke",
        "input_schema": "schema://test/input/v1",
        "input": {"x": 1},
        "idempotency_key": "idempotency-1",
    }
    response = client.post(
        "/internal/agent-execution/v2/invoke",
        json=payload,
        headers={"Authorization": "Bearer ok"},
    )
    assert response.status_code == 200
    assert response.json()["output"]["echo"] == {"x": 1}


def test_fastapi_factory_rejects_bad_auth() -> None:
    client = TestClient(_app())
    assert client.get("/health/live").status_code == 200


def test_platform_resume_requires_signed_body_and_rejects_headers() -> None:
    observed: dict[str, object] = {}

    async def authorize(request, authorization):
        if authorization != "Bearer ok":
            raise PermissionError

    async def resume(
        run_id, request, platform_dispatch=False, platform_resume_input=None
    ):
        observed.update(
            {
                "run_id": run_id,
                "operation": request.operation,
                "input": request.input,
                "resume_input": platform_resume_input,
                "dispatch": platform_dispatch,
            }
        )
        return {"resumed": True}

    app = create_fastapi_agent_app(
        title="resume-agent",
        agent_id="resume-agent",
        version="1.0.0",
        capabilities=["resume"],
        authorize=authorize,
        resume=resume,
    )
    client = TestClient(app)
    payload = {
        "protocol_version": "agent-execution/v2",
        "context_token": TOKEN,
        "scope": {
            "run_id": "run-resume",
            "tenant_id": "t",
            "department_id": "d",
            "application_id": "a",
            "agent_instance_id": "i",
            "installation_id": "installation-i",
            "agent_id": "resume-agent",
            "agent_version_id": "v1",
            "principal_type": "user",
            "principal_id": "u",
            "session_id": "s",
            "authorization_epoch": 1,
            "trace_id": "0" * 32,
        },
        "operation": "run",
        "input_schema": "schema://resume-agent/input/v1",
        "input": {"original": True},
        "idempotency_key": "idempotency-resume",
    }
    response = client.post(
        "/internal/agent-execution/v2/runs/run-resume/resume",
        json=payload,
        headers={
            "Authorization": "Bearer ok",
            "X-Platform-Resume-Dispatch": "true",
            "X-Platform-Resume-Input": '{"approved":true}',
        },
    )
    assert response.status_code == 400
    assert observed == {}
    payload["operation"] = "resume"
    payload["resume_input"] = {"decision": "approve"}
    response = client.post(
        "/internal/agent-execution/v2/runs/run-resume/resume",
        json=payload,
        headers={"Authorization": "Bearer ok"},
    )
    assert response.status_code == 200
    assert observed["resume_input"] == {"decision": "approve"}
    assert observed["operation"] == "resume"
