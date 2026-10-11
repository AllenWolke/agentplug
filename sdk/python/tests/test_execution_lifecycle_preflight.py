from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from agent_platform_sdk.errors import DomainExecutionError
from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.execution_lifecycle import ExecutionLifecycle
from agent_platform_sdk.fastapi_factory import create_fastapi_agent_app
from agent_platform_sdk.lifecycle import MemoryRunStore
from agent_platform_sdk.models import AppError, ExecuteRequest, ExecuteResponse
from agent_platform_sdk.task_registry import ExecutionTaskRegistry


def _context_token() -> str:
    claims = {"execution_revision": 1, "lease_token_hash": "0" * 64}
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{encoded}.fixture-signature"


def _payload(operation: str, run_id: str) -> dict[str, object]:
    return {
        "protocol_version": "agent-execution/v2",
        "context_token": _context_token(),
        "scope": {
            "tenant_id": "tenant",
            "department_id": "department",
            "application_id": "application",
            "agent_instance_id": "documents-installation",
            "installation_id": "documents-installation",
            "agent_id": "documents",
            "agent_version_id": "documents-v1",
            "principal_type": "user",
            "principal_id": "user-1",
            "session_id": "session-1",
            "run_id": run_id,
            "authorization_epoch": 1,
            "trace_id": "0" * 32,
        },
        "operation": operation,
        "idempotency_key": f"idempotency-{run_id}",
        "input_schema": "schema://documents/input/v1",
        "input": {},
    }


def _lifecycle_app(*, business, validate_input):
    store = MemoryRunStore()
    registry = ExecutionTaskRegistry()

    async def authorize(_request, _authorization):
        return None

    lifecycle = ExecutionLifecycle(
        store=store,
        registry=registry,
        business=business,
        authorize_current=lambda _request: _allow(),
        output_schema="schema://documents/output/v1",
        validate_input=validate_input,
    )
    app = create_fastapi_agent_app(
        title="documents",
        agent_id="documents",
        version="1",
        capabilities=["invoke", "run", "resume", "cancel"],
        authorize=authorize,
        invoke=lifecycle.invoke,
        run=lifecycle.run,
        resume=lifecycle.resume,
        cancel=lifecycle.cancel,
        task_registry=registry,
        finalize_response=lifecycle.finalize_response,
    )
    return app, lifecycle, store, registry


async def _allow() -> None:
    return None


def _reject_missing_document(request: ExecuteRequest) -> None:
    if not request.input.get("document_id"):
        raise DomainExecutionError("INVALID_REQUEST")


@pytest.mark.parametrize("operation", ["invoke", "run"])
def test_input_rejection_returns_terminal_response_after_registry_exit(operation: str) -> None:
    business_calls: list[str] = []

    async def business(_request):
        business_calls.append("called")
        return {"unexpected": True}

    app, lifecycle, store, registry = _lifecycle_app(
        business=business, validate_input=_reject_missing_document,
    )
    request_data = _payload(operation, f"bad-{operation}")
    request = ExecuteRequest.model_validate(request_data)
    path = (
        "/internal/agent-execution/v2/invoke"
        if operation == "invoke"
        else "/internal/agent-execution/v2/runs"
    )

    with TestClient(app) as client:
        response = client.post(path, json=request_data)

    assert response.status_code in {200, 202}
    body = response.json()
    assert body["run_id"] == request.scope.run_id
    assert body["status"] == "failed"
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert body["error"]["message"] == "business request rejected"
    record = store.get_run(request.scope.run_id)
    assert record is not None and record.status == "failed"
    assert [event.event_type for event in record.events] == ["accepted", "failed"]
    assert record.events[-1].payload == {"code": "INVALID_REQUEST"}
    assert registry.has_exit_proof(request)
    assert business_calls == []


def test_explicit_budget_rejection_is_failed_with_exit_proof_and_exact_replay() -> None:
    calls = []

    async def business(_request):
        calls.append("budget admission")
        raise GatewayError("MODEL_BUDGET_EXCEEDED", "secret-vendor-body")

    app, lifecycle, store, registry = _lifecycle_app(
        business=business, validate_input=lambda _request: None,
    )
    payload = _payload("invoke", "budget-rejected")
    request = ExecuteRequest.model_validate(payload)
    with TestClient(app) as client:
        response = client.post("/internal/agent-execution/v2/invoke", json=payload)
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed" and body["error"] == {
            "code": "MODEL_BUDGET_EXCEEDED",
            "message": "governed model budget exhausted", "retryable": False, "details": {},
        }
        assert not body.get("output") and "secret-vendor-body" not in response.text
        assert registry.has_exit_proof(request)
        failed = store.get_run(request.scope.run_id)
        assert failed.events[-1].payload == {"code": "MODEL_BUDGET_EXCEEDED"}
        # Lifecycle same-generation replay does not invoke business a second time.
        import asyncio
        replay = asyncio.run(lifecycle.invoke(request))
        assert replay.model_dump() == ExecuteResponse.model_validate(body).model_dump()
        lifecycle.finalize_response(request, replay)
    assert calls == ["budget admission"]


@pytest.mark.parametrize("code", ["MODEL_INVOCATION_UNKNOWN", "TOOL_RESULT_UNKNOWN"])
def test_unknown_effect_does_not_become_known_budget_failure(code: str) -> None:
    async def business(_request):
        raise GatewayError(code, "secret-upstream")

    app, lifecycle, store, registry = _lifecycle_app(
        business=business, validate_input=lambda _request: None,
    )
    payload = _payload("invoke", "unknown-" + code)
    request = ExecuteRequest.model_validate(payload)
    with TestClient(app) as client:
        response = client.post("/internal/agent-execution/v2/invoke", json=payload)
    assert response.status_code >= 400 and "status" not in response.json()
    assert registry.has_exit_proof(request)
    forged = ExecuteResponse(run_id=request.scope.run_id, status="failed",
        output_schema=lifecycle.output_schema,
        error=AppError(code="MODEL_BUDGET_EXCEEDED", message="governed model budget exhausted", retryable=False))
    with pytest.raises(DomainExecutionError, match="RUN_RESULT_UNCONFIRMED"):
        lifecycle.finalize_response(request, forged)


@pytest.mark.parametrize("business_fails", [True, False])
def test_stop_ack_after_terminal_execution_preserves_original_outcome(business_fails: bool) -> None:
    async def business(_request):
        if business_fails:
            raise DomainExecutionError("INVALID_REQUEST")
        return {"receipt": "original result"}

    app, _lifecycle, store, _registry = _lifecycle_app(
        business=business, validate_input=lambda _request: None,
    )
    payload = _payload("invoke", "terminal-stop-" + str(business_fails))
    run_id = payload["scope"]["run_id"]
    with TestClient(app) as client:
        client.post("/internal/agent-execution/v2/invoke", json=payload)
        before = store.get_run(run_id)
        payload["operation"] = "cancel"
        response = client.post(f"/internal/agent-execution/v2/runs/{run_id}/cancel", json=payload)
        assert response.status_code == 200 and response.json()["status"] == "cancelled"
        assert not response.json().get("output") and not response.json().get("error")
        after = store.get_run(run_id)
        assert before == after and before.status == ("failed" if business_fails else "succeeded")


def test_business_exception_cannot_be_promoted_to_preflight_terminal_response() -> None:
    async def business(_request):
        raise DomainExecutionError("INVALID_REQUEST")

    app, lifecycle, store, registry = _lifecycle_app(
        business=business, validate_input=lambda _request: None,
    )
    request_data = _payload("invoke", "business-error")
    request = ExecuteRequest.model_validate(request_data)

    with TestClient(app) as client:
        response = client.post("/internal/agent-execution/v2/invoke", json=request_data)

    assert response.status_code == 422
    assert response.json()["code"] == "INVALID_REQUEST"
    assert "status" not in response.json()
    assert registry.has_exit_proof(request)
    record = store.get_run(request.scope.run_id)
    assert record is not None and record.status == "failed"
    fabricated = ExecuteResponse(
        run_id=request.scope.run_id,
        status="failed",
        output_schema="schema://documents/output/v1",
        error=AppError(
            code="INVALID_REQUEST", message="business request rejected", retryable=False,
        ),
    )
    with pytest.raises(DomainExecutionError, match="RUN_RESULT_UNCONFIRMED"):
        lifecycle.finalize_response(request, fabricated)


def test_invalid_resume_stays_an_unbound_error_without_terminal_run_record() -> None:
    business_calls: list[str] = []

    async def business(_request):
        business_calls.append("called")
        return {"unexpected": True}

    app, _lifecycle, store, _registry = _lifecycle_app(
        business=business, validate_input=_reject_missing_document,
    )
    request_data = _payload("resume", "bad-resume")
    request_data["resume_input"] = {"choice": "continue"}
    path = "/internal/agent-execution/v2/runs/bad-resume/resume"

    with TestClient(app) as client:
        response = client.post(path, json=request_data)

    assert response.status_code == 422
    assert response.json()["code"] == "INVALID_REQUEST"
    assert "status" not in response.json()
    assert store.get_run("bad-resume") is None
    assert business_calls == []
