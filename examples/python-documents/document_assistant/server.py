"""SDK-owned execution routes; application supplies verification and business hooks."""
from __future__ import annotations

import base64
import os
import json
from pathlib import Path

import httpx

from agent_platform_sdk.capability_client import CapabilityGatewayClient
from agent_platform_sdk.capability_context import CapabilityContext
from agent_platform_sdk.fastapi_factory import create_fastapi_agent_app
from agent_platform_sdk.execution_lifecycle import ExecutionLifecycle
from agent_platform_sdk.event_authority import EventAuthorityClient
from agent_platform_sdk.lifecycle import MemoryRunStore
from agent_platform_sdk.task_registry import ExecutionTaskRegistry
from agent_platform_sdk.models import ExecuteRequest, EventRequest
from agent_platform_sdk.security import (ContextVerifier, ContextVerificationError,
    internal_token, internal_signing_secret, signed_internal_headers, validate_deployed_model_mode)

from .business import (answer_document, validate_document_input, document_recovery_checkpoint_selector,
    INPUT_SCHEMA, OUTPUT_SCHEMA)

AGENT_ID = "example-python-documents"


def build_app(public_key: bytes, *, issuer: str = "platform-runtime-gateway", audience: str = "agent-runtime",
              platform_url: str | None = None, transport: httpx.AsyncBaseTransport | None = None):
    verifier = ContextVerifier(public_key, issuer, audience)
    manifest_path = Path(__file__).resolve().parents[1] / "manifest.json"
    if not manifest_path.is_file():
        manifest_path = Path("/workspace/examples/python-documents/manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    capabilities = ["invoke", "run", "resume", "cancel", "events"]
    if (manifest.get("agent_id") != AGENT_ID or manifest.get("capabilities") != capabilities
        or manifest.get("schemas", {}).get("input") != INPUT_SCHEMA
        or manifest.get("schemas", {}).get("output") != OUTPUT_SCHEMA):
        raise RuntimeError("published manifest does not match the execution contract")

    def authorize(request: ExecuteRequest | EventRequest, authorization: str):
        if request.scope.agent_id != AGENT_ID or authorization != "Bearer " + request.context_token:
            raise PermissionError
        try:
            if isinstance(request, EventRequest):
                return verifier.verify_event(request.context_token, request)
            return verifier.verify(request.context_token, request)
        except ContextVerificationError:
            raise PermissionError from None

    def capability_client(request: ExecuteRequest):
        trusted = authorize(request, "Bearer " + request.context_token)
        context = CapabilityContext.from_verified(trusted)
        return CapabilityGatewayClient(context, base_url=platform_url, transport=transport)

    async def business(request: ExecuteRequest):
        return await answer_document(request, capability_client(request))

    async def authorize_current(request: ExecuteRequest):
        await capability_client(request).validate_current_execution()

    async def load_checkpoint(request: ExecuteRequest, namespace: str, key: str, schema_id: str):
        return await capability_client(request).load_checkpoint(namespace, key, schema_id, revision=0)

    async def load_recovery_checkpoint(request: ExecuteRequest, reference: dict):
        return await capability_client(request).load_recovery_checkpoint(reference)

    event_authority = EventAuthorityClient(base_url=platform_url, transport=transport)

    async def authorize_events(request: EventRequest):
        authorize(request, "Bearer " + request.context_token)
        await event_authority.check(request)

    registry = ExecutionTaskRegistry()
    lifecycle = ExecutionLifecycle(store=MemoryRunStore(), registry=registry,
        business=business, authorize_current=authorize_current,
        output_schema=OUTPUT_SCHEMA, validate_input=validate_document_input,
        authorize_events=authorize_events, load_checkpoint=load_checkpoint,
        load_recovery_checkpoint=load_recovery_checkpoint,
        recovery_checkpoint_selector=document_recovery_checkpoint_selector)

    return create_fastapi_agent_app(
        title="Document assistant", agent_id=AGENT_ID, version="0.2.9",
        capabilities=capabilities, authorize=authorize,
        invoke=lifecycle.invoke, run=lifecycle.run, resume=lifecycle.resume,
        replay_runtime_recovery=lifecycle.replay_runtime_recovery,
        cancel=lifecycle.cancel, events=lifecycle.events, task_registry=registry,
        finalize_response=lifecycle.finalize_response,
        manifest_extra=manifest,
    )


def main() -> None:
    import uvicorn
    validate_deployed_model_mode()
    key = os.environ.get("AGENT_PLATFORM_PUBLIC_KEY_BASE64", "").strip()
    if not key:
        key_path = os.environ.get("AGENT_PLATFORM_PUBLIC_KEY_FILE", "").strip()
        if key_path:
            key = Path(key_path).read_text(encoding="utf-8").strip()
    if not key or not os.environ.get("PLATFORM_CAPABILITY_URL", "").strip():
        raise RuntimeError("platform verification key and capability URL required")
    token = internal_token()
    if not internal_signing_secret() or not os.environ.get("AGENT_CLIENT_ID", "").strip():
        raise RuntimeError("platform signing and Agent workload credentials required")
    signed_internal_headers(b"{}", token, method="POST", request_target="/internal/context/renew")
    public_key = base64.b64decode(key, validate=True)
    if len(public_key) != 32:
        raise RuntimeError("raw Ed25519 public key required")
    app = build_app(public_key, issuer=os.getenv("AGENT_PLATFORM_ISSUER", "platform-runtime-gateway"),
                    audience=os.getenv("AGENT_PLATFORM_AUDIENCE", "agent-runtime"))
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")), access_log=False)


if __name__ == "__main__":
    main()
