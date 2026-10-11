"""Signed HTTP preflight rejects bad input before invoking business hooks."""

import json
import threading

import pytest

import server
from agent_platform_sdk import MemoryRunStore
from test_lifecycle import Minter, ServerKit, envelope


@pytest.mark.parametrize("operation", ["invoke", "run"])
def test_input_rejection_is_terminal_and_has_no_business_effects(operation):
    minter = Minter()
    calls = []

    def validate(_trusted):
        calls.append("validate")
        raise ValueError("private input must never appear in response")

    app = server.build_execution_server(
        minter.private.public_key(), agent_id="conformance-agent",
        issuer=minter.issuer, audience=minter.audience, store=MemoryRunStore(),
        invoke=lambda _trusted: calls.append("business") or {},
        run=lambda *_args: calls.append("business") or {}, validate_input=validate,
    )
    httpd = app.serve(("127.0.0.1", 0))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    client = object.__new__(ServerKit)
    client.base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        payload = envelope("x" * 32, "invalid-run", operation)
        token = minter.execute_token(payload, [operation])
        payload["context_token"] = token
        path = "/internal/agent-execution/v2/" + ("invoke" if operation == "invoke" else "runs")
        status, raw = client.post(path, payload, token)
        assert status == 422
        body = json.loads(raw)
        assert body["status"] == "failed" and body["run_id"] == "invalid-run"
        assert body["error"]["code"] == "INVALID_REQUEST" and body["error"]["retryable"] is False
        assert "private input" not in raw and calls == ["validate"]
        status, _ = client.post(path, payload, token, auth="Bearer forged")
        assert status == 401 and calls == ["validate"]
    finally:
        httpd.shutdown()
        httpd.server_close()
