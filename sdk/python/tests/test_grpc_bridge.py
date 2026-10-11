from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import grpc
import pytest
from google.protobuf.json_format import ParseDict

from agent_platform_sdk.grpc_bridge import AgentExecutionBridge
from agent_platform_sdk.proto import agent_execution_v2_pb2 as pb
from agent_platform_sdk.proto import agent_execution_v2_pb2_grpc as pb_grpc


def test_grpc_bridge_restores_only_valid_w3c_parent() -> None:
    from opentelemetry import trace

    class MetadataContext:
        def __init__(self, values: list[tuple[str, str]]) -> None:
            self.values = values

        def invocation_metadata(self) -> list[tuple[str, str]]:
            return self.values

    parent = "00-11111111111111111111111111111111-2222222222222222-01"
    token = AgentExecutionBridge._attach_trace_context(
        MetadataContext([("traceparent", parent), ("baggage", "private-secret")])  # type: ignore[arg-type]
    )
    assert token is not None
    try:
        assert trace.get_current_span().get_span_context().trace_id == int("1" * 32, 16)
    finally:
        AgentExecutionBridge._detach_trace_context(token)
    for values in (
        [("traceparent", "invalid")],
        [("traceparent", parent), ("traceparent", parent)],
    ):
        assert AgentExecutionBridge._attach_trace_context(MetadataContext(values)) is None  # type: ignore[arg-type]


class _AgentHTTPHandler(BaseHTTPRequestHandler):
    records: list[dict[str, Any]] = []
    malformed_events = False

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        self.records.append(
            {
                "path": self.path,
                "body": body,
                "authorization": self.headers.get("Authorization"),
                "dispatch": self.headers.get("X-Platform-Resume-Dispatch"),
                "resume_input": self.headers.get("X-Platform-Resume-Input"),
            }
        )
        if self.path.endswith("/events"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            event = {
                "run_id": body["scope"]["run_id"],
                "seq": 1,
                "event_type": "started",
                "occurred_at": "2026-09-25T01:02:03Z",
                "payload": {"stage": "begin"},
            }
            data = json.dumps(event, separators=(",", ":"))
            if self.malformed_events:
                self.wfile.write(f"id: 1\nevent: started\ndata: {data}".encode())
            else:
                self.wfile.write(f"id: 1\nevent: started\ndata: {data}\n\n".encode())
            return

        output = {
            "method": self.path.rsplit("/", 1)[-1],
            "operation": body["operation"],
            "question": body["input"].get("question"),
            "authorization": self.headers.get("Authorization"),
            "dispatch": self.headers.get("X-Platform-Resume-Dispatch", ""),
            "resume_input": json.dumps(
                body.get("resume_input", {}), separators=(",", ":")
            ),
        }
        response = {
            "protocol_version": "agent-execution/v2",
            "run_id": body["scope"]["run_id"],
            "status": "succeeded",
            "output_schema": "schema://test/output/v1",
            "output": output,
        }
        raw = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _request(operation: str = "invoke") -> pb.ExecuteRequest:
    return ParseDict(
        {
            "protocol_version": "agent-execution/v2",
            "context_token": "x" * 48,
            "scope": {
                "tenant_id": "tenant",
                "department_id": "department",
                "application_id": "application",
                "agent_instance_id": "install",
                "installation_id": "install",
                "agent_id": "qa-agent",
                "agent_version_id": "v1",
                "principal_type": "service_principal",
                "principal_id": "client-1",
                "session_id": "session-1",
                "run_id": "run-1",
                "authorization_epoch": 1,
                "trace_id": "0" * 32,
            },
            "operation": operation,
            "idempotency_key": "idempotency-1",
            "input_schema": "schema://test/input/v1",
            "input": {"question": "test"},
        },
        pb.ExecuteRequest(),
    )


def _event_request() -> pb.EventRequest:
    return ParseDict(
        {
            "protocol_version": "agent-execution/v2",
            "context_token": "x" * 48,
            "scope": {
                "tenant_id": "tenant",
                "department_id": "department",
                "application_id": "application",
                "agent_instance_id": "install",
                "installation_id": "install",
                "agent_id": "qa-agent",
                "agent_version_id": "v1",
                "principal_type": "service_principal",
                "principal_id": "client-1",
                "session_id": "session-1",
                "run_id": "run-1",
                "authorization_epoch": 1,
                "trace_id": "0" * 32,
            },
            "after_seq": 0,
            "policy_snapshot_hash": "a" * 64,
        },
        pb.EventRequest(),
    )


@pytest.fixture
def bridge_servers(monkeypatch):
    # Signed internal HTTP calls must not be redirected through host proxies.
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    _AgentHTTPHandler.records = []
    _AgentHTTPHandler.malformed_events = False
    http_server = ThreadingHTTPServer(("127.0.0.1", 0), _AgentHTTPHandler)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()
    return http_server, http_thread


@pytest.mark.asyncio
async def test_bridge_forwards_unary_and_scoped_resume_metadata(bridge_servers) -> None:
    http_server, http_thread = bridge_servers
    grpc_server = grpc.aio.server()
    pb_grpc.add_AgentExecutionServiceServicer_to_server(
        AgentExecutionBridge(f"http://127.0.0.1:{http_server.server_port}"), grpc_server
    )
    grpc_port = grpc_server.add_insecure_port("127.0.0.1:0")
    await grpc_server.start()
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{grpc_port}", options=(("grpc.enable_http_proxy", 0),)) as channel:
            client = pb_grpc.AgentExecutionServiceStub(channel)
            token = "x" * 48
            invoke = await client.Invoke(
                _request(), metadata=(("authorization", f"Bearer {token}"),)
            )
            assert invoke.run_id == "run-1"
            assert invoke.output.fields["operation"].string_value == "invoke"

            resume = await client.Resume(
                ParseDict({"resume_input": {"approved": True}}, _request("resume")),
                metadata=(("authorization", f"Bearer {token}"),),
            )
            assert resume.output.fields["dispatch"].string_value == ""
            assert (
                resume.output.fields["resume_input"].string_value == '{"approved":true}'
            )

            # Protobuf Struct uses double for all JSON numbers. The bridge
            # must normalize integral values to Go encoding/json's canonical
            # integer form or the signed request body hash will differ.
            numeric = _request()
            numeric.input.fields["whole"].number_value = 7.0
            numeric.input.fields["nested"].list_value.values.add().number_value = 3.0
            await client.Invoke(
                numeric, metadata=(("authorization", f"Bearer {token}"),)
            )

        assert _AgentHTTPHandler.records[0]["path"].endswith("/invoke")
        assert _AgentHTTPHandler.records[0]["authorization"] == f"Bearer {token}"
        assert _AgentHTTPHandler.records[1]["path"].endswith("/runs/run-1/resume")
        assert _AgentHTTPHandler.records[1]["body"]["operation"] == "resume"
        assert _AgentHTTPHandler.records[1]["dispatch"] is None
        assert _AgentHTTPHandler.records[1]["body"]["resume_input"] == {
            "approved": True
        }
        normalized_input = _AgentHTTPHandler.records[2]["body"]["input"]
        assert normalized_input["whole"] == 7 and isinstance(
            normalized_input["whole"], int
        )
        assert normalized_input["nested"] == [3] and isinstance(
            normalized_input["nested"][0], int
        )
    finally:
        await grpc_server.stop(grace=0)
        http_server.shutdown()
        http_server.server_close()
        http_thread.join(timeout=2)


@pytest.mark.asyncio
async def test_bridge_events_use_protobuf_and_reject_missing_auth(
    bridge_servers,
) -> None:
    http_server, http_thread = bridge_servers
    grpc_server = grpc.aio.server()
    pb_grpc.add_AgentExecutionServiceServicer_to_server(
        AgentExecutionBridge(f"http://127.0.0.1:{http_server.server_port}"), grpc_server
    )
    grpc_port = grpc_server.add_insecure_port("127.0.0.1:0")
    await grpc_server.start()
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{grpc_port}", options=(("grpc.enable_http_proxy", 0),)) as channel:
            client = pb_grpc.AgentExecutionServiceStub(channel)
            with pytest.raises(grpc.aio.AioRpcError) as denied:
                await client.Invoke(_request())
            assert denied.value.code() == grpc.StatusCode.UNAUTHENTICATED
            assert _AgentHTTPHandler.records == []

            events = client.Events(
                _event_request(), metadata=(("authorization", f"Bearer {'x' * 48}"),)
            )
            event = await events.read()
            assert event.run_id == "run-1"
            assert event.seq == 1
            assert event.event_type == "started"
            assert event.payload.fields["stage"].string_value == "begin"
            assert await events.read() is grpc.aio.EOF
    finally:
        await grpc_server.stop(grace=0)
        http_server.shutdown()
        http_server.server_close()
        http_thread.join(timeout=2)


@pytest.mark.asyncio
async def test_bridge_rejects_invalid_resume_metadata_and_truncated_sse(
    bridge_servers,
) -> None:
    http_server, http_thread = bridge_servers
    grpc_server = grpc.aio.server()
    pb_grpc.add_AgentExecutionServiceServicer_to_server(
        AgentExecutionBridge(f"http://127.0.0.1:{http_server.server_port}"), grpc_server
    )
    grpc_port = grpc_server.add_insecure_port("127.0.0.1:0")
    await grpc_server.start()
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{grpc_port}", options=(("grpc.enable_http_proxy", 0),)) as channel:
            client = pb_grpc.AgentExecutionServiceStub(channel)
            token = "x" * 48
            invalid_metadata = [
                (
                    ("authorization", f"Bearer {token}"),
                    ("x-platform-resume-input", "[]"),
                ),
                (
                    ("authorization", f"Bearer {token}"),
                    ("x-platform-resume-dispatch", "true"),
                    ("x-platform-resume-input", "NaN"),
                ),
                (
                    ("authorization", f"Bearer {token}"),
                    ("x-platform-resume-dispatch", "true"),
                    ("x-platform-resume-dispatch", "true"),
                    ("x-platform-resume-input", "{}"),
                ),
            ]
            for index, metadata in enumerate(invalid_metadata):
                with pytest.raises(grpc.aio.AioRpcError) as invalid:
                    await client.Resume(_request("run"), metadata=metadata)
                assert (
                    invalid.value.code() == grpc.StatusCode.INVALID_ARGUMENT
                ), f"case {index}: {invalid.value.code()} {invalid.value.details()}"

            with pytest.raises(grpc.aio.AioRpcError) as wrong_auth:
                await client.Invoke(
                    _request(), metadata=(("authorization", "Bearer wrong-token"),)
                )
            assert wrong_auth.value.code() == grpc.StatusCode.UNAUTHENTICATED

            with pytest.raises(grpc.aio.AioRpcError) as wrong_operation:
                await client.Invoke(
                    _request(),
                    metadata=(
                        ("authorization", f"Bearer {token}"),
                        ("x-platform-resume-dispatch", "true"),
                        ("x-platform-resume-input", "{}"),
                    ),
                )
            assert wrong_operation.value.code() == grpc.StatusCode.INVALID_ARGUMENT
            assert _AgentHTTPHandler.records == []

            _AgentHTTPHandler.malformed_events = True
            events = client.Events(
                _event_request(), metadata=(("authorization", f"Bearer {token}"),)
            )
            with pytest.raises(grpc.aio.AioRpcError) as malformed:
                await events.read()
            assert malformed.value.code() == grpc.StatusCode.DATA_LOSS
    finally:
        await grpc_server.stop(grace=0)
        http_server.shutdown()
        http_server.server_close()
        http_thread.join(timeout=2)
