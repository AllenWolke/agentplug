"""Local test-only Python gRPC bridge used by the Go interoperability test."""
from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import grpc
from agent_platform_sdk.grpc_bridge import AgentExecutionBridge
from agent_platform_sdk.proto import agent_execution_v2_pb2_grpc as pb_grpc


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        if self.path.endswith("/events"):
            event = {
                "run_id": payload["scope"]["run_id"],
                "seq": 1,
                "event_type": "started",
                "occurred_at": "2026-09-25T01:02:03Z",
                "payload": {"source": "python-bridge"},
            }
            raw = f"id: 1\nevent: started\ndata: {json.dumps(event, separators=(',', ':'))}\n\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        output = {
            "operation": payload["operation"],
            "authorization": self.headers.get("Authorization", ""),
            "resume_dispatch": self.headers.get("X-Platform-Resume-Dispatch", ""),
            "resume_input": json.dumps(payload.get("resume_input", {}), separators=(",", ":")),
        }
        response = {
            "protocol_version": "agent-execution/v2",
            "run_id": payload["scope"]["run_id"],
            "status": "succeeded",
            "output_schema": "schema://interop/output/v1",
            "output": output,
        }
        raw = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


async def _serve(http_port: int) -> None:
    server = grpc.aio.server(options=[("grpc.max_receive_message_length", 8 << 20), ("grpc.max_send_message_length", 8 << 20)])
    pb_grpc.add_AgentExecutionServiceServicer_to_server(
        AgentExecutionBridge(f"http://127.0.0.1:{http_port}"), server
    )
    port = server.add_insecure_port("127.0.0.1:0")
    if port == 0:
        raise OSError("failed to bind Python gRPC test server")
    await server.start()
    print(port, flush=True)
    await server.wait_for_termination()


def main() -> None:
    http_server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=http_server.serve_forever, daemon=True).start()
    try:
        asyncio.run(_serve(http_server.server_port))
    finally:
        http_server.shutdown()
        http_server.server_close()


if __name__ == "__main__":
    main()
