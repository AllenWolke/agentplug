"""Ephemeral OTLP/HTTP receiver for cross-service trace acceptance.

Only trace IDs, span IDs, parent IDs, service names and span names are retained.
临时 OTLP 接收器仅保留追踪拓扑，不记录属性、请求正文或凭据。
"""

from __future__ import annotations

import argparse
import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)


class CaptureServer(ThreadingHTTPServer):
    def __init__(self, host: str, port: int) -> None:
        super().__init__((host, port), CaptureHandler)
        self.spans: list[dict[str, str]] = []
        self.lock = threading.Lock()


class CaptureHandler(BaseHTTPRequestHandler):
    server: CaptureServer

    def log_message(self, *_args: object) -> None:
        # A telemetry payload can contain sensitive attributes. Never log it.
        # 遥测原文可能含敏感属性，禁止记录请求正文。
        return

    def do_GET(self) -> None:
        if self.path != "/spans":
            self.send_error(404)
            return
        with self.server.lock:
            data = json.dumps(self.server.spans, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        if self.path != "/v1/traces":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 4 * 1024 * 1024:
            self.send_error(413)
            return
        raw = self.rfile.read(length)
        if self.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
        message = ExportTraceServiceRequest()
        try:
            message.ParseFromString(raw)
        except Exception:
            self.send_error(400)
            return
        captured = []
        for resource in message.resource_spans:
            service = next(
                (
                    value.value.string_value
                    for value in resource.resource.attributes
                    if value.key == "service.name"
                ),
                "unknown",
            )
            for scope in resource.scope_spans:
                for span in scope.spans:
                    captured.append(
                        {
                            "service": service,
                            "name": span.name,
                            "trace_id": span.trace_id.hex(),
                            "span_id": span.span_id.hex(),
                            "parent_id": span.parent_span_id.hex(),
                        }
                    )
        with self.server.lock:
            self.server.spans.extend(captured)
        body = ExportTraceServiceResponse().SerializeToString()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    CaptureServer("0.0.0.0", args.port).serve_forever()


if __name__ == "__main__":
    main()
