"""Small deterministic webhook receiver used only by the Kafka E2E fixture.

The receiver deliberately keeps state in memory.  It is not a production
notification service; its purpose is to expose observable delivery counts and
failure toggles while the real PostgreSQL-backed platform and Kafka run in containers.
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class ReceiverState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.events: list[dict[str, Any]] = []
        self.fail_remaining = 0
        self.failure_calls = 0

    def append(self, event: dict[str, Any]) -> None:
        with self.lock:
            self.events.append(event)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "count": len(self.events),
                "events": list(self.events),
                "fail_remaining": self.fail_remaining,
                "failure_calls": self.failure_calls,
            }


def make_handler(state: ReceiverState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _json(self, status: int, value: Any) -> None:
            body = json.dumps(value, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
            if self.path == "/healthz":
                self._json(200, {"status": "ok"})
                return
            if self.path == "/events":
                self._json(200, state.snapshot())
                return
            self._json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
            if self.path == "/control/fail":
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    payload = json.loads(raw or b"{}")
                    count = int(payload.get("count", 0))
                except (ValueError, TypeError, json.JSONDecodeError):
                    self._json(400, {"error": "invalid_count"})
                    return
                with state.lock:
                    state.fail_remaining = max(0, count)
                self._json(200, {"fail_remaining": state.fail_remaining})
                return
            if self.path != "/events":
                self._json(404, {"error": "not_found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid_json"})
                return
            with state.lock:
                if state.fail_remaining > 0:
                    state.fail_remaining -= 1
                    state.failure_calls += 1
                    remaining = state.fail_remaining
                    self._json(503, {"error": "injected_failure", "remaining": remaining})
                    return
            if not isinstance(payload, dict) or not payload.get("id"):
                self._json(400, {"error": "invalid_event"})
                return
            state.append(payload)
            self._json(202, {"accepted": True, "id": payload["id"]})

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(ReceiverState()))
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
