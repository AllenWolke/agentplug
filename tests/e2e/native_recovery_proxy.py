"""Opt-in, loopback-only fault boundary for new owned acceptance Runs.

Forwards original bytes and authentication unchanged. Never persists headers,
arguments, credentials or returned content. No provider response is fabricated.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Gate:
    def __init__(self, directory: Path, upstream_host="platform-app", upstream_port=8081):
        self.directory = directory
        self.host, self.port = upstream_host, upstream_port
        self.lock = threading.RLock()
        self.committed = None
        self.recovered = False

    def config(self):
        return json.loads((self.directory / "active.json").read_text(encoding="utf-8"))

    def event(self, kind, **fields):
        record = {"event": kind, "time_ns": time.time_ns(), **fields}
        with self.lock, (self.directory / "events.jsonl").open("a", encoding="utf-8") as output:
            output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            output.flush()
            os.fsync(output.fileno())

    def reserve(self, path, identifier):
        # Upper bounds include internal rewrite + embedding calls. Only one
        # example gate is exercised at a time; no cross-process writer exists.
        amount = 4 if path.startswith("/internal/knowledge/") else 1
        config = self.config()
        budget_path = self.directory.parent / "budget.json"
        with self.lock:
            budget = json.loads(budget_path.read_text(encoding="utf-8"))
            if budget["reserved_upper_bound"] + amount > budget["limit"]:
                self.event("budget_denied", path=path, run_id=config["run_id"])
                return False
            budget["reserved_upper_bound"] += amount
            budget["reservations"].append({"run_id": config["run_id"], "path": path,
                                           "operation_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
                                           "upper_bound": amount})
            temporary = budget_path.with_suffix(".pending")
            temporary.write_text(json.dumps(budget, indent=2) + "\n", encoding="utf-8")
            temporary.replace(budget_path)
            return True

    def forward(self, method, path, headers, raw):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=60)
        safe_headers = {key: value for key, value in headers.items()
                        if key.lower() not in {"host", "connection", "transfer-encoding", "content-length"}}
        safe_headers["Content-Length"] = str(len(raw))
        safe_headers["Connection"] = "close"
        try:
            connection.request(method, path, raw, safe_headers)
            response = connection.getresponse()
            data = response.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024:
                raise ValueError("upstream response exceeds fixed acceptance limit")
            return response.status, response.getheader("Content-Type", "application/json"), data
        finally:
            connection.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, content_type, data):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()
        self.close_connection = True

    def reject(self, code):
        self.reply(503, "application/json", json.dumps({"error_code": code}).encode())

    def do_GET(self):
        if self.path == "/health/ready":
            self.reply(200, "application/json", b'{"ready":true}')
        else:
            self.reject("ACCEPTANCE_METHOD_DENIED")

    def do_POST(self):
        gate = self.server.gate
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4 * 1024 * 1024:
                return self.reject("ACCEPTANCE_BODY_DENIED")
            raw = self.rfile.read(size)
            envelope = json.loads(raw)
            context, command = envelope.get("context", {}), envelope.get("input", {})
            run_id = context.get("task_id", context.get("run_id", ""))
            config = gate.config()
            owned = run_id == config["run_id"]
            name, call_id = command.get("name"), command.get("call_id")
            operation = {key: command.get(key) for key in ("name", "call_id", "payload")}
            digest = hashlib.sha256(json.dumps(operation, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            with gate.lock:
                committed = gate.committed
            if owned and committed and self.path == "/internal/tool/invoke" and call_id == committed["call_id"]:
                gate.event("duplicate_invoke_denied", run_id=run_id, call_id=call_id)
                return self.reject("ACCEPTANCE_DUPLICATE_INVOKE_DENIED")
            is_model = self.path in {"/internal/model/generate", "/internal/model/embed"}
            if owned and committed and is_model:
                gate.event("next_model_held_before_forward", run_id=run_id, receipt_consumed=gate.recovered)
                deadline = time.monotonic() + 90
                while not (gate.directory / "abort").exists() and time.monotonic() < deadline:
                    time.sleep(.05)
                return self.reject("ACCEPTANCE_UNSENT_MODEL_STOPPED")
            billable = is_model or self.path in {"/internal/knowledge/search", "/internal/knowledge/answer"}
            if owned and billable and not gate.reserve(self.path, str(command.get("idempotency_key", command.get("request_id", digest)))):
                return self.reject("ACCEPTANCE_MODEL_BUDGET_EXHAUSTED")
            status, content_type, data = gate.forward("POST", self.path, dict(self.headers), raw)
            if owned and self.path == "/internal/tool/invoke" and name == "notify.self" and status == 200:
                result = json.loads(data).get("data", {})
                event_id = result.get("data", {}).get("message_id")
                if not isinstance(event_id, str) or not event_id.startswith("agent-tool-"):
                    raise ValueError("real notification receipt identity missing")
                with gate.lock:
                    gate.committed = {"call_id": call_id, "digest": digest, "event_id": event_id}
                gate.event("notification_committed_response_held", run_id=run_id, call_id=call_id,
                           operation_sha256=digest, event_id=event_id)
                deadline = time.monotonic() + 20
                while not (gate.directory / "drop").exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                gate.event("original_response_dropped", run_id=run_id, call_id=call_id)
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                return
            if owned and self.path == "/internal/tool/receipt" and committed and call_id == committed["call_id"]:
                if digest != committed["digest"] or status != 200:
                    raise ValueError("original receipt query changed identity or failed")
                receipt = json.loads(data).get("data", {})
                if receipt.get("version") != "tool-receipt/v1" or receipt.get("status") != "completed" or receipt.get("call_id") != call_id:
                    raise ValueError("real original receipt binding missing")
                with gate.lock:
                    gate.recovered = True
                gate.event("original_receipt_returned", run_id=run_id, call_id=call_id,
                           operation_sha256=digest, event_id=committed["event_id"])
            self.reply(status, content_type, data)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            gate.event("gate_error", path=self.path)
            try:
                self.reject("ACCEPTANCE_GATE_FAILED")
            except OSError:
                pass


def server(directory, host="127.0.0.1", port=8087, upstream_host="platform-app", upstream_port=8081):
    result = ThreadingHTTPServer((host, port), Handler)
    result.daemon_threads = True
    result.gate = Gate(Path(directory), upstream_host, upstream_port)
    return result


if __name__ == "__main__":
    server(Path(os.environ.get("ACCEPTANCE_CONTROL_DIR", "/control"))).serve_forever()
