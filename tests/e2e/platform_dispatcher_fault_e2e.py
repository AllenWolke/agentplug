"""Black-box SQL/Docker fault matrix for the platform Dispatcher.

This test deliberately uses a host-side HTTP Agent stub.  The platform container
still performs the real PostgreSQL-backed Run/Lease/Dispatcher/Gateway path; only the
remote Agent business response is scripted so timeout, retry and cancellation
are deterministic. / 该脚本使用宿主机 HTTP Agent 桩，但平台容器仍经过真实
PostgreSQL Run/Lease/Dispatcher/Gateway 链路；只对 Agent 业务响应做确定性注入。
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


BASE_URL = os.getenv("PLATFORM_URL", "http://127.0.0.1:40682").rstrip("/")
INTERNAL_TOKEN = os.getenv("INTERNAL_TOKEN", "lexagent-test-token")


class StubState:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.calls = 0
        self.lock = threading.Lock()

    def next_call(self) -> int:
        with self.lock:
            self.calls += 1
            return self.calls


class AgentStub(BaseHTTPRequestHandler):
    server: "StubServer"

    def log_message(self, *_args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        call = self.server.state.next_call()
        mode = self.server.state.mode
        if mode == "retry-success" and call == 1:
            self._write_json(503, {"code": "UPSTREAM_UNAVAILABLE", "message": "retry", "retryable": True})
            return
        if mode == "always-fail":
            self._write_json(503, {"code": "UPSTREAM_UNAVAILABLE", "message": "fail", "retryable": True})
            return
        if mode in {"timeout", "cancel"}:
            # The platform runtime policy bounds this request.  For cancel the
            # caller interrupts the request before this bounded sleep returns.
            time.sleep(30)
        run_id = self.path.rsplit("/", 1)[-1] if "/resume" in self.path else self.server.run_id
        self._write_json(200, {"protocol_version": "agent-execution/v2", "run_id": run_id, "status": "succeeded"})

    def _write_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            # Client cancellation is expected in the cancel case.
            pass


class StubServer(ThreadingHTTPServer):
    def __init__(self, state: StubState) -> None:
        super().__init__(("0.0.0.0", 0), AgentStub)
        self.state = state
        self.run_id = ""


def request(method: str, path: str, payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    raw = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    merged = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}
    merged.update(headers or {})
    if raw is not None:
        merged["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE_URL + path, data=raw, headers=merged, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        return exc.code, json.loads(body) if body else {}


def scope(run_id: str) -> dict[str, Any]:
    return {
        "tenant_id": "tenant-dispatcher-fault-e2e",
        "department_id": "compliance",
        "application_id": "business-app",
        "agent_instance_id": "fault-instance",
        "agent_id": "fault-agent",
        "principal_type": "service_principal",
        "principal_id": "fault-machine",
        "installation_id": "fault-installation",
        "agent_version_id": "fault-v1",
        "session_id": f"session-{run_id}",
        "run_id": run_id,
        "authorization_epoch": 1,
        "trace_id": "0123456789abcdef0123456789abcdef",
    }


def headers_for(run_scope: dict[str, Any]) -> dict[str, str]:
    return {
        "X-Tenant-ID": run_scope["tenant_id"],
        "X-Department-ID": run_scope["department_id"],
        "X-Application-ID": run_scope["application_id"],
        "X-Agent-Instance-ID": run_scope["agent_instance_id"],
        "X-Agent-ID": run_scope["agent_id"],
        "X-Principal-ID": run_scope["principal_id"],
        "X-Principal-Type": run_scope["principal_type"],
        "X-Installation-ID": run_scope["installation_id"],
        "X-Agent-Version-ID": run_scope["agent_version_id"],
        "X-Session-ID": run_scope["session_id"],
        "X-Authorization-Epoch": "1",
        "X-Trace-ID": run_scope["trace_id"],
    }


def create_run(server: StubServer, mode: str, *, attempts: int, timeout_seconds: int) -> tuple[str, dict[str, Any]]:
    run_id = f"fault-e2e-{mode}-{uuid.uuid4().hex[:12]}"
    server.run_id = run_id
    run_scope = scope(run_id)
    request_payload = {
        "protocol_version": "agent-execution/v2",
        "context_token": "ctx-" + "x" * 60,
        "scope": run_scope,
        "operation": "invoke",
        "idempotency_key": f"idem-{uuid.uuid4().hex}",
        "input_schema": "schema://fault-agent/input/v1",
        "input": {
            "policy_snapshot": {
                "content_hash": "a" * 64,
                "runtime": {"max_attempts": attempts, "task_timeout_seconds": timeout_seconds, "lease_seconds": 5},
            }
        },
    }
    status, body = request(
        "POST",
        "/modules/execution/platform/runs",
        {
            "run_id": run_id,
            "scope": run_scope,
            "agent_version_id": "fault-v1",
            "idempotency_key": request_payload["idempotency_key"],
            "fingerprint": uuid.uuid4().hex,
            "request": request_payload,
            "agent_endpoint": f"http://host.docker.internal:{server.server_port}",
        },
    )
    if status != 200:
        raise AssertionError(f"create {mode} failed: {status} {body}")
    return run_id, run_scope


def wait_terminal(run_id: str, run_scope: dict[str, Any], expected: str, timeout: float = 25) -> dict[str, Any]:
    deadline = time.time() + timeout
    current: dict[str, Any] = {}
    while time.time() < deadline:
        status, current = request("GET", f"/modules/execution/platform/runs/{run_id}", headers=headers_for(run_scope))
        if status != 200:
            raise AssertionError(f"get {run_id} failed: {status} {current}")
        if current.get("status") == expected:
            return current
        if current.get("status") in {"failed", "cancelled", "succeeded"} and current.get("status") != expected:
            break
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} expected {expected}, got {current}")


def events(run_id: str, run_scope: dict[str, Any]) -> list[dict[str, Any]]:
    status, body = request("POST", f"/modules/execution/platform/runs/{run_id}/events", {"scope": run_scope, "after_seq": 0})
    if status != 200:
        raise AssertionError(f"events failed: {status} {body}")
    return body if isinstance(body, list) else []


def run_retry_matrix() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for mode, expected, attempts, timeout_seconds, expected_failures in ((
        ("retry-success", "succeeded", 2, 5, 1),
        ("always-fail", "failed", 2, 5, 2),
        ("timeout", "failed", 2, 1, 2),
    )):
        state = StubState(mode)
        server = StubServer(state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            run_id, run_scope = create_run(server, mode, attempts=attempts, timeout_seconds=timeout_seconds)
            wait_terminal(run_id, run_scope, expected)
            run_events = events(run_id, run_scope)
            failures = [item for item in run_events if item.get("event_type") == "attempt_failed"]
            if len(failures) != expected_failures:
                raise AssertionError(f"{mode}: expected {expected_failures} attempt_failed events, got {failures}")
            if mode == "timeout" and any(item.get("payload", {}).get("code") != "AGENT_EXECUTION_TIMEOUT" for item in failures):
                raise AssertionError(f"timeout classification is not stable: {failures}")
            if mode in {"retry-success", "always-fail"} and any(not item.get("payload", {}).get("retryable") for item in failures):
                raise AssertionError(f"retryable upstream error lost its retry flag: {failures}")
            result[mode] = {"run_id": run_id, "calls": state.calls, "attempt_failed": len(failures), "status": expected}
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
    return result


def run_cancel_matrix() -> dict[str, Any]:
    state = StubState("cancel")
    server = StubServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        run_id, run_scope = create_run(server, "cancel", attempts=1, timeout_seconds=30)
        deadline = time.time() + 10
        current: dict[str, Any] = {}
        while time.time() < deadline:
            status, current = request("GET", f"/modules/execution/platform/runs/{run_id}", headers=headers_for(run_scope))
            if status == 200 and current.get("status") == "running":
                break
            time.sleep(0.2)
        if current.get("status") != "running":
            raise AssertionError(f"cancel run never became running: {current}")
        status, cancelled = request(
            "POST",
            f"/modules/execution/platform/runs/{run_id}/cancel",
            {"scope": run_scope, "expected_revision": current["revision"]},
        )
        if status != 200 or cancelled.get("status") != "cancelled":
            raise AssertionError(f"cancel failed: {status} {cancelled}")
        run_events = events(run_id, run_scope)
        if not any(item.get("event_type") == "task_cancelled" for item in run_events):
            raise AssertionError(f"cancel event missing: {run_events}")
        return {"run_id": run_id, "calls": state.calls, "status": "cancelled", "task_cancelled": True}
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


if __name__ == "__main__":
    output = {"retry_matrix": run_retry_matrix(), "cancel_matrix": run_cancel_matrix()}
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    print("PLATFORM_DISPATCHER_FAULT_E2E=PASS")
