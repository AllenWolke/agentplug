"""Tests the conformance runner through a fake HTTP Agent, not an SDK import."""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import os
import base64
import hashlib
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _Agent(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None: pass

    def _json(self, status: int, payload: dict[str, object]) -> None:
        raw = json.dumps(payload).encode(); self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_GET(self) -> None:
        self._json(200, {"manifest_version": "agent-manifest/v1", "agent_id": "black-box-test", "version": "2.0.0", "execution_protocols": ["agent-execution/v2"], "capabilities": ["invoke", "run", "resume", "cancel", "events"], "schemas": {"input": "schema://black-box-test/input/v1", "output": "schema://black-box-test/output/v1", "event": "schema://black-box-test/event/v1", "checkpoint": "schema://black-box-test/checkpoint/v1"}, "runtime": {"transport": "http", "isolation": "container"}})

    def do_POST(self) -> None:
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.loads(raw)
        if not isinstance(body, dict) or not body.get("scope", {}).get("run_id"):
            self._json(400, {"code": "REQUEST_INVALID"}); return
        if self.path.endswith("/invoke") and "run_id" not in body.get("scope", {}): self._json(400, {"code": "REQUEST_INVALID"}); return
        run_id = body["scope"]["run_id"]
        if self.path.endswith("/events"):
            event = json.dumps({"run_id": run_id, "seq": 1, "event_type": "progress", "occurred_at": "2026-01-01T00:00:00Z", "payload": {}})
            payload = f"id: 1\nevent: progress\ndata: {event}\n\n".encode(); self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers(); self.wfile.write(payload); return
        self._json(202 if self.path.endswith("/runs") else 200, {"protocol_version": "agent-execution/v2", "run_id": run_id, "status": "running"})


class _RunOnlyAgent(_Agent):
    """Fixture for a valid capability subset without invoke. / 仅 run 能力的合法 Agent。"""

    def do_GET(self) -> None:
        self._json(200, {"manifest_version": "agent-manifest/v1", "agent_id": "run-only-agent", "version": "2.0.0", "execution_protocols": ["agent-execution/v2"], "capabilities": ["run", "resume", "cancel", "events"], "schemas": {"input": "schema://run-only/input/v1", "output": "schema://run-only/output/v1", "event": "schema://run-only/event/v1", "checkpoint": "schema://run-only/checkpoint/v1"}, "runtime": {"transport": "http", "isolation": "container"}})


@contextlib.contextmanager
def agent_server(handler: type[BaseHTTPRequestHandler]) -> object:
    """Start a temporary HTTP fixture server. / 启动临时 HTTP 测试服务。"""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try: yield server
    finally: server.shutdown(); thread.join(); server.server_close()


@contextlib.contextmanager
def agent() -> object:
    with agent_server(_Agent) as server:
        yield server


class RunnerTest(unittest.TestCase):
    def test_signed_lifecycle_fixture_covers_all_operations(self) -> None:
        scope = {"tenant_id": "t", "department_id": "d", "application_id": "a", "agent_instance_id": "i", "agent_id": "id", "agent_version_id": "v", "principal_type": "user", "principal_id": "u", "session_id": "s", "run_id": "run-1", "authorization_epoch": 1, "trace_id": "0" * 32}
        execution = lambda operation: {"protocol_version": "agent-execution/v2", "context_token": "signed-by-gateway", "scope": scope, "operation": operation, "idempotency_key": "idempotency-key", "input_schema": "schema://test/v1", "input": {"policy_snapshot": {"content_hash": "a" * 64}}}
        fixture = {"invoke": execution("invoke"), "run": execution("run"), "resume": execution("resume"), "cancel": execution("cancel"), "events": {"protocol_version": "agent-execution/v2", "context_token": "signed-by-gateway", "scope": scope, "after_seq": 0, "policy_snapshot_hash": "a" * 64}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as output:
            json.dump(fixture, output); fixture_path = output.name
        try:
            with agent() as server:
                result = subprocess.run([sys.executable, "conformance/runner/run.py", "--base-url", f"http://127.0.0.1:{server.server_port}", "--lifecycle-fixture", fixture_path], capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        finally: Path(fixture_path).unlink(missing_ok=True)

    def test_go_example_passes_black_box_signed_lifecycle(self) -> None:
        """Run the public runner against the real Go HTTP process.

        对真实 Go HTTP 进程执行公共 runner，而非仅调用 Go Handler。
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = Ed25519PrivateKey.generate()
        raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        scope = {"tenant_id": "tenant-a", "department_id": "business-department", "application_id": "business-app", "agent_instance_id": "instance-a", "agent_id": "example-go-eino", "agent_version_id": "v2", "principal_type": "user", "principal_id": "user-a", "session_id": "session-a", "run_id": "conformance-run", "authorization_epoch": 1, "trace_id": "0" * 32}
        policy_hash = "a" * 64

        def sign(envelope: dict[str, object], action: str) -> dict[str, object]:
            unsigned = {key: value for key, value in envelope.items() if key != "context_token"}
            body_hash = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            now = int(time.time()); header = {"alg": "EdDSA"}
            claims = {"iss": "platform-runtime-gateway", "aud": "example-go-eino", "subject_type": "user", "sub": "user-a", "tenant_id": "tenant-a", "application_id": "business-app", "agent_instance_id": "instance-a", "authorization_epoch": 1, "actions": [action], "policy_snapshot_hash": policy_hash, "body_hash": body_hash, "iat": now, "exp": now + 60}
            encode = lambda value: base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=")
            head, payload = encode(header), encode(claims); envelope["context_token"] = b".".join((head, payload, base64.urlsafe_b64encode(private.sign(head + b"." + payload)).rstrip(b"="))).decode()
            return envelope

        def execution(action: str) -> dict[str, object]:
            return sign({"protocol_version": "agent-execution/v2", "context_token": "", "scope": scope, "operation": action, "idempotency_key": "conformance-" + action, "input_schema": "schema://example/input/v1", "input": {"policy_snapshot": {"content_hash": policy_hash}}}, action)

        # Event payload has a distinct canonical body shape from ExecuteRequest.
        events = sign({"protocol_version": "agent-execution/v2", "context_token": "", "scope": scope, "after_seq": 0, "policy_snapshot_hash": policy_hash}, "events")
        fixture = {"invoke": execution("invoke"), "run": execution("run"), "resume": execution("resume"), "cancel": execution("cancel"), "events": events}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as output:
            json.dump(fixture, output); fixture_path = output.name
        server = None
        try:
            with __import__("socket").socket() as sock:
                sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
            env = os.environ | {"AGENT_PORT": str(port), "AGENT_PLATFORM_PUBLIC_KEY_BASE64": base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode(), "GOCACHE": str(Path("tmp/ar15-conformance-gocache").resolve())}
            server = subprocess.Popen(["go", "run", "."], cwd="agents/examples/go-eino", env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            deadline = time.time() + 20
            while True:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/.well-known/agent-manifest.json", timeout=0.5): break
                except OSError:
                    if time.time() > deadline: self.fail("Go example did not start: " + (server.stderr.read() if server.stderr else ""))
                    time.sleep(0.1)
            result = subprocess.run([sys.executable, "conformance/runner/run.py", "--base-url", f"http://127.0.0.1:{port}", "--lifecycle-fixture", fixture_path], capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        finally:
            Path(fixture_path).unlink(missing_ok=True)
            if server is not None:
                server.terminate(); server.wait(timeout=10)
                if server.stdout: server.stdout.close()
                if server.stderr: server.stderr.close()

    def test_capability_subset_is_conformant(self) -> None:
        """A run-only Agent must not be forced to implement invoke.

        仅声明 run/resume/cancel/events 的 Agent 不应被错误要求实现 invoke。
        """
        with agent_server(_RunOnlyAgent) as server:
            result = subprocess.run([sys.executable, "conformance/runner/run.py", "--base-url", f"http://127.0.0.1:{server.server_port}"], capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)


if __name__ == "__main__": unittest.main()
