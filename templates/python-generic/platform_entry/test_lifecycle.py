"""Lifecycle tests over real HTTP against the template's own wiring.

模板自身接线的真实 HTTP 生命周期测试：invoke、run → events（SSE 重放）→
resume 幂等 → cancel 终态快照，以及协作式取消。令牌完全按平台网关的方式
现场铸造（Minter），证明只有持有平台私钥的调用方才能驱动业务接缝。
"""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import server
from agent_platform_sdk import EventRequest, ExecuteRequest, MemoryRunStore
from agent_platform_sdk.security import canonical_body_hash, canonical_event_hash


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def scope(run_id: str) -> dict[str, Any]:
    return {"tenant_id": "tenant-a", "department_id": "business-department", "application_id": "business-app",
            "agent_instance_id": "instance-a", "installation_id": "installation-a",
            "agent_id": "conformance-agent", "agent_version_id": "v2",
            "principal_type": "user", "principal_id": "user-a", "session_id": "session-a",
            "run_id": run_id, "authorization_epoch": 1, "trace_id": "0" * 32}


def envelope(token: str, run_id: str, operation: str = "run", idempotency: str = "idem-key-0001") -> dict[str, Any]:
    return {"protocol_version": "agent-execution/v2", "context_token": token, "scope": scope(run_id),
            "operation": operation, "idempotency_key": idempotency,
            "input_schema": "schema://example/input/v1",
            "input": {"policy_snapshot": {"content_hash": "a" * 64}}}


def event_envelope(token: str, run_id: str, after_seq: int = 0) -> dict[str, Any]:
    return {"protocol_version": "agent-execution/v2", "context_token": token, "scope": scope(run_id),
            "after_seq": after_seq, "policy_snapshot_hash": "a" * 64}


class Minter:
    """Signs execution capabilities exactly like the platform gateway: the body
    hash covers the wire envelope minus the bearer token itself.

    完全按平台网关的方式签发执行能力令牌：正文哈希覆盖除令牌外的线上信封。
    """

    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.issuer = "platform-runtime-gateway"
        self.audience = "conformance-agent"

    def execute_token(self, payload: dict[str, Any], operations: list[str], *, iat: int | None = None) -> str:
        request = ExecuteRequest.model_validate(payload)
        return self._sign(operations, canonical_body_hash(request), iat)

    def event_token(self, payload: dict[str, Any], *, iat: int | None = None) -> str:
        request = EventRequest.model_validate(payload)
        return self._sign(["events"], canonical_event_hash(request), iat)

    def _sign(self, operations: list[str], body_hash: str, iat: int | None) -> str:
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": self.audience, "subject_type": "user", "sub": "user-a",
                  "tenant_id": "tenant-a", "application_id": "business-app", "agent_instance_id": "instance-a",
                  "installation_id": "installation-a",
                  "authorization_epoch": 1, "actions": operations,
                  "policy_snapshot_hash": "a" * 64, "body_hash": body_hash,
                  "iat": now if iat is None else iat, "exp": (now if iat is None else iat) + 120}
        h = b64(json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode())
        p = b64(json.dumps(claims).encode())
        return f"{h}.{p}.{b64(self.private.sign(f'{h}.{p}'.encode()))}"


def parse_json(raw: str) -> dict[str, Any]:
    return json.loads(raw)


def parse_sse(raw: str) -> list[dict[str, str]]:
    frames = []
    for block in raw.split("\n\n"):
        if not block.strip():
            continue
        frames.append({line.split(": ", 1)[0]: line.split(": ", 1)[1] for line in block.splitlines() if ": " in line})
    return frames


class ServerKit:
    """A real HTTP ExecutionServer wired through the template factory.

    通过模板工厂装配的真实 HTTP ExecutionServer：默认使用模板真实业务接缝，
    也可注入用于协作式取消的挂起型业务。
    """

    def __init__(self, run: Any = None) -> None:
        self.minter = Minter()
        self.store = MemoryRunStore()
        self.execution = server.build_execution_server(
            self.minter.private.public_key(),
            agent_id="conformance-agent", audience=self.minter.audience, issuer=self.minter.issuer,
            store=self.store, run=run,
        )
        self.httpd = self.execution.serve(("127.0.0.1", 0))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def post(self, path: str, payload: dict[str, Any], token: str, *, auth: str | None = None) -> tuple[int, str]:
        body = json.dumps(payload).encode()
        request = urllib.request.Request(self.base + path, data=body, method="POST")
        request.add_header("Authorization", auth if auth is not None else "Bearer " + token)
        request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def invoke(self, run_id: str, operations: list[str], *, idempotency: str = "idem-key-0001") -> tuple[int, str]:
        payload = envelope("x" * 32, run_id, "invoke", idempotency)
        token = self.minter.execute_token(payload, operations)
        payload["context_token"] = token
        return self.post("/internal/agent-execution/v2/invoke", payload, token)

    def run(self, run_id: str, operations: list[str], *, idempotency: str = "idem-key-0001") -> tuple[int, str]:
        payload = envelope("x" * 32, run_id, "run", idempotency)
        token = self.minter.execute_token(payload, operations)
        payload["context_token"] = token
        return self.post("/internal/agent-execution/v2/runs", payload, token)

    def lifecycle(self, run_id: str, action: str, operations: list[str], *, input: dict[str, Any] | None = None) -> tuple[int, str]:
        payload = envelope("x" * 32, run_id, action, f"idem-{action}")
        if input is not None:
            payload["input"] = {"policy_snapshot": {"content_hash": "a" * 64}, **input}
        if action == "resume":
            payload["resume_input"] = input or {"decision": "approve"}
        token = self.minter.execute_token(payload, operations)
        payload["context_token"] = token
        return self.post(f"/internal/agent-execution/v2/runs/{run_id}/{action}", payload, token)

    def events(self, run_id: str, *, after_seq: int = 0) -> tuple[int, str]:
        payload = event_envelope("x" * 32, run_id, after_seq)
        token = self.minter.event_token(payload)
        payload["context_token"] = token
        return self.post(f"/internal/agent-execution/v2/runs/{run_id}/events", payload, token)


def wait_for_status(kit: ServerKit, run_id: str, status: str) -> None:
    for _ in range(300):
        record = kit.store.get_run(run_id)
        if record is not None and record.status == status:
            return
        time.sleep(0.01)
    raise AssertionError(f"run {run_id} never reached {status}")


def test_invoke_serves_the_business_output() -> None:
    kit = ServerKit()
    try:
        status, raw = kit.invoke("run-invoke", ["invoke"], idempotency="idem-invoke")
        body = parse_json(raw)
        assert status == 200 and body["run_id"] == "run-invoke" and body["status"] == "succeeded"
        assert body["output"] == {"echo": {"policy_snapshot": {"content_hash": "a" * 64}}}
    finally:
        kit.close()


def test_unverified_callers_never_reach_the_business_seam() -> None:
    kit = ServerKit()
    try:
        # A different platform key must never pass. / 不同的平台密钥绝不放行。
        forged = Minter()
        payload = envelope("x" * 32, "run-401", "run")
        token = forged.execute_token(payload, ["run"])
        payload["context_token"] = token
        status, raw = kit.post("/internal/agent-execution/v2/runs", payload, token)
        assert status == 401 and parse_json(raw)["code"] == "CAPABILITY_INVALID"
        # A stolen header cannot be paired with a different body.
        # 窃取的头部无法与别的正文配对。
        payload = envelope("x" * 32, "run-401", "run")
        token = kit.minter.execute_token(payload, ["run"])
        payload["context_token"] = token
        status, raw = kit.post("/internal/agent-execution/v2/runs", payload, token, auth="Bearer forged")
        assert status == 401
        # The delegated actions must include the operation. / 被委派动作必须含该操作。
        status, raw = kit.run("run-401", ["invoke"])
        assert status == 401
        assert kit.store.get_run("run-401") is None
    finally:
        kit.close()


def test_serves_the_full_lifecycle_legs_with_sse_replay() -> None:
    kit = ServerKit()
    try:
        status, raw = kit.run("run-full", ["run", "resume", "cancel", "invoke"])
        assert status == 202 and parse_json(raw)["status"] == "running"
        wait_for_status(kit, "run-full", "succeeded")

        status, raw = kit.events("run-full")
        assert status == 200
        frames = parse_sse(raw)
        assert [f["event"] for f in frames] == ["accepted", "started", "progress", "completed"]
        for frame in frames:
            data = parse_json(frame["data"])
            assert data["run_id"] == "run-full" and int(frame["id"]) == data["seq"]

        # Resume replays idempotently on a finished run. / 完成的运行上重放 resume 幂等。
        status, raw = kit.lifecycle("run-full", "resume", ["resume", "run", "invoke"])
        assert status == 202 and parse_json(raw)["status"] == "succeeded"

        # Cancel on a terminal run replays the terminal snapshot.
        # 终态运行上重放取消，返回终态快照。
        status, raw = kit.lifecycle("run-full", "cancel", ["cancel", "run", "invoke"])
        assert status == 202 and parse_json(raw)["status"] == "succeeded"
    finally:
        kit.close()


def test_run_honours_cooperative_cancellation() -> None:
    released = threading.Event()

    def parker(trusted: Any, events: Any, cancelled: threading.Event) -> dict[str, Any]:
        # Park until cancel or release so cooperative cancellation is real.
        # 挂起直到取消或放行，让协作式取消真实生效。
        events.append("progress", {"stage": "business"})
        while not cancelled.is_set() and not released.is_set():
            time.sleep(0.01)
        if cancelled.is_set():
            raise RuntimeError("run was cancelled")
        return {"done": True}

    kit = ServerKit(run=parker)
    try:
        status, _ = kit.run("run-cancel", ["run", "cancel", "invoke"])
        assert status == 202
        for _ in range(300):
            if any(e.event_type == "progress" for e in kit.store.events_after("run-cancel", 0)):
                break
            time.sleep(0.01)
        status, raw = kit.lifecycle("run-cancel", "cancel", ["cancel", "run", "invoke"])
        assert status == 202 and parse_json(raw)["status"] == "cancelled"
        # The cancellation is observable in the event history.
        # 取消在事件历史中可观察。
        record = kit.store.get_run("run-cancel")
        assert record.status == "cancelled"
        assert any(e.event_type == "cancelled" for e in record.events)
    finally:
        released.set()
        kit.close()
