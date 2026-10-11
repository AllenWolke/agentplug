"""Lifecycle tests over real HTTP against the template's own wiring.

python-langgraph 模板的真实 HTTP 生命周期测试：invoke、run 命中人工审核门时挂起
（waiting 事件经 SSE 可观察）、平台 resume 驱动 Command(resume=...) 完成、挂起期间
cancel 生效。PostgreSQL 重连恢复由隔离数据库验收覆盖。令牌完全按平台网关的方式现场
铸造（Minter），证明只有持有平台私钥的调用方才能驱动业务接缝。
"""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

import server
from agent_platform_sdk import EventRequest, ExecuteRequest, MemoryRunStore
from agent_platform_sdk.security import canonical_body_hash, canonical_event_hash


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def scope(run_id: str) -> dict[str, Any]:
    return {"tenant_id": "tenant-a", "department_id": "business-department", "application_id": "business-app",
            "agent_instance_id": "instance-a", "installation_id": "installation-a", "agent_id": "conformance-agent", "agent_version_id": "v2",
            "principal_type": "user", "principal_id": "user-a", "session_id": "session-a",
            "run_id": run_id, "authorization_epoch": 1, "trace_id": "0" * 32}


def envelope(token: str, run_id: str, operation: str = "run", idempotency: str = "idem-key-0001",
             input: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"protocol_version": "agent-execution/v2", "context_token": token, "scope": scope(run_id),
            "operation": operation, "idempotency_key": idempotency,
            "input_schema": "schema://example/input/v1",
            "input": input if input is not None else {"policy_snapshot": {"content_hash": "a" * 64}}}


def event_envelope(token: str, run_id: str, after_seq: int = 0) -> dict[str, Any]:
    return {"protocol_version": "agent-execution/v2", "context_token": token, "scope": scope(run_id),
            "after_seq": after_seq, "policy_snapshot_hash": "a" * 64}


REVIEW_INPUT = {"policy_snapshot": {"content_hash": "a" * 64}, "requires_review": True}


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
                  "tenant_id": "tenant-a", "application_id": "business-app", "agent_instance_id": "instance-a", "installation_id": "installation-a",
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
    """A real HTTP ExecutionServer wired through the template factory with the
    template's real LangGraph business graph. / 通过模板工厂与真实 LangGraph
    业务图装配的真实 HTTP ExecutionServer。
    """

    def __init__(self) -> None:
        self.minter = Minter()
        self.store = MemoryRunStore()
        self.execution = server.build_execution_server(
            self.minter.private.public_key(),
            agent_id="conformance-agent", audience=self.minter.audience, issuer=self.minter.issuer,
            store=self.store, graph=server.build_graph(MemorySaver()),
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

    def invoke(self, run_id: str, operations: list[str], *, idempotency: str = "idem-key-0001",
               input: dict[str, Any] | None = None) -> tuple[int, str]:
        payload = envelope("x" * 32, run_id, "invoke", idempotency, input)
        token = self.minter.execute_token(payload, operations)
        payload["context_token"] = token
        return self.post("/internal/agent-execution/v2/invoke", payload, token)

    def run(self, run_id: str, operations: list[str], *, idempotency: str = "idem-key-0001",
            input: dict[str, Any] | None = None) -> tuple[int, str]:
        payload = envelope("x" * 32, run_id, "run", idempotency, input)
        token = self.minter.execute_token(payload, operations)
        payload["context_token"] = token
        return self.post("/internal/agent-execution/v2/runs", payload, token)

    def lifecycle(self, run_id: str, action: str, operations: list[str], *, input: dict[str, Any] | None = None) -> tuple[int, str]:
        payload = envelope("x" * 32, run_id, action, f"idem-{action}", input)
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
        assert body["output"]["planned"] is True
        assert body["output"]["approval"] == "not_required"
    finally:
        kit.close()


def test_invoke_surfaced_with_a_review_gate_reports_it() -> None:
    kit = ServerKit()
    try:
        status, raw = kit.invoke("run-invoke-gate", ["invoke"], idempotency="idem-invoke-gate",
                                 input=REVIEW_INPUT)
        body = parse_json(raw)
        # Synchronous invoke cannot complete the gate; the question is surfaced.
        # 同步 invoke 无法完成审核门；问题随输出返回。
        assert status == 200 and body["output"]["status"] == "review_required"
        assert body["output"]["review"] == {"question": "approve the plan?"}
    finally:
        kit.close()


def test_run_interrupt_parks_waits_and_resume_completes() -> None:
    kit = ServerKit()
    try:
        status, raw = kit.run("run-review", ["run", "resume", "cancel", "invoke"], input=REVIEW_INPUT)
        assert status == 202 and parse_json(raw)["status"] == "running"
        wait_for_status(kit, "run-review", "waiting")

        # The waiting event is observable through the SSE replay and carries
        # the review question. / waiting 事件经 SSE 重放可观察，并携带审核问题。
        status, raw = kit.events("run-review")
        assert status == 200
        frames = parse_sse(raw)
        types = [f["event"] for f in frames]
        assert types == ["accepted", "started", "progress", "waiting"]
        waiting = parse_json(frames[-1]["data"])
        assert waiting["payload"] == {"question": "approve the plan?"}
        progress = parse_json(frames[2]["data"])
        assert progress["payload"]["thread_id"] == server.thread_id_for(ExecuteRequest.model_validate(envelope("x" * 32, "run-review", "run")).scope)

        # The resume leg delivers the review answer and the run completes.
        # resume 腿送达审核答案，运行随即完成。
        status, raw = kit.lifecycle("run-review", "resume", ["resume", "run", "invoke"],
                                    input={"approval": "approved"})
        assert status == 202 and parse_json(raw)["status"] == "running"
        wait_for_status(kit, "run-review", "succeeded")
        record = kit.store.get_run("run-review")
        assert record.output["approval"] == "approved"
        assert any(e.event_type == "completed" for e in record.events)
    finally:
        kit.close()


def test_cancel_while_waiting_cancels_the_run() -> None:
    kit = ServerKit()
    try:
        status, _ = kit.run("run-cancel", ["run", "resume", "cancel", "invoke"], input=REVIEW_INPUT)
        assert status == 202
        wait_for_status(kit, "run-cancel", "waiting")
        status, raw = kit.lifecycle("run-cancel", "cancel", ["cancel", "run", "invoke"])
        assert status == 202 and parse_json(raw)["status"] == "cancelled"
        record = kit.store.get_run("run-cancel")
        assert record.status == "cancelled"
        assert any(e.event_type == "cancelled" for e in record.events)
    finally:
        kit.close()


def test_thread_id_is_derived_from_the_verified_scope() -> None:
    request = ExecuteRequest.model_validate(envelope('x' * 32, 'run-thread', 'run'))
    expected = server.thread_id_for(request.scope)
    assert expected.startswith('scope-v2:')
    for field in ('tenant_id', 'department_id', 'application_id', 'installation_id',
                  'agent_instance_id', 'agent_id', 'agent_version_id', 'principal_type',
                  'principal_id', 'session_id', 'run_id'):
        changed = request.scope.model_copy(update={field: getattr(request.scope, field) + '-other'})
        assert server.thread_id_for(changed) != expected, field


def verify_postgres_restart(runtime_dsn: str) -> None:
    """Called by the owned PostgreSQL fixture, never by a real application DB."""
    env = {'PLATFORM_CHECKPOINTER': 'postgres', 'CHECKPOINT_DSN': runtime_dsn,
           'PLATFORM_ENV': 'production'}
    request = ExecuteRequest.model_validate(envelope('x' * 32, 'run-restart', 'run'))
    config = {'configurable': {'thread_id': server.thread_id_for(request.scope)}}
    first = server.resolve_checkpointer(env)
    connection = first.conn
    try:
        graph = server.build_graph(first)
        assert '__interrupt__' in graph.invoke({'input': dict(REVIEW_INPUT)}, config)
    finally:
        server.close_checkpointer(first)
    assert connection.closed
    second = server.resolve_checkpointer(env)
    try:
        graph = server.build_graph(second)
        assert graph.get_state(config).next == ('review',)
        changed = request.scope.model_copy(update={'principal_id': 'unrelated-user'})
        assert not graph.get_state({'configurable': {'thread_id': server.thread_id_for(changed)}}).next
        final = graph.invoke(Command(resume={'approval': 'approved'}), config)
        assert final['output']['approval'] == 'approved'
    finally:
        server.close_checkpointer(second)
    assert second.conn.closed
