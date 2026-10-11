"""Exercise the real platform notification path against Compose Kafka.

The test intentionally uses only standard-library HTTP so it is runnable on
Windows, Linux and macOS without installing an additional test dependency.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import time
import urllib.error
import urllib.request
import uuid
from typing import Any


def request(
    url: str,
    method: str = "GET",
    token: str | None = None,
    payload: Any = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            parsed = json.loads(body) if body else None
        except json.JSONDecodeError:
            parsed = body
        return exc.code, parsed


def wait_health(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last: object = None
    while time.time() < deadline:
        try:
            status, body = request(url)
            last = (status, body)
            if status == 200:
                return
        except (OSError, TimeoutError) as exc:
            last = repr(exc)
        time.sleep(0.5)
    raise AssertionError(f"health endpoint did not become ready: {url}: {last}")


def wait_for_count(receiver_url: str, expected: int, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: dict[str, Any] = {}
    while time.time() < deadline:
        status, body = request(f"{receiver_url.rstrip('/')}/events")
        if status == 200 and isinstance(body, dict):
            last = body
            if int(body.get("count", 0)) >= expected:
                return body
        time.sleep(0.5)
    raise AssertionError(f"webhook receiver did not reach {expected}: {last}")


def receiver_control(receiver_url: str, payload: dict[str, Any]) -> dict[str, Any]:
    status, body = request(f"{receiver_url.rstrip('/')}/control/fail", "POST", payload=payload)
    assert status == 200, (status, body)
    assert isinstance(body, dict), body
    return body


def wait_for_failure_calls(receiver_url: str, expected: int, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    latest: dict[str, Any] = {}
    while time.time() < deadline:
        status, body = request(f"{receiver_url.rstrip('/')}/events")
        if status == 200 and isinstance(body, dict):
            latest = body
            if int(body.get("failure_calls", 0)) >= expected:
                return body
        time.sleep(0.25)
    raise AssertionError(f"webhook receiver did not reach {expected} failures: {latest}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform-url", required=True)
    parser.add_argument("--receiver-url", required=True)
    parser.add_argument("--internal-token", required=True)
    parser.add_argument("--event-prefix", default="kafka-e2e")
    args = parser.parse_args()

    wait_health(f"{args.platform_url.rstrip('/')}/health/ready")
    wait_health(f"{args.receiver_url.rstrip('/')}/healthz")

    event_id = f"{args.event_prefix}-{uuid.uuid4().hex}"
    event = {
        "id": event_id,
        "tenant_id": "tenant-kafka-e2e",
        "department_id": "compliance",
        "application_id": "business-app",
        "topic": "platform.audit",
        "event_type": "kafka_e2e_probe",
        "partition_key": "kafka-e2e",
        "payload": {"purpose": "real-kafka-channel-adapter"},
    }
    endpoint = f"{args.platform_url.rstrip('/')}/modules/notification/events"
    status, accepted = request(endpoint, "POST", args.internal_token, event)
    assert status == 202, (status, accepted)

    delivered = wait_for_count(args.receiver_url, 1)
    received = [item for item in delivered.get("events", []) if item.get("id") == event_id]
    assert len(received) == 1, delivered

    # Enqueueing the exact same immutable event is idempotent; Kafka must not
    # result in a second ChannelAdapter call for the same Event.ID.
    status, duplicate = request(endpoint, "POST", args.internal_token, event)
    assert status == 202, (status, duplicate)
    time.sleep(2)
    status, after_duplicate = request(f"{args.receiver_url.rstrip('/')}/events")
    assert status == 200, (status, after_duplicate)
    received_after = [item for item in after_duplicate.get("events", []) if item.get("id") == event_id]
    assert len(received_after) == 1, after_duplicate

    # The business audit endpoint writes the audit row and its notification
    # outbox row in one SQL transaction.  Publishing that event through the
    # same Kafka/ChannelAdapter path proves the cross-module audit boundary,
    # not only the synthetic notification endpoint.
    # 业务审计接口在同一个 SQL 事务中写审计事实和通知 Outbox；再走同一条
    # Kafka/ChannelAdapter 链路，验证跨模块审计边界而不是只验证合成通知。
    audit_id = f"{args.event_prefix}-audit-{uuid.uuid4().hex}"
    audit_event = {
        "id": audit_id,
        "tenant_id": event["tenant_id"],
        "department_id": event["department_id"],
        "application_id": event["application_id"],
        "actor_type": "machine",
        "actor_id": "kafka-e2e-machine",
        "trace_id": f"trace-{audit_id}",
        "aggregate_type": "kafka_probe",
        "aggregate_id": event_id,
        "action": "notification_probe",
        "outcome": "accepted",
        "summary": "redacted kafka audit probe",
        # Keep the outbox ready immediately; RecordTx intentionally uses the
        # audit timestamp as next_attempt_at.  A future fixture timestamp would
        # correctly defer delivery and make this E2E look flaky.
        # Outbox 会使用审计时间作为 next_attempt_at；测试时间必须是当前时间，
        # 否则未来时间会按正确语义延迟投递，造成假失败。
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    scope_headers = {
        "X-Tenant-ID": event["tenant_id"],
        "X-Department-ID": event["department_id"],
        "X-Application-ID": event["application_id"],
    }
    audit_endpoint = f"{args.platform_url.rstrip('/')}/modules/audit/events"
    status, accepted_audit = request(audit_endpoint, "POST", args.internal_token, audit_event)
    assert status == 201, (status, accepted_audit)
    audit_delivery = wait_for_count(args.receiver_url, 2)
    audit_received_id = f"audit-{audit_id}"
    assert [item for item in audit_delivery.get("events", []) if item.get("id") == audit_received_id], audit_delivery
    status, audit_page = request(audit_endpoint, "GET", args.internal_token, headers=scope_headers)
    assert status == 200 and isinstance(audit_page, dict), (status, audit_page)
    assert any(item.get("id") == audit_id for item in audit_page.get("items", [])), audit_page

    # A transient channel outage must leave the Kafka offset uncommitted and
    # retry the exact Event.ID. It may produce several broker deliveries but
    # reaches the ChannelAdapter only once after recovery.
    # 临时通道故障必须保留 Kafka offset，并重试同一 Event.ID；恢复后通道只成功一次。
    receiver_control(args.receiver_url, {"count": 1})
    retry_id = f"{args.event_prefix}-retry-{uuid.uuid4().hex}"
    retry_event = {**event, "id": retry_id, "payload": {"purpose": "retry-after-channel-failure"}}
    status, accepted = request(endpoint, "POST", args.internal_token, retry_event)
    assert status == 202, (status, accepted)
    retry_snapshot = wait_for_count(args.receiver_url, 3)
    retry_received = [item for item in retry_snapshot.get("events", []) if item.get("id") == retry_id]
    assert len(retry_received) == 1, retry_snapshot
    assert int(retry_snapshot.get("failure_calls", 0)) >= 1, retry_snapshot

    # Exhausting the configured retry budget must leave no successful channel
    # side effect. kafka-go then sends the source record to its DLQ before it
    # commits the source offset; the number of injected failures is the same
    # as PLATFORM_KAFKA_MAX_ATTEMPTS in this isolated profile.
    # 耗尽重试预算后不得产生通道副作用；kafka-go 先写 DLQ 再提交源 offset。
    dlq_attempts = 5
    receiver_control(args.receiver_url, {"count": dlq_attempts})
    dlq_id = f"{args.event_prefix}-dlq-{uuid.uuid4().hex}"
    dlq_event = {**event, "id": dlq_id, "payload": {"purpose": "dlq-after-channel-failure"}}
    status, accepted = request(endpoint, "POST", args.internal_token, dlq_event)
    assert status == 202, (status, accepted)
    failure_snapshot = wait_for_failure_calls(args.receiver_url, 1 + dlq_attempts, timeout=35)
    time.sleep(1.0)
    status, terminal_snapshot = request(f"{args.receiver_url.rstrip('/')}/events")
    assert status == 200, (status, terminal_snapshot)
    assert not [item for item in terminal_snapshot.get("events", []) if item.get("id") == dlq_id], terminal_snapshot

    print(json.dumps({
        "event_id": event_id,
        "retry_event_id": retry_id,
        "dlq_event_id": dlq_id,
        "delivered_once": True,
        "duplicate_suppressed": True,
        "retry_recovered": True,
        "dlq_delivery_suppressed": True,
        "failure_calls": failure_snapshot["failure_calls"],
    }))


if __name__ == "__main__":
    main()
