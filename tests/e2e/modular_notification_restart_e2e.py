"""Verify notification delivery recovery after Platform/Kafka restart.

The probe is deliberately two-phase so the PowerShell harness can restart the
real containers between a durable channel failure and recovery.  / 探针拆成两
阶段，使 PowerShell 能在真实通道失败后重启 Platform/Kafka，再验证恢复。
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def request(url: str, method: str = "GET", token: str | None = None, payload: Any = None) -> tuple[int, Any]:
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return exc.code, raw


def wait_health(url: str, timeout: float = 45.0) -> None:
    deadline = time.time() + timeout
    last: object = None
    while time.time() < deadline:
        try:
            status, body = request(url)
            last = (status, body)
            if status == 200:
                return
        except OSError as exc:
            last = repr(exc)
        time.sleep(0.5)
    raise AssertionError(f"health endpoint did not become ready: {url}: {last}")


def receiver(receiver_url: str, method: str = "GET", payload: Any = None) -> tuple[int, Any]:
    return request(f"{receiver_url.rstrip('/')}/events", method, payload=payload)


def control(receiver_url: str, count: int) -> None:
    status, body = request(f"{receiver_url.rstrip('/')}/control/fail", "POST", payload={"count": count})
    if status != 200:
        raise AssertionError((status, body))


def snapshot(receiver_url: str) -> dict[str, Any]:
    status, body = receiver(receiver_url)
    if status != 200 or not isinstance(body, dict):
        raise AssertionError((status, body))
    return body


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("prepare", "verify"), required=True)
    parser.add_argument("--platform-url", required=True)
    parser.add_argument("--receiver-url", required=True)
    parser.add_argument("--internal-token", required=True)
    parser.add_argument("--state-file", required=True)
    args = parser.parse_args()

    wait_health(f"{args.platform_url.rstrip('/')}/health/ready")
    wait_health(f"{args.receiver_url.rstrip('/')}/healthz")
    endpoint = f"{args.platform_url.rstrip('/')}/modules/notification/events"
    state_path = Path(args.state_file)

    if args.phase == "prepare":
        before = snapshot(args.receiver_url)
        event_id = f"kafka-restart-{int(time.time())}-{id(before)}"
        event = {
            "id": event_id,
            "tenant_id": "tenant-kafka-restart-e2e",
            "department_id": "compliance",
            "application_id": "business-app",
            "topic": "platform.audit",
            "event_type": "kafka_restart_probe",
            "partition_key": "kafka-restart",
            "payload": {"purpose": "platform-kafka-restart-recovery"},
        }
        control(args.receiver_url, 1)
        status, accepted = request(endpoint, "POST", args.internal_token, event)
        if status != 202:
            raise AssertionError((status, accepted))
        deadline = time.time() + 35
        failed = False
        while time.time() < deadline:
            current = snapshot(args.receiver_url)
            if int(current.get("failure_calls", 0)) >= int(before.get("failure_calls", 0)) + 1:
                failed = True
                if any(item.get("id") == event_id for item in current.get("events", [])):
                    raise AssertionError("event unexpectedly reached the channel before restart")
                break
            time.sleep(0.25)
        if not failed:
            raise AssertionError("channel failure was not observed before restart")
        state_path.write_text(json.dumps({"event": event}, ensure_ascii=False), encoding="utf-8")
        print(json.dumps({"phase": "prepare", "event_id": event_id, "channel_failure_observed": True}))
        return

    state = json.loads(state_path.read_text(encoding="utf-8"))
    event = state["event"]
    event_id = event["id"]
    deadline = time.time() + 45
    delivered: dict[str, Any] | None = None
    while time.time() < deadline:
        current = snapshot(args.receiver_url)
        matching = [item for item in current.get("events", []) if item.get("id") == event_id]
        if matching:
            delivered = current
            break
        time.sleep(0.5)
    if delivered is None:
        raise AssertionError("event did not recover after Platform/Kafka restart")
    matching = [item for item in delivered.get("events", []) if item.get("id") == event_id]
    if len(matching) != 1:
        raise AssertionError(f"restart recovery duplicated channel delivery: {delivered}")
    status, duplicate = request(endpoint, "POST", args.internal_token, event)
    if status != 202:
        raise AssertionError((status, duplicate))
    time.sleep(2)
    after = snapshot(args.receiver_url)
    matching_after = [item for item in after.get("events", []) if item.get("id") == event_id]
    if len(matching_after) != 1:
        raise AssertionError(f"post-restart duplicate event was delivered twice: {after}")
    print(json.dumps({"phase": "verify", "event_id": event_id, "restart_recovered": True, "delivered_once": True, "duplicate_suppressed": True}))


if __name__ == "__main__":
    main()
