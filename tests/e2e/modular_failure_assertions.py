"""Strict negative Run evidence checks. / 严格负向运行证据检查。"""

from typing import Any


def assert_preflight_rejection(status: int, response: Any, expected_code: str) -> None:
    """Require a typed rejection before any Run exists. / 创建 Run 前须明确拒绝。"""
    if (
        status != 422
        or not isinstance(response, dict)
        or response.get("code") != expected_code
        or response.get("retryable") is not False
    ):
        raise RuntimeError("preflight did not reject with its precise domain code")


def assert_failure_events(
    events: Any,
    expected_code: str,
    expected_retryable: bool,
    *,
    require_attempt: bool = True,
) -> dict[str, Any]:
    """Reject generic failure; pre-dispatch IAM denial must have zero attempts.

    拒绝笼统失败；投递前 IAM 拒绝必须没有 Agent 执行尝试。
    """
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        raise RuntimeError("failure event replay must be an object array")
    finals = [e for e in events if e.get("event_type") == "task_failed"]
    attempts = [e for e in events if e.get("event_type") == "attempt_failed"]
    if (
        len(finals) != 1
        or (require_attempt and not attempts)
        or (not require_attempt and attempts)
    ):
        raise RuntimeError(
            "failure event and dispatch attempt count do not match the scenario"
        )
    final = finals[0].get("payload")
    if not isinstance(final, dict) or final.get("code") != expected_code:
        actual = final.get("code") if isinstance(final, dict) else None
        raise RuntimeError(
            f"terminal error code mismatch: expected={expected_code} actual={actual}"
        )
    for attempt in attempts:
        payload = attempt.get("payload")
        if (
            not isinstance(payload, dict)
            or payload.get("code") != expected_code
            or payload.get("retryable") is not expected_retryable
        ):
            raise RuntimeError(
                "attempt error code/retryable does not match the scenario"
            )
    if not expected_retryable and require_attempt and len(attempts) != 1:
        raise RuntimeError("non-retryable domain failure was retried")
    if any(e.get("event_type") in {"task_completed", "review_waiting"} for e in events):
        raise RuntimeError("negative Run also emitted a successful business event")
    return {
        "code": expected_code,
        "retryable": expected_retryable,
        "attempts": len(attempts),
    }
