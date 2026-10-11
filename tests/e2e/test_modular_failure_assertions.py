"""Regression of acceptance logic; not Docker evidence. / 验收逻辑回归，非 Docker 证据。"""

import pytest

from modular_failure_assertions import assert_failure_events, assert_preflight_rejection


def events(code="RULE_BUNDLE_INVALID", retryable=False):
    return [
        {
            "event_type": "attempt_failed",
            "payload": {"code": code, "retryable": retryable},
        },
        {"event_type": "task_failed", "payload": {"code": code}},
    ]


def test_exact_non_retryable_failure():
    assert assert_failure_events(events(), "RULE_BUNDLE_INVALID", False) == {
        "code": "RULE_BUNDLE_INVALID",
        "retryable": False,
        "attempts": 1,
    }


@pytest.mark.parametrize(
    "bad",
    [
        [],
        {},
        [None],
        events("INTERNAL_ERROR"),
        events(retryable=True),
        events(retryable="false"),
        events()[1:],
        events() + [events()[0]],
        events() + [events()[1]],
        events() + [{"event_type": "task_completed"}],
        [{"event_type": "attempt_failed", "payload": None}, events()[1]],
    ],
)
def test_wrong_or_incomplete_evidence_fails(bad):
    with pytest.raises(RuntimeError):
        assert_failure_events(bad, "RULE_BUNDLE_INVALID", False)


def test_temporary_failure_preserves_all_retry_attempts():
    sample = events("CAPABILITY_UNAVAILABLE", True)
    sample.insert(0, sample[0].copy())
    assert (
        assert_failure_events(sample, "CAPABILITY_UNAVAILABLE", True)["attempts"] == 2
    )


def test_pre_dispatch_authorization_failure_has_no_agent_attempt():
    sample = [
        {"event_type": "task_failed", "payload": {"code": "AUTHORIZATION_DENIED"}}
    ]
    assert (
        assert_failure_events(
            sample, "AUTHORIZATION_DENIED", False, require_attempt=False
        )["attempts"]
        == 0
    )
    with pytest.raises(RuntimeError):
        assert_failure_events(
            events("AUTHORIZATION_DENIED"),
            "AUTHORIZATION_DENIED",
            False,
            require_attempt=False,
        )


def test_preflight_rejection_exact_domain_code():
    assert_preflight_rejection(
        422,
        {"code": "UNSUPPORTED_REPORT_TYPE", "retryable": False},
        "UNSUPPORTED_REPORT_TYPE",
    )


@pytest.mark.parametrize(
    "status,payload",
    [
        (202, {"code": "UNSUPPORTED_REPORT_TYPE", "retryable": False}),
        (500, {"code": "INTERNAL_ERROR", "retryable": False}),
        (422, {"code": "INVALID_REQUEST", "retryable": False}),
        (422, {"code": "UNSUPPORTED_REPORT_TYPE", "retryable": "false"}),
        (422, []),
    ],
)
def test_preflight_rejection_never_accepts_generic_or_wrong_shape(status, payload):
    with pytest.raises(RuntimeError):
        assert_preflight_rejection(status, payload, "UNSUPPORTED_REPORT_TYPE")
