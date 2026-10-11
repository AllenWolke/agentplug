"""Regression tests for asynchronous conversation projection readiness."""

from unittest.mock import patch

import pytest

import run_assertions as subject


def test_projection_waits_for_eventual_message():
    message = {"role": "assistant", "content": "answer"}
    with patch.object(
        subject,
        "_http",
        side_effect=[(200, {"items": []}), (200, {"items": [message]})],
    ) as request, patch.object(subject.time, "sleep"):
        assert subject._wait_assistant_projection("http://test/messages", {}) == [
            message
        ]
        assert request.call_count == 2


def test_projection_empty_until_deadline_fails():
    with patch.object(subject, "_http", return_value=(200, {"items": []})):
        with pytest.raises(RuntimeError, match="deadline"):
            subject._wait_assistant_projection("http://test/messages", {}, timeout=0)


@pytest.mark.parametrize("response", [(403, {}), (200, {"items": None})])
def test_projection_contract_and_authorization_errors_fail_immediately(response):
    with patch.object(subject, "_http", return_value=response) as request:
        with pytest.raises(RuntimeError):
            subject._wait_assistant_projection("http://test/messages", {})
        assert request.call_count == 1
