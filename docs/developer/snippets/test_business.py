"""Business acceptance cases for the support-assistant onboarding example."""
from types import SimpleNamespace
from threading import Event

import pytest

from domain.business import recommend, run


def test_support_answer_preserves_question_and_explains_next_steps():
    result = recommend({"question": "  How do I investigate a timeout?  "})
    assert result["question"] == "How do I investigate a timeout?"
    assert "service health" in result["answer"]
    assert "recent changes" in result["answer"]
    assert result["source"] == "deterministic-local-example"


@pytest.mark.parametrize("payload", [None, [], {}, {"question": 12}, {"question": ""}, {"question": "   "}])
def test_invalid_questions_do_not_produce_an_answer(payload):
    with pytest.raises(ValueError):
        recommend(payload)


def test_cancelled_task_does_not_produce_a_business_result():
    stopped = Event()
    stopped.set()
    trusted = SimpleNamespace(request=SimpleNamespace(input={"question": "Investigate a timeout"}))
    with pytest.raises(RuntimeError, match="cancelled"):
        run(trusted, [], stopped)
