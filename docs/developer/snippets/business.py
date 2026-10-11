"""Minimal deterministic business hooks; no model key or platform database access."""


def validate_payload(payload):
    """Pure input check: no network, storage, model calls or other effects."""
    if not isinstance(payload, dict) or not isinstance(payload.get("question"), str) or not payload["question"].strip():
        raise ValueError("question must be a non-empty string")


def validate_input(trusted):
    validate_payload(trusted.request.input)


def recommend(payload):
    validate_payload(payload)
    question = payload["question"].strip()
    return {"question": question, "answer": "Check service health, recent changes and authorized run history.",
            "source": "deterministic-local-example"}


def invoke(trusted):
    return recommend(trusted.request.input)


def run(trusted, events, cancelled):
    if cancelled.is_set():
        raise RuntimeError("run was cancelled")
    events.append("progress", {"stage": "checking-question"})
    return recommend(trusted.request.input)
