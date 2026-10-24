"""Project measured model usage without inventing missing cache hits or cost."""
from __future__ import annotations

from .capability_client import GatewayError


def chat_usage(usage: dict) -> dict:
    if not isinstance(usage, dict):
        raise GatewayError("MODEL_USAGE_INVALID", "model usage must be an object")
    result = {
        "prompt_tokens": usage.get("input_tokens", usage.get("prompt_tokens")),
        "completion_tokens": usage.get("output_tokens", usage.get("completion_tokens")),
    }
    for value in result.values():
        if value is not None and (type(value) is not int or value < 0):
            raise GatewayError("MODEL_USAGE_INVALID", "model usage must contain measured token counts")
    fields = ("cached_input_tokens", "uncached_input_tokens")
    if any(field in usage for field in fields):
        hit, miss = (usage.get(field) for field in fields)
        if (type(hit) is not int or type(miss) is not int or hit < 0 or miss < 0
                or result["prompt_tokens"] is None or hit + miss != result["prompt_tokens"]):
            raise GatewayError("MODEL_USAGE_INVALID", "inconsistent measured context cache usage")
        result.update(cached_input_tokens=hit, uncached_input_tokens=miss)
    return result
