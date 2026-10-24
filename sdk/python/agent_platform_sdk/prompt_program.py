"""Read optional staged instructions from an immutable published template.

The complete published template stays the system message. A selected stage
is data in the user turn, never a replacement or caller-authored system prompt.
Legacy text templates have no enabled execution modes.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .capability_client import GatewayError


def parse_prompt_program(template: str) -> dict[str, Any]:
    if not isinstance(template, str) or not template.strip():
        raise GatewayError("PROMPT_PROGRAM_REJECTED", "published template required")
    try:
        value = json.loads(template)
    except (ValueError, TypeError):
        return {"version": "legacy-prompt", "execution_modes": [], "stages": {}}
    if not isinstance(value, dict) or value.get("version") != "agentplug-prompt-program/v1":
        return {"version": "legacy-prompt", "execution_modes": [], "stages": {}}
    if (set(value) != {"version", "instructions", "default_stage", "execution_modes", "stages"}
            or not isinstance(value.get("instructions"), str) or not value["instructions"].strip()
            or not isinstance(value.get("execution_modes"), list) or len(value["execution_modes"]) > 8
            or any(not isinstance(mode, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", mode)
                   for mode in value["execution_modes"])
            or len(set(value["execution_modes"])) != len(value["execution_modes"])
            or not isinstance(value.get("stages"), dict) or not 1 <= len(value["stages"]) <= 8
            or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name)
                   or not isinstance(body, str) or not body.strip() for name, body in value["stages"].items())
            or value.get("default_stage") not in value["stages"]):
        raise GatewayError("PROMPT_PROGRAM_REJECTED", "invalid published stage configuration")
    return value


def stage_messages(program: dict, stage: str, payload: dict) -> list[dict]:
    if program.get("version") != "agentplug-prompt-program/v1" or stage not in program.get("stages", {}):
        raise GatewayError("PROMPT_STAGE_REJECTED", "published stage required")
    if not isinstance(payload, dict) or "stage" in payload:
        raise GatewayError("PROMPT_STAGE_REJECTED", "stage is selected by the adapter")
    return [{"role": "user", "content": json.dumps({"stage": stage, "input": payload},
                                                    ensure_ascii=False, allow_nan=False)}]
