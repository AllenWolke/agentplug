"""Validate platform business cancellation; local gateway stop is separate."""
from __future__ import annotations
from dataclasses import dataclass
import re
from typing import Any

class CancellationEvidenceError(ValueError):
    def __init__(self) -> None:
        super().__init__("platform cancellation evidence unconfirmed")

@dataclass(frozen=True)
class CancellationState:
    version: str
    disposition: str
    progress: dict[str, Any] | None
    complete: bool

def read_cancellation_state(status: str, value: Any = None) -> CancellationState | None:
    if status not in ("cancelling", "cancelled"):
        if value is not None:
            raise CancellationEvidenceError()
        return None
    if value is None:
        return CancellationState("cancellation-state/v1", "historical_unverified" if status == "cancelled" else "pending_unverified", None, False)
    if not isinstance(value, dict) or value.get("version") != "cancellation-state/v1":
        raise CancellationEvidenceError()
    disposition = value.get("disposition")
    if disposition in ("historical_unverified", "pending_unverified"):
        if status != ("cancelled" if disposition == "historical_unverified" else "cancelling") or value.get("progress") is not None:
            raise CancellationEvidenceError()
        return CancellationState("cancellation-state/v1", disposition, None, False)
    if disposition not in ("verified", "in_progress"):
        raise CancellationEvidenceError()
    p = value.get("progress")
    if not isinstance(p, dict) or p.get("version") != "cancellation-compensation/v1" or type(p.get("stop_confirmed")) is not bool:
        raise CancellationEvidenceError()
    if not isinstance(p.get("cancellation_id"), str) or not re.fullmatch(r"[0-9a-f]{64}", p["cancellation_id"]):
        raise CancellationEvidenceError()
    fields = ("total", "compensated", "no_effect", "unresolved", "needs_attention")
    if any(type(p.get(k)) is not int or not 0 <= p[k] <= 16384 for k in fields):
        raise CancellationEvidenceError()
    phase = p.get("phase")
    if phase not in ("stopping", "compensating", "needs_attention", "complete") or p["compensated"] + p["no_effect"] + p["unresolved"] != p["total"] or p["needs_attention"] > p["unresolved"]:
        raise CancellationEvidenceError()
    if (phase == "stopping") == p["stop_confirmed"] or (phase == "needs_attention") != (p["needs_attention"] > 0):
        raise CancellationEvidenceError()
    if disposition == "verified":
        if status != "cancelled" or phase != "complete" or p["unresolved"] != 0 or not p["stop_confirmed"]:
            raise CancellationEvidenceError()
    elif status != "cancelling" or phase == "complete":
        raise CancellationEvidenceError()
    clean = {key: p[key] for key in ("version", "cancellation_id", "phase", "stop_confirmed", *fields)}
    return CancellationState("cancellation-state/v1", disposition, clean, disposition == "verified")
