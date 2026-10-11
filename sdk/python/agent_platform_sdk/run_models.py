"""Small run result values shared by production and development providers.

Keeping this value object outside ``local_runtime`` lets production Agent
imports avoid loading the development-only ExecutionManager/Store module.
生产 Agent 只需要结果值对象，不应因为导入 SDK 而加载本地执行账本。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """Business result returned by an Agent work hook."""

    status: str
    event_payload: dict[str, Any]


__all__ = ["ExecutionOutcome"]
