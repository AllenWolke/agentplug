from __future__ import annotations

import json
from pathlib import Path

from agent_platform_sdk import ExecuteRequest


def test_shared_execution_fixture() -> None:
    root = Path(__file__).resolve().parents[3]
    payload = json.loads((root / "contracts/fixtures/execution-v2-request.json").read_text(encoding="utf-8"))
    request = ExecuteRequest.model_validate(payload)
    assert request.protocol_version == "agent-execution/v2"
    assert request.scope.authorization_epoch == 3
    assert request.model_dump(mode="json", exclude_none=True) == payload
