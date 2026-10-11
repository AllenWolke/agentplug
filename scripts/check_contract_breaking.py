from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"


def fail(message: str) -> None:
    raise ValueError(message)


def require_text(path: Path, values: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    missing = [value for value in values if value not in text]
    if missing:
        fail(f"{path.relative_to(ROOT)} removed required contract tokens: {missing}")


def require_schema(path: Path, required: list[str]) -> None:
    schema = json.loads(path.read_text(encoding="utf-8"))
    actual = set(schema.get("required", []))
    missing = sorted(set(required) - actual)
    if missing:
        fail(f"{path.relative_to(ROOT)} removed required properties: {missing}")


def main() -> int:
    """Reject semantic removals from the published v2 compatibility floor.

    拒绝从已发布 v2 兼容基线删除操作、作用域字段或错误字段。新增可选字段允许；
    修改既有语义必须发布新协议版本，不能静默改写 v2。
    """

    floor = json.loads((CONTRACTS / "compatibility-v2.json").read_text(encoding="utf-8"))
    openapi = CONTRACTS / "openapi" / "agent-execution-v2.yaml"
    proto = CONTRACTS / "proto" / "agent_execution_v2.proto"
    context = CONTRACTS / "jsonschema" / "context-v1.json"
    error = CONTRACTS / "jsonschema" / "error-v1.json"

    require_text(openapi, [floor["protocol_version"], *[f"operationId: {name}" for name in (
        "invokeAgent", "createAgentRun", "resumeAgentRun", "cancelAgentRun", "streamAgentRunEvents"
    )]])
    require_text(proto, ["rpc Invoke", "rpc Run", "rpc Resume", "rpc Cancel", "rpc Events", "string protocol_version = 1;"])
    require_text(openapi, ["post:", "schema: {$ref: '#/components/schemas/EventRequest'}", "EventRequest:"])
    require_schema(context, floor["scope_required"])
    require_schema(error, floor["error_required"])

    require_text(ROOT / "platform/internal/contract/execution.go", [
        "type ScopeKey", "type ExecuteRequest", "type EventRequest",
    ])
    require_text(ROOT / "platform/internal/contract/errors.go", [floor["protocol_version"], "type AppError"])
    generated = (
        ROOT / "sdk/python/agent_platform_sdk/generated/execution_v2.py",
        ROOT / "sdk/java/agent-platform-sdk/src/main/java/com/lexagent/sdk/ExecutionContract.java",
    )
    for path in generated:
        require_text(path, [floor["protocol_version"], "ScopeKey", "ExecuteRequest", "EventRequest", "AppError"])

    print("Agent Execution Contract v2 compatibility gate passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"contract compatibility gate failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
