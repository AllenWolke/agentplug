from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
OPERATIONS = {"invoke", "run", "resume", "cancel"}
SCOPE_FIELDS = {
    "tenant_id", "department_id", "application_id", "agent_instance_id", "installation_id",
    "agent_id", "agent_version_id", "principal_type", "principal_id",
    "session_id", "run_id", "authorization_epoch", "trace_id",
}


def _fail(message: str) -> None:
    raise ValueError(message)


def lint() -> None:
    """Verify HTTP, Proto, JSON Schema and generated types as one contract.

    将 HTTP、Proto、JSON Schema 和多语言类型作为同一个契约校验，防止各自漂移。
    """

    openapi_path = CONTRACTS / "openapi" / "agent-execution-v2.yaml"
    openapi = openapi_path.read_text(encoding="utf-8")
    if not openapi.startswith("openapi: 3.1.0"):
        _fail("OpenAPI 3.1.0 is required")
    scope_match = re.search(r"ScopeKey:\s+type: object.*?required: \[([^]]+)]", openapi, re.S)
    if scope_match is None:
        _fail("ScopeKey required fields are missing")
    scope_required = {item.strip() for item in scope_match.group(1).split(",")}
    if not SCOPE_FIELDS.issubset(scope_required):
        _fail(f"ScopeKey misses {sorted(SCOPE_FIELDS - scope_required)}")
    operation_match = re.search(r"operation: \{type: string, enum: \[([^]]+)]}", openapi)
    operation_enum = {item.strip() for item in operation_match.group(1).split(",")} if operation_match else set()
    if operation_enum != OPERATIONS:
        _fail(f"execution operation drift: {sorted(operation_enum)}")
    events_match = re.search(r"/runs/\{run_id}/events:\s+post:\s+operationId: streamAgentRunEvents.*?requestBody:", openapi, re.S)
    if events_match is None:
        _fail("events must use one signed POST body")

    for name in ("manifest-v1.json", "context-v1.json", "event-v1.json", "error-v1.json"):
        value = json.loads((CONTRACTS / "jsonschema" / name).read_text(encoding="utf-8"))
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            _fail(f"{name} must declare JSON Schema 2020-12")

    proto = (CONTRACTS / "proto" / "agent_execution_v2.proto").read_text(encoding="utf-8")
    if not re.search(r"message EventRequest\s*\{\s*string protocol_version = 1;", proto):
        _fail("Proto EventRequest misses protocol_version field 1")
    for rpc in ("Invoke", "Run", "Resume", "Cancel", "Events"):
        if f"rpc {rpc}" not in proto:
            _fail(f"Proto misses {rpc}")
    if "google.protobuf.Struct resume_input = 8;" not in proto:
        _fail("Proto must carry resume_input in the signed request")
    if "resume_input:" not in openapi:
        _fail("HTTP contract must carry resume_input in the signed request")

    generated = (
        ("Platform Go execution contract", ROOT / "platform/internal/contract/execution.go", ("ScopeKey", "ExecuteRequest", "EventRequest")),
        ("Platform Go error contract", ROOT / "platform/internal/contract/errors.go", ("AppError",)),
        ("Python", ROOT / "sdk/python/agent_platform_sdk/generated/execution_v2.py", ("agent-execution/v2", "ScopeKey", "ExecuteRequest", "EventRequest", "AppError")),
        ("Java", ROOT / "sdk/java/agent-platform-sdk/src/main/java/com/lexagent/sdk/ExecutionContract.java", ("agent-execution/v2", "ScopeKey", "ExecuteRequest", "EventRequest", "AppError")),
    )
    for label, path, tokens in generated:
        text = path.read_text(encoding="utf-8")
        for token in tokens:
            if token not in text:
                _fail(f"{label} generated type misses {token}")


def main() -> int:
    try:
        lint()
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"execution contract lint failed: {exc}", file=sys.stderr)
        return 1
    print("execution contract lint passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
