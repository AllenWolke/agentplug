"""Validate versioned Agent productization contracts without third-party deps.

The checker intentionally performs structural checks in addition to JSON parsing so it
can run in a clean Windows, Linux or macOS checkout.  The API services perform the
same semantic checks at runtime.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REQUIRED = [
    "contracts/agent-template/v1/template.schema.json",
    "contracts/agent-template/v1/code-ownership.schema.json",
    "contracts/agent-template/v1/inventory.schema.json",
    "contracts/agent-mapping/v1/mapping.schema.json",
    "contracts/agent-evaluation/v1/dataset.schema.json",
    "contracts/agent-evaluation/v1/sample.schema.json",
    "contracts/agent-evaluation/v1/suite.schema.json",
    "contracts/agent-evaluation/v1/metric.schema.json",
    "contracts/agent-evaluation/v1/evidence.schema.json",
    "contracts/agent-evaluation/v1/agentctl-output.schema.json",
]
TEMPLATE_MANIFESTS = [
    "templates/python-generic/manifest.json",
    "templates/python-langgraph/manifest.json",
    "templates/go-generic/manifest.json",
    "templates/go-eino/manifest.json",
    "templates/java-generic/manifest.json",
    "templates/java-spring-ai/manifest.json",
]


def main() -> int:
    errors: list[str] = []
    for name in REQUIRED:
        path = ROOT / name
        if not path.exists():
            errors.append(f"missing contract: {name}")
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("type") != "object":
                errors.append(f"{name}: root type must be object")
            if payload.get("additionalProperties") is not False:
                errors.append(f"{name}: additionalProperties must be false")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{name}: {exc}")
    for name in TEMPLATE_MANIFESTS:
        path = ROOT / name
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            required = {"manifest_version", "agent_id", "version", "execution_protocols", "capabilities", "schemas", "runtime"}
            missing = sorted(required - payload.keys())
            if missing:
                errors.append(f"{name}: missing {','.join(missing)}")
            if payload.get("manifest_version") != "agent-manifest/v1":
                errors.append(f"{name}: unsupported manifest version")
            if "agent-execution/v2" not in payload.get("execution_protocols", []):
                errors.append(f"{name}: execution-v2 protocol is required")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{name}: {exc}")
    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "contracts": len(REQUIRED)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
