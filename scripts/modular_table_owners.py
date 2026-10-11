"""Reviewed table registry; never infer ownership from the existing writer.
显式审阅的表所有权登记，不根据当前写入方自动推断。
"""

import json
from pathlib import Path

TABLE_OWNERS = json.loads(
    (
        Path(__file__).resolve().parents[1] / "contracts/architecture/table-owners.json"
    ).read_text(encoding="utf-8")
)


def module_for(relative: str) -> str:
    normalized = relative.replace("\\", "/")
    # Only reviewed canonical SDK modules and their checked template copies.
    # A neighboring SDK or business Agent file receives no database ownership.
    for prefix in (
        "sdk/python/agent_platform_sdk/",
        "templates/python-generic/platform_entry/agent_platform_sdk/",
        "templates/python-langgraph/platform_entry/agent_platform_sdk/",
    ):
        if normalized == prefix + "checkpoint_schema.py":
            return "checkpoint-sdk"
        if normalized == prefix + "generation_exit.py":
            return "execution-sdk"
    parts = normalized.split("/")
    if len(parts) >= 4 and parts[:2] == ["platform", "internal"]:
        return parts[2]
    return "unclassified"
