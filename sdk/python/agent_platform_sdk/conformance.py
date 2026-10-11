"""Reusable protocol assertions for Agent integration tests."""

from __future__ import annotations

from typing import Any


REQUIRED_MANIFEST_KEYS = frozenset({"manifest_version", "agent_id", "version", "capabilities", "execution_protocols"})


def validate_manifest(manifest: dict[str, Any], expected_agent_id: str) -> None:
    """Fail fast when an Agent advertises an incomplete or wrong identity."""
    missing = REQUIRED_MANIFEST_KEYS.difference(manifest)
    if missing:
        raise AssertionError(f"manifest missing keys: {sorted(missing)}")
    if manifest["manifest_version"] != "agent-manifest/v1":
        raise AssertionError("unsupported manifest version")
    if manifest["agent_id"] != expected_agent_id:
        raise AssertionError("manifest agent id mismatch")
    if "agent-execution/v2" not in manifest["execution_protocols"]:
        raise AssertionError("execution v2 is not advertised")
    if not isinstance(manifest["capabilities"], list) or not manifest["capabilities"]:
        raise AssertionError("manifest must advertise at least one capability")
