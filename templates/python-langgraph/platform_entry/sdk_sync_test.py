"""Vendored SDK sync check, mirroring the Go templates' sdk_sync_test.go.

钉住单一事实源规则：vendored 平台 SDK 副本必须与 sdk/python/agent_platform_sdk
逐字节一致。生成项目独立存在（SDK 兄弟目录缺失）时跳过。
"""

from __future__ import annotations

from pathlib import Path

import pytest

PLATFORM_ENTRY = Path(__file__).resolve().parent
SDK_ROOT = Path(__file__).resolve().parents[3] / "sdk" / "python" / "agent_platform_sdk"
# Every production SDK module is part of the generated project's contract.
# Test fixtures in the vendored tree may differ from repository SDK tests.
VENDORED_FILES = tuple(
    path.name for path in sorted(SDK_ROOT.glob("*.py"))
    if not path.name.startswith("test_")
)


def test_vendored_sdk_stays_in_sync_with_the_source_of_truth() -> None:
    if not SDK_ROOT.is_dir():
        pytest.skip("platform SDK sibling not present (standalone generated project)")
    for name in VENDORED_FILES:
        source = (SDK_ROOT / name).read_bytes()
        vendored = (PLATFORM_ENTRY / "agent_platform_sdk" / name).read_bytes()
        assert source == vendored, f"vendored {name} drifted from the platform SDK; re-vendor it"
