#!/usr/bin/env python3
"""Run the repository-level heterogeneous Adapter conformance matrix.

Each Adapter is tested in its own Go module so the gate exercises the code that
is actually built for deployment, rather than checking that directories or
README files exist. The report is deliberately JSON and bounded so CI, Docker
and a future distributed runner can consume the same evidence.

运行仓库级异构 Adapter 一致性矩阵。每个 Adapter 在自己的 Go module 中执行真实
测试，门禁不会把目录或 README 存在误认为实现完成。报告使用有界 JSON，便于 CI、
Docker 和未来拆分后的分布式 Runner 复用同一份证据。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / ".tmp" / "adapter-conformance-report.json"
MAX_OUTPUT = 12_000

ADAPTERS: tuple[dict[str, Any], ...] = (
    {
        "id": "legacy-http",
        "module": "adapters/legacy-http",
        "required_files": (
            "cmd/adapter/main.go",
            "internal/conformance/conformance_test.go",
            "internal/descriptor/descriptor.go",
            "internal/mapping/mapping.go",
        ),
        "capabilities": ("invoke", "events"),
    },
    {
        "id": "grpc-mapping",
        "module": "adapters/grpc-mapping",
        "required_files": (
            "cmd/adapter/main.go",
            "cmd/adapter/main_test.go",
            "internal/descriptor/descriptor.go",
        ),
        "capabilities": ("invoke",),
    },
    {
        "id": "process",
        "module": "adapters/process",
        "required_files": (
            "cmd/adapter/main.go",
            "cmd/adapter/main_test.go",
            "internal/runner/runner.go",
        ),
        "capabilities": ("invoke",),
    },
    {
        "id": "sidecar",
        "module": "adapters/sidecar",
        "required_files": (
            "cmd/adapter/main.go",
            "cmd/adapter/main_test.go",
            "internal/proxy/proxy.go",
        ),
        "capabilities": ("invoke", "events"),
    },
)


def bounded(text: str) -> str:
    if len(text) <= MAX_OUTPUT:
        return text
    return text[-MAX_OUTPUT:]


def run_adapter(adapter: dict[str, Any], cache: Path) -> dict[str, Any]:
    adapter_id = str(adapter["id"])
    module_dir = ROOT / str(adapter["module"])
    missing = [name for name in adapter["required_files"] if not (module_dir / name).is_file()]
    result: dict[str, Any] = {
        "id": adapter_id,
        "module": str(Path(str(adapter["module"]))),
        "required_capabilities": list(adapter["capabilities"]),
        "required_files": list(adapter["required_files"]),
        "missing_files": missing,
        "command": ["go", "test", "-count=1", "./..."],
        "result": "FAIL",
    }
    if missing:
        result["error"] = "required Adapter implementation/test files are missing"
        return result
    env = os.environ.copy()
    # Keep the gate reproducible on Windows workstations whose global Go cache
    # may be ACL-restricted. / 在 Windows 宿主全局 Go 缓存可能受 ACL 限制，使用
    # 项目内独立缓存保证门禁可复现。
    env["GOCACHE"] = str(cache)
    env["GOWORK"] = "off"
    started = time.monotonic()
    completed = subprocess.run(
        ["go", "test", "-count=1", "./..."],
        cwd=str(module_dir),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    result["exit_code"] = completed.returncode
    result["output"] = bounded((completed.stdout or "") + (completed.stderr or ""))
    result["result"] = "PASS" if completed.returncode == 0 else "FAIL"
    return result


def main() -> int:
    cache = ROOT / ".tmp" / "go-cache-adapter-conformance"
    cache.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    results = [run_adapter(adapter, cache) for adapter in ADAPTERS]
    document = {
        "schema": "adapter-conformance/v1",
        "contract": "agent-execution/v2",
        "ok": all(item["result"] == "PASS" for item in results),
        "adapters": results,
    }
    REPORT.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": document["ok"], "report": str(REPORT), "adapters": [item["result"] for item in results]}, ensure_ascii=False))
    return 0 if document["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
