from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "platform",
    "cli",
    "adapters",
    "workers",
    "agents/examples",
    "examples",
    "contracts",
    "tests/e2e",
    "frontend",
    "sdk/go",
    "templates",
)
SKIP_PARTS = {
    ".git",
    ".cache",
    ".tmp",
    "node_modules",
    "vendor",
    ".go-build-cache",
}


def main() -> int:
    candidates = [
        path
        for module in MODULES
        for path in (ROOT / module).rglob("*.go")
        if not path.name.endswith(".pb.go")
        and not any(part in SKIP_PARTS or part.startswith(".tmp-go-cache") for part in path.parts)
    ]
    outputs: list[str] = []
    errors: list[str] = []
    for start in range(0, len(candidates), 100):
        result = subprocess.run(
            ["gofmt", "-l", *map(str, candidates[start : start + 100])],
            check=False,
            capture_output=True,
            text=True,
            # 中文工作区路径由 gofmt 按 UTF-8 输出；Windows 的默认 GBK
            # 解码会让质量门禁自身崩溃。/ gofmt emits UTF-8 paths; using
            # the Windows locale codec can crash the quality gate itself.
            encoding="utf-8",
            errors="replace",
        )
        outputs.extend(line for line in (result.stdout or "").splitlines() if line.strip())
        if result.returncode:
            errors.append((result.stderr or "gofmt failed without diagnostic output").strip())
    if outputs or errors:
        print("\n".join(outputs + errors), file=sys.stderr)
        print("gofmt gate failed; run gofmt -w on the listed files", file=sys.stderr)
        return 1
    print(f"gofmt gate passed ({len(candidates)} source files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
