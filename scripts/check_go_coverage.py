from __future__ import annotations

import re
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "platform": {
        "./internal/identity": 25.0,
        "./internal/catalog": 35.0,
        "./internal/runtime": 40.0,
        "./internal/execution": 40.0,
        "./internal/conversation": 25.0,
        "./internal/evaluationproduct": 45.0,
        "./internal/modelgateway": 70.0,
        "./internal/policyasset": 30.0,
        "./internal/authorization": 70.0,
    },

}
PERCENT = re.compile(r"coverage:\s+([0-9.]+)%")


def main() -> int:
    failures: list[str] = []
    environment = os.environ.copy()
    for module, packages in TARGETS.items():
        command = ["go", "test", "-cover", *packages]
        result = subprocess.run(
            command,
            cwd=ROOT / module,
            check=False,
            capture_output=True,
            text=True,
            # Go emits UTF-8 package paths; decoding with the Windows GBK
            # locale can crash the quality gate before it evaluates coverage.
            encoding="utf-8",
            errors="replace",
            env=environment,
        )
        output = (result.stdout or "") + (result.stderr or "")
        print(output, end="")
        if result.returncode:
            failures.append(f"{module}: go test failed")
            continue
        lines = [line for line in output.splitlines() if "coverage:" in line]
        if len(lines) != len(packages):
            failures.append(f"{module}: expected {len(packages)} coverage results, got {len(lines)}")
            continue
        for package, line in zip(packages, lines, strict=True):
            match = PERCENT.search(line)
            actual = float(match.group(1)) if match else -1.0
            minimum = packages[package]
            if actual < minimum:
                failures.append(f"{module}/{package}: {actual:.1f}% < {minimum:.1f}%")
    if failures:
        print("Coverage gate failed:\n" + "\n".join(failures), file=sys.stderr)
        return 1
    print("Critical-package coverage gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
