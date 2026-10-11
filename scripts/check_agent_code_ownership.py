"""Prevent productized Agents from copying platform responsibilities."""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENT_ROOTS = [ROOT / "agents", ROOT / "examples", ROOT / "templates"]
FORBIDDEN = re.compile(
    r"(jwt|tenant[_-]?middleware|run[_-]?state|model[_-]?gateway|tool[_-]?manager|audit[_-]?repository|publish[_-]?rollback|local_runtime|build_local_run_provider)",
    re.IGNORECASE,
)
FORBIDDEN_PRODUCTION_IMPORTS = (
    re.compile(r"(?:from|import)\s+agent_platform_sdk\.local_runtime\b"),
    re.compile(r"from\s+agent_platform_sdk\s+import\s+[^\n]*\bbuild_local_run_provider\b"),
)
ALLOW = {"platform_entry", "domain", "graph", "workflow", "prompts", "eval", "tests", "schemas", "tools", "adapter"}


def main() -> int:
    findings: list[str] = []
    for root in AGENT_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or any(part == "tmp" or part.startswith(".tmp") or part.startswith(".cache") for part in path.parts) or ".git" in path.parts:
                continue
            rel_parts = path.relative_to(root).parts
            if not rel_parts:
                continue
            # External legacy source is inspected, never judged as a generated Agent.
            if rel_parts[0] in {"LexAgent", "GraphFraudAssistant"}:
                continue
            if any(part in ALLOW for part in rel_parts):
                continue
            if FORBIDDEN.search(path.name):
                findings.append(str(path.relative_to(ROOT)))
            # The local ExecutionManager/Store is a shared test/development
            # adapter only.  Production Agent entrypoints may not import it;
            # an explicit ``dev_runtime`` lazy import remains allowed.
            if path.suffix == ".py" and "tests" not in rel_parts and "app" in rel_parts:
                text = path.read_text(encoding="utf-8", errors="replace")
                if any(pattern.search(text) for pattern in FORBIDDEN_PRODUCTION_IMPORTS):
                    findings.append(str(path.relative_to(ROOT)) + ":production-local-runtime-import")
    if findings:
        print("forbidden duplicated platform responsibilities:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print('{"ok":true,"ownership":"clean"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
