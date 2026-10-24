"""Synchronize the six embedded SDKs from this project's public SDK sources."""
from __future__ import annotations

import argparse
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAYOUTS = (
    (("python-generic", "python-langgraph"), "sdk/python/agent_platform_sdk", "platform_entry/agent_platform_sdk", (".py", ".pyi")),
    (("go-generic", "go-eino"), "sdk/go/agentplatform", "platform_entry/agentplatform", (".go",)),
    (("java-generic", "java-spring-ai"), "sdk/java/agent-platform-sdk/src/main/java/com/lexagent/sdk", "platform_entry/com/lexagent/sdk", (".java",)),
)


def production_file(path, extensions):
    return (path.is_file() and path.suffix in extensions and "__pycache__" not in path.parts
            and not path.name.startswith("test_") and not path.name.endswith("_test.go"))


def embedded_payload(source, target):
    payload = source.read_bytes()
    if source.suffix == ".go":
        payload = payload.replace(b'"github.com/lexagent/agent-platform-sdk-go/agentplatform',
                                  b'"generated-agent/platform_entry/agentplatform')
    return payload


def mappings():
    for names, source, target, extensions in LAYOUTS:
        base = ROOT / source
        for path in sorted(base.rglob("*")):
            if not production_file(path, extensions):
                continue
            for template in names:
                yield path, ROOT / "templates" / template / target / path.relative_to(base)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    differences = []
    count = 0
    expected = set()
    for source, target in mappings():
        count += 1
        expected.add(target)
        payload = embedded_payload(source, target)
        if not target.exists() or target.read_bytes() != payload:
            differences.append(str(target.relative_to(ROOT)))
            if not args.check:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
    stale = []
    for names, source, target, extensions in LAYOUTS:
        for name in names:
            for path in (ROOT / "templates" / name / target).rglob("*"):
                if production_file(path, extensions) and path not in expected:
                    stale.append(str(path.relative_to(ROOT)))
    if stale:
        print("Unexpected embedded SDK source; review before removal:\n" + "\n".join(stale))
        return 1
    version = tomllib.loads((ROOT / "sdk/python/pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    invalid_metadata = []
    for name in ("python-generic", "python-langgraph", "go-generic", "go-eino", "java-generic", "java-spring-ai"):
        metadata = json.loads((ROOT / "templates" / name / "manifest.json").read_text(encoding="utf-8"))["metadata"]
        if metadata.get("sdk_capabilities_version") != version:
            invalid_metadata.append(name)
    if invalid_metadata:
        print("SDK version metadata drift: " + ", ".join(invalid_metadata))
        return 1
    if args.check and differences:
        print("SDK/template drift:\n" + "\n".join(differences))
        return 1
    print(f"Public SDK/template {'verified' if args.check else 'synchronized'}: {count} files; {len(differences)} differences")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
