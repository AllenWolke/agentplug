"""Verify the modular Compose process boundary.

This gate is intentionally small and dependency-free. It checks the active
Compose process boundary, platform Go source, and host orchestration scripts,
rather than inspecting a running container, so CI can catch a regression
before Docker is available.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.yaml"
PLATFORM = ROOT / "platform"
PLATFORM_SCRIPTS = (ROOT / "scripts" / "platform.ps1", ROOT / "scripts" / "platform.sh")
QUALITY_WORKFLOW = ROOT / ".github" / "workflows" / "three-project-quality.yml"
FORBIDDEN_SERVICES = {
    "go-backend",
    "go-harness",
    "evaluation-worker",
    "notification-service",
    "usage-reconciler",
}


def service_blocks(text: str) -> dict[str, str]:
    """Return top-level service blocks without requiring PyYAML."""

    lines = text.splitlines()
    in_services = False
    starts: list[tuple[str, int]] = []
    for index, line in enumerate(lines):
        if line == "services:":
            in_services = True
            continue
        if not in_services:
            continue
        match = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
        if match:
            starts.append((match.group(1), index))
        elif line and not line.startswith((" ", "\t")):
            break
    blocks: dict[str, str] = {}
    for position, (name, start) in enumerate(starts):
        end = starts[position + 1][1] if position + 1 < len(starts) else len(lines)
        blocks[name] = "\n".join(lines[start:end])
    return blocks


def check() -> list[str]:
    errors: list[str] = []
    if not COMPOSE.is_file():
        return [f"missing {COMPOSE}"]
    blocks = service_blocks(COMPOSE.read_text(encoding="utf-8"))
    if list(blocks).count("platform-app") != 1:
        errors.append("compose.yaml must define exactly one platform-app service")
    platform_block = blocks.get("platform-app", "")
    if "dockerfile: platform/Dockerfile" not in platform_block:
        errors.append("platform-app must build platform/Dockerfile")
    for service in sorted(FORBIDDEN_SERVICES):
        if service in blocks:
            errors.append(f"legacy trusted service remains in modular Compose: {service}")

    if not PLATFORM.is_dir():
        errors.append(f"missing {PLATFORM}")
    else:
        # The platform process must not depend on the old internal HTTP glue.
        # Agent/RAG URLs are intentionally allowed because they are remote
        # provider boundaries, not platform-to-platform calls.
        for path in PLATFORM.rglob("*.go"):
            if path.name in {"process_manifest.go", "process_manifest_test.go"}:
                # The manifest is the one intentional place where the legacy
                # names are listed as forbidden values.
                continue
            text = path.read_text(encoding="utf-8")
            for token in sorted(FORBIDDEN_SERVICES):
                if token in text:
                    errors.append(f"legacy process token {token!r} referenced by {path.relative_to(ROOT)}")

    # The clean cutover exposes only canonical modular Compose actions; stale
    # multi-project aliases must not remain callable.
    # 清洁切换只暴露规范化模块 Compose 命令，不保留旧多项目命令别名。
    legacy_actions = ("e2e-three-project", "e2e-three-project-local", "e2e-three-project-reuse-rag")
    legacy_compose_marker = "deploy/compose/legacy/docker-compose"
    for script in PLATFORM_SCRIPTS:
        if not script.is_file():
            errors.append(f"missing platform orchestration script: {script}")
            continue
        text = script.read_text(encoding="utf-8")
        relative = script.name
        if legacy_compose_marker in text:
            errors.append(f"active platform orchestrator still references archived Compose: {relative}")
        for action in legacy_actions:
            if action in text:
                errors.append(f"retired compatibility action remains in {relative}: {action}")

    # The macOS portability job must execute Compose config, not turn a
    # missing Docker CLI/plugin into a green artifact. A hosted runner does
    # not need a Docker Engine for `compose config`, but it must have a parser.
    # macOS 可移植性门禁必须真实执行 Compose config；不能把缺 CLI/插件伪装成通过。
    if not QUALITY_WORKFLOW.is_file():
        errors.append(f"missing quality workflow: {QUALITY_WORKFLOW.relative_to(ROOT)}")
    else:
        workflow = QUALITY_WORKFLOW.read_text(encoding="utf-8")
        macos_start = workflow.find("  macos-gate:")
        next_job = workflow.find("\n  compose-e2e:", macos_start + 1) if macos_start >= 0 else -1
        macos_job = workflow[macos_start:next_job if next_job >= 0 else None]
        if macos_start < 0:
            errors.append("quality workflow is missing macos-gate")
        else:
            required_macos_gates = (
                "brew install docker docker-compose",
                "docker compose version",
                "bash -n scripts/platform.sh",
                "docker compose -f compose.yaml --profile modular config --quiet",
                "python scripts/verify_modular_process.py",
            )
            for gate in required_macos_gates:
                if gate not in macos_job:
                    errors.append(f"macos-gate does not require portability check: {gate}")
            if '"compose_config":"not_executed"' in macos_job and '"status":"portable_gate_passed"' in macos_job:
                errors.append("macos-gate can report pass without executing Compose config")
    return errors


if __name__ == "__main__":
    failures = check()
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        raise SystemExit(1)
    print("modular process boundary check passed")
