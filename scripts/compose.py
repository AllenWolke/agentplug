"""Manage this project's Compose stack without invoking a shell."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["up", "down", "status", "build", "smoke", "config", "reset", "e2e-modular", "init", "upgrade", "run"])
    parser.add_argument("--stack", choices=["platform", "eval", "eval-services", "compensation"], default="platform",
                        help="select the platform or an independent optional tool stack")
    parser.add_argument(
        "--env-file", type=Path, action="append", default=None,
        help="Compose interpolation env file; may be repeated in precedence order (default: repository .env)",
    )
    parser.add_argument("--project", help="defaults to the selected stack's isolated project name")
    parser.add_argument("--profile", choices=["modular", "full", "manual", "fixture", "judge", "maintenance"])
    parser.add_argument("--service", help="explicit service for an optional one-off run")
    parser.add_argument("--command", nargs=argparse.REMAINDER, help="literal tool arguments for run; place this option last")
    parser.add_argument("--examples", action="store_true", help="include the three SDK example services")
    parser.add_argument("--runtime", action="store_true", help="include the isolated Code Runtime overlay; requires --examples")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--build-images", action="store_true", help="build isolated current-source images for e2e-modular")
    parser.add_argument("--no-build", action="store_true", help="use prepared images for initialization/upgrade")
    parser.add_argument("--diagnostic-directory", type=Path, help="operator-private failure logs; may contain connection details")
    args = parser.parse_args()
    stack_project = "agentplug" if args.stack == "platform" else "agentplug-" + args.stack
    args.project = args.project or stack_project
    if not re.fullmatch(re.escape(stack_project) + r"(?:-test-[a-z0-9-]+)?", args.project):
        parser.error("project must match the selected stack or its isolated -test-* namespace")
    allowed_profiles = {"platform": ["modular", "full"], "eval": ["manual"],
                        "eval-services": ["fixture", "judge"], "compensation": ["maintenance"]}
    if args.profile is not None and args.profile not in allowed_profiles[args.stack]:
        parser.error("profile does not belong to the selected stack")
    args.profile = args.profile or {"platform": "modular", "eval": "manual"}.get(args.stack)
    if args.stack == "eval-services" and args.profile is None:
        parser.error("eval-services requires an explicit --profile fixture or judge")
    if args.stack != "platform" and (args.examples or args.runtime or args.action in {"init", "upgrade", "smoke", "e2e-modular"}):
        parser.error("platform initialization, readiness and overlays require --stack platform")
    if args.action != "run" and (args.service or args.command is not None):
        parser.error("--service and --command require the run action")
    run_services = {"eval": ["agent-eval"], "eval-services": ["fixture-api", "fixture-agent", "judge-agent"],
                    "compensation": ["reversible-api", "reversible-api-migrate"]}
    if args.action == "run" and args.service not in run_services.get(args.stack, []):
        parser.error("run requires an explicit service belonging to an optional stack")
    if args.action == "reset" and not args.force:
        parser.error("reset removes this project's volumes and requires --force")
    if args.runtime and not args.examples:
        parser.error("--runtime requires --examples so the platform's example-agent targets are present")
    settings = [path.resolve() for path in (args.env_file or [ROOT / ".env"])]
    if args.action == "e2e-modular":
        if args.examples or args.runtime:
            parser.error("e2e-modular uses its own isolated fixed Compose configuration and does not accept overlays")
        if len(settings) != 1:
            parser.error("e2e-modular accepts one compatibility --env-file at most")
        verifier = ROOT / "tests/e2e/public_project_e2e.py"
        if not verifier.is_file():
            parser.error("public project end-to-end acceptance is not implemented yet")
        command = [sys.executable, str(verifier), "--env-file", str(settings[0])]
        if args.build_images:
            command.append("--build-images")
        return subprocess.run(command, cwd=ROOT).returncode
    missing_settings = [str(path) for path in settings if not path.is_file()]
    if missing_settings:
        parser.error("environment file is missing; configure it before starting")
    base = ["docker", "compose", "--project-directory", str(ROOT), "--project-name", args.project]
    for path in settings:
        base.extend(["--env-file", str(path)])
    extension_root = ROOT / "deploy/compose"
    compose_files = [ROOT / "compose.yaml"] if args.stack == "platform" else [extension_root / ("compose." + args.stack + ".yaml")]
    if args.action in {"init", "upgrade"}:
        compose_files.append(extension_root / "compose.init.yaml")
    if args.examples:
        compose_files.append(extension_root / "compose.examples.yaml")
    if args.runtime:
        compose_files.append(extension_root / "compose.runtime.yaml")
    for compose_file in compose_files:
        base.extend(["-f", str(compose_file)])
    if args.profile:
        base.extend(["--profile", args.profile])
    if args.action in {"init", "upgrade"}:
        from initialize_compose import initialize_stack, PUBLIC_JOBS
        return initialize_stack(base, ROOT, PUBLIC_JOBS, build=not args.no_build,
                                diagnostic_directory=args.diagnostic_directory)
    actions = {
        "up": ["up", "-d", "--build", "--wait", "--wait-timeout", "180"],
        "down": ["down", "--remove-orphans"],
        "build": ["build"],
        "config": ["config", "--quiet"],
        "reset": ["down", "--volumes", "--remove-orphans"],
        "run": ["run", "--rm", "--no-deps", args.service, *(args.command or [])],
    }
    if args.action == "status":
        from compose_status import print_status
        return print_status(base, ROOT)
    if args.action == "smoke":
        # Inspect observed container state; never infer readiness from a planned
        # service name, a cached status, or merely successful Compose parsing.
        import json
        result = subprocess.run(base + ["ps", "--format", "json"], cwd=ROOT, capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
        if result.returncode:
            return result.returncode
        raw = result.stdout.strip()
        if not raw:
            print("No running application stack", file=sys.stderr)
            return 1
        try:
            rows = json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines()]
        except (ValueError, TypeError):
            print("Unexpected Compose status format", file=sys.stderr)
            return 1
        required = {"platform-app", "frontend", "postgres", "metric-runner", "kafka"}
        health_required = set(required)
        if args.examples:
            required.update({"example-python", "example-go", "example-java"})
        if args.runtime:
            required.add("code-runtime")
        observed = {row.get("Service"): row for row in rows}
        failed = [name for name in sorted(required) if observed.get(name, {}).get("State") != "running"
                  or (name in health_required and observed.get(name, {}).get("Health") != "healthy")]
        if failed:
            print("Not ready: " + ", ".join(failed), file=sys.stderr)
            return 1
        print("Selected stack readiness passed")
        return 0
    try:
        return subprocess.run(base + actions[args.action], cwd=ROOT).returncode
    except FileNotFoundError:
        print("Docker CLI is unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
