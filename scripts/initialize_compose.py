"""Run explicit schema/topic initialization with automatically removed containers."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

PUBLIC_JOBS = ("platform-migrate", "kafka-topic-bootstrap")
INTERVIEW_JOBS = (
    "platform-migrate", "postgres-workflow-prepare", "checkpoint-bootstrap",
    "workflow-grants", "kafka-topic-bootstrap",
)
INFRASTRUCTURE = {"postgres", "kafka", "metric-runner", "minio", "code-runtime"}


def initialize_stack(base: list[str], root: Path, jobs: tuple[str, ...], *, build: bool = True,
                     diagnostic_directory: Path | None = None) -> int:
    """Fail closed before DDL when application writers are still running.

    The caller supplies its own project, files and credentials. Never inspect
    another deployment, import data, seed accounts or print rendered secrets.
    """
    try:
        observed = subprocess.run(base + ["ps", "--all", "--format", "json"], cwd=root,
                                  capture_output=True, text=True, encoding="utf-8", errors="replace")
        if observed.returncode:
            print("Cannot inspect deployment state; initialization was not started.", file=sys.stderr)
            return observed.returncode
        raw = observed.stdout.strip()
        rows = json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines()]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("unexpected status")
        if any(row.get("State") in {"running", "restarting", "paused"}
               and row.get("Service") not in INFRASTRUCTURE for row in rows):
            print("Stop application services in a maintenance window before initialization/upgrade. "
                  "Preserve database and Kafka volumes.", file=sys.stderr)
            return 1
        initialized = base + ["--profile", "init"]
        rendered = subprocess.run(initialized + ["config", "--format", "json"], cwd=root,
                                  capture_output=True, text=True, encoding="utf-8", errors="replace")
        if rendered.returncode:
            print("Initialization configuration is invalid; credential-bearing output withheld.", file=sys.stderr)
            return rendered.returncode
        services = json.loads(rendered.stdout)["services"]
        if any(name not in services for name in jobs):
            print("Initialization configuration is incomplete for this project.", file=sys.stderr)
            return 1
        if services["platform-app"]["image"] != services["platform-migrate"]["image"]:
            print("Platform and schema initialization must use the same versioned image.", file=sys.stderr)
            return 1
        if "checkpoint-bootstrap" in jobs and services["checkpoint-bootstrap"]["image"] != services["regulatory-validation-agent"]["image"]:
            print("Checkpoint initialization must match the regulatory SDK image version.", file=sys.stderr)
            return 1

        def execute(arguments: list[str]) -> int:
            result = subprocess.run(initialized + arguments, cwd=root, capture_output=True)
            if result.returncode:
                if diagnostic_directory is not None:
                    diagnostic_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                    log = diagnostic_directory / (arguments[-1] + ".failed.log")
                    with log.open("wb") as stream:
                        log.chmod(0o600)
                        stream.write(result.stdout + result.stderr)
                print("Initialization stopped at " + arguments[0] + ": " + arguments[-1]
                      + "; exit " + str(result.returncode) + ". No application was started. "
                      "Check the selected configuration and database permissions.", file=sys.stderr)
                if diagnostic_directory is not None:
                    print("Failure details saved to the selected private diagnostic directory.", file=sys.stderr)
            return result.returncode

        builders = [name for name in jobs if services[name].get("build")]
        if build and builders:
            print("Building initialization images from the selected project.")
            code = execute(["build", *builders])
            if code:
                return code
        code = execute(["up", "-d", "--no-build", "--wait", "--wait-timeout", "180", "postgres", "kafka"])
        if code:
            return code
        for name in jobs:
            print("Initializing " + name + " ...", flush=True)
            # No implicit dependency containers, ports, persistent job names,
            # retry loops or account seeds. Compose removes even failed jobs.
            code = execute(["run", "--rm", "--no-deps", "-T", name])
            if code:
                return code
            print(name + " completed; temporary container removed.")
        print("Initialization complete. Start application services with the normal up command.")
        return 0
    except FileNotFoundError:
        print("Docker CLI is unavailable", file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError):
        print("Unexpected initialization configuration/state; no further step was run.", file=sys.stderr)
        return 1

