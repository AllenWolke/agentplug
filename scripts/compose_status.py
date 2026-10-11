"""Display observed Compose state, distinguishing completed initialization jobs."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


INIT_SERVICES = frozenset({
    "platform-migrate", "kafka-topic-bootstrap", "checkpoint-bootstrap",
    "postgres-workflow-prepare", "workflow-grants",
})


def status_label(row: dict) -> str:
    state = row.get("State", "unknown")
    if row.get("Service") in INIT_SERVICES:
        if state == "exited":
            code = row.get("ExitCode")
            if code == 0:
                return "completed (exit 0)"
            if isinstance(code, int):
                return f"FAILED (exit {code})"
            return "exited (exit code unknown)"
        return f"initializing ({state})"
    health = row.get("Health")
    return f"{state} ({health})" if health else state


def print_status(base: list[str], root: Path) -> int:
    try:
        result = subprocess.run(base + ["ps", "--all", "--format", "json"],
                                cwd=root, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", check=False)
    except FileNotFoundError:
        print("Docker CLI is unavailable", file=sys.stderr)
        return 1
    if result.returncode:
        print("Cannot read Compose status; check the selected deployment configuration.", file=sys.stderr)
        return result.returncode
    raw = result.stdout.strip()
    if not raw:
        print("No containers found for the selected project.")
        return 0
    try:
        rows = json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines()]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("unexpected rows")
    except (ValueError, TypeError):
        print("Unexpected Compose status format", file=sys.stderr)
        return 1
    print(f"{'SERVICE':<34} {'TYPE':<8} STATUS")
    for row in sorted(rows, key=lambda item: item.get("Service", "")):
        service = row.get("Service", "unknown")
        kind = "init" if service in INIT_SERVICES else "service"
        print(f"{service:<34} {kind:<8} {status_label(row)}")
    print("Explicit initialization uses temporary --rm containers. Legacy completed jobs may be removed. "
          "Kafka and other services must remain running.")
    # This is a status view, not a readiness gate. Failed jobs and unhealthy
    # services make it fail, while absent services need a separate smoke gate.
    failed = any(
        (row.get("Service") in INIT_SERVICES and row.get("State") == "exited" and row.get("ExitCode") != 0)
        or (row.get("Service") not in INIT_SERVICES and
            (row.get("State") != "running" or row.get("Health") == "unhealthy"))
        for row in rows
    )
    return int(failed)
