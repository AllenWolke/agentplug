"""Completed init jobs must not hide failed migration or stopped Kafka."""
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("compose_status", ROOT / "scripts/compose_status.py")
STATUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATUS)


@pytest.mark.parametrize("service,state,code,expected", [
    ("platform-migrate", "exited", 0, "completed (exit 0)"),
    ("checkpoint-bootstrap", "exited", 0, "completed (exit 0)"),
    ("platform-migrate", "exited", 1, "FAILED (exit 1)"),
    ("platform-migrate", "exited", None, "exited (exit code unknown)"),
    ("kafka", "exited", 0, "exited"),
])
def test_completed_requires_known_successful_init_exit(service, state, code, expected):
    assert STATUS.status_label({"Service": service, "State": state, "ExitCode": code}) == expected


@pytest.mark.parametrize("format", ["array", "jsonl"])
@pytest.mark.parametrize("job_code,broker_state,expected", [(0, "running", 0), (1, "running", 1), (0, "exited", 1)])
def test_status_reports_init_success_without_accepting_failed_migration_or_stopped_kafka(
    monkeypatch, capsys, format, job_code, broker_state, expected,
):
    rows = [{"Service": "platform-migrate", "State": "exited", "ExitCode": job_code},
            {"Service": "kafka", "State": broker_state, "Health": "healthy"}]
    payload = json.dumps(rows) if format == "array" else "\n".join(json.dumps(row) for row in rows)
    monkeypatch.setattr(STATUS.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, payload))
    assert STATUS.print_status(["docker", "compose"], ROOT) == expected
    assert "platform-migrate" in capsys.readouterr().out
