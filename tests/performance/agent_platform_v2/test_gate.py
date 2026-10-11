"""Release gate must reject incomplete or failed measured runs."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from gate import evaluate


def live_record() -> dict[str, object]:
    return {
        "candidate": "candidate-digest",
        "environment": "isolated-preproduction",
        "sample_source": "load-run-20260929",
        "load_model": "five-concurrent-single-tenant-qa",
        "started_at": "2026-09-29T00:00:00Z",
        "finished_at": "2026-09-29T00:01:00Z",
        "execution_mode": "live",
        "metric": "time_to_first_token_seconds",
        "concurrency": 5,
        "request_count": 10,
        "error_count": 0,
        "samples": [0.1] * 10,
    }


@pytest.mark.parametrize(
    ("changes", "expected_status", "expected_code"),
    [
        ({"samples": [0.1] * 10}, "PASS", 0),
        ({"started_at": "2026-09-29T08:00:00+08:00"}, "PASS", 0),
        ({"samples": [2.0] * 10}, "PASS", 0),
        ({"samples": [2.0001] * 10}, "FAIL", 1),
        ({"samples": [10.0] * 10}, "FAIL", 1),
        ({"samples": [], "request_count": 10}, "BLOCKED", 1),
        ({"samples": [0.1] * 9, "request_count": 9}, "BLOCKED", 1),
        ({"samples": [float("nan")] * 10}, "BLOCKED", 1),
        ({"samples": [float("inf")] * 10}, "BLOCKED", 1),
        ({"samples": [-1.0] * 10}, "BLOCKED", 1),
        ({"error_count": 1, "request_count": 11}, "FAIL", 1),
        ({"execution_mode": "mock"}, "BLOCKED", 1),
        ({"metric": "full_response_seconds"}, "BLOCKED", 1),
        ({"sample_source": ""}, "BLOCKED", 1),
        ({"load_model": ""}, "BLOCKED", 1),
        ({"started_at": "not-a-timestamp"}, "BLOCKED", 1),
        ({"started_at": "2026-09-29T00:00:00"}, "BLOCKED", 1),
        ({"finished_at": "2026-09-28T23:59:59Z"}, "BLOCKED", 1),
        ({"finished_at": "2026-09-29T00:00:00Z"}, "BLOCKED", 1),
        ({"concurrency": 0}, "BLOCKED", 1),
    ],
)
def test_cli_exit_code_tracks_pass_fail_and_blocked(
    tmp_path: Path, changes: dict[str, object], expected_status: str, expected_code: int
) -> None:
    script = Path(__file__).with_name("gate.py")
    record = live_record()
    record.update(changes)
    path = tmp_path / "run.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    process = subprocess.run([sys.executable, str(script), str(path)], capture_output=True, text=True)
    assert process.returncode == expected_code
    assert json.loads(process.stdout)["status"] == expected_status


@pytest.mark.parametrize("contents", ["{", "not JSON"])
def test_cli_rejects_unparseable_input(tmp_path: Path, contents: str) -> None:
    script = Path(__file__).with_name("gate.py")
    path = tmp_path / "run.json"
    path.write_text(contents, encoding="utf-8")
    process = subprocess.run([sys.executable, str(script), str(path)], capture_output=True, text=True)
    assert process.returncode == 2
    assert json.loads(process.stdout)["status"] == "BLOCKED"


def test_incomplete_or_invalid_evidence_never_passes() -> None:
    for change in (
        {"execution_mode": "mock"},
        {"metric": "full_response_seconds"},
        {"sample_source": ""},
        {"load_model": ""},
        {"finished_at": "2026-09-28T23:59:59Z"},
        {"error_count": 1, "request_count": 11},
        {"samples": [float("nan")] * 10},
        {"samples": [-1.0] * 10},
        {"concurrency": 0},
        {"request_count": 11},
    ):
        record = copy.deepcopy(live_record())
        record.update(change)
        assert evaluate(record)["status"] != "PASS", change
