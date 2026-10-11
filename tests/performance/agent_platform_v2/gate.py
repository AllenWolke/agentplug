"""Fail-closed first-token latency gate for a recorded live load run."""
from __future__ import annotations

import json
import math
import statistics
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

MINIMUM_SAMPLES = 10
MAX_P95_SECONDS = 2.0


def evaluate(record: Any) -> dict[str, object]:
    if not isinstance(record, dict):
        return {"status": "BLOCKED", "reason": "run metadata is required"}
    required_text = ("candidate", "environment", "sample_source", "load_model", "started_at", "finished_at")
    if any(not isinstance(record.get(field), str) or not record[field].strip() for field in required_text):
        return {"status": "BLOCKED", "reason": "run identity, load model or sample provenance is missing"}
    try:
        started_at = datetime.fromisoformat(record["started_at"].replace("Z", "+00:00"))
        finished_at = datetime.fromisoformat(record["finished_at"].replace("Z", "+00:00"))
        if started_at.utcoffset() is None or finished_at.utcoffset() is None or finished_at <= started_at:
            raise ValueError("invalid sampling interval")
    except ValueError:
        return {"status": "BLOCKED", "reason": "valid ordered timezone-aware sampling interval is required"}
    if record.get("execution_mode") != "live" or record.get("metric") != "time_to_first_token_seconds":
        return {"status": "BLOCKED", "reason": "live first-token samples are required"}
    concurrency = record.get("concurrency")
    requests = record.get("request_count")
    errors = record.get("error_count")
    if any(type(value) is not int for value in (concurrency, requests, errors)):
        return {"status": "BLOCKED", "reason": "integer load and error counts are required"}
    if concurrency < 1 or requests < MINIMUM_SAMPLES or errors < 0 or errors > requests:
        return {"status": "BLOCKED", "reason": "invalid load and error counts"}
    samples = record.get("samples")
    if not isinstance(samples, list) or len(samples) < MINIMUM_SAMPLES:
        return {"status": "BLOCKED", "reason": "insufficient samples", "count": len(samples) if isinstance(samples, list) else 0}
    if len(samples) + errors != requests:
        return {"status": "BLOCKED", "reason": "sample count does not match requests and errors"}
    if any(type(sample) not in (int, float) or not math.isfinite(sample) or sample < 0 for sample in samples):
        return {"status": "BLOCKED", "reason": "samples must be finite non-negative seconds"}
    ordered = sorted(samples)
    p95 = ordered[math.ceil(len(ordered) * 0.95) - 1]
    status = "PASS" if p95 <= MAX_P95_SECONDS and errors == 0 else "FAIL"
    return {
        "status": status,
        "count": len(samples),
        "errors": errors,
        "p50_seconds": statistics.median(ordered),
        "p95_seconds": p95,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(json.dumps({"status": "BLOCKED", "reason": "usage: gate.py RUN_JSON"}))
        return 2
    try:
        record = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": f"invalid run file: {type(error).__name__}"}))
        return 2
    result = evaluate(record)
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
