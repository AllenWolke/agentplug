# Agent Platform v2 performance gate

The latency gate accepts a recorded **live first-token** run. It requires a
candidate, environment, sample source, load model, timezone-aware start and
finish time in chronological order, concurrency,
total request count, error count, and seconds-valued samples. Mock runs,
missing evidence, malformed samples, and insufficient samples are `BLOCKED`.
P95 above 2 seconds or any request error is `FAIL`. Only `PASS` exits zero.

```json
{
  "candidate": "approved-image-digest-and-policy-version",
  "environment": "preproduction-cluster-name",
  "sample_source": "immutable-load-run-artifact-id",
  "load_model": "approved-five-concurrent-single-tenant-qa-mix",
  "started_at": "2026-09-29T00:00:00Z",
  "finished_at": "2026-09-29T00:01:00Z",
  "execution_mode": "live",
  "metric": "time_to_first_token_seconds",
  "concurrency": 5,
  "request_count": 10,
  "error_count": 0,
  "samples": [0.1, 0.2, 0.2, 0.3, 0.4, 0.4, 0.5, 0.6, 0.8, 0.9]
}
```

Call `python tests/performance/agent_platform_v2/gate.py RUN_JSON` from the
repository root and use its exit code as the release decision. Metadata is a
required audit record; the release process must independently verify its source.
