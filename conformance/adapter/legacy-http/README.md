# Legacy HTTP Adapter Conformance Fixture

This fixture proves the PF-11 acceptance case: a legacy HTTP Agent is onboarded
with a **mapping document and no code change**.

本夹具证明 PF-11 验收场景：存量 HTTP Agent **仅凭一份映射文档、无需改代码**即可接入。

## Contents

| File | Meaning |
| --- | --- |
| `descriptor.json` | The published adapter descriptor: authoritative upstream `endpoint`/`path`, the pinned `mapping_hash`, the registered `plan_path`, the declared `capabilities` and the `limits`. |
| `plan.json` | The immutable mapping plan the runtime loads from `plan_path`. Its `hash` and `revision` must match the descriptor. |

## What the fixture locks down

1. `endpoint`/`path` come from the descriptor, not from environment variables.
2. The descriptor pins the plan document (`plan_path` + `mapping_hash` +
   `revision`), so a stale or foreign plan is refused.
3. `capabilities` may only name what the runtime implements; `events` is valid
   because `events_path` is registered.
4. The mapping alone determines the upstream request and the platform response,
   which is why the legacy Agent needs no code change.

The executable check lives in
`adapters/legacy-http/internal/conformance/conformance_test.go`; it loads this
fixture through the real `descriptor` and `planloader` packages, so the fixture
cannot drift away from the runtime behaviour it documents.
