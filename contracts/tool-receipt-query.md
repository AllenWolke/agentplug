# Read-only tool receipt query v1

`POST /internal/tool/receipt` uses the existing signed Agent envelope and current caller/workload authorization. Input: `name`, exact `call_id`, original object `payload`, optional `confirmation_token`. Extra input fields are rejected. Authorization derives the existing `tool.invoke` resource action from the route/name; the published tool policy remains enforced.

Response data: `version=tool-receipt/v1`, `tool_name`, `call_id`, `status`, `receipt`. Status is `not_found`, `running`, `failed`, `unknown` or `completed`; only `completed` includes the bound, sanitized `runtime-observation/v1` receipt. Scope comes from verified execution context, never request-owned identity. Original name/arguments fingerprint must match. No lease/token/owner internals or raw failure messages are returned.

The operation is read-only: no Reserve/Acquire/Begin, provider execution, receipt repair or ledger update. It does not turn missing, failed, expired or unknown records into permission to execute. `not_found` alone is not proof that a delayed request cannot subsequently commit. Runtime recovery workers may independently coordinate known business receipts under their existing safeguards.

Tools requiring operation approval require a valid token for this query too; final result disclosure rechecks the token record/expiry and current policy, Run, resource and workload boundaries. If an earlier token expired, a fresh approved token for the same immutable operation is required. Revocation cannot be bypassed by switching from invoke to receipt query.

Memory and SQL stores provide an optional narrow read port; unavailable adapters fail closed. SQL lookup uses a plain SELECT with no mutation and preserves receipt numeric precision. Signed request replays are result access and remain subject to current authorization.

For registered isolated Code only, an existing running/unknown platform record may additionally query the controller's encrypted receipt under fresh operation-bound approval. This is a read-only controller request, never Code execution or platform ledger repair. A completed controller receipt returns its original sanitized Observation, including a known failed outcome; ledger status and timestamps remain unchanged. Missing platform records do not trigger this fallback. Other executors retain the plain platform-store lookup behavior.

Platform endpoint and Go/Python/Java Harness recovery source integration are implemented. Independent SDK port-fixture acceptance is recorded separately from actual SQL endpoint evidence; combined real-platform process recovery, governed model receipt query and normal approval/UI resume remain pending. A successful endpoint or SDK fixture alone is not complete recovery acceptance.
