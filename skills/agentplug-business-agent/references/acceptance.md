# Business-agent acceptance

Use paths below relative to the confirmed AgentPlug repository, not the installed skill directory. Current implementation and contracts take precedence over stale examples.

## Required capability mapping

Read `docs/developer/en/capabilities.md` and the actual SDK implementation. For each needed concern record:

| Concern | What to inspect | Evidence |
| --- | --- | --- |
| Execution and trusted context | SDK factory / verifier; manifest identity and schemas | Signed execution success, wrong identity/signature rejection |
| Models and prompts | Gateway client, published prompt, approved version/price | Correct response, denial/budget handling, usage record |
| Knowledge | Public retrieval client, real source/index, ACL, citations | Relevant answer and source evidence; unauthorized content excluded |
| Tools | Gateway client, published bindings, schema, confirmation | Allowed operation, invalid args/denial, receipt handling after unknown response |
| Memory | Scoped namespace/key/schema and public gateway | Correct scope, no cross-user/company leak |
| Checkpoints and recovery | Scoped persistent store/reference; cancellation protocol | Claimed restart/resume behavior, no repeated side effects |
| Skills / delegation | Published allowed skills/child installations and shared budget | Correct binding, bounded execution, cancellation and results |
| Audit and errors | Platform events/receipts, meaningful business error | Traceable effects without secrets in logs |

Not all agents need all capabilities. A required shared concern implemented privately is a reuse finding. An unneeded concern is not applicable. Do not turn review into an arbitrary percentage score.

## Deployment completeness

Check matching agent ID, immutable version, actual artifact digest, schema materials, image entrypoint, dependency/runtime versions, public verification key, issuer/audience, platform-reachable endpoint, readiness, workload credentials, current installation binding and published six-policy snapshot.

For host/Compose/K8s check actual DNS, ports, Secret mounts, volume ownership, resource and network limits. Generic templates use in-memory stores; do not infer crash recovery or multi-instance safety. Test only features the business claims, while retaining essential v2 lifecycle correctness.

## Minimum final evidence

Record test command/environment/result; actual image and catalog IDs; deployment observation and installation state; policy snapshot; workload binding; departmental ceiling; affected user package/batch receipts; authorized run and correct business output; denial cases; cancellation/recovery evidence; remaining prerequisites.

Keep secret values and real business contents private. Public reports can contain sanitized IDs/errors and concise outcomes. A report imported from a prior deployment is not proof of the current artifact or authorization revision.
