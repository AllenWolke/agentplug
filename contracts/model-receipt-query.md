# Read-only model receipt v1

`POST /internal/model/receipt` accepts the exact original generation input: messages, function names, approved prompt template hash, idempotency key, temperature and max tokens. It uses the current signed execution context, caller/workload resource authorization, policy snapshot and approved model selection. Scope and fingerprint must match the original invocation. Current model access and execution/resource authority are checked again before returning content.

Response: `version=model-receipt/v1`, `idempotency_key`, `status`, `receipt`. Status is `not_found`, `running`, `failed`, `reconcile` or `completed`. Only completed records expose their original finalized result, including recorded usage. A completed ledger entry can still contain an incomplete model answer; consumers must preserve its completion status. Other states never imply permission to retry a vendor request.

The operation is a plain ledger lookup. It does not reserve budget, acquire execution leases, repair records, charge usage or invoke a provider. SQL reads use the runtime database identity; missing records remain missing. Changed input produces a conflict rather than returning another operation's answer. Unknown stored statuses and corrupt receipts fail closed. Responses disable HTTP caching.

Go, Python and Java Harness runners persist the exact approved, windowed model request as `model_request` before dispatch. After interruption they query that stored request, validate version/key/status and use only a completed receipt. They do not prepare a different context or dispatch generation again. Older interrupted checkpoints lacking this field stop rather than reconstructing or replaying the request. The transient request is removed after successful receipt processing. Confirmation credentials never enter this checkpoint field.

Stage evidence is recorded in `docs/新增需求/github作品改造/T3-20-三语言模型回执恢复阶段记录.md`. This is not acceptance of the complete Runtime/Harness or formal three-Agent deployment.

## Embedding and read-only RAG recovery (development)

POST /internal/model/embed/receipt accepts the original texts/idempotency_key. It selects the approved embedding policy and normalizes exactly as embed (user messages, published prompt hash, one conservative output token, temperature zero), then validates the original embedding fingerprint and current model/embed authority. It returns model-receipt/v1; only completed exposes the real receipt. No provider call, reservation, reconciliation mutation or release.

POST /internal/knowledge/answer/recovery uses exactly the original answer input. A private composition context switches every governed model stage to the same authorized receipt reader, preserving original request/policy/stage-derived operation keys. Missing/unknown receipts stop with KNOWLEDGE_RECONCILIATION_REQUIRED; changed fingerprints conflict. Existing cache/retrieval/current document and Skill checks remain required. Recovery reports original invocation usage and zero new model requests; that is not proof of a vendor no-charge decision. Python run_knowledge_harness persists its dispatch boundary and pinned dependencies through public State, and never caches output in checkpoints as a disclosure shortcut. Compiled source only; actual crash/cache-cold/index-change/revocation scenarios remain unaccepted.
