# Shared capabilities, SDK 2.1 and example agents

[Project](../../README_EN.md) · [Developer path](../developer/en/README.md) · [简体中文](public-capabilities-2.1.zh.md)

This update moves shared model, knowledge, workflow, authorization and cancellation behavior into the platform and its Go, Python and Java SDKs. Business agents retain their own inputs, decisions and outputs. This page describes developer-facing changes without deployment-specific credentials or execution records.

## Shared platform capabilities

| Area | Changes | Integration boundary |
| --- | --- | --- |
| Models | Automatic routing, candidate quality admission, availability checks, bounded failover, physical attempt records and provider protocol adapters | Configured model selection remains the default; automatic selection requires published policy |
| Structured output and cost | JSON Schema responses, prefix caching, cached-token pricing and model/routing/billing metadata | Final structured generation and Function Calling use separate requests; missing cost is not zero cost |
| Workflows | Extended Harness, durable stages, step workflows, original batch windows, deadlines, bounded concurrency and controlled retries | Recovery retains original operation identity and deadlines; uncertain submitted operations are recovered by reading original receipts |
| Checkpoints | Capacity negotiation, quota reservation, CAS cursors and paginated recovery references | Scope and reference validation remain mandatory; conflicts require rereading the current head |
| Knowledge | Governed multi-source fusion, durable search/answer workflows, read-only recovery, index receipts and current authorization of cached/frozen references | Source and date filters form part of idempotency; cached evidence does not replace current caller/workload ACLs |
| Remote tools | Bound operation identity, idempotency lifetime and read-only original receipts | An accepted request does not prove completion; a lost response does not authorize a new submission |
| Governance | Department agent access packages, workload version sets, self-escalation restrictions and continuous authorization | Existing company, department, membership and batch-grant interfaces remain supported |
| Notifications and cancellation | Kafka delivery, self inbox, withdrawal of delivered notifications, compensation, durable stop confirmation and budget closure evidence | Enable through deployment configuration; publication, delivery and inbox arrival are separate states |
| Observation and evaluation | Stage performance observations, evaluation case reuse and independent review | Preserve actual attribution; business agents do not receive gold answers or certify their own quality |

Connection reuse, rate limits at the send boundary, decoding caches and retries after confirmed transaction rollback are shared infrastructure. Authorization decisions are not decoding-cache entries, and unknown commits are not retryable evidence.

## SDKs and templates

The repository's shared SDK capability version is **2.1.0**; the six templates are **1.1.0**. Go and Java gain the chat, embedding, prompt, memory and knowledge convenience APIs already available in Python. All three languages support structured output, execution-policy reads, durable knowledge workflows, reference authorization, checkpoint cursors and paginated recovery.

| Capability | Python | Go | Java |
| --- | --- | --- | --- |
| Chat / embeddings | `client.chat` / `embed` | `client.Chat` / `Embed` | `client.capabilities().chat` / `embed` |
| Knowledge | `search_knowledge` / `answer_knowledge` / `replay_knowledge` | `SearchKnowledge` / `AnswerKnowledge` / `ReplayKnowledge` | `searchKnowledge` / `answerKnowledge` / `replayKnowledge` |
| Reference authorization | `authorize_references` / `authorize_cached_result` | `AuthorizeReferences` / `AuthorizeCachedResult` | `authorizeReferences` / `authorizeCachedResult` |
| Durable orchestration | `DurableStageClient` / `run_step_workflow` | `DurableStageClient` / `RunStepWorkflow` | `DurableStageClient` / `StepWorkflow.run` |
| Checkpoint progress | `CheckpointCursor` | `OpenCheckpointCursor` | `CheckpointCursor.open` |

Go APIs are exposed on the capability client or its public facade; Java convenience methods are on `client.capabilities()`. Python reference authorization uses functions from `reference_authorization`, passing the existing client. Obtain clients from SDK-verified execution contexts. LangGraph-specific integration remains Python-only; shared recovery and isolation semantics are implemented in all languages.

Use the current `agentctl` for `go-generic`, `go-eino`, `python-generic`, `python-langgraph`, `java-generic` or `java-spring-ai`. Keep the generated `template.lock`, embedded SDK and dependency versions together. Go retains its existing module path; use the repository's Java/Python build instructions. See [capability APIs](../developer/en/capabilities.md) and the detailed [SDK guide, Chinese](../开发者指南/三语言SDK业务Agent开发指南.md).

## Example agent changes

All three example agents are **0.3.0**, with **v3 input/output schemas**. Their execution protocol remains `agent-execution/v2`.

- **[Go operations](../../examples/go-operations/README.md):** shared calls use SDK convenience APIs; frozen knowledge is authorized again before use and return; recovery, send limits, observation and model metadata use shared semantics. The agent still produces read-only diagnosis and uses its existing tool switches and fixed document-assistance plan.
- **[Java tickets](../../examples/java-tickets/README.md):** shared calls use SDK APIs, frozen citations are reauthorized, and approval continuation, receipt recovery and model attribution use common contracts. Ticket text remains data; the agent produces drafts and uses a fixed collaboration plan.
- **[Python documents](../../examples/python-documents/README.md):** v3 adds optional `as_of` and `source_ids`, bound to idempotency and recovery fingerprints. Citation authorization and governance metadata are shared. `direct` remains the default; `tool_loop`, notification, sandbox and collaboration remain explicit choices.

v3 outputs add `model_metadata` while retaining actual platform attribution. Historical v2 schemas, manifests and recovery fingerprints are preserved; Java also retains its v1 path. Existing requests keep their corresponding output contracts.

## Fixes

- Correct legitimate event-history reads when execution and history authorization versions advance independently; revocation and cross-user denial remain enforced.
- Handle confirmed browser cancellation revision conflicts with bounded rereads and fresh authorization, without repeating business operations or model calls.
- Protect historical unknown operations and pending cancellation/accounting records from automatic recovery, and enforce Kafka consumer start boundaries.
- Add optional model-host DoH resolution for environments whose proxy DNS returns synthetic addresses, retaining TLS and address checks.
- Align CI and active image builds on Go 1.26.10 and upgrade `klauspost/compress` to 1.18.7 for security fixes.
- Complete manual GitHub Actions entry points, SDK/template synchronization and explicit hidden report uploads; include Python ASGI startup dependencies and executable temporary directories for helper processes.

## Configuration and compatibility

Features require published resources, policy and separate caller/workload authorization. They do not create provider assets, knowledge bindings or permissions automatically.

| Feature | Activation |
| --- | --- |
| Automatic routing, structured output, cache pricing | Publish model, price and installation policies; agents cannot override provider identity or prices |
| Notifications / compensation | Configure `PLATFORM_EVENT_BUS_MODE`, Kafka delivery and `PLATFORM_CANCELLATION_COMPENSATION_ENABLED`; compensation defaults to `false`, while event-bus behavior follows deployment configuration |
| Historical recovery protection | Back up existing state and configure SHA-bound holds and consumer boundaries before enabling background processing; retain existing consumer groups and unknown records |
| External knowledge | Configure independent `PLATFORM_EXTERNAL_KNOWLEDGE_URL`, `PLATFORM_EXTERNAL_KNOWLEDGE_BASE_IDS` and a credential file; blank configuration retains native knowledge |
| Optional model DNS | Set `PLATFORM_MODEL_DNS_OVER_HTTPS_HOSTS_JSON` to an explicit host list; blank keeps ordinary DNS and `[]` disables the extension |
| Agent timing | `AGENT_PLATFORM_CAPABILITY_TIMING=1` enables timing without logging bodies or credentials |

Migrations append to this project's existing history. Company/department management, membership, batch grants and console entry points remain compatible. Explicit empty tool/knowledge lists retain their restrictive meaning. Unknown costs, tool results and submissions remain unknown; they are not settled as zero or automatically replayed.

See [configuration](../developer/en/configuration.md), [deployment](../developer/en/deployment.md), [upgrade details, Chinese](../developer/zh/public-capabilities-upgrade.md), and [notification/recovery operations, Chinese](../developer/zh/notification-cancellation-operations.md). Preserve existing accounts, authorization and historical data, and introduce new behavior through versioned assets.
