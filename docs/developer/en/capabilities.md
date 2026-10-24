# Shared capabilities and reuse

[Developer path](README.md) · [简体中文](../zh/capabilities.md)

The repository's shared SDK capability version is **2.1.0**, templates are **1.1.0**, and example agents are **0.3.0 with v3 schemas**. See the [capability and example release notes](../../releases/public-capabilities-2.1.en.md) for changes, configuration and historical compatibility.

Business agents own domain decisions, workflows and outputs. Platform/SDK services own verification, model routing, retrieval and lifecycle infrastructure. Methods below are from [Python CapabilityGatewayClient](../../../sdk/python/agent_platform_sdk/capability_client.py) and are asynchronous: use `await`. See corresponding [Go](../../../sdk/go/) and [Java](../../../sdk/java/) SDKs.

| Need | SDK entry | Prerequisites and effects |
| --- | --- | --- |
| Chat / embeddings | `chat`, `embed` | Approved models/prices, published model policy, caller and workload access; produces usage and internal charges |
| Structured final output | `chat(..., require_json=True, response_schema=...)` | Supported model and policy; use a separate request from Function Calling |
| Tool-driven model loops | `generate_with_functions`, `run_harness` | Runtime/tool policy and bounded rounds; no direct vendor SDK fallback |
| Published prompt | `resolve_prompt` | Current published prompt asset |
| Business tool | `invoke_tool` | Approved tool, schema, risk and confirmation; can modify external state |
| Enterprise retrieval | `search_knowledge`, `run_knowledge_harness`, `answer_knowledge` | Real sources/indexes, embeddings, policy and dual-identity ACLs; preserve citations |
| Memory | `memory_load`, `memory_save` | Scoped namespace/key/schema; no unscoped shared cache |
| Checkpoints / recovery | `load_checkpoint`, `save_checkpoint`, `load_recovery_checkpoint` | Matching installation, run and schema authority |
| Current execution validity | `validate_current_execution` | Current installation, binding, run and authorization facts |
| Skills | `load_skill`, `load_skill_bindings` | Published skill, runtime allowance and resource access |
| Agent groups | `run_agent_group` and coordination interfaces | Delegation, child installation/resources, shared budget and cancellation |

Reuse is driven by business needs. A deterministic rule agent need not call a model merely to improve a reuse score. Review all required shared infrastructure and explain capabilities that are not needed.

## Trusted context and credentials

The [Python business server](../../../examples/python-documents/document_assistant/server.py) demonstrates verification followed by `CapabilityContext.from_verified` and capability-client construction. Use current SDK signatures. User-supplied tenant IDs or decoded tokens are not trusted contexts.

Provider credentials remain mounted on the platform. Agents receive their own workload credentials, verification public key, capability URL and installation binding. Never copy platform `.env`, database DSNs or signing private keys into agents.

## Knowledge

Platform knowledge manages source versions, parsing/chunking, index generations and published projections. Retrieval combines authorized strategies such as vector/keyword fusion. Agents provide business queries, approved scope, Top K and cache mode, then consume results and citations.

See [document assistant business code](../../../examples/python-documents/document_assistant/business.py). Working code still needs real document bindings, indexing, approved embeddings and current ACLs in the target installation.

## Side effects and accounting

`invoke_tool(..., confirmed=True)` does not grant platform approval. Follow confirmation, commit and receipt protocols. For timeouts with uncertain external effects, query the original receipt rather than resend writes blindly.

Platform prices are internal accounting parameters, not guarantees of vendor invoices. Reconcile uncertain reservations with original evidence; do not resend model requests to create accounting evidence. Parent/child runs share budgets while workflows still bound rounds and delegation size.

## Cross-language SDK 2.1 APIs

Python methods are asynchronous. Go exposes methods on `CapabilityClient` or its `PublicCapabilities()` facade; Java exposes convenience APIs on `client.capabilities()`. All clients must originate from SDK-verified execution contexts. Python reference authorization uses functions from the `reference_authorization` module, such as `await authorize_cached_result(client, result, knowledge_scope)`, rather than same-named client methods.

| Capability | Python | Go | Java facade |
| --- | --- | --- | --- |
| Chat / embeddings | `chat` / `embed` | `Chat` / `Embed` | `chat` / `embed` |
| Prompt | `resolve_prompt` | `ResolvePrompt` | `resolvePrompt` |
| Memory | `memory_load` / `memory_save` | `MemoryLoad` / `MemorySave` | `memoryLoad` / `memorySave` |
| Knowledge | `search_knowledge` / `answer_knowledge` / `replay_knowledge` | `SearchKnowledge` / `AnswerKnowledge` / `ReplayKnowledge` | `searchKnowledge` / `answerKnowledge` / `replayKnowledge` |
| Current reference ACL | `authorize_references` / `authorize_cached_result` | `AuthorizeReferences` / `AuthorizeCachedResult` | `authorizeReferences` / `authorizeCachedResult` |
| Durable knowledge | `run_knowledge_search` / `run_knowledge_harness` | `RunKnowledgeSearch` / `RunKnowledgeHarness` | `KnowledgeWorkflow.search` / `answer` |
| Execution policy | `load_execution_policy` | `LoadExecutionPolicy` | `loadExecutionPolicy` |

The SDKs also share durable stages, step workflows, extended Harness behavior, checkpoint capacity/cursors, paginated recovery, bounded concurrency and original deadline semantics. LangGraph-specific integration stays in Python.

Automatic model routing is explicit policy behavior. Preserve returned model, routing, cache and billing metadata without inventing missing values. JSON Schema final generation and Function Calling use separate calls. Knowledge source/date filters belong to idempotency and recovery identity; authorize cached or frozen references against current ACLs before use and return.

Notifications require published tool mappings, independent approval and caller/workload access. Kafka publication, delivery and inbox arrival are distinct. Cancellation requires actual stop, compensation and budget evidence; an accepted tool response is not proof of delivery. See [release configuration](../../releases/public-capabilities-2.1.en.md#configuration-and-compatibility) and the [detailed SDK guide, Chinese](../../开发者指南/三语言SDK业务Agent开发指南.md#sdk-21-公共能力接入).

## Reuse acceptance

Record business need → SDK/component → policy/authorization → actual test evidence. Check for duplicated JWT logic, role tables, model gateways, vector database access, lifecycle state machines, tool approval or cross-tenant memory caches. Replace duplicated infrastructure with shared ports or document the required extension.

`python scripts/check_agent_code_ownership.py` covers registered repository directories. It does not automatically inspect an external business repository and is not, by itself, a complete reuse assessment.
