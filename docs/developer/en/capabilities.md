# Shared capabilities and reuse

[Developer path](README.md) · [简体中文](../zh/capabilities.md)

Business agents own domain decisions, workflows and outputs. Platform/SDK services own verification, model routing, retrieval and lifecycle infrastructure. Methods below are from [Python CapabilityGatewayClient](../../../sdk/python/agent_platform_sdk/capability_client.py) and are asynchronous: use `await`. See corresponding [Go](../../../sdk/go/) and [Java](../../../sdk/java/) SDKs.

| Need | SDK entry | Prerequisites and effects |
| --- | --- | --- |
| Chat / embeddings | `chat`, `embed` | Approved models/prices, published model policy, caller and workload access; produces usage and internal charges |
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

## Reuse acceptance

Record business need → SDK/component → policy/authorization → actual test evidence. Check for duplicated JWT logic, role tables, model gateways, vector database access, lifecycle state machines, tool approval or cross-tenant memory caches. Replace duplicated infrastructure with shared ports or document the required extension.

`python scripts/check_agent_code_ownership.py` covers registered repository directories. It does not automatically inspect an external business repository and is not, by itself, a complete reuse assessment.
