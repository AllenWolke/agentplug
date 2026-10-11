# Secondary development and extensions

[Developer path](README.md) · [简体中文](../zh/extending.md)

Keep business changes in independent agents. Extend the platform when multiple businesses need a capability that current ports cannot express.

| Change | Location | Validation |
| --- | --- | --- |
| Workflow/rules | Agent `domain/`, `graph/`, `prompts/`, `eval/` | Schemas, meaningful outcomes, failure/cancellation/recovery |
| Framework | Business layer of Eino/LangGraph/Spring AI templates | Preserve SDK verification and lifecycle |
| Provider | Model governance/gateway and approved endpoint/Secret/version | Approval, timeouts/receipts, pricing/usage, dual-identity authority |
| Tool/MCP | Platform adapters and published policy | Schema, allowed functions, risk, confirmation and receipts |
| Knowledge | Knowledge-owned sources/tasks/projections | Versioning, incremental/deletion, CAS, ACL and recovery |
| Shared capability | Owning module, port and SDKs | Three clients, errors, access, budgets, events/audit |
| UI | Features and locales | Permissions, effects, empty/failure states, Chinese/English and tests |
| Persistence | Owner migration and architecture contracts | Ownership, schema checks and backup compatibility |

Find current contracts/owners first. Preserve managed paths and inject hooks; preview upgrades rather than changing hashes. New tables update [table ownership](../../../contracts/architecture/table-owners.json) and migrations; cross-module reads use owning ports or registered projections. Protocol changes update SDKs/templates and compatibility/error tests together.

```text
python scripts/verify_modular_boundaries.py
python scripts/check_agent_code_ownership.py
python scripts/check_agent_productization_contracts.py
```

Use appropriate business tests and isolated real behavior/access checks. `agentctl test` needs `--base-url`; runner paths depend on current directory and signed fixtures must be valid. It does not create production identities. Fixture success does not replace actual provider/cluster/Code Runtime acceptance. Preserve backup/migration/observation/recovery for live changes and report missing prerequisites honestly.
