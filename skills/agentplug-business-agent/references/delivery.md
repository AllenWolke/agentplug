# Deployment and binding workflow

Read `docs/developer/en/delivery.md`, `deployment.md` and the selected deployment templates from the confirmed repository. Use current source fields; the paths and API names here are navigation, not a substitute for current schemas.

## Existing commands

| Surface | Use | Boundary |
| --- | --- | --- |
| `tests/e2e/developer_walkthrough.py` | Fresh custom-agent setup, development, tests, publish/bind, ordinary-user acceptance and owned cleanup | Isolated tutorial only; zero external provider calls, not production deployment |
| `scripts/local.py` | Build/run native platform, gateway and Runner | Separate private service configs; external database prerequisite |
| `scripts/compose.py` | Config/build/up/status/smoke/down and explicit extensions | Base launcher does not automatically include a custom agent |
| `deploy/k8s/production/apply.ps1` | Approved render, secrets/signatures, lock, migration, rollout | Candidate templates require real overlay, clean committed source and cluster acceptance |
| `cli/agentctl` | Scaffold/validate/test/package/publish | Packaging or a draft submission is not deployment acceptance |
| `platform/cmd/example-release-bundle` | Offline plans for the three actual examples | Not a generic live deployment orchestrator |
| `scripts/publish_public_policy_release.py` | Prepare/author/publish example policies | Six types, independent human publisher, actual model/knowledge prerequisites |
| `platform/cmd/deployment-observe` | Operator/controller observation | Current revision/hash and actual image/probe; no forged readiness |
| `platform/cmd/configure-workloads` | Scoped workload maintenance with preview/input digest | Operator-only database credential; current authenticated actor and actual supported schema |

For a custom agent, construct its catalog/policy/identity requests from current public module contracts. Fixed-example helpers must not silently create example users/identities as part of a custom delivery.

The executable custom tutorial is `docs/developer/en/walkthrough.md`; its underlying API flow is `tests/e2e/developer_agent_delivery.py`. Inspect its real requests for scoped author query parameters, supported installation mode, six minimal policies, independent workload grants, department digest-bound authentication and exact daily-use package query fields. Adapt artifacts, endpoints, resources and acceptance assertions to the requested business; do not assume deterministic tutorial results prove provider or cluster integration.

## Browser authority and current requests

`frontend/src/api.js` connects browser operations to `/api/modules/<module>/...`. Read `requestPlatformModule`, authentication, CSRF/fresh-authentication handling and current request constructors before automation. Keep sessions private. Do not call internal controller endpoints with browser or agent credentials.

| Action | Existing Identity surface | Read constructor |
| --- | --- | --- |
| Add department membership | `memberships:preview` then `memberships:change` | Identity membership commands |
| Set company-approved departmental agents | `department-agent-changes:preview` then `department-agent-changes` | `frontend/src/features/identity/department-agent-policy.js` |
| Fetch current daily-use dependencies | `agent-use-package` | `BatchAgentUseForm.jsx` |
| Batch assign users | `permission-batches:preview` then `permission-batches` | `permission-batch.js`, `PermissionBatchProgress.jsx` |
| Recover an uncertain batch | `permission-batches/<key>` and `:continue` | Reuse original key; inspect per-subject results |

Company workspace is the tenant, department is the organizational scope, internal Application holds installations/policy. Platform administrators appoint company administrators; company administrators create departments, assign departmental roles and establish agent ceilings. Departmental administrators allocate access within that ceiling. Optional permission administrators operate only under actual delegation.

Daily-use packages can cover personal conversation actions and published model/knowledge/tool/memory dependencies. They do not imply sharing/export/content-change/administration. Preserve explicit denies, expiration and prior unrelated grants. Administrators cannot add their own business access.

## Final target-platform checks

1. Actual desired artifact runs at the platform-reachable endpoint; readiness is observed by the deployment controller.
2. Catalog installation is active; exact version and policy snapshot agree.
3. Current independent workload binding and capability grants are effective.
4. Company/department ceilings and intended users' current memberships/packages agree.
5. Assigned ordinary user obtains a correct terminal business result through the browser/platform; required capability evidence exists.
6. Unassigned and cross-company users cannot run or access resources; claimed cancellation/recovery is verified.

Record each operation receipt and current revision. On failure identify the smallest unmet prerequisite and preserve completed work. An unsupported environment is pending, not passed.
