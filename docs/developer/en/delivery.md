# From business project to a usable platform agent

[Developer path](README.md) · [简体中文](../zh/delivery.md)

The goal is that **specific users in the intended company and department execute a specific agent version through the platform**. Source tests, image startup and catalog visibility are intermediate outcomes.

Start with the [complete walkthrough](walkthrough.md) for an executable custom-agent route with actual requests and acceptance receipts.

## Prepare the target once

Record platform origin/method, company/department/internal Application, agent/version, real artifact digest, reachable endpoint, workload identity, capabilities, users, operations and expiry. Read actual records rather than guessing IDs or borrowing example IDs.

Prepare artifacts and an impact plan before authorized changes. The [delivery skill](skill.md) orchestrates this path; existing governance applies.

## 1. Business behavior and reuse

Use [first-agent development](first-agent.md); prepare schemas, manifest, version and evaluation cases. Map required features to [shared capabilities](capabilities.md), explaining unused features. Test success, invalid input, denial, dependency failures, timeout, cancellation and promised recovery. In-memory state is not durable recovery. Separate fixture results from real-provider tests and preserve approved provider/data scope.

## 2. Artifact and catalog

Build the correct image, record its actual digest and publish it where the target can pull it. Local image IDs and registry digests are different. Retain schemas, manifest, evaluation and SDK/template versions.

The catalog separates **Definition → Version → Installation → Deployment**. Publish through evaluation and approval, then install into the target Application. Policies and deployment observations remain independent. `agentctl package` does not publish; `agentctl publish` does not finish approval or deployment.

For fixed examples, `platform/cmd/example-release-bundle` prepares requests using actual `--example`, `--artifact-digest`, `--publisher`, `--endpoint`. It does not approve or observe readiness. Custom agents use their own materials. Check current [API wiring](../../../frontend/src/api.js) and [Catalog source](../../../platform/internal/catalog/); preserve independent author/evaluator/publisher responsibilities.

Scoped authors include `tenant_id`, `department_id`, `application_id` query parameters on definition/version POST requests, matching their selected scope. Installation mode is `managed` or `external`, not `service`.

## 3. Policies

An installation needs six types: **model, prompt, tool, memory, knowledge and runtime**, with a matching published snapshot. Approved models/prices, endpoint/Secret references, real sources/indexes, tools and skills must exist. Unused types express minimal allowance.

Provider keys stay on the platform. Production prompts use published assets, not direct bootstrap JSON. [publish_public_policy_release.py](../../../scripts/publish_public_policy_release.py) supports `prepare`, `create-drafts`, `publish` for the examples, with independent author/publisher. Explicitly provide actual scope and verify supported shapes; see the [detailed Chinese reference](../../开发者指南/业务Agent挂载与已有用户授权指南.md).

Unused tools and knowledge use explicit `allowed_tools: []` and `allowed_scopes: []` to deny access; missing/null lists cannot be published. The deterministic tutorial uses a zero-budget model placeholder without an actual provider endpoint, which is not evidence of a configured model integration.

## 4. Service and installation

Deploy through [host/Compose/K8s](deployment.md). Match public key, agent ID, issuer/audience, capability URL and workload authentication. Endpoints must be reachable **from the platform network**. Loopback in a container/Pod means itself; use Compose service names or K8s Service DNS as appropriate.

The controller checks actual image/readiness and uses [deployment-observe](../../../platform/cmd/deployment-observe/) with preview/hash/revision constraints. Installation becomes `active` only after observation. Do not forge readiness via SQL or an ordinary-user API.

## 5. Workload identity

Use independent credentials per agent, create the workload and bind its exact installation/version/policy, observed source network and resources. Browser credentials are not workload credentials. Binding, resource authorization and installation state are independent checks.

Use machine administration or operator-only [configure-workloads](../../../platform/cmd/configure-workloads/) with actual preview/input-digest contracts. Platform DB credentials must not enter agents or ordinary-user environments.

**Installation binding does not grant execution.** Preview/commit separate workload grants for the installation's required actions: the tutorial uses `run`, `history.read`, `cancel`, `history.continue`, each with `source_id` and explicit data scope. Required model/retrieval/tool resource grants must cover the workload as well as the caller.

New departments approve no agents by default. After creating/binding the workload, establish the company-approved department ceiling below before granting bounded workload/user resources.

## 6. Company, department and user binding

| Level | Actor / action | Effect |
| --- | --- | --- |
| Company | Platform appoints company administrator | User belongs to one company |
| Department | Company administrator assigns department and role | Membership alone does not enable agents |
| Department agent ceiling | Company administrator → Available agents | Eligible installations, operations and expiry |
| User access | Authorized company/department administrator selects users → Enable agent use | Personal-session actions and published resource dependencies |
| Special operations | Separate authorization | Sharing/export/content modification/administration excluded from daily defaults |

Daily-use packages cover personal sessions and required published model, knowledge, tool and memory resources. Each batch supports at most 50 users. Preview, authenticate freshly, commit and inspect per-user results. Existing grants and deny rules remain; deny wins.

Department administrators grant to other members only within the company's ceiling and their scope. An administrator's own business access requires another authorized actor.

Automation reuses [existing constructors](../../../frontend/src/features/identity/permission-batch.js): `department-agent-changes:preview` → `department-agent-changes`; `agent-use-package` → `permission-batches:preview` → `permission-batches`. Preserve revisions, package digest, fresh authentication and original key. Do not insert Grant rows.

Query the daily-use package with only `department_id`, `application_id`, `installation_id`; tenant is inferred from the authenticated account. Department-ceiling commands have their own tenant/department fields and digest-bound fresh authentication.

## 7. Actual acceptance

Record ordinary-user run ID, scope/version, terminal state and correct output; real capability results/citations/receipts; unassigned/cross-company denial; promised cancellation/recovery and actual side effects; audit/usage/binding receipts; probes, secret ownership and recovery compatibility.

Deliver a password-free account/company/department/agent/operation/management checklist. Missing prerequisites remain pending. Query original receipts/batches after uncertain responses instead of resending with a new key. Recovery follows concrete authorization, installation, version and schema boundaries, not deletion of unrelated data.
