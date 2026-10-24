# Full walkthrough: from an empty platform to an ordinary user's agent run

[Developer path](README.md) · [简体中文](../zh/walkthrough.md)

This connects [platform setup](quickstart.md), [business development](first-agent.md) and [delivery](delivery.md). Acceptance means an ordinary department user runs a custom support assistant through the platform and receives the expected answer; unassigned users cannot run it or read that user's session, and forged company scopes are rejected.

## Execute the complete route

Install Python 3.12+, Go 1.26.10+, Docker Engine / Docker Desktop and Compose v2. The engine must be running. Network access is needed for Python packages, Go modules and base images. From the repository root:

```text
python -m pip install "cryptography>=50,<51"
python tests/e2e/developer_walkthrough.py --report .tmp/developer-walkthrough-report.json
```

This performs real deployment and governance calls, creating tutorial organizations, users, an independent workload, agent versions, policies and grants. It copies public source into a fresh `.tmp/` directory and generates independent credentials, ports, a Compose project, volumes and image tags. It does not read your existing deployment's `.env` or use its database. The deterministic agent makes no external model requests.

Success prints `PASS` and the report path, then removes this run's containers, volumes, image tags, source copy and virtual environment. The report remains. Failure retains the exact environment and private diagnostic logs. Unknown requests retain their original run and idempotency keys.

Use `--keep` to log in and inspect the completed environment:

```text
python tests/e2e/developer_walkthrough.py --keep --report .tmp/developer-walkthrough-report.json
```

The report provides `origin` and `retained_workspace`. Initial administrator credentials are in that workspace's `source/.local-secrets/first-admin.json`; tutorial credentials are in `source/.local-secrets/tutorial-accounts.json`. These private local files must not enter reports, issues, chats or Git. Afterwards replace the placeholder with the exact workspace:

```text
python tests/e2e/developer_walkthrough.py --cleanup .tmp/<this-run-workspace>
```

Use `--resume .tmp/<this-run-workspace> --report .tmp/developer-walkthrough-report.json` after a failure to inspect and continue its recorded state. Resume uses that copy's source and completed phases. After changing platform source, end the old environment and run a fresh case; old images do not validate new code.

## What the route performs

| Step | Action and actor | Evidence |
| --- | --- | --- |
| 1 | Generate configuration, migrate, bootstrap and start the platform using quick-start commands | Five healthy base services and administrator login |
| 2 | Scaffold with agentctl, add business hooks, tests and schemas | Ownership validation and business / SDK tests without skips |
| 3 | Appoint a company administrator and assign department membership / administration | One company per account, explicit department scopes |
| 4 | `agent.author` submits the definition/version; an independent administrator evaluates and publishes | Different submitter and approver |
| 5 | Author six policies; independently publish assets and snapshot | Actual version, revision and hash agreement |
| 6 | Run the business image; controller verifies image and readiness | Deployment observation and active installation |
| 7 | Create and bind an independent workload; assign department membership and management | Current workload binding and department memberships |
| 8 | Company administrator sets the ceiling before granting workload execution; department administrator assigns a daily-use package | Bounded workload/user access, previews, digests, revisions and per-user batch receipts |
| 9 | `support.user` submits through the platform and reads history | Successful run and correct business answer / metadata |
| 10 | Replay the same key; test invalid input, unauthorized access and company-scope forgery | Unchanged history, failed invalid input and denied access |

Review [developer_agent_delivery.py](../../../tests/e2e/developer_agent_delivery.py) for actual governance requests and [developer_walkthrough.py](../../../tests/e2e/developer_walkthrough.py) for setup, testing and owned cleanup. Report `operations` include methods, paths and requests with secrets redacted. Completed phases, catalog/policy/batch/run receipts, expected results and denials support acceptance.

## Adapt to your business

Change business-owned domain, prompts, orchestration and evaluation files, then rewrite schemas, answer assertions and failure cases. This tutorial produces deterministic guidance. Models, retrieval or tools require real platform resources, published policies and capability receipt / citation / denial tests.

| Wiring detail | Actual contract used here |
| --- | --- |
| Scoped catalog submission | Definition and version POST requests include `tenant_id`, `department_id`, `application_id` query parameters matching the author's selected scope |
| Schemas | [Input](../snippets/input.schema.json) and [output](../snippets/output.schema.json) describe actual business objects; manifest references alone are insufficient |
| Installation | `deployment_mode: managed`; supported values are `managed` and `external` |
| Unused tools / knowledge | Explicit `allowed_tools: []` and `allowed_scopes: []` deny calls; missing/null lists cannot be published. The tutorial model profile has zero budget and no actual provider endpoint |
| Readiness | Check HTTP success from the platform container at `http://support-assistant:8080/health/ready`; a response body is not required |
| Workload authorization | Binding does not grant `run`. Preview/commit explicit `run`, `history.read`, `cancel`, `history.continue` grants for this installation, including `source_id` and data scope; add actual capability resources when needed |
| Authorization order | New departments have no available agents by default; establish the company-approved ceiling before workload and user resource grants |
| Department ceiling | Read current revision, preview, authenticate freshly against its digest, then submit digest and expiry |
| Daily-use package | Query only `department_id`, `application_id`, `installation_id`; tenant is inferred from login. An extra `tenant_id` is rejected |
| Batch grants | Use current package digest and principal revisions, preview, commit, continue and inspect individual outcomes; do not write grants directly to SQL |
| Business outcome | Read session `/messages` and verify answer and metadata, not merely successful run status |

Local image content IDs are used only on this single host. Other hosts and K8s require a pullable registry digest, environment-specific Service DNS, secrets and source networking; see [deployment](deployment.md).

## Accounts for acceptance

| Account | Scope and purpose |
| --- | --- |
| `platform.admin` | Initial company; independent publication, company-admin appointment and deployment control |
| `company.admin` | Initial company / Support; organization, members, workloads and department ceilings |
| `department.manager` | Initial company / Support; other members' daily-use grants, no implicit business run access |
| `agent.author` | Initial company / Support; development and submission, separate publication required |
| `support.user` | Initial company / Support; support assistant and own history, no export/share/administration |
| `unassigned.user` | Initial company / Support; restricted catalog entry, no run or another user's history access |

This verifies single-host delivery, business success, invalid input, idempotency and authorization boundaries. The company is provisioned by first-administrator initialization; browser organization management stays within the account's company. The isolation check rejects an ordinary user's forged company scope; it does not claim a separately provisioned other-company account's full onboarding/runtime acceptance. Real providers, indexes, durable recovery, multiple replicas and production K8s require separate acceptance.
