# Developer learning path

For a complete first delivery, follow the [empty-platform to ordinary-user walkthrough](walkthrough.md): one command performs real setup, development, tests, independent publication, organizational access and user acceptance, with receipts and owned cleanup.

[Project](../../../README_EN.md) · [简体中文](../zh/README.md) · [日本語](../ja/README.md) · [Deutsch](../de/README.md)

Understand the platform/agent boundary, run a business project, then deliver it to actual users. Follow the stages in order; optional services can wait.

| Stage | Guide | Completion criterion |
| --- | --- | --- |
| Understand responsibilities | [Architecture and source map](architecture.md) | Locate business logic, authorization and shared capabilities |
| Install the base platform | [Quick start](quickstart.md), [three deployment methods](deployment.md) | Services healthy; your administrator can sign in |
| Build business behavior | [First agent](first-agent.md) | Business and SDK lifecycle tests pass; image builds |
| Reuse shared infrastructure | [Capabilities](capabilities.md) | Map required capabilities to SDK APIs, policies and authorization |
| Deliver to users | [Publication, deployment and access](delivery.md) | Active installation; authorized user completes a real run; unauthorized user is denied |
| Extend | [Secondary development](extending.md) | Contracts, boundaries, tests and migration reflect the change |

The [repository skill](skill.md) can guide this workflow. It does not provide deployment infrastructure, administrator authority or fabricated acceptance evidence.

## Five concepts

| Concept | Meaning |
| --- | --- |
| Agent Definition | Stable identity and catalog information for a business assistant |
| Agent Version | Immutable manifest, artifact and evaluation association |
| Installation | A version installed into a company / department / internal Application |
| Deployment | Actual service endpoint, desired state and deployment observation |
| Policy Snapshot | Published model, prompt, tool, memory, knowledge and runtime policies for an installation |

An existing image, installation record, ready endpoint and authorized user are separate facts. Diagnose the missing stage rather than granting every permission.

Use [configuration](configuration.md) for environment variables, [troubleshooting](troubleshooting.md) for failures, and [delivery](delivery.md) when an agent is missing or cannot run. Existing Chinese [SDK](../../开发者指南/三语言SDK业务Agent开发指南.md) and [mounting](../../开发者指南/业务Agent挂载与已有用户授权指南.md) guides remain detailed references for advanced scenarios.
