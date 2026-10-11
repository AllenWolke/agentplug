# Business-agent development and delivery skill

[Developer path](README.md) · [简体中文](../zh/skill.md)

[`agentplug-business-agent`](../../../skills/agentplug-business-agent/SKILL.md) is reusable coding-assistant guidance for development, reuse review, testing and end-to-end delivery using current SDKs, launchers and governance APIs. Loading it grants no production authority and creates no bypass service.

## Install or read directly

From the repository root, copy it to your Codex skills directory. This command works in PowerShell and typical shells and refuses an existing destination:

```text
python -c "import os,shutil; from pathlib import Path; root=Path(os.environ.get('CODEX_HOME',str(Path.home()/'.codex'))); shutil.copytree('skills/agentplug-business-agent',root/'skills/agentplug-business-agent')"
```

Reload skills in your client and invoke `$agentplug-business-agent`. Other assistants supporting `SKILL.md` can read the repository file directly. The skill locates the actual platform and agent project rather than treating its installation directory as source.

## Example requests

Development/review only:

```text
Use $agentplug-business-agent to build a ticket assistant in the project directory I provide.
Reuse AgentPlug model, knowledge and tool capabilities, check completeness,
run local business/protocol tests, and prepare a delivery plan. Do not deploy in this phase.
```

End-to-end delivery:

```text
Use $agentplug-business-agent to review shared-capability reuse in my existing business agent.
Use my actual platform, company, department, agent project and intended-user information.
Prepare reviewable artifact/version/policy/deployment/binding changes with their effects,
then deploy and batch-authorize users within my authorization.
Verify a real run as the assigned ordinary user and denial for unassigned/cross-company users.
Deliver a password-free login checklist and actual evidence; unmet prerequisites are not passed tests.
```

Provide platform origin/method, project path, agent identity/version, company/department, users, operations and expiry. Supply credentials through private configuration/authentication tools, not chat messages containing `.env`, cookies or provider keys.

## Outputs and limits

Expect capability mapping, omissions, test outcomes, concrete delivery/access plan and run/receipt/batch evidence. Unneeded capabilities are not failures. Fixed-example helpers are not arbitrary-agent deployment tools.

Independent publication, workload authentication, department ceilings, current use packages and fresh authentication still apply. Unknown responses require original receipt lookup. Distinguish static validation, service readiness, active installation and a successful ordinary-user business run before reporting availability.
