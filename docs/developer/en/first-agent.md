# Build your first business agent

[Developer path](README.md) · [简体中文](../zh/first-agent.md)

Create a deterministic support assistant to verify project structure and SDK wiring before platform publication. No paid model or enterprise knowledge setup is required for this local business example. Install Go 1.26.10+, Python 3.12+ and Docker for image builds.

## 1. Generate

For setup through publication and user access in one route, start with the [complete walkthrough](walkthrough.md). This page expands its business-project steps.

From the repository root:

```text
cd cli/agentctl
go run ./cmd/agentctl create --template python-generic --language python --name support-assistant --output out/support-assistant
go run ./cmd/agentctl validate --path out/support-assistant
cd ../..
```

Output is relative to the CLI working directory; existing directories are not overwritten. The generated `cli/agentctl/out/support-assistant/` is ignored by Git. Move a formal project into its own repository while retaining template/SDK version facts.

`manifest.json` defines identity, protocol, capabilities and schema references. `platform_entry/` is template-managed SDK wiring. Put business behavior in `domain/`, optional graphs/prompts/evaluations in their respective directories. `template.lock` records ownership; do not edit hashes to bypass upgrades.

## 2. Add business hooks

From the repository root:

```text
python -c "import shutil; p='cli/agentctl/out/support-assistant/'; files={'business.py':'domain/business.py','server.py':'domain/server.py','test_business.py':'eval/test_business.py','input.schema.json':'eval/input.schema.json','output.schema.json':'eval/output.schema.json','requirements-dev.txt':'requirements-dev.txt','Dockerfile.business':'Dockerfile.business','dockerignore.business':'.dockerignore'}; [shutil.copyfile('docs/developer/snippets/'+s,p+d) for s,d in files.items()]"
cd cli/agentctl/out/support-assistant
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -c "from domain.business import recommend; print(recommend({'question':'How do I investigate a timeout?'}))"
```

Expected: an object with `question`, `answer` and `source`. Business-owned `invoke(trusted)` and `run(trusted, events, cancelled)` hooks use the SDK factory. The asynchronous hook reports progress and observes cancellation; it does not replace the SDK state machine.

Use the business-owned `domain/server.py` and `Dockerfile.business`. The original template Dockerfile still starts its echo behavior.

The entry also registers a pure `validate_input(trusted)` callback: no network, storage or model calls. The SDK verifies the signature before validation and returns a terminal `INVALID_REQUEST` for `ValueError` before business execution. Unknown failures during execution retain conservative effect-confirmation handling.

## 3. Test

In the generated project, PowerShell:

```powershell
$env:PYTHONPATH = 'platform_entry'
python -m pytest platform_entry eval -q
```

Linux/macOS:

```bash
PYTHONPATH=platform_entry python -m pytest platform_entry eval -q
```

Tests cover SDK wiring, lifecycle, capability contracts, business answers, invalid input and cancellation. Projects generated inside the full platform repository find shared fixtures and SDK source in ancestors; these checks must run without skips. Outside the repository, missing shared fixtures cause skips that are not passes. Supplement with the original template suite from the repository root: in PowerShell set `$env:PYTHONPATH='templates/python-generic/platform_entry'`, then run `python -m pytest templates/python-generic/platform_entry -q`; on Linux/macOS run `PYTHONPATH=templates/python-generic/platform_entry python -m pytest templates/python-generic/platform_entry -q`. Afterwards return to the business project and restore `PYTHONPATH=platform_entry`.

Add business tests for valid/invalid input, meaningful results, dependency denial/failure, timeouts and cancellation effects. HTTP 200 alone is not business correctness.

The dev requirements include pytest, its async plugin and FastAPI for vendored SDK tests. They are not added to the business image's runtime requirements. The complete walkthrough installs them in its own virtual environment.

The template uses `MemoryRunStore`. Persistent recovery, long asynchronous work and multiple instances require a scoped durable Store and recovery tests; an image build does not prove those features.

## 4. Start the execution entry

Extract only the **public key** from your local development platform `.env` into the generated project:

```text
python -c "from pathlib import Path; lines=Path('../../../../.env').read_text(encoding='utf-8-sig').splitlines(); value=next(x.split('=',1)[1].strip() for x in lines if x.startswith('PLATFORM_CONTEXT_PUBLIC_KEY=')); Path('platform-public-key.txt').write_text(value,encoding='utf-8')"
```

PowerShell:

```powershell
$env:PYTHONPATH = 'platform_entry'
$env:AGENT_PLATFORM_PUBLIC_KEY_FILE = (Join-Path (Get-Location) 'platform-public-key.txt')
$env:AGENT_PLATFORM_AGENT_ID = 'support-assistant'
$env:AGENT_PLATFORM_ISSUER = 'platform'
$env:AGENT_PLATFORM_AUDIENCE = 'agent-runtime'
$env:PORT = '18084'
python -m domain.server
```

Linux/macOS:

```bash
PYTHONPATH=platform_entry AGENT_PLATFORM_PUBLIC_KEY_FILE=platform-public-key.txt AGENT_PLATFORM_AGENT_ID=support-assistant AGENT_PLATFORM_ISSUER=platform AGENT_PLATFORM_AUDIENCE=agent-runtime PORT=18084 python -m domain.server
```

Check `http://127.0.0.1:18084/health/ready` in another terminal. Execution endpoints require signed v2 requests from the platform; raw business input is not an authenticated execution envelope. Keep verification enabled.

## 5. Build an image

From the generated project:

```text
docker build -f Dockerfile.business -t agentplug:support-assistant-dev .
cd ../../../..
```

Formal publication needs an actual artifact digest, manifest, business schemas, evaluation and deployment configuration. Template schema references do not create your input/output JSON schemas; author and register them in publication materials without falsifying ownership hashes.

The tutorial `.dockerignore` excludes development credentials and the public-key file. Mount the target platform public key and the agent's independent credentials through deployment configuration at runtime; do not bake private files into the image.

## 6. Deliver

Follow [publication, deployment and binding](delivery.md) or use the [delivery skill](skill.md). Add real model/knowledge behavior using [capabilities](capabilities.md) and the [document assistant](../../../examples/python-documents/README.md), keeping provider keys, SQL and approval infrastructure on the platform.
