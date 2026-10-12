# Local, Docker and Kubernetes deployment

[Developer path](README.md) · [简体中文](../zh/deployment.md)

Deployment changes process locations, not authorization or publication requirements. Use [Compose quick start](quickstart.md) first. Host processes suit platform development; Kubernetes suits teams with cluster operations experience.

## Local source and host processes

Install Go 1.26.9+, Node.js 20+, Python 3.12+ and PostgreSQL 16 + pgvector. Provision the database, migration/schema-owner account and independent `platform_runtime` DML role. Local migration can provision the development runtime role with an explicit `PLATFORM_DEV_RUNTIME_PASSWORD`; production uses DBA-managed roles.

Copy the public templates into private configuration without overwriting existing files:

```text
python -c "from pathlib import Path; import shutil; d=Path('.local-secrets/local'); d.mkdir(parents=True,exist_ok=True); [shutil.copyfile('deploy/local/'+n+'.env.example',d/(n+'.env')) for n in ('migration','platform','frontend','runner') if not (d/(n+'.env')).exists()]"
```

| File | Configure |
| --- | --- |
| `migration.env` | Migration `DB_DSN`; development-role password, explicitly empty in production |
| `platform.env` | DML `DB_DSN`; independent internal, gateway, HMAC and Runner credentials; matching Ed25519 keys; demo seed disabled |
| `frontend.env` | `PLATFORM_URL` on port 8080; `PLATFORM_GATEWAY_TOKEN` matching its dedicated platform credential; local authentication |
| `runner.env` | `LEXAGENT_METRIC_SERVICE_TOKEN` matching platform `PLATFORM_METRIC_RUNNER_TOKEN`; no unrelated secrets |

Replace every placeholder. Host values are literal, not shell expressions. Do not give every process the root Compose `.env`. Use POSIX mode 0600 or private Windows ACLs. Host development can start with `EVENT_BUS_MODE=disabled` and notifications `none`; that does not validate Kafka. Supply Kafka/topics when needed. Knowledge needs its DSN/index configuration; production also requires knowledge connection and telemetry.

```text
python scripts/local.py build
python scripts/local.py run migrate --env-file .local-secrets/local/migration.env
```

Expected build result: `NATIVE BUILD PASS`, with `.local-build/bin/` and `frontend/dist/` artifacts. Startup does not run migrations.

Create private `.local-secrets/local/first-admin.json` with a real **DML DSN**, private password of 10..128 bytes and operator identifiers. This is a shape, not executable credential material:

```json
{
  "version": 1,
  "db_dsn": "postgresql://platform_runtime:REPLACE_WITH_RUNTIME_PASSWORD@127.0.0.1:5432/agentplug?sslmode=disable",
  "tenant_id": "tenant-demo",
  "tenant_name": "Development Company",
  "department_id": "dept-platform",
  "department_name": "Platform Administration",
  "application_id": "app-platform-admin",
  "application_name": "Platform Administration",
  "principal_id": "platform.admin",
  "operator_id": "deployment.operator",
  "local_password": "REPLACE_WITH_YOUR_PRIVATE_PASSWORD",
  "approval_reference": "local-development-initialization"
}
```

```text
python scripts/local.py bootstrap-admin --config .local-secrets/local/first-admin.json
```

Only an empty identity store can be initialized. Production replaces the password with real OIDC issuer/subject according to the [administrator reference, Chinese](../../../deploy/README-first-administrator.md).

Start these in separate terminals:

```text
python scripts/local.py run runner --env-file .local-secrets/local/runner.env
python scripts/local.py run platform --env-file .local-secrets/local/platform.env
python scripts/local.py run frontend --env-file .local-secrets/local/frontend.env
```

Template ports: platform 8080, capabilities 8081, Runner 8085, console 33000. Check platform `/health/ready`, frontend `/healthz` and login. Use Ctrl+C for development, a service manager for production. See [Linux systemd reference, Chinese](../../../deploy/local/README-linux-production.md).

## Docker Compose

[Quick start](quickstart.md) covers preparation, init, administrator bootstrap, startup and health. The modular base has five services; business agents are optional.

| Operation | Command |
| --- | --- |
| Validate without secrets | `python scripts/compose.py config --env-file .env` |
| Start | `python scripts/compose.py up --env-file .env` |
| Inspect | `python scripts/compose.py status --env-file .env` |
| Base health | `python scripts/compose.py smoke --env-file .env` |
| Stop, retain volumes | `python scripts/compose.py down --env-file .env` |
| Upgrade after backup / stop writes | `python scripts/init_platform.py upgrade --env-file .env` |

For the three fixed examples, prepare independent machine credentials and validate the overlay:

```text
python scripts/bootstrap_public_examples.py --prepare-machine-env
python scripts/compose.py config --env-file .env --env-file .local-secrets/public-examples/machines.env --examples
```

Offline preparation creates no platform identities or grants. Before startup, complete [installation/policy/binding requirements](delivery.md). Custom agents use their own IDs and services. Production additionally needs TLS/OIDC, separate database roles, Secrets, backup and recovery; see [Compose production reference, Chinese](../../../deploy/compose/README-production.md).

## Kubernetes cluster deployment

### Existing foundation

[Base kustomization](../../../deploy/k8s/production/kustomization.yaml) selects Namespace, ConfigMap, four Deployments, migration Job, ServiceAccount, Services, NetworkPolicy and Ingress. Other YAMLs are not automatically selected.

PostgreSQL + pgvector and model services are external. Base configuration disables events/notifications and provides no Kafka cluster. Add business-agent Deployment/Service in your overlay. The platform uses one replica and `Recreate`; this is not accepted multi-instance HA.

Provide a cluster, NetworkPolicy-capable CNI, Ingress/TLS, real IdP, databases, image registry/signing and telemetry. Tooling requires kubectl, PowerShell, cosign and Python with PyYAML. See [official Kustomize documentation](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/).

### 1. Prepare an operator overlay

Replace all container images with real immutable digests; migration matches the platform image. Configure actual TLS/OIDC/step-up/telemetry/model endpoints. Provision external Secrets matching the [platform](../../../deploy/k8s/production/secret.example.yaml) and [OIDC](../../../deploy/k8s/production/oidc-secret.example.yaml) shapes; do not apply placeholder Secret files.

Separate migration/runtime accounts, configure the knowledge DSN and approved egress CIDRs/gateways. Agents access capabilities and approved business resources, not platform databases or vendors directly. Supply their image, Service, public key, workload Secret, limits, probes and network policies. The [PostgreSQL](../../../deploy/k8s/overlays/external-postgres-example/README.md) and [egress](../../../deploy/k8s/overlays/external-egress-example/README.md) examples also contain placeholders.

### 2. Render and inspect

Confirm kubeconfig context. The first command renders without mutation; the second checks your completed private overlay:

```text
kubectl kustomize deploy/k8s/production
```

```powershell
kubectl kustomize .local-secrets/k8s-overlay | python scripts/validate_production_release.py --namespace lexagent
```

The original base is expected to fail preflight because of placeholders. Do not remove validation or apply every directory YAML directly.

### 3. Approved release

Use a clean, committed source checkout. Render the completed overlay and use `--draft-manifest --commit <full SHA>` to generate a draft outside source. Review the canonical configuration hash and all images. Cosign checks signatures, `source_commit` and signed SPDX SBOMs.

After backup, stop-write preparation and release authorization, use actual values:

```powershell
./deploy/k8s/production/apply.ps1 -Namespace lexagent -KustomizePath <approved-overlay> -ReleaseManifestPath <approved-manifest> -SignatureIdentity <identity> -SignatureIssuer <issuer>
```

The script verifies dependencies, locks the release, completes migration before workload updates and waits for rollouts. It does not provision external infrastructure or business access. Read current [schema source](../../../platform/internal/schemaversion/schema.go), not historic prose versions.

### 4. Accept the target deployment

Verify probes, actual deployment observation, OIDC login, allowed/denied networking, telemetry and backup recovery. Bootstrap a real IdP administrator before exposing a new identity store. Follow [delivery](delivery.md) for company/department/user binding, ordinary-user runs, denial and recovery.

The templates are a service-oriented deployment foundation, not proof of full microservice extraction, real production-cluster acceptance or HA.
