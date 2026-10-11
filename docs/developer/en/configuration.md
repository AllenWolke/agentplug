# Configuration stages and full reference

[Developer path](README.md) · [简体中文](../zh/configuration.md)

For first startup, generate credentials and confirm ports with `python scripts/prepare_local_development.py`. Keep local authentication and event defaults. Leave models, OIDC, MCP, Code Runtime and compatibility variables alone until needed.

## Configuration formats are not interchangeable

| Deployment | Configuration | Mapping example |
| --- | --- | --- |
| Compose | Root `.env`, interpolated and mapped by Compose | `PLATFORM_DB_DSN` → process `DB_DSN`; `PLATFORM_EVENT_BUS_MODE` → `EVENT_BUS_MODE` |
| Host processes | Private copies of four `deploy/local/*.env.example` files | Platform reads `DB_DSN`, `EVENT_BUS_MODE`; frontend reads `PLATFORM_GATEWAY_TOKEN` |
| Kubernetes | ConfigMap, external Secrets and operator overlays | `secretKeyRef` / `envFrom`; root `.env` is not loaded automatically |

## Decide what to configure now

The preparation script generates initial credentials. Keep default ports and local mode unless ports conflict. Leave Compose DSN overrides empty for its managed local database. Before a real agent runs, configure model endpoint/secret references, approved versions, knowledge connections, installation and six policies. Most of these are platform objects managed through APIs, not environment variables. Production additionally requires OIDC, TLS, telemetry, separate migration credentials and external Secrets.

An empty value can select a Compose default, disable an optional feature, or mean missing configuration for an enabled feature. It does not always mean automatic setup. Table defaults come only from the public template, never from private local configuration.

## Credentials and addresses

Execution private keys, database passwords, gateway tokens, Runner tokens and provider keys have different owners. Agents receive public verification material and their own workload configuration. Editing `.env` does not update running containers: validate and recreate affected services through the deployment workflow. The launcher uses `config --quiet` so interpolated credentials are not printed.

## First startup: generated credentials and safe defaults

| Variable | Template default / empty | Purpose and timing |
| --- | --- | --- |
| `APP_ENV` | `development` | Runtime mode; development locally, production in production. |
| `DB_DRIVER` | `pgx` | Database driver; keep pgx. |
| `DB_PASSWORD` | placeholder; generate when needed | Initial owner password for Compose PostgreSQL; independent random value. |
| `PLATFORM_RUNTIME_DB_PASSWORD` | placeholder; generate when needed | Platform DML-role password; distinct from the owner / migration account. |
| `INTERNAL_TOKEN` | placeholder; generate when needed | Platform internal service authentication; do not distribute to agents. |
| `BROWSER_GATEWAY_TOKEN` | empty | Independent browser gateway secret; must differ from INTERNAL_TOKEN. |
| `METRIC_RUNNER_TOKEN` | placeholder; generate when needed | Independent platform-to-isolated-runner credential. |
| `INTERNAL_SIGNING_SECRET` | placeholder; generate when needed | Internal request HMAC and evaluation evidence signing; independent random value. |
| `PLATFORM_CONTEXT_PUBLIC_KEY` | empty | Execution-context Ed25519 public key; agents receive only the public half. |
| `PLATFORM_CONTEXT_PRIVATE_KEY` | empty | Execution-context Ed25519 private key; platform only, matching the public key. |
| `ACCESS_TOKEN_SIGNING_KEY` | empty | Stable browser access-token signing secret; separate from execution keys. |
| `FRONTEND_HOST_PORT` | `3000` | Console host port; default 3000. |
| `POSTGRES_HOST_PORT` | `5432` | Database host port; default 5432. |
| `PLATFORM_HOST_PORT` | `38082` | Platform HTTP host port; default 38082. |
| `PLATFORM_INTERNAL_HOST_PORT` | `38083` | Internal capability host port; default 38083, loopback-bound. |
| `PLATFORM_HOST_BIND` | `127.0.0.1` | Platform host bind; keep 127.0.0.1 locally. |
| `FRONTEND_HOST_BIND` | `127.0.0.1` | Console bind; keep 127.0.0.1 locally. |
| `FRONTEND_AUTH_MODE` | `local` | Authentication mode; local passwords or trusted oidc proxy. |
| `COOKIE_SECURE` | `false` | Send cookies over HTTPS only; false for local HTTP, true for production HTTPS. |
| `PLATFORM_DEMO_IDENTITY_BOOTSTRAP` | `false` | Demo identity seeding; false for your own accounts, true forbidden in production. |

## Database and migration: usually empty for local Compose

| Variable | Template default / empty | Purpose and timing |
| --- | --- | --- |
| `PLATFORM_DB_DSN` | empty | Override platform runtime DSN; empty selects the Compose platform_runtime connection. |
| `PLATFORM_MIGRATION_DB_DSN` | empty | Override migration DSN; empty selects the Compose owner; use a separate migration role in production. |
| `KNOWLEDGE_DATABASE_DSN` | empty | Platform knowledge projection PostgreSQL connection; required for knowledge / production, never for agents. |

## Agents and models: configure after base startup

| Variable | Template default / empty | Purpose and timing |
| --- | --- | --- |
| `PLATFORM_CONTEXT_AUDIENCE` | `agent-runtime` | Execution signature audience; must match agent verification settings. |
| `PLATFORM_RUN_EXECUTOR` | `platform` | Run executor; platform by default, disabled only for explicit isolation. |
| `PLATFORM_POLICY_RESOLVER` | `sql` | Published policy resolver; use sql for normal operation. |
| `PLATFORM_MODEL_ENDPOINTS_JSON` | empty | Operator JSON allowlist mapping service:// references to model endpoints; no API keys. |
| `PLATFORM_MODEL_SECRET_DIR` | `./.local-secrets/model-providers` | Host model-secret directory mounted read-only into the platform. |
| `PLATFORM_MODEL_SECRET_ROOT` | `/run/secrets/model-providers` | Model-secret root for non-Compose processes; root Compose fixes /run/secrets/model-providers. |
| `PLATFORM_WORKLOAD_SECRET_DIR` | `./.local-secrets/agent-workloads` | Host credential directory for indexing workloads; distinct from provider secrets. |
| `PLATFORM_POLICY_BOOTSTRAP_JSON` | empty | Direct policy injection for isolated development; normally empty, forbidden in production. |
| `PLATFORM_PROMPT_TEMPLATES_JSON` | empty | Prompt-body map for isolated development; production uses published assets and forbids injection. |
| `PLATFORM_RUN_TREE_BUDGET_ENABLED` | `true` | Parent/child agent budget control; keep true and configure approved budgets. |
| `PLATFORM_RUN_WORKERS` | `4` | Root-run worker count; affects execution capacity. |
| `PLATFORM_CHILD_RUN_WORKERS` | `4` | Reserved workers per delegation depth; 1..32, subject to overall limits. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | empty | Telemetry collector endpoint; optional locally, required for production startup. |

## Events and notifications: keep local defaults

| Variable | Template default / empty | Purpose and timing |
| --- | --- | --- |
| `PLATFORM_EVENT_BUS_MODE` | `kafka` | Compose event-bus choice; kafka maps to process EVENT_BUS_MODE. |
| `PLATFORM_KAFKA_BROKERS` | `kafka:9092` | Kafka brokers; kafka:9092 in Compose. |
| `PLATFORM_KAFKA_CLIENT_ID` | `lexagent-platform` | Kafka client identifier; not a user account. |
| `PLATFORM_KAFKA_NOTIFICATION_TOPIC` | `platform.audit` | Notification consumer topic. |
| `PLATFORM_KAFKA_NOTIFICATION_GROUP` | `lexagent-platform-notification-v1` | Notification consumer group; changes affect offsets. |
| `PLATFORM_KAFKA_NOTIFICATION_DLQ` | `platform.notification-dlq.v1` | Dead-letter topic for failed deliveries. |
| `PLATFORM_KAFKA_MAX_ATTEMPTS` | `5` | Maximum notification delivery attempts. |
| `PLATFORM_KAFKA_RETRY_BACKOFF` | `1s` | Notification retry delay in Go duration syntax, for example 1s. |
| `PLATFORM_NOTIFICATION_ADAPTER` | `audit` | Notification adapter; audit writes platform audit, other values require runtime validation. |
| `PLATFORM_NOTIFICATION_WEBHOOK_URL` | empty | Approved endpoint for webhook notifications; no external call by default. |

## Production OIDC: unnecessary for local password login

| Variable | Template default / empty | Purpose and timing |
| --- | --- | --- |
| `OIDC_PROXY_TRUSTED` | `false` | Trust a deployment-verified internal OIDC proxy; do not enable blindly. |
| `OIDC_PROXY_AUTH_URL` | empty | Internal proxy authentication-check URL. |
| `OIDC_ISSUER_URL` | empty | Real IdP issuer matching platform identity bindings. |
| `OIDC_AUTH_URL` | empty | Browser login redirect entry point. |
| `OIDC_STEP_UP_CLIENT_ID` | empty | Fresh-authentication OIDC client ID; configure together with the following two fields. |
| `OIDC_STEP_UP_CLIENT_SECRET` | empty | Fresh-authentication client secret; gateway only. |
| `OIDC_STEP_UP_REDIRECT_URL` | empty | Registered HTTPS callback ending /auth/step-up/oidc/callback. |

## Optional extensions and operations: opt in when needed

| Variable | Template default / empty | Purpose and timing |
| --- | --- | --- |
| `PLATFORM_CONVERSATION_ERASURE_ENABLED` | `true` | Conversation erasure worker; pause and reconcile during controlled restoration. |
| `PLATFORM_CANCELLATION_COMPENSATION_ENABLED` | `false` | Explicit cancellation-compensation rollout; base stack does not add compensation services. |
| `PLATFORM_REVERSIBLE_API_BINDINGS_FILE` | empty | Container path to reversible API bindings; consumed by the relevant extension. |
| `PLATFORM_REVERSIBLE_API_CA_FILE` | empty | Reversible API TLS CA file; requires private mounts. |
| `PLATFORM_LEGACY_MODEL_ACCOUNTING_RESERVATIONS` | empty | Selected historical reservations for accounting; original evidence required, no resend. |
| `PLATFORM_MCP_BINDINGS_DIR` | `./deploy/mcp` | Host MCP binding directory; defaults to the template directory. |
| `PLATFORM_MCP_BINDINGS_FILE` | empty | Container MCP configuration path; empty disables MCP. |
| `CODE_RUNTIME_PRIVATE_IP` | empty | Fixed private Code Runtime controller IP; not needed for base startup. |
| `CODE_RUNTIME_SUBNET` | empty | Dedicated Code Runtime subnet; must not overlap existing networks. |
| `CODE_RUNTIME_DOCKER_SOCKET_GID` | empty | Actual Docker socket group ID; do not guess from the OS. |
| `CODE_RUNTIME_DOCKER_CLI_IMAGE` | empty | Reviewed Docker CLI image reference / digest. |
| `EVALUATION_ARTIFACT_S3_SECRET_KEY` | empty | Independent MinIO credential for full stack; modular does not enable MinIO. |
| `DEMO_PASSWORD_SYSTEM_ADMIN` | empty | Legacy demo-login password; unused by local first-administrator initialization. |

## Legacy compatibility: not read by the current base stack

| Variable | Template default / empty | Purpose and timing |
| --- | --- | --- |
| `API_KEY` | placeholder; generate when needed | Historical API-key variable; does not enable current browser or agent authentication. |
| `OAUTH_ACCESS_PRIVATE_KEY` | empty | Historical OAuth name; not the active execution signing configuration. |
| `OAUTH_ACCESS_PRIVATE_KEY_FILE` | empty | Historical OAuth file variable; not read by the modular platform. |
| `CREDIT_SYSTEM_CLIENT_ID` | `credit-system` | Historical credit client ID; not read by the base stack. |
| `CREDIT_SYSTEM_CLIENT_SECRET` | placeholder; generate when needed | Historical credit client secret; not read by the base stack. |
| `MEMORY_ENCRYPTION_KEY` | placeholder; generate when needed | Historical variable; setting it does not prove current memory encryption. |
| `MODEL_PROVIDER` | `mock` | Historical mock/provider variable; does not create governed models or policies. |
| `MODEL_BASE_URL` | empty | Historical endpoint; active endpoints use PLATFORM_MODEL_ENDPOINTS_JSON. |
| `MODEL_API_KEY` | empty | Historical inline secret; current models use mounted platform secret references. |
| `MODEL_CHAT_MODEL` | `mock-model` | Historical default chat model; not a ModelVersion. |
| `MODEL_EMBEDDING_MODEL` | `mock-embedding` | Historical embedding model; not an approved version. |
| `MODEL_CHAT_MODELS` | `mock-model` | Historical chat list; current model catalog is governed by the platform. |
| `MODEL_EMBEDDING_MODELS` | `mock-embedding` | Historical embedding list; does not create active embedding configuration. |
| `MODEL_CATALOG_JSON` | empty | Historical JSON catalog; not a replacement for governance APIs. |
| `MODEL_TIMEOUT_SECONDS` | `30` | Historical timeout; not passed to the platform by base Compose. |
| `CHECKPOINT_DSN` | empty | Used by separate Python workflow initialization; base Compose does not distribute it to agents. |
| `AGENT_WORKER_CONCURRENCY` | `4` | Historical agent worker variable; does not control current root/child platform workers. |

## Production and special variables

`PLATFORM_DEV_RUNTIME_PASSWORD` belongs to initialization: if undefined locally, init uses the runtime password to provision the development role. In production, a DBA provisions the role and this variable is explicitly empty. `AUTO_MIGRATE=false` is a production process constraint; migrations run as separate jobs/commands. This table covers the root `.env.example`, not every possible module variable.

Sources: [Compose](../../../compose.yaml), [init extension](../../../deploy/compose/compose.init.yaml), [platform startup validation](../../../platform/internal/bootstrap/config.go), [host launcher](../../../scripts/local.py). Follow [deployment](deployment.md) for production. Legacy `MODEL_PROVIDER=mock` does not create an active governed model.
