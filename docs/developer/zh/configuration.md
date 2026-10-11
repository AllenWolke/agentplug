# 配置分层与完整参数参考

[开发者路线](README.md) · [English](../en/configuration.md)

首次启动只需要生成凭据和确认端口。使用 `python scripts/prepare_local_development.py`，保留默认本地认证与事件设置；先不要填写模型、OIDC、MCP、Code Runtime 和历史兼容参数。

## 三种配置文件不能混用

| 场景 | 配置载体 | 示例映射 |
| --- | --- | --- |
| Compose | 根 `.env`，由 Compose 替换并映射变量 | `PLATFORM_DB_DSN` → 平台 `DB_DSN`；`PLATFORM_EVENT_BUS_MODE` → `EVENT_BUS_MODE` |
| 主机进程 | `deploy/local/` 四个 `.env.example` 的私有副本 | 平台直接读取 `DB_DSN`、`EVENT_BUS_MODE`；前端读取 `PLATFORM_GATEWAY_TOKEN` |
| K8s | ConfigMap、外部 Secret 与私有 Kustomize 覆盖层 | `secretKeyRef` / `envFrom`；不自动加载根 `.env` |

## 如何决定现在要填什么

首次启动区的凭据由脚本随机生成，端口和 local 模式保留默认。自建 Compose 的 DSN 覆盖值留空。接入真实 Agent 时，配置模型端点 / 密钥引用、批准版本、知识连接、安装与六类策略；这些对象主要通过平台管理接口维护，不应全部塞进 `.env`。生产另行配置 OIDC、TLS、遥测、独立迁移账号与外部 Secret。

空值的含义按下表区分：有的使用 Compose 默认，有的关闭可选功能，有的在启用对应功能时是缺失配置。空值不是统一的“自动配置”。表中的默认值来自公开模板，绝不来自本机私有 `.env`。

## 凭据与地址规则

平台私钥、数据库密码、浏览器令牌、Runner 令牌和供应商密钥有不同归属。Agent 只接收公钥和自己工作负载所需的配置。修改 `.env` 后已有容器不会自动更新；先校验配置，再按部署变更流程重建相关服务。不要把含密码的 `docker compose config` 输出贴到 Issue，统一入口已使用 `--quiet`。

## 首次启动：由准备命令生成或保留默认

| 参数 | 模板默认 / 空值 | 用途和填写时机 |
| --- | --- | --- |
| `APP_ENV` | `development` | 运行模式；本地 development，生产必须 production。 |
| `DB_DRIVER` | `pgx` | 数据库驱动；保持 pgx。 |
| `DB_PASSWORD` | 占位值，需生成 | Compose 自建 PostgreSQL 的初始化管理员密码；独立随机值。 |
| `PLATFORM_RUNTIME_DB_PASSWORD` | 占位值，需生成 | 平台 DML 账号密码；不同于迁移 / 数据库管理员。 |
| `INTERNAL_TOKEN` | 占位值，需生成 | 平台内部服务认证；不下发给业务 Agent。 |
| `BROWSER_GATEWAY_TOKEN` | 空 | 浏览器网关的独立认证密钥；不能与 INTERNAL_TOKEN 共用。 |
| `METRIC_RUNNER_TOKEN` | 占位值，需生成 | 平台与隔离评测 Runner 之间的独立认证密钥。 |
| `INTERNAL_SIGNING_SECRET` | 占位值，需生成 | 内部请求 HMAC 与评测证据签名；独立随机值。 |
| `PLATFORM_CONTEXT_PUBLIC_KEY` | 空 | 执行上下文 Ed25519 公钥；Agent 只持公钥。 |
| `PLATFORM_CONTEXT_PRIVATE_KEY` | 空 | 执行上下文 Ed25519 私钥；仅平台持有，必须与公钥匹配。 |
| `ACCESS_TOKEN_SIGNING_KEY` | 空 | 浏览器访问令牌的稳定签名密钥；随机生成，不是执行私钥。 |
| `FRONTEND_HOST_PORT` | `3000` | 控制台主机端口；默认 3000。 |
| `POSTGRES_HOST_PORT` | `5432` | 数据库主机端口；默认 5432。 |
| `PLATFORM_HOST_PORT` | `38082` | 平台业务 HTTP 主机端口；默认 38082。 |
| `PLATFORM_INTERNAL_HOST_PORT` | `38083` | 内部能力主机端口；默认 38083，始终回环绑定。 |
| `PLATFORM_HOST_BIND` | `127.0.0.1` | 平台公开端口绑定地址；本地保留 127.0.0.1。 |
| `FRONTEND_HOST_BIND` | `127.0.0.1` | 控制台绑定地址；本地保留 127.0.0.1。 |
| `FRONTEND_AUTH_MODE` | `local` | 身份方式；local 为本地密码，oidc 为可信身份代理。 |
| `COOKIE_SECURE` | `false` | 仅 HTTPS 发送 Cookie；本地 HTTP false，生产 HTTPS true。 |
| `PLATFORM_DEMO_IDENTITY_BOOTSTRAP` | `false` | 演示身份种子开关；自己的空库账号使用 false，生产禁止 true。 |

## 数据库部署与迁移：自建 Compose 通常留空

| 参数 | 模板默认 / 空值 | 用途和填写时机 |
| --- | --- | --- |
| `PLATFORM_DB_DSN` | 空 | 覆盖平台运行连接；空值使用 Compose platform_runtime 连接。 |
| `PLATFORM_MIGRATION_DB_DSN` | 空 | 覆盖迁移连接；空值使用 Compose owner，生产使用独立迁移账号。 |
| `KNOWLEDGE_DATABASE_DSN` | 空 | 平台知识投影 PostgreSQL 连接；知识接入 / 生产需配置，不给 Agent。 |

## Agent 和模型接入：完成基础启动后再配置

| 参数 | 模板默认 / 空值 | 用途和填写时机 |
| --- | --- | --- |
| `PLATFORM_CONTEXT_AUDIENCE` | `agent-runtime` | 执行签名 audience；与 Agent 校验配置一致。 |
| `PLATFORM_RUN_EXECUTOR` | `platform` | 实际执行器；默认 platform，disabled 仅用于明确的隔离场景。 |
| `PLATFORM_POLICY_RESOLVER` | `sql` | 当前发布策略来源；正常使用 sql。 |
| `PLATFORM_MODEL_ENDPOINTS_JSON` | 空 | service:// 引用到真实模型端点的运维白名单 JSON；不包含 API Key。 |
| `PLATFORM_MODEL_SECRET_DIR` | `./.local-secrets/model-providers` | 宿主机模型密钥目录；只读挂载到平台。 |
| `PLATFORM_MODEL_SECRET_ROOT` | `/run/secrets/model-providers` | 非 Compose 进程的模型密钥解析根目录；根 Compose 固定为 /run/secrets/model-providers。 |
| `PLATFORM_WORKLOAD_SECRET_DIR` | `./.local-secrets/agent-workloads` | 知识索引工作负载凭据的宿主目录；不是模型供应商目录。 |
| `PLATFORM_POLICY_BOOTSTRAP_JSON` | 空 | 隔离开发的直接策略注入；通常空，生产禁止。 |
| `PLATFORM_PROMPT_TEMPLATES_JSON` | 空 | 隔离开发的 Prompt 正文映射；生产使用发布资产，禁止直接注入。 |
| `PLATFORM_RUN_TREE_BUDGET_ENABLED` | `true` | 父子 Agent 预算控制；保持 true，须有对应策略预算。 |
| `PLATFORM_RUN_WORKERS` | `4` | 根运行工作线程数；影响运行容量。 |
| `PLATFORM_CHILD_RUN_WORKERS` | `4` | 每个委派深度的保留线程数；范围 1..32，受总容量约束。 |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | 空 | 遥测收集端点；本地可空，生产启动要求配置。 |

## 事件与通知：本地保留默认

| 参数 | 模板默认 / 空值 | 用途和填写时机 |
| --- | --- | --- |
| `PLATFORM_EVENT_BUS_MODE` | `kafka` | Compose 事件总线选择；kafka 映射到进程 EVENT_BUS_MODE。 |
| `PLATFORM_KAFKA_BROKERS` | `kafka:9092` | Kafka broker 列表；本地 kafka:9092。 |
| `PLATFORM_KAFKA_CLIENT_ID` | `lexagent-platform` | Kafka 客户端标识；不是账号。 |
| `PLATFORM_KAFKA_NOTIFICATION_TOPIC` | `platform.audit` | 通知消费主题。 |
| `PLATFORM_KAFKA_NOTIFICATION_GROUP` | `lexagent-platform-notification-v1` | 通知消费组；改变会影响消费位置。 |
| `PLATFORM_KAFKA_NOTIFICATION_DLQ` | `platform.notification-dlq.v1` | 失败消息的死信主题。 |
| `PLATFORM_KAFKA_MAX_ATTEMPTS` | `5` | 通知投递最大尝试次数。 |
| `PLATFORM_KAFKA_RETRY_BACKOFF` | `1s` | 通知重试间隔，Go duration 格式，例如 1s。 |
| `PLATFORM_NOTIFICATION_ADAPTER` | `audit` | 通知出口；audit 写平台审计，其他选项以进程校验为准。 |
| `PLATFORM_NOTIFICATION_WEBHOOK_URL` | 空 | 使用 webhook 通知时的批准端点；默认不调用外部系统。 |

## 生产 OIDC：本地密码登录无需填写

| 参数 | 模板默认 / 空值 | 用途和填写时机 |
| --- | --- | --- |
| `OIDC_PROXY_TRUSTED` | `false` | 是否信任经过部署验证的内部 OIDC 代理；不可无条件启用。 |
| `OIDC_PROXY_AUTH_URL` | 空 | 内部代理认证检查地址。 |
| `OIDC_ISSUER_URL` | 空 | 真实 IdP issuer，须匹配平台身份绑定。 |
| `OIDC_AUTH_URL` | 空 | 浏览器登录跳转入口。 |
| `OIDC_STEP_UP_CLIENT_ID` | 空 | 再次认证 OIDC 客户端 ID；与后两项一起配置。 |
| `OIDC_STEP_UP_CLIENT_SECRET` | 空 | 再次认证客户端密钥；仅网关持有。 |
| `OIDC_STEP_UP_REDIRECT_URL` | 空 | IdP 登记的 HTTPS 再认证回调 /auth/step-up/oidc/callback。 |

## 可选扩展与运维：按需启用

| 参数 | 模板默认 / 空值 | 用途和填写时机 |
| --- | --- | --- |
| `PLATFORM_CONVERSATION_ERASURE_ENABLED` | `true` | 会话擦除工作器开关；受控恢复期间暂停并核对队列。 |
| `PLATFORM_CANCELLATION_COMPENSATION_ENABLED` | `false` | 取消补偿扩展的显式启用开关；基础栈不自动加入补偿服务。 |
| `PLATFORM_REVERSIBLE_API_BINDINGS_FILE` | 空 | 可逆 API 绑定文件的容器路径；仅相应扩展使用。 |
| `PLATFORM_REVERSIBLE_API_CA_FILE` | 空 | 可逆 API TLS CA 文件；需配套私有挂载。 |
| `PLATFORM_LEGACY_MODEL_ACCOUNTING_RESERVATIONS` | 空 | 指定历史预留进行对账；需要原供应商证据，不允许重发。 |
| `PLATFORM_MCP_BINDINGS_DIR` | `./deploy/mcp` | 宿主 MCP 适配配置目录；默认模板目录。 |
| `PLATFORM_MCP_BINDINGS_FILE` | 空 | 启用 MCP 的容器配置路径；空值关闭。 |
| `CODE_RUNTIME_PRIVATE_IP` | 空 | Code Runtime 控制器固定私网 IP；基础启动不需要。 |
| `CODE_RUNTIME_SUBNET` | 空 | Code Runtime 专用网段；不得与已有网络重叠。 |
| `CODE_RUNTIME_DOCKER_SOCKET_GID` | 空 | 实际 Docker socket 的组 ID；不能按操作系统猜测。 |
| `CODE_RUNTIME_DOCKER_CLI_IMAGE` | 空 | 经审查的 Docker CLI 镜像引用 / 摘要。 |
| `EVALUATION_ARTIFACT_S3_SECRET_KEY` | 空 | full 栈 MinIO 的独立密钥；默认 modular 不启用 MinIO。 |
| `DEMO_PASSWORD_SYSTEM_ADMIN` | 空 | 旧演示登录密码；local 模式与首位管理员流程不使用。 |

## 历史兼容参数：当前基础栈不读取，首次部署无需填写

| 参数 | 模板默认 / 空值 | 用途和填写时机 |
| --- | --- | --- |
| `API_KEY` | 占位值，需生成 | 历史 API Key 参数；不能开启当前浏览器或 Agent 认证。 |
| `OAUTH_ACCESS_PRIVATE_KEY` | 空 | 历史 OAuth 名称；不是当前执行签名配置。 |
| `OAUTH_ACCESS_PRIVATE_KEY_FILE` | 空 | 历史 OAuth 文件名称；当前模块化平台不读取。 |
| `CREDIT_SYSTEM_CLIENT_ID` | `credit-system` | 历史 credit 客户端标识；当前基础栈不读取。 |
| `CREDIT_SYSTEM_CLIENT_SECRET` | 占位值，需生成 | 历史 credit 客户端密钥；当前基础栈不读取。 |
| `MEMORY_ENCRYPTION_KEY` | 占位值，需生成 | 历史参数；设置它不表示当前记忆数据已经加密。 |
| `MODEL_PROVIDER` | `mock` | 历史 mock / provider 参数；不创建当前治理模型或策略。 |
| `MODEL_BASE_URL` | 空 | 历史端点参数；当前端点使用 PLATFORM_MODEL_ENDPOINTS_JSON。 |
| `MODEL_API_KEY` | 空 | 历史内联密钥参数；当前模型使用平台挂载密钥引用。 |
| `MODEL_CHAT_MODEL` | `mock-model` | 历史默认模型名；不替代 ModelVersion。 |
| `MODEL_EMBEDDING_MODEL` | `mock-embedding` | 历史默认 Embedding 名；不替代批准版本。 |
| `MODEL_CHAT_MODELS` | `mock-model` | 历史候选列表；当前模型目录由治理模块管理。 |
| `MODEL_EMBEDDING_MODELS` | `mock-embedding` | 历史候选列表；不创建 Embedding 配置。 |
| `MODEL_CATALOG_JSON` | 空 | 历史 JSON 目录；不替代模型治理 API。 |
| `MODEL_TIMEOUT_SECONDS` | `30` | 历史超时参数；当前基础 Compose 不传入平台。 |
| `CHECKPOINT_DSN` | 空 | 独立 Python workflow 初始化可用；基础 Compose 不下发给业务 Agent。 |
| `AGENT_WORKER_CONCURRENCY` | `4` | 历史 Agent worker 参数；不控制当前平台根 / 子运行线程。 |

## 生产与特殊参数

`PLATFORM_DEV_RUNTIME_PASSWORD` 是初始化任务参数：本地未定义时使用运行密码预置开发角色；生产必须由 DBA 预置角色并显式留空。它不是长期平台进程参数。`AUTO_MIGRATE=false` 是生产进程约束；迁移通过专门 Job / 命令执行。其他扩展参数以对应部署模板与启动代码为准，这份表覆盖根 `.env.example`，不是所有模块环境变量的无限清单。

权威来源：[Compose](../../../compose.yaml)、[初始化扩展](../../../deploy/compose/compose.init.yaml)、[平台启动校验](../../../platform/internal/bootstrap/config.go)、[本地进程入口](../../../scripts/local.py)。生产按[部署步骤](deployment.md)配置，历史 `MODEL_PROVIDER=mock` 不会自动创建可用模型，也不会开启当前模型治理。
