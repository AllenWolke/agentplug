# 业务 Agent 挂载与已有用户授权指南

> 新读者先读[快速开始](../developer/zh/quickstart.md)和[业务 Agent 交付路线](../developer/zh/delivery.md)。这两页区分基础启动、实际部署、公司 / 部门上限及用户使用包；本页保留固定三语言示例和维护场景的详细步骤，不需要在首次体验前逐项配置。

挂载包含三个独立步骤：发布 Agent 版本、在应用内安装和部署实例、为已有用户配置身份与资源权限。超级管理员的管理身份不默认带有业务运行权。本文使用真实浏览器登录会话；不构造可信网关身份头、不直接修改权限数据库。

## 1. 明确应用与实例

本仓库三个演示业务用户使用 `tenant-demo / dept-demo / app-demo`。各自对应以下安装实例：

| 已有用户 | Agent | 机器主体 | 安装实例 ID |
|---|---|---|---|
| `demo.go.user` | `example-go-operations` | `example-go-machine` | `example-go-operations-installation` |
| `demo.python.user` | `example-python-documents` | `example-python-machine` | `example-python-documents-installation` |
| `demo.java.user` | `example-java-tickets` | `example-java-machine` | `example-java-tickets-installation` |

表格是示例配置的默认对应关系。完成平台初始化和Agent注册后，从平台读取实际资源、版本与状态，再办理已有用户授权；安装ID可以保持不变并升级到新的已发布版本。

三个机器主体由 Identity 的工作负载创建流程单独建立，不属于五个人类账号的演示初始化。新环境每个机器只创建一次；已存在时先检查主体、凭据和安装绑定，不能重复提交创建请求。机器主体不设人类登录密码或角色。

### 空库首次初始化

复制 `.env.example` 为私有 `.env`，为数据库所有者、平台运行数据库用户、内部认证、浏览器网关、HMAC、Metric Runner和Access Token签名分别配置独立随机凭据。设置 `DB_DRIVER=pgx`、`FRONTEND_AUTH_MODE=local`、`PLATFORM_DEMO_IDENTITY_BOOTSTRAP=false`、`PLATFORM_RUN_EXECUTOR=disabled`；生成Ed25519原始密钥对，以Base64配置 `PLATFORM_CONTEXT_PRIVATE_KEY` 和 `PLATFORM_CONTEXT_PUBLIC_KEY`。本机使用 `COOKIE_SECURE=false`；远程部署须配置HTTPS。数据库DSN留空时Compose按独立密码自动拼装，`PLATFORM_DEV_RUNTIME_PASSWORD` 保持未设置以启用开发环境DML角色引导。

先执行 `python scripts/compose.py config`，空库首次部署执行 `python scripts/init_platform.py`，然后执行 `python scripts/compose.py up`。日常启动只执行 `up`；版本升级在维护窗口执行 `python scripts/init_platform.py upgrade`。显式迁移任务使用数据库迁移身份，平台进程使用受限的 `platform_runtime`。空身份库尚无默认登录密码。

在 `.local-secrets/first-administrator.json` 准备以下配置。用真实随机值替换两个占位项，不要把配置提交Git；Linux文件权限设为600。`db_dsn` 使用刚刚建立的DML账户，不能使用postgres超级用户。

```json
{
  "version": 1,
  "db_dsn": "postgresql://platform_runtime:YOUR_RUNTIME_PASSWORD@postgres:5432/agentplug?sslmode=disable",
  "tenant_id": "tenant-demo",
  "tenant_name": "示例租户",
  "department_id": "dept-platform",
  "department_name": "平台管理",
  "application_id": "app-platform-admin",
  "application_name": "平台管理",
  "principal_id": "system.admin",
  "operator_id": "deployment.operator",
  "approval_reference": "initial-public-deployment",
  "local_password": "YOUR_RANDOM_ADMIN_PASSWORD"
}
```

执行 `python scripts/bootstrap_first_admin.py --config .local-secrets/first-administrator.json`，然后用system.admin真实密码登录管理端。该命令只允许空身份库，一旦初始化完成便拒绝再次覆盖。创建其他已有用户或新增用户仍走正常预览、提交、授权流程；五账号只是示例数据约定。

运行 `python scripts/compose.py e2e-modular` 可独立验证空库迁移、五账号创建登录和刷新/退出撤销。该命令自动生成随机测试凭据、独立端口与项目名，清理专属容器和数据库卷；它不读取开发库数据，也不代替三Agent及真实模型的业务验收。

干净开发环境把 `.env.example` 复制为私有 `.env` 时，保留 `PLATFORM_DEMO_IDENTITY_BOOTSTRAP=false`。若启用开发种子，它只放入无凭据主体和组织记录，与真实用户创建流程冲突。首管理员登录后，使用下列公开脚本补建业务部门、应用以及四个独立本地账户。每个密码都会分别提示输入和重复确认，不会写入脚本输出或仓库；`permission.admin` 此时也只是无角色账户，不能登录就等同获得权限。

```powershell
python scripts/bootstrap_public_examples.py --administrator system.admin --create-organization --create-accounts --grant-demo-workspaces
```

该命令逐项读取现有资源，组织资源只在缺失时创建；Identity 组织 API 没有 preview 端点，脚本显示准确 ID 并要求键入确认。账户和 `app-demo` 成员关系通过 Identity API 预览后提交，并要求键入精确 ID。四个账户最初仅加入 `app-platform-admin`；脚本仅给三位业务用户和 `system.admin` 增加 `app-demo` 成员关系，不授予 `operator` 角色、安装运行权或其他业务 Grant。成员关系只允许选择工作空间。每位用户首次登录后仍需由获授权管理员按后文流程显式授予目标安装和资源权限。`permission.admin` 的真实任命和委托应另由受权人员按平台管理员流程办理，不能由本脚本升权。

示例容器启动前先离线生成三台机器各自独立的随机凭据。此阶段不登录、不调用 Identity API，也不创建机器主体；生成的同一私有文件供 Compose 启动和稍后的主体创建复用，避免“容器启动需要凭据、注册又依赖容器就绪”的循环依赖。

```powershell
python scripts/bootstrap_public_examples.py --prepare-machine-env
python scripts/compose.py config --profile full --examples --env-file .env --env-file .local-secrets/public-examples/machines.env
python scripts/compose.py up --profile full --examples --env-file .env --env-file .local-secrets/public-examples/machines.env
```

此时 Compose 只启动示例进程，不会创建Catalog资源、安装、机器主体、绑定或权限。先完成Catalog Definition/Version发布、安装及真实部署，并等控制器观测为 `active`。机器身份创建和安装绑定是两个独立步骤：在活动安装就绪后可先创建无业务权限的机器主体；必须等每个目标 Version 的六类 PolicyAsset Snapshot 都发布并由 GET 核验后，才绑定到唯一对应安装。

```powershell
python scripts/bootstrap_public_examples.py --administrator system.admin --create-machine-principals `
  --agent-cidr example-go-machine=REPLACE_WITH_GO_SOURCE_CIDR `
  --agent-cidr example-python-machine=REPLACE_WITH_PYTHON_SOURCE_CIDR `
  --agent-cidr example-java-machine=REPLACE_WITH_JAVA_SOURCE_CIDR
```

替换三个 CIDR 为平台实际观测到的机器来源地址，通常应使用 `/32` 或 `/128`；不要提交整段共享网段。脚本只读取离线准备好的秘密，不轮换或打印；主体创建前逐台核对活动安装和现有身份，创建每个缺失主体需键入机器 ID。Identity 工作负载主体 API 没有 preview 端点，因此脚本明确标出直接管理写入；主体不含角色或 Grant。文件位于Git忽略的 `.local-secrets` 下，POSIX使用owner-only模式，Windows移除继承ACL并仅授予当前用户和SYSTEM。生产环境使用 TLS 和私有文件 ACL。

完成三项Skill的独立注册、审核和发布，并由不同作者/发布者完成三份六类 PolicyAsset Draft 与 Snapshot CAS 后，再执行绑定。绑定命令会先读取全部活动安装的当前版本和对应六资产 Snapshot；任一 Snapshot 未发布、缺引用或版本不符时都会在绑定 POST 前停止。绑定本身不授予模型、工具、知识、记忆或Skill业务权限：

```powershell
python scripts/bootstrap_public_examples.py --administrator system.admin --bind-machines
```

也可在所有六类策略发布后使用 `--create-machines` 一次完成缺失主体与绑定；此组合命令同样先验证三份 Snapshot。凭据准备、principal create、binding POST 均是独立管理操作；不确定的写入结果应先 GET 核对当前主体/绑定，不要重放旧请求。`--examples` 不会替代后续的 Model AccessPolicy、角色、Resource Grant 或知识索引审批。

创建和绑定身份不等于业务运行授权。启动后的检查点读取Grant、各主体运行与公共能力Grant、模型和知识策略及其服务侧配置仍须分别完成；`--examples` 不会替代这些审批。

### 准备三个真实版本的 Catalog、Skill 和完整策略

先构建目标镜像并从部署制品读取实际 `sha256:<64位小写十六进制摘要>`。复制对应的完整六策略样板到私有目录，配置平台已批准的聊天和Embedding模型版本、模型价格，并在确有真实文档后填写 `document_bindings`。Python/Java模板的日额为 `budget_cents:500`，Go模板为 `budget_cents:1000`，方便多用例重复评估；这些是有限的UTC日额度。单次Run示例为 `limit_tokens:16000`、`limit_micros:1600000`，按当前获批 `100000 micros/1K tokens` 价格设置，不是全场景成功承诺。包含协作、工具与多轮 Harness 的综合场景使用 `limit_tokens:32000`、`limit_micros:3200000`。实际场景需按保守预留评审，可显式调低上限；发布助手检查正数、不得超过32K tokens/3.2M micros，日额不得超过1000 cents，且micros上限不得高于按所填模型价格与token上限计算的金额。不得把 `budget_override` 当作发布捷径。

模型日额度来自平台发布的策略快照，业务请求不能覆盖。新Run采用新快照，已接受Run保留自己的冻结策略；同一Agent版本、工作空间和UTC日窗口共用累计费用和预留金额。发布额度变更不会创建新窗口或清除既有账本；新请求按其受信快照额度准入，旧预留仍按原凭据结算或进入协调。窗口的额度字段记录最近成功准入的策略值，不能单凭该字段判断所有历史Run的冻结额度。降低额度至已用费用或预留之下会拒绝新的模型调用，不会抹去已经发生的费用。

```powershell
New-Item -ItemType Directory -Force .local-secrets/public-examples/policies | Out-Null
Copy-Item deploy/local/example-go-operations.policy-input.template.json .local-secrets/public-examples/policies/go.json
Copy-Item deploy/local/example-python-documents.policy-input.template.json .local-secrets/public-examples/policies/python.json
Copy-Item deploy/local/example-java-tickets.policy-input.template.json .local-secrets/public-examples/policies/java.json
```

Go、Python、Java模板分别含 model、prompt、tool、memory、knowledge、runtime 六类资产，scope 和首版 ID 与当前公开 Manifest 对齐。预算预留需覆盖请求/输出的UTF-8内容、函数Schema与工具transcript、检索正文与引用、重排结果及AgentGroup子树摘要，并为tokenizer差异留余量。最近Java002真实账本诊断中，前序已结算约539 tokens/53900 micros，后续一次尝试预留7336 tokens/733600 micros，合计约7875 tokens/787500 micros；这支持当前16K/1.6M的有限封顶候选，但仍未覆盖所有输入、循环和树场景，封顶时应失败关闭。单次或前几次结果都不能证明全场景成功。可按目标场景收紧上限；独立基本场景保留16K/1.6M封顶；含协作和工具循环的综合场景经评审使用32K/3.2M有限封顶，均不得绕过预留检查。更新Manifest版本、安装 ID 或Asset内容时，复制私有模板并重新计算scope/摘要；历史已发布schema和资产不得原地覆盖。使用发布助手的 `prepare` 阶段离线调用现有请求准备器，并把完整计划以UTF-8安全写入Git忽略目录：

```text
python scripts/publish_public_policy_release.py --stage prepare --example examples/go-operations --artifact-digest sha256:REPLACE_WITH_REAL_IMAGE_DIGEST --publisher ACTUAL_POLICY_AUTHOR --version-id example-go-operations-v0.2.6 --installation-id example-go-operations-installation --deployment-id example-go-operations-deployment --endpoint http://example-go:8080 --policy-input .local-secrets/public-examples/policies/go.json --output .local-secrets/public-examples/policies/go.plan.json
python scripts/publish_public_policy_release.py --stage prepare --example examples/python-documents --artifact-digest sha256:REPLACE_WITH_REAL_IMAGE_DIGEST --publisher ACTUAL_POLICY_AUTHOR --version-id example-python-documents-v0.2.8 --installation-id example-python-documents-installation --deployment-id example-python-documents-deployment --endpoint http://example-python:8080 --policy-input .local-secrets/public-examples/policies/python.json --output .local-secrets/public-examples/policies/python.plan.json
python scripts/publish_public_policy_release.py --stage prepare --example examples/java-tickets --artifact-digest sha256:REPLACE_WITH_REAL_IMAGE_DIGEST --publisher ACTUAL_POLICY_AUTHOR --version-id example-java-tickets-v0.2.6 --installation-id example-java-tickets-installation --deployment-id example-java-tickets-deployment --endpoint http://example-java:8080 --policy-input .local-secrets/public-examples/policies/java.json --output .local-secrets/public-examples/policies/java.plan.json
```

准备器只输出草案，不登录或写平台。按请求计划在真实浏览器工作空间中注册并评测 Definition/Version；发布者与评测/批准者按 Catalog 分权规则使用不同账户，所有提交都从当前资源读取修订号。安装后先实际部署对应镜像，再让部署控制器观测 readiness，只有真实观察成功后才把安装转为 `active`。`system.admin` 的管理权限不能替代执行权限。

自动化多阶段验收应在同一个 Python 进程内按顺序调用对应阶段，避免每一步都重新登录。隔离回放控制器在进程内按项目、用户、来源和scope复用真实浏览器会话，并在每次复用前重新验证 `/auth/me`；只在已记录的Access Cookie过期时间已到时尝试正常刷新。Cookie仅留在内存，进程退出后不保存或复用。单独启动一次阶段CLI会创建新进程和新登录；不要用循环快速启动许多需要同一用户登录的CLI命令，遵守平台登录限流并为必要的独立登录留出限流窗口。失效或身份不匹配的缓存会话会失败关闭，不会自动重登或重放写请求。

Skill按示例目录 `skills/guidance.v1.json` 注册为不可变版本。先重新 Inspect 实际内容、作者和版本摘要，再由不同人员按请求计划执行 review，最后按读取到的当前 Release 修订执行 publish。Skill API 没有预览接口；每次变更前都要重新读取目标并核验当前 IAM，过期修订重新读取而不是重放。策略计划以 `example-release-bundle` 离线生成后，可由公开 `publish_public_policy_release.py` 分两个人类阶段提交：`create-drafts` 仅创建六个新ID的Draft，`publish` 必须使用不同的人类账户，现场读取六资产修订及当前Snapshot并用真实 `expected_revision` 提交CAS。PolicyAsset API 没有独立策略 Review/Preview 端点；工具要求逐阶段键入确认、强制作者与发布者不同，但组织授权仍由当前目标范围 `policy.manage` 控制，平台本身不强制双人策略审批。发布助手会在PolicyAsset读取或写入前 GET Model Governance 价格列表，验证 `model_version_id` 指向的聊天模型存在唯一当前生效且已批准的 PriceVersion，并逐项核对策略中的聊天模型费率；调用者还需要价格读取权限。价格 API 没有 total/cursor，返回满200条时助手停止，因为无法证明唯一性。它不会自动检查 Embedding PriceVersion，Embedding 版本/价格仍需单独核验。助手拒绝占位模型/Embedding、缺失的聊天模型费率、空Knowledge文档绑定、零或超出16K/1.6M上限以及与当前聊天模型价格不匹配的RunBudget；必须按实际 Model Governance 配置及场景完成检查。当前有限预算只是显式运行上限，不能证明全场景成功。`policy_fragments` 只是提示，不是完整策略或权限。

策略发布器只在 `--stage publish` 执行策略门禁：登录并切换工作空间所需的认证/工作空间 POST 仍会发生；占位模型/Embedding、空知识绑定、缺失或无效的聊天模型价格字段、预算错误，或无法读取并匹配当前有效聊天模型 PriceVersion，只会阻止后续PolicyAsset与Snapshot业务写入。`--stage create-drafts` 可先创建占位Draft。PriceVersion 是平台按 Model Governance 配置的内部计价参数，不等同于供应商账单金额。发布阶段通过 Model Governance 价格列表 GET 检查聊天模型唯一当前有效、已批准的版本及费率；没有该读取权限、列表满200条、无唯一生效版本或输入不匹配时停止。Embedding 价格不由该助手自动校验。

将准备器完整输出保存到私有计划文件后，策略作者与发布者分别独立登录。发布者须与六个Draft的 `created_by` 均不同，且分别具有目标操作的当前权限；409冲突或请求结果不明时先读取实际资产与Snapshot状态，不重放旧CAS：

```powershell
python scripts/publish_public_policy_release.py --plan .local-secrets/public-examples/policies/go.plan.json --stage create-drafts --username ACTUAL_POLICY_AUTHOR
python scripts/publish_public_policy_release.py --plan .local-secrets/public-examples/policies/go.plan.json --stage publish --username DIFFERENT_POLICY_PUBLISHER
```

Python样例真实知识链路另需在 `KNOWLEDGE_DATABASE_DSN` 配置平台专用 PostgreSQL/pgvector 数据库。仓库 Compose 的 Postgres 镜像包含 pgvector；托管数据库需确认服务端提供 `vector` 扩展，平台知识 schema 初始化身份还需获准创建该扩展和知识表，或由 DBA 预先安装扩展。Model Governance 中要注册已批准的聊天、Embedding（及启用重排时的 Reranker）模型版本和运维管理的 Provider Endpoint/SecretRef。若使用仓库本地 DeepSeek/Embedding 辅助器，将原始密钥放在私有 `.local-secrets/model-providers/deepseek.key` 与 `embedding.key`，再运行 `python scripts/prepare_local_model_credentials.py --embedding-model ACTUAL_MODEL_ID --embedding-base-url https://ACTUAL_EMBEDDING_HOST/v1`；脚本只输出非秘密元数据，生成运行时私有挂载。端点 JSON 保存受控 HTTPS 地址，不保存 API Key；业务Agent不持数据库或模型厂商密钥。创建规范知识源后，通过源/文档 API 写入经确认所有者和 ACL 的文档，再使用 `POST /api/modules/knowledge/indexes/python-documents/tasks` 建立索引并核验成功代际；已发布 KnowledgePolicy 的 `allowed_scopes`、每条 `document_bindings`（真实源、文档版本、所有者与有效状态）必须对应同一批数据。空 `document_bindings` 不代表知识接线完成。Go 和 Java模板分别预留 `go-operations` 与 `java-tickets` 知识范围，需按各自真实资料完成同样的源、ACL、索引、策略和主体授权。

可选 Code Runtime 还要按[守卫运行手册](../../workers/code-runtime/README.md)准备三种固定镜像的实际 SHA-256、单独的控制器私有 Profile/网络与资源限制，然后按需使用 `python scripts/compose.py ... --examples --runtime`。Linux 内核需满足 Landlock ABI ≥ 3。启用 `code.*` 必须同时更新不可变 ToolPolicy、安装对应 Profile，并分别授予调用人与绑定机器资源权限；调用每项 Code 工具仍需要当前调用人的独立风险批准。配置存在不等于沙箱调用验收通过。

## 2. 安装已发布版本

先按 [开发指南](三语言SDK业务Agent开发指南.md) 完成 SDK 开发、真实评测和发布。管理界面进入 Agent 目录，选择已发布版本，在目标应用创建安装实例，配置部署与保留策略。

对应 API 使用 `/api/modules/catalog/installations` 和 `/api/modules/catalog/installations/{id}/deployments`；实际请求结构由 `example-release-bundle` 生成。实例处于 `provisioning` 时先启动服务，由部署控制器核验真实运行状态，再提交从 `provisioning` 到 `active` 的版本化状态变更。运行地址或镜像标签存在不等于实例已经就绪。

生成器默认按 Manifest 语义版本生成新的 Version、Installation 和 Deployment ID。指定 `--existing-definition <id>` 时，它只为经 GET 核实为已发布、归当前提交者所有且 Agent ID 匹配的 Definition 生成新版本流程；仍会计划创建新的版本专属安装，不会升级或替换既有 Installation。要保留原安装并升级，使用独立的安装升级操作。生成结果只是人工审阅的请求草案，细节见[三语言 SDK 开发指南](三语言SDK业务Agent开发指南.md)；其中 Skill 发布步骤需重新检查当前权限与实际修订，`policy_fragments` 仅是合并片段，不构成完整发布策略或授权。使用草案前，在控制面按实际作用域完成策略合并、审核发布、安装、部署和激活，并记录控制器就绪状态。

## 3. 先检查成员关系与工作空间

权限管理界面查看目标用户的权限详情和有效成员关系。用户必须属于安装实例所在应用；管理员办理成员关系变更时同样先预览再提交。租户角色需要能覆盖租户的成员关系，应用成员关系不能支撑租户级权限管理员任命。

读取用户权限详情：

```http
GET /api/modules/identity/principals/demo.python.user/access-profile
```

读取当前登录用户的可用工作空间与权限：

```http
GET /api/modules/identity/me/workspaces
GET /api/modules/identity/me/permissions
```

界面选择目标工作空间，再办理该范围的授权。不要通过业务请求中的任意 tenant、application 或用户字段覆盖当前会话工作空间。

## 4. 使用身份预设并预览差异

进入用户列表，选择已有用户，打开“身份与权限配置”，选择业务操作员预设、应用成员范围和唯一对应安装实例。填写原因及有效期，点击预览，核对新增角色、资源 Grant、自动撤销项和数据范围，确认后提交。

以下为 Python 用户的 API 示例。`CURRENT_REVISION` 必须替换为刚读取的用户修订；幂等键应由本次操作生成：

```json
{
  "subject_type": "user",
  "subject_id": "demo.python.user",
  "expected_revision": "CURRENT_REVISION",
  "idempotency_key": "本次操作的唯一键",
  "reason": "授权本人使用文档助手",
  "preset": {
    "preset_code": "operator",
    "preset_version": 1,
    "scope": {
      "scope_type": "application",
      "tenant_id": "tenant-demo",
      "department_id": "dept-demo",
      "application_id": "app-demo"
    },
    "resource_ids": ["example-python-documents-installation"]
  }
}
```

先提交 `POST /api/modules/identity/authorization-changes:preview`。预览中的 `change` 是规范化提交命令；向其加入返回的 `plan_digest` 和 `plan_expires_at`，再提交 `POST /api/modules/identity/authorization-changes`。`expected_revision` 的实际 JSON 类型是数字，上例字符串是明确占位，不可直接发送。修改命令、过期或并发变更后必须重新预览，不能猜测 CAS 修订。

`operator` 预设只为所选实例产生发现、运行、取消、本人历史读取与继续的资源权限；角色的动作清单不等于所有资源都获授权。敏感分享、导出、删除不默认授予。新增公共模型、知识、工具和记忆资源权限在资源授权编辑器逐项办理，绑定到同一安装实例与明确资源，避免通配符。

## 5. 配置公共能力的双重边界

业务用户和 Agent 机器身份分别需要对应模型生成/Embedding、知识检索、工具调用、记忆读写等资源 Grant。用户只操作自己的历史；知识可使用明确组织范围和文档集合，仍必须通过平台元数据过滤。机器身份使用自己的凭据和安装实例工作负载绑定，不能共享人类账号或绕过调用人检查。

Go、Python、Java 示例还分别需要一个机器 `history.read` Grant，供 SDK 在批准检查点读取前通过事件接口重新核对机器权限。公开部署清单是 [`example-machine-history-grants.json`](../../deploy/local/example-machine-history-grants.json)：每条仅包含对应 `service_principal`、对应安装实例、`history.read` 和 `approved_organization` 数据范围。该范围只在这个安装实例的资源 Grant 下生效；事件接口还会独立检查当前人类调用人的历史权限，因此它不授予机器跨安装读取，也不代替调用人权限。

先确保安装处于 `active`，然后为三台机器各自创建工作负载身份并绑定唯一对应的安装。工作负载身份使用 `POST /api/modules/identity/workload-principals`，绑定使用 `POST /api/modules/identity/workload-bindings`；创建与绑定需要目标应用的 `machine.manage`。`client_secret` 由部署者生成并只保存在私有配置中，`EXAMPLE_GO_CLIENT_ID`、`EXAMPLE_PYTHON_CLIENT_ID`、`EXAMPLE_JAVA_CLIENT_ID` 分别设为上表机器主体 ID，密钥按示例 Compose 的私有环境配置传入。不要把凭据写入仓库或共享给另一台机器。

工作负载创建请求不接受角色或 Grant；其 `client_secret` 至少32个字符，需与随后写入私有环境文件的机器密钥一致。下面的安装 ID、Agent ID、当前已发布版本 ID 和 CIDR 均须替换为目标环境核实值：

```json
{
  "principal_id": "example-go-machine",
  "scope": {
    "type": "application",
    "tenant_id": "tenant-demo",
    "department_id": "dept-demo",
    "application_id": "app-demo"
  },
  "network_cidrs": ["ACTUAL_AGENT_CIDR"],
  "idempotency_key": "create-example-go-machine-once",
  "reason": "Create the Go example workload identity",
  "client_secret": "GENERATE_AND_KEEP_PRIVATE"
}
```

绑定请求只允许此主体关联对应版本的安装，并独立记录工作负载管理审计：

```json
{
  "binding": {
    "tenant_id": "tenant-demo",
    "department_id": "dept-demo",
    "application_id": "app-demo",
    "installation_id": "example-go-operations-installation",
    "agent_id": "example-go-operations",
    "agent_version_id": "CURRENT_PUBLISHED_VERSION_ID",
    "principal_id": "example-go-machine"
  },
  "expected_revision": 0,
  "idempotency_key": "bind-example-go-machine-once",
  "reason": "Bind the Go workload to its installation"
}
```

绑定本身不授予业务权限；若主体、凭据或绑定已经存在，应读取当前状态并沿用，不重复创建或使用旧版本的猜测修订号。工作负载 API 的安全约束和校验也可查看 [`workload_creation.go`](../../platform/internal/identity/workload_creation.go) 与 [`workload_binding.go`](../../platform/internal/identity/workload_binding.go)。

使用能够切换到 `tenant-demo / dept-demo / app-demo`、且在目标应用有 `authorization.read`、`authorization.grant` 和 `machine.manage` 的浏览器管理员执行：

```powershell
python scripts/seed_example_machine_history_grants.py --administrator permission.admin
```

脚本通过浏览器登录并切换到示例应用工作空间，只读取已有主体、活动安装和工作负载绑定。每项先调用授权预览，确认计划仅新增该机器自己的一个 `history.read` Grant，随后要求键入安装 ID 才提交；已存在的同范围授权会跳过，冲突授权会停止等待人工处理。它不会创建机器、凭据、角色或人类授权，也不会更改 `permission.admin` 或 `system.admin` 的业务权限。生产 OIDC 环境应在受信浏览器管理界面完成相同的预览和提交流程，不通过本地密码脚本。

这个步骤只补齐检查点读取权限，不会授予机器 `run`、`history.continue`、分享、导出、删除、模型、知识、工具或记忆权限。继续按后续小节和对应的已发布策略，为每个机器显式预览并提交其余所需资源 Grant；调用人仍须拥有同一操作的独立权限。管理账号不因承担审批或工作负载管理职责获得业务运行权。

同一个安装实例可以挂到多个已有用户。对每个用户分别预览并提交`operator`预设和公共资源授权；保持`owner`数据范围即可隔离各自会话、历史和记忆。机器身份继续绑定该安装和当前Agent版本，无需为每个业务用户增加一套Agent机器凭据。

知识检索还要完成三项配置：在规范源中记录文档真实所有者和明确ACL；在已发布知识策略的`document_bindings`中绑定文档ID、版本和所有者；给调用人与机器分别授予对应知识资源权限。共享实例中的不同用户可以绑定不同文档，平台先求权限交集，再进行混合检索、Top-K和重排。只增加安装运行权不能获得另一个用户的手册。

添加或修改文档时，`PUT /api/modules/knowledge/sources/{knowledge_id}/documents/{document_id}`带当前`expected_source_revision`和`expected_document_version`；再通过知识索引任务接口发布全量或增量代际。新增文档必须进入明确的知识策略绑定；不能只写源和向量索引就当作已授权。管理员通过策略发布端口发布新的不可变资产和版本化快照，保留旧版本供历史审计。删除测试文档使用墓碑，并等待增量索引发布成功后撤回临时维护身份。

`permission.admin` 必须先获得真实管理员任命，再由超级管理员通过密码再认证办理明确委托。委托限制应用、角色、动作、资源、数据范围和可授权期限；管理员资格不等于可办理任意授权。委托不覆盖的请求应拒绝，不能把权限管理员升级为超级管理员解决。

办理目标应用的任命和委托前，先通过成员关系预览/提交给权限管理员添加该应用的有效成员关系，再切换到该工作空间；只有管理员应用成员关系不能代替业务应用成员关系。

委托中的安装资源和公共能力资源使用不同字段，不能混用。安装的 `discover`、`run`、`cancel`、`history.read` 授权用应用作用域和 `resources` 指定唯一安装；模型、工具、知识、记忆、Skill 等公共能力用 `resource_bindings` 同时绑定资源类型、资源 ID 和安装 ID。例如只允许办理一个安装的运行授权时，委托边界片段为：

```json
{
  "scope": {
    "scope_type": "application",
    "tenant_id": "tenant-demo",
    "department_id": "dept-demo",
    "application_id": "app-demo"
  },
  "roles": [],
  "actions": ["run"],
  "resources": ["example-go-operations-installation"],
  "resource_bindings": [],
  "data_scope_types": ["owner"],
  "management_actions": ["authorization.change"],
  "allow_permanent": false,
  "max_duration_seconds": 3600
}
```

这只是 `delegation` 的边界片段，完整请求还需填写唯一 ID、`subject_id=permission.admin`、`status=active`、`revision=1` 及明确的未来 `expires_at`。先读取权限管理员的当前修订，再通过 `POST /api/modules/identity/delegations:preview` 检查完整请求，以返回的摘要进行 `delegation.manage` 再认证，最后提交委托；实际授权另走预览和 CAS 提交。应用作用域没有赋予任意安装权限：这里的动作只有 `run`，资源只有一个安装，授权期限不得超过一小时及委托自身到期时间。

公共能力的委托不能照搬上述安装字段。例如模型权限应使用 `actions=["model.generate"]` 和 `resource_bindings=[{"resource_type":"model","resource_id":"实际发布的模型资源ID","installation_id":"example-go-operations-installation"}]`，并固定该安装的作用域、数据范围和期限；不要把模型 ID 放进安装的 `resources`。一个授权批次中每条 Grant 都必须完整落在一条有效委托内，不能把不同委托的动作、资源和期限拼接。若预览返回 403，先核对这个边界和目标用户成员关系，不提交或扩大角色来绕过拒绝。


### 发布Harness循环限额

Harness循环限额属于已发布Runtime资产的一部分，由具备目标范围`policy.manage`的管理员修改。通过`/modules/policyasset`读取当前Runtime资产和快照，保留其余Runtime策略字段，只更新`harness`对象；随后按读取到的修订号调用`PUT /modules/policyasset/assets/runtime/{id}`，`POST /modules/policyasset/assets/runtime/{id}/publish`，再调用`POST /modules/policyasset/snapshots/publish`发布新的不可变策略快照。每次写入都要提交完整作用域（租户、部门、应用、Agent、Agent版本）和当前`expected_revision`；收到修订冲突后重新读取，不重试旧版本号。发布Runtime资产本身不会自动切换正在运行的Agent，也不会替代快照发布、Agent版本绑定或用户/机器资源授权。

可配置范围是`max_rounds` 1..8、`max_tool_calls` 1..16、`max_repeated_calls` 1..4、`max_elapsed_seconds` 10..3600以及`limit_behavior`=`error`或`incomplete`。SDK每次Harness入口只读`POST /internal/runtime/harness-policy`的当前策略摘要和限制；SDK选项只能收紧轮次/工具数，重复调用数、绝对期限与超限行为遵循发布策略。绝对期限从平台`server_time_ms`起算，审批等待和停机时间均在期限内，继续运行不重置期限。预算耗尽、策略循环限额和其他部分结果分别保留`MODEL_BUDGET_EXCEEDED`、`HARNESS_LIMIT_EXCEEDED`、`HARNESS_INCOMPLETE`错误语义；不要把partial输出当作完整成功结果。三个SDK的Harness检查点不可跨语言迁移或人工重建，即使都采用`harness-loop/v1`字段约定。字段协议详见[Harness循环协议](../../contracts/harness-loop.md)。

## 6. 验证挂载成功

目标用户重新读取权限并进入对应工作空间，Agent 目录仅显示获授权实例。使用示例业务输入创建运行，检查输出与本人历史。另两个业务用户、管理账号及其他机器身份访问该实例应拒绝；管理员如确需业务访问也要显式办理对应资源权限。

查看“我的权限”和权限解释，区分角色动作、资源 Grant、数据范围、deny、有效期及机器身份边界。不要用隐藏按钮或前端路由代替服务端鉴权。

## 7. 撤权与改岗

读取最新权限详情，从预览命令提交 `revoke_grant_ids` 或 `revoke_binding_ids`，填写原因及本次幂等键，核对差异后提交。离开成员范围还会撤销失去覆盖的允许权限；显式 deny 保留，再加入组织不应自动恢复旧授权。

验证新运行被拒绝、在途公共能力重新检查权限、缓存不能绕过撤权、历史仍遵循当前数据范围。登录凭证撤销使用认证会话管理；删除 Refresh Token 阻止续期，短期 Access Token 的剩余有效期与业务实时鉴权共同决定当前请求边界，不能宣称只删除 Refresh Token 就立即使全部 Access Token 失效。

## 8. 常见拒绝

| 现象 | 检查内容 |
|---|---|
| 403 权限拒绝 | 当前工作空间、有效成员关系、角色、资源 Grant、deny、委托、调用人和机器身份 |
| 409 冲突 | 用户或资源最新修订、预览时效、幂等键是否复用不同命令 |
| 目录可见但运行失败 | 实例部署就绪、运行权限及各公共能力权限/策略是否齐全 |
| 知识为空或缓存失效 | 源版本、索引代际、ACL、知识绑定与缓存模式 |
| 模型或预算失败 | 已批准模型部署、策略预算、真实账本和未结算请求 |

最终以实际登录、运行、拒绝、撤权及账本验收为准，不以请求草案或前端展示作为完成证据。

### 升级已参与协作的 Agent

发布新版本时，盘点该安装的全部调用人，包括通过 Router/AgentGroup 委托调用的用户。新版本使用新的 model、memory 等资产 ID 时，自有用户和机器的授权更新不会自动迁移其他调用人的资源 Grant。逐主体读取权限详情，只将已有精确 Grant 的资源引用替换到目标安装的新发布资产；保留动作、allow/deny、数据范围、有效期与委托，先预览差异，再按当前用户修订提交。不要给协作用户新增目标实例的直接 `run` 或 `history.read` 权限来解决公共能力拒绝。

以当前已发布快照和六份资产的实际修订作为升级基线，不复用初次准备文件中的过时内容。读取当前快照及其引用的 model、prompt、tool、memory、knowledge、runtime 资产，核对摘要和修订后生成离线发布计划。尤其检查 Knowledge 的 `document_bindings[].document_version` 与规范源、活动向量索引中同一文档的版本一致；文档版本号不同于源/索引修订号。发布新的Runtime预算时也须保留其他五资产的实际当前内容，不能仅更新Runtime而将Knowledge退回旧版本。

模型访问策略也绑定安装、Agent版本和主体。为原已授权的协作调用人创建并批准新版本策略，保留已评审的 provider/model 白名单和访问类别。发布前对所有协作边逐项核验 `memory.read/write`、`model.generate/embed`、知识、Skill和工具的实际目标资源；用 `POST /api/modules/identity/permissions:explain` 检查新发布资产。旧资产不再属于当前安装版本时，解释接口可能返回资源校验错误，不能据此认定新版已有授权。

授权变更会使在途执行的权限版本失效。先结束或取消涉及这些主体的执行，再迁移，完成后用新Run验证跨Agent协作、直接跨用户调用拒绝和历史边界。保持失败Run及账本，禁止替换其资产引用后重放。

## 新公共能力的发布与授权边界

当前SDK/平台接口包含Go、Java的批准暂停与签名恢复，以及Python SDK的`HarnessPause.from_result`适配。工具批准走独立的人类控制面，不使用`business.review`或Execution的Review决策接口。只有不可变ToolPolicy中登记的工具/Schema、用户和机器的`tool.invoke`权限及读取原Harness检查点的当前权限均成立时，才能继续办理；批准不会授予新的资源Grant。

真实流程是`pending → preview → 再次认证 → approve → 显式resume`。浏览器先向`POST /api/modules/tool-approvals/pending`提交`{"operation":{"run_id":"<原Run>","pending_key":"<Harness key>"}}`；平台重读`harness-loop/v1`当前FIFO队首，返回`name`、`call_id`、`pending_key`、`checkpoint_revision`和`payload:null`。后续工具接口使用同一`operation`引用与服务器生成的`claims`；`payload`必须为空，不提交或保存工具参数。

再次认证先读取`GET /auth/step-up/method`。本地登录在`POST /api/modules/tool-approvals/step-up`输入当前密码；OIDC 登录在`POST /auth/step-up/oidc/start`提交`action`和当前预览返回的`request_digest`，通过受信网关验证身份提供方的签名 ID Token、PKCE、nonce、当前账号及新鲜的`auth_time`后，取得短期单次`step_up_token`。动作只能是`tool.approval.approve`或`tool.approval.revoke`，纯 OIDC 账号不需要本地密码。浏览器不能调用内部 challenge/complete 接口或提交认证时间作为证据。

把认证凭证连同原操作引用及 claims 提交给`/approve`或`/revoke`。凭证仅证明当前登录会话对确切动作和摘要完成了再次认证，业务批准事务还会复核任务、策略、人员与机器 IAM、参数及待执行检查点。另一登录会话或权限已撤销时拒绝；认证方式不会扩大业务或管理权限。本地与 OIDC 的批准、撤销和审计回滚使用同一业务事务。

批准后必须另行点击继续，由`POST /api/modules/tool-approvals/resume`提交引用和 claims。撤销需针对同一操作再次认证后调用`/revoke`。认证期间预览到期时重新预览，取消或不确定结果不自动重发。

批准响应中的`confirmation_token`以及短期`step_up_token`只可在当次调用中短暂使用。浏览器组件只保留批准编号、过期时间或恢复回执；不将token写入localStorage、sessionStorage、业务input、宿主状态、事件、日志或检查点。平台Gateway在派发时复核当前用户/机器权限与原检查点，再为同一批准签名恢复请求；Agent收到的Token只在本次签名`resume_input.confirmation_token`中交给SDK，不能用于换参数、主体、安装、版本、会话或Run。

若显式resume请求超时或响应不明，不能自动重发；用原Run查询`GET /api/modules/execution/platform/runs/{runID}`（前端API封装`api.executionRunStatus(runID, signal)`）核对状态。若仍未知，停止自动继续并由运维按原Run协调。批准或撤销后仍要逐次重新检查当前授权，撤权不会因已有检查点绕过。

公共State读取语义：只有从未创建的状态谱系返回`checkpoint:null`；已有谱系的当前检查点到期或指定历史正文不可用时，平台返回`409 STATE_CONTINUITY_LOST`。三语言SDK的Load接口传播该HTTP错误，Harness不会将错误吞成冷启动。业务/Harness不得复用旧Run重新生成模型结果或重派发工具。用户若决定重新提交，需先核验原操作的未知副作用并创建新Run；这代表新的业务操作，不是旧Run恢复。

普通进程故障恢复`runtime-recovery/v1`和上文人工批准的pending恢复是不同入口。只有平台在确认旧处理器/进程实际停止、原Run持久事实和新执行世代成立后，才能签发新的Agent执行v2 `operation=resume`；请求复用原Scope、input/schema和幂等键，携带平台保存的停止引用。SDK再次核对旧修订/租约、原请求和策略摘要，逐项通过当前授权读取引用所指的最新State，再做当前执行权限复查。继续执行的AgentGroup再次故障时，外层恢复可携带`group_resume`，但必须以本次真实停止引用及其当前检查点为准；旧AgentGroup handoff只证明此前那次等待退出，不能代替本次停止证明。调用人不能在业务Run请求里自造`runtime-recovery-stop/v1`、停止证明、`confirmation_token`或内部resume命令；浏览器查询Run状态也不构成恢复授权。缺少可验证的旧退出、当前检查点或当前权限时必须拒绝。协议细节见[受控执行恢复](../RUNTIME-RECOVERY.md)和[字段约束](../../contracts/runtime-recovery.md)。

SDK的`MemoryRunStore`和进程内事件是L1；新进程只可在上述平台命令验证通过后建立新的本地投影，不恢复丢失的本地历史。已发出的模型/工具操作只能使用平台只读回执对账；回执未知时不重派发并保留未知状态。是否成功恢复须核对目标平台的旧处理器停止证明、当前检查点、授权和只读回执。

上述入口的使用依赖兼容的SDK和平台版本、不可变镜像/Manifest/策略版本、服务器签名材料、已发布工具策略与Schema，以及调用人和机器资源授权。Python文档助手可选`workflow_mode="tool_loop"`，默认`direct`不增加Harness模型调用。普通`runtime-recovery/v1`要求平台签发停止引用，SDK核对当前State与授权后建立新执行世代；发布前按目标安装逐项配置并运行相应集成检查，不能沿用旧发布Hash。

三个示例新增可选`notify_me:true`，Python还须`workflow_mode:"tool_loop"`。它们选择已发布Function `notify_self`，对应公共写工具`notify.self`，平台限定接收人为当前可信人类调用人。参数仅title/text，不开放receiver_id或其他接收人字段。挂载时应分别为用户和相应Agent机器提供`tool.invoke`对`notify.self`资源的明确Grant，并将该工具、函数Schema和`require_confirmation:["notify.self"]`合入新版本ToolPolicy；管理权不隐含此业务权限。

这类授权只允许提出具体操作，不替代独立批准。使用前述原Run pending引用流程办理预览、再次认证、批准和显式resume；若没有原检查点、工具策略未发布、Grant缺失或批准已撤销/到期，应保持拒绝。输出notify_me是用户请求回显；实际是否受理从工具Observation/Outbox事实核对，受理不代表已送达。

### 有序业务恢复计划

普通进程故障的业务恢复使用SDK有序检查点计划，不复用人工批准Flow。每个示例在SDK构造入口显式配置业务selector：Go `ServerConfig.RecoveryCheckpointSelector`，Java `ServerConfig.Builder.recoveryCheckpointSelector(...)`，Python `ExecutionLifecycle(recovery_checkpoint_selector=...)`。缺少selector时普通恢复默认拒绝。恢复前平台必须确认旧处理器确已退出并签发停止引用；SDK对引用中的每个当前State逐项复读和比对。计划固定业务步骤，既有Skill/Context等附属检查点可以共存，但不能替代证据或Harness。首次步骤只有在签名引用未包含该key、SDK当前Load精确返回匹配state key且`checkpoint:null`时才可启动，并需匹配原业务输入摘要；之后的步骤须有前序真实持久检查点完成回执，再核验当前head。业务返回值本身不能证明步骤完成。

| 示例 | 固定恢复步骤 |
|---|---|
| Go 运维 | `operations/diagnosis-evidence`（`schema://example-go-operations/evidence/v1`）→ `harness/diagnosis-model`（`schema://agentplug/harness-loop/v1`） |
| Python 文档 direct | `knowledge-harness/document-answer`（`schema://agentplug/knowledge-harness/v1`） |
| Python 文档 `tool_loop` | `documents/document-tool-evidence`（`schema://example-python-documents/tool-evidence/v1`）→ `harness/document-tools`（`schema://agentplug/harness-loop/v1`）→ `knowledge-harness/document-answer`（`schema://agentplug/knowledge-harness/v1`） |
| Java 工单 | `tickets/draft-evidence`（`schema://example-java-tickets/evidence/v1`）→ `harness/ticket-model`（`schema://agentplug/harness-loop/v1`） |

Go/Java的业务证据缺失时拒绝普通恢复；Python文档的首次证据只冻结输入与Prompt摘要，后续Harness/Knowledge仍需各自的真实阶段检查点。普通恢复同进程重复命令仅可在当前授权复查且SDK持有已退出的同一私有活动世代时只读回放已有结果，不会重进业务Handler；跨进程或新执行世代重新完成引用和计划核验。Python类型与selector位于公共SDK模块`agent_platform_sdk.recovery_context`，顶层导出步骤、计划和选择器类型。五个示例人类账号不会自动获得跨Agent或目标资源权限。部署时为业务配置覆盖其检查点的selector，并核验实际平台停止证明、当前State及权限。详细代码片段见[三语言SDK开发指南](三语言SDK业务Agent开发指南.md#有序业务检查点计划)和[恢复协议](../../contracts/runtime-recovery.md)。

## 可选 Code Runtime 的输入与授权

三个业务示例均新增可选`sandbox_check`布尔值，缺省为`false`。启用只允许Harness暴露对应已发布Function，不代表模型一定选择它或代码已经执行。Conversation请求的业务`request`可以分别写为：

| 示例 | `request`内容 | Function映射 |
|---|---|---|
| Go运维 | `{"service":"orders","symptom":"响应延迟升高","sandbox_check":true}` | `sandbox_python` → `code.python` |
| Python文档 | `{"question":"文档金额如何合计？","workflow_mode":"tool_loop","sandbox_check":true}` | `sandbox_python` → `code.python` |
| Java工单 | `{"ticket_id":"DEMO-001","summary":"分析请求超时","sandbox_check":true}` | `sandbox_javascript` → `code.javascript` |

Python的输入Schema/业务校验要求`sandbox_check=true`同时有`workflow_mode="tool_loop"`；Go和Java没有该模式字段。三个示例都把启用选择绑定到冻结业务/evidence指纹，批准恢复不能切换。调用方只传`sandbox_check`布尔值，不传代码；模型提出的Function参数由当前ToolPolicy限制为封闭对象`{"code":"..."}`，字符串长度1..65536。示例要求仅对已提供的事实做短小只读分析，不访问文件、网络、环境变量、凭据或密钥，也不执行修复或其他副作用。实际Code隔离Profile、镜像和资源限制由平台运维绑定，不能把模型提示当作沙箱隔离。

启用权限需要完整链条：Manifest的`tool.invoke:code.python`或`tool.invoke:code.javascript`、不可变ToolPolicy中的`sandbox_python`/`sandbox_javascript`到`code.*`映射及`require_confirmation`、平台实际Code Profile/控制器配置，以及目标人类用户和绑定机器身份对相应`code.*`资源的显式Grant。发布准备器`platform/cmd/example-release-bundle`只生成合并用策略片段，不会补齐六类策略、配置隔离Profile或创建Grant。缺少这些配置时，即使业务输入为true也应被平台拒绝；管理员角色不隐式授权。

模型提交Code Function后沿用原`pending → preview → step-up → approve → 显式resume`流程。SDK Harness把已核验的完整工具回执作为`untrusted_data` Observation继续模型循环；恢复已发出的工具操作只查询只读receipt接口。缺失、未知或未完成回执不会自动重新调用`code.*`，应保留未知并核查原Run。输出`sandbox_check`仅回显请求，不能证明代码已获批、执行或成功。三示例对应说明见[运维Go示例](../../examples/go-operations/README.md)、[文档Python示例](../../examples/python-documents/README.md)、[工单Java示例](../../examples/java-tickets/README.md)。

### 构建Code守卫镜像并配置网络边界

Code执行依赖平台运维按仓库`workers/code-runtime/images/Dockerfile`分别构建Python、JavaScript和Shell镜像。构建使用仓库根目录作为上下文；每个镜像构建完成后，通过`docker image inspect <本地构建Tag> --format '{{.Id}}'`读取实际不可变ID，并将`sha256:<64位小写十六进制>`值分别配置到控制器私有`code-runtime.json`的`images.python`、`images.javascript`和`images.shell`。准备器`platform/cmd/prepare-code-runtime`同样要求实际镜像ID。Tag只用于本地查找，不能代替配置中的ID；运行时要求镜像已存在于同一Docker daemon，且校验镜像ID、语言标签、`landlock-v3`文件守卫标签、非root用户及入口命令。构建完成后还须将镜像部署到目标Docker daemon，并把实测ID写入对应控制器配置。

镜像入口以`65532:65532`运行`code-sandbox-guard`。Linux Docker Engine内核须支持Landlock ABI 3，缺少时守卫失败关闭。文件访问只允许固定系统目录读取，写入限定于容器内部临时`/workspace`、`/tmp`和`/dev/shm`，不挂载宿主机文件；容器使用`--network none`、只读根文件系统、移除全部capabilities、`no-new-privileges`和seccomp。Code容器默认不能访问任何网络或外部API。

需要访问外部服务时，应另外配置平台注册的`api.*`只读API Tool，而不是打开Code容器网络：端点由运维绑定为固定HTTPS URL/路径，请求只能为GET，模型只能提供配置`query_keys`中的查询值；端点禁止由调用方覆盖，重定向拒绝，超时为1..5秒，响应限制为1KiB..1MiB。绑定按租户、应用和Agent范围配置，仍需当前ToolPolicy允许该工具，并为人类调用人与机器身份授予`tool.invoke`资源权限；可选SecretRef只由平台侧私有凭证解析器读取，不能交给业务Agent或代码执行器。此能力不支持任意URL请求或写API。容器守卫和运行边界详见[Code Runtime运行手册](../../workers/code-runtime/README.md)。

协作发起的人类用户还需在目标应用内绑定 `agent_delegate` v2 角色（role_code=agent_delegate、role_version=2）；仅添加 `agent.delegate` Grant 会因 ROLE_REQUIRED 被拒绝。随后分别给调用人及父 Agent 机器授予父安装与目标安装的精确 agent.delegate Grant，目标 Agent 机器仍需自己的 run 和公共资源权限。发布 Runtime.delegation 的 allowed_agent_ids、task_types、max_depth、max_children，禁止通配符和业务输入临时选择路由。全部机器授权应在 Run 创建前固定；等待期间补充机器权限会改变固定授权版本，旧 Run 不能借此继续执行。

协作需要独立agent.delegate权限、发布的Runtime.delegation约束、固定目标任务类型，以及调用人、父Agent机器、目标Agent机器的权限交集。授权时先预览具体目标和范围，再提交；初始五个人类账号不会自动获得其他Agent的直接运行或历史读取权。三语言RunAgentGroup接口只在这些条件成立时规划/准备/准入/汇聚。非终态child会通过独立`AgentGroupPause`进入平台等待；平台以实际处理器退出收据、原固定计划和当前State为依据等待/唤醒父Run，唤醒后由新执行世代和新租约恢复原gather。恢复时重新检查当前IAM与检查点，并且只允许消费原gather、读取原child结果；处理器在成功返回前必须消费这次gather，不新建或重派发子Run，也不将子输出当作可信指令。若这次继续执行又发生进程故障，必须走普通`runtime-recovery/v1`并提供平台确认的本次真实停止证明，再以`group_resume`绑定同一个gather；其检查点需与本次停止引用中同key的当前State引用一致，旧AgentGroup收据不是新故障证明。服务端保存原目标、输入指纹和子Run，跨用户结果始终拒绝。细节见[AgentGroup等待协议](../../contracts/agent-group-waiting.md)和[普通故障恢复协议](../../contracts/runtime-recovery.md)。

保持管理员管理权与业务运行权分离。五个初始人类账号及三个业务机器身份的权限不会因新增Skill、函数或协作自动改变。正式启用前，应在目标部署检查运行恢复、子任务并发、跨主体访问和撤权后的拒绝，并分别核验平台运行记录、用户权限、机器绑定与资源Grant。
