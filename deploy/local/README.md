# 本地主机进程部署

首次部署从[本地源码逐步说明](../../docs/developer/zh/deployment.md#本地源码与主机进程)或 [English guide](../../docs/developer/en/deployment.md#local-source-and-host-processes)开始。本页保留复杂场景的补充参考；配置模板为 `migration.env.example`、`platform.env.example`、`frontend.env.example`、`runner.env.example` 四份。

通用主机入口为 `python scripts/local.py`，用于构建和运行平台、前端与 Metric Runner。空库首位管理员和公开示例初始化步骤见[干净环境挂载与授权指南](../../docs/开发者指南/业务Agent挂载与已有用户授权指南.md#空库首次初始化)。该指南中的 Identity 脚本需要真实浏览器登录；机器身份要在目标 Catalog 安装已激活后才能创建。三个示例分别见 [Go 运维助手](../../examples/go-operations/README.md)、[Python 文档助手](../../examples/python-documents/README.md) 和 [Java 工单助手](../../examples/java-tickets/README.md)。

首次启动示例容器前运行 `bootstrap_public_examples.py --prepare-machine-env` 离线生成随机、互相独立的机器凭据文件；不调用API或创建主体。将 `.local-secrets/public-examples/machines.env` 作为后置 `--env-file` 交给Compose。Catalog安装经真实部署控制器观测为 `active` 后，再运行 `--create-machines`，为每台机器提供平台实际观测到的最小CIDR，创建主体并绑定唯一匹配安装。机器创建API没有preview，脚本逐项显式确认；不创建角色或业务Grant。安装激活、身份和绑定核验通过后，使用 [`seed_example_machine_history_grants.py`](../../scripts/seed_example_machine_history_grants.py) 按授权预览逐项批准检查点的 `history.read`。该Grant仅涉及历史读取，不替代运行、模型、知识、工具、记忆等其他主体和资源的单独授权。

六类策略模板位于 [`example-go-operations.policy-input.template.json`](example-go-operations.policy-input.template.json)、[`example-python-documents.policy-input.template.json`](example-python-documents.policy-input.template.json) 和 [`example-java-tickets.policy-input.template.json`](example-java-tickets.policy-input.template.json)。先复制到 `.local-secrets/public-examples/policies/`，配置实际模型版本、Embedding和Knowledge文档绑定，再用 [`publish_public_policy_release.py`](../../scripts/publish_public_policy_release.py) 的 `prepare` 阶段生成离线计划。模板保持日额500 cents，示例Run上限为16000 tokens/1600000 micros；按Model Governance平台配置价格100000 micros/1K tokens核验并可按具体场景调低，不代表所有场景都能成功，也不表示供应商账单金额。`create-drafts` 与 `publish` 必须由不同人类登录执行；后者读取实际资产/快照版本并提交CAS。PolicyAsset API没有独立preview/review接口，工具通过审查摘要和键入确认控制提交，不替代目标范围 `policy.manage` 检查。

`create-drafts` 可以提交模型/Embedding和Knowledge仍为占位值的六项Draft。只有 `publish` 阶段在登录及切换工作空间之后、任何PolicyAsset或Snapshot业务写入之前，才会因模型/Embedding占位值、平台配置价格或预算不合规、空Knowledge文档绑定而停止；认证与工作空间选择所需的POST仍会发生。

发布阶段会通过 `GET /api/modules/model-governance/prices?model_version_id=…&limit=200` 读取当前 PriceVersion；只有存在唯一已批准且当前生效、USD 币种及正费率都有效，且策略中的输入/输出费率逐项相同，才会继续读取 PolicyAsset 并提示发布。该只读检查需要当前主体拥有 Model Governance 价格读取权限。平台价格是内部计价参数，不代表供应商账单；Draft 阶段不读取此端点。

需要 Go 1.26.10+、Node 20/22、Python 3.12+ 和 PostgreSQL 16 + pgvector；Java SDK 构建需要 JDK 21 与 Maven。安装 SDK 可执行 `python -m pip install -e "./sdk/python[grpc,telemetry]"`，随后 `python -m pip check`。`python scripts/local.py build` 构建平台、迁移、网关、Runner 与前端静态制品，失败返回非零，不回退 Docker。

本目录四份 `*.env.example` 定义迁移、平台、网关和 Runner 的配置形状，复制到私有 `.local-secrets/local/` 并填写真实配置。迁移账户与平台 DML 账户分离，Runner 仅持自身令牌，前端仅持网关所需令牌。平台持 Ed25519 私钥，业务 Agent 仅持公钥。不得向业务 Agent 下发平台数据库或模型厂商凭据。配置按字面值读取，不支持 shell 扩展；拒绝占位值。权限使用 POSIX 0600/0400 或 Windows 私有 ACL。

先备份、停止写入，再使用迁移配置执行 `python scripts/local.py run migrate --env-file .local-secrets/local/migration.env`。运行配置不能包含迁移账户。新生产库管理员使用[首位管理员流程](../README-first-administrator.md)，不使用开发演示种子。

生产使用 OIDC、TLS、Secure Cookie、再次认证与可访问的遥测端点；内部端口保持回环或受控网络。Linux 运行账户、资源边界见[Linux部署说明](README-linux-production.md)。Agent 的知识检索通过平台公共能力执行；知识源、索引、策略和用户/机器权限须在目标租户、应用及安装上分别配置并核验。
