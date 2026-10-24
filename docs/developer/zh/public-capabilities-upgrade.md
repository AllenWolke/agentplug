# 公共能力升级与 SDK 2.1

首次了解功能请先读[公共能力与示例更新说明](../../releases/public-capabilities-2.1.zh.md)和[三语言接口用法](capabilities.md)。本页侧重迁移、恢复协议与既有部署的兼容处理。

本次升级只在 `agentplug` 实施。对照项目只用于读取公共层源码，不构建、测试、部署或修改其文件、容器和数据。平台能力对齐与本项目新增的 Go/Java SDK 支持分别验收，不代表两个项目源码一致。

最终测试结果、部署后复验和回退步骤见 [2026-10-22 验收记录](public-capabilities-acceptance-20261022.md)，实际运行版本见[部署清单](public-capabilities-deployment-20261022.json)。

下表列出实现范围。最终通过情况以隔离回归记录为准，代码存在或编译成功不等于集成验收通过。

| 公共平台能力 | 主要实现位置 | 默认行为与边界 |
| --- | --- | --- |
| 模型自动路由、质量准入、可用性、有限故障切换和物理尝试记录 | `platform/internal/capability/model_route*`、`platform/internal/policyasset/model_routing*` | 默认使用已配置模型，自动选择须显式启用；未知发送结果不切换或重发 |
| 结构化输出、供应商协议适配、前缀缓存和缓存 Token 计价 | `platform/internal/modelgateway`、`platform/internal/modelgovernance` | JSON Schema 最终生成与 Function Calling 分开请求；未知费用不按零结算 |
| 扩展 Harness、步骤工作流和批处理原始窗口 | `sdk`、`platform/cmd/platform/harness_policy.go` | 恢复不重新开始截止时间；待确认调用只读原回执 |
| 检查点容量、额度预留、游标和恢复引用分页 | `platform/internal/capability/checkpoint*`、`sdk` | 缺省 64 个修订；显式协商上限 4096；分页集合最多 8192 个引用 |
| 多来源知识融合、只读检索恢复、索引回执与当前引用授权 | `platform/internal/capability/knowledge*`、`platform/internal/knowledge` | 使用本项目独立知识配置；缓存和冻结证据不替代当前 ACL |
| 远端工具身份、幂等有效期与原操作收据 | `platform/internal/capability`、`platform/internal/toolgateway` | 丢响应只查原操作收据；未知提交保持未知 |
| 部门 Agent 审批包、工作负载版本集合和持续授权 | `platform/internal/identity/department_agent_package*`、`workload_versions.go` | 同时保留本项目部门能力上限、公司管理和批量授权；新增部门管理角色为显式 v3，旧角色定义不改写 |
| 授权等待续接、停止确认和预算关闭证明 | `platform/internal/execution`、`platform/internal/compensation`、`platform/internal/usagecost` | 未证明实际退出不报告停止完成；未确认预算不释放为零 |
| 阶段观测、评测案例复用和独立审核 | `platform/internal/audit`、`platform/internal/evaluationproduct`、`contracts/agent-evaluation` | 自评不替代独立验证；性能收益须实测 |
| 连接复用、发送边界限流、纯解码缓存及已回滚事务重试 | `sdk`、`platform/internal/jsonvaluecache`、`platform/internal/sqlutil` | 不缓存授权决定；未知提交不重试；限流等待计入原预算 |

## 三语言支持

这些是本项目额外补齐的 SDK 支持，对照项目不回写。三种语言保留惯用接口，通过公共网关执行，不持有供应商密钥或业务数据库连接。

| 能力 | Python | Go | Java |
| --- | --- | --- | --- |
| 对话、Embedding、Prompt、记忆、知识搜索/回答/回放 | `CapabilityGatewayClient` | `CapabilityClient` / `PublicCapabilities` | `CapabilityClient.capabilities()` / `PublicCapabilities` |
| JSON Schema、路由/缓存/实际计费元数据保留 | `chat` | `Chat` | `chat` |
| 当前引用授权、父文档证据检查 | `authorize_references` / `authorize_cached_result` | `AuthorizeReferences` / `AuthorizeCachedResult` | `authorizeReferences` / `authorizeCachedResult` |
| 持久化搜索与回答 | `run_knowledge_search` / `run_knowledge_harness` | `RunKnowledgeSearch` / `RunKnowledgeHarness` | `KnowledgeWorkflow.search` / `answer` |
| 持久化阶段调用、Prompt 分阶段程序 | `DurableStageClient` / `prompt_program` | `DurableStageClient` / `PromptProgram` | `DurableStageClient` / `PromptProgram` |
| 步骤工作流与只读恢复 | `run_step_workflow` | `RunStepWorkflow` | `StepWorkflow.run` |
| 扩展 Harness | `run_harness` 扩展参数 | `HarnessOptions` 扩展字段 | `HarnessRunner.Options` 扩展字段 |
| 执行策略、原批处理窗口 | `load_execution_policy` | `LoadExecutionPolicy` | `loadExecutionPolicy` |
| 检查点容量与 CAS 游标 | `CheckpointCursor` | `OpenCheckpointCursor` | `CheckpointCursor.open` |
| 分页恢复、截止预算、有界并发、受控重试、阶段观测 | SDK 公共模块 | SDK 公共模块 | SDK 公共类 |
| LangGraph 框架适配 | 保留专用集成 | 使用通用恢复与工作流接口 | 使用通用恢复与工作流接口 |

共享夹具为 [public-capabilities-v1.json](../../../contracts/fixtures/public-capabilities-v1.json)、[workflow-recovery-public-v1.json](../../../contracts/fixtures/workflow-recovery-public-v1.json) 和 [recovery-checkpoint-set-v1.json](../../../contracts/fixtures/recovery-checkpoint-set-v1.json)。三语言使用同一组正常执行、重复请求、参数冲突、撤权、超时、预算不足、工具丢响应、只读恢复和取消场景，核对实际发送次数、原回执查询次数、错误分类及终态；另外固定容量边界、未知元数据和分页引用的排序、转义及摘要。各语言内部业务指纹仍须与本语言已发布版本兼容，不能用其他语言的状态对象直接替代历史检查点。

### 调用与恢复

Go 可从已验证执行上下文取得 `CapabilityClient`，调用 `client.Chat(ctx, messages, options)`、`client.SearchKnowledge(ctx, query, scope, options)`。Java 使用 `client.capabilities().chat(messages, options)`。Python 保持现有便捷接口。返回的路由、模型版本、缓存、计费字段应原样保留；缺失字段不推断为零。

持久化搜索要求显式日期。来源列表和日期属于幂等身份，恢复时不得更换。阶段执行器把真实发送放在 `Execute/execute`，把原回执查询放在 `Recover/recover`；不能将调用超时解释为“未发送”。检查点游标的 `begin` 返回恢复标志时，也必须先查原操作回执。CAS 确认失败后重新读取服务器当前头，不以进程内进度覆盖它。

局部截止预算限制应用工作，不能扩大平台预算。自定义执行器应把 SDK 提供的剩余时间传给每次 I/O，并响应取消；SDK 不把仍在执行的线程或协程标记为已退出。受控重试必须由调用方提供已确认的只读或未提交证据，授权失败立即停止。

## 模板与示例

六种模板发布为 1.1.0，内嵌本项目 SDK 公共能力版本 2.1.0。Python 包和 Java 构件版本为 2.1.0；Go 保留现有模块路径，模板直接内嵌对应源码。运行 `python scripts/sync_public_sdks.py --check` 检查副本漂移，修改 SDK 后先运行不带 `--check` 的同步命令。

三个示例发布为 0.3.0，主输入/输出 Schema 为 v3。`input.v2.schema.json`、`output.v2.schema.json` 和旧版本 manifest 保留原字节；旧签名输入继续选择 v2 输出及原恢复指纹，Java 另保留已有 v1 行为。v3 增加 `model_metadata`，只展示平台实际返回的归属信息。Python v3 可选 `as_of`、`source_ids`；缺省仍走 `direct`，不会因为元数据适配而额外调用模型。

固定协作职责不变。新请求选择对应 v3 子契约，历史 v2 请求仍验证 v2 子契约；发布时必须同时保留历史 Catalog 版本、冻结路由及其允许的工作负载版本集合。不得把历史策略原地改成新的 Schema，也不得用重建账号代替授权升级。

三个示例在使用和返回冻结知识之前复核当前引用权限。缺少可验证的历史文档身份时停止恢复并等待核对，不能把未知来源当作已授权。发送边界采用有界并发；可通过 `AGENT_PLATFORM_CAPABILITY_TIMING=1` 开启不包含正文、凭据和原始异常的调用耗时日志。

外部知识服务为可选配置：`PLATFORM_EXTERNAL_KNOWLEDGE_URL`、`PLATFORM_EXTERNAL_KNOWLEDGE_BASE_IDS` 及 `PLATFORM_EXTERNAL_KNOWLEDGE_API_KEY_FILE`。密钥文件路径须属于本项目独立挂载目录，容器内可使用 `/run/secrets/model-providers/` 下的专用文件。变量为空时保留平台自身 PostgreSQL 知识路径；不得填入对照项目服务、凭据或知识库标识。

若本机代理 DNS 返回 `198.18.*` 假 IP，可在本项目环境显式填写 `PLATFORM_MODEL_DNS_OVER_HTTPS_HOSTS_JSON`，列出需要 Google HTTPS IPv4 DNS 的模型域名。解析仅发送域名问题，不发送模型凭据、Prompt 或身份，且不缓存 DNS 答案；未列出的域名仍使用原 DNS。响应的域名链、地址及模型连接仍经过安全校验，TLS 校验继续启用，查询失败不回退到假 IP。留空或 `[]` 保持原行为，不改变主机或其他项目 DNS。协议参见 [Google JSON DNS API](https://developers.google.com/speed/public-dns/docs/doh/json)。

取消补偿与可撤回的本人通知使用显式开关 `PLATFORM_CANCELLATION_COMPENSATION_ENABLED=true`，Compose 已透传，缺省仍为 `false`。启用前须完成显式迁移和对应组件验证；不能把通知工具的 `accepted` 当作消息送达。Kafka 发布、投递记录及本人收件箱分别证明三个边界，费用或工具结果未知时继续保留原状态。

本项目当前部署已显式启用 Kafka 和取消补偿，并使用 SHA 绑定清单保护历史取消、未知工具和人工核对模型记录；原 Kafka 消费组不重置，新的消费组与最低分区偏移一同固定。配置、历史保护及回退方法见[运行说明](notification-cancellation-operations.md)，当前真实业务回归结果见[启用验收](notification-compensation-acceptance-20261022.md)。默认配置继续保持原行为，其他部署不能直接复制本项目的运行标识、消费组或起点。

三个示例已进一步完成正式环境通知送达后撤回、Java/Python 审批等待期间重启续接，以及进程暂停和工具响应丢失后的只读收据恢复，范围和原始证据见[真实恢复补验](native-recovery-acceptance-20261022.md)。供应商未知费用、进程崩溃替换等未注入场景不据此扩充验收结论。

事件读取保持原执行身份及固定部署不变，分别核对当前执行权限与当前历史读取权限；两种权限的版本号独立变化不应误拒合法本人读取。撤权、跨用户、跨父任务、策略不符仍拒绝。浏览器取消仅对已确认的修订冲突进行最多三次重新读取和授权检查，不重发业务操作或模型调用。

## 迁移、部署与回退

数据库从本项目 `2026101004` 追加到 `2026102201`。已发布迁移编号与校验和保留，不采用对照项目的迁移分支，不导入监管业务表。空工具、空知识列表继续表示禁用能力，不能解释为全部允许。

本次先对本项目已有 PostgreSQL、Kafka、Code Runtime 状态卷离线归档，并在独立临时卷还原、比对逐文件哈希。私有备份清单位于本项目 `.tmp/public-capability-upgrade/backups/`；它不属于源码交付。配置中无法读取的文件须单独记录并核实用途，不计作已备份。

完整隔离回归通过后才执行 `python scripts/compose.py upgrade`，再使用本项目 Compose 配置启动平台、前端和三个示例。实际部署还需指定本项目使用的 `--env-file`、`--examples`、`--runtime` 及独立端口；以当前 [部署说明](deployment.md) 和 `python scripts/compose.py --help` 为准。不得对现有卷执行 reset 或删除卷操作。

回退使用备份源码/镜像和对应配置，把归档恢复到新建的本项目回退卷后切换服务。旧程序可能拒绝较新的 Schema 标记，因此不能仅替换旧镜像继续连接已升级数据库；必须先完成对应数据版本的恢复验证。原升级卷保留供核对，禁止覆盖为对照项目卷。

## 回归记录

统一入口 [unit.ps1](../../../scripts/unit.ps1) 已纳入评测 CLI、评测契约模块及 SDK/模板漂移检查。独立依赖回归使用 [verify_public_knowledge_postgres.py](../../../scripts/verify_public_knowledge_postgres.py) 和现有示例回放脚本，生成带唯一 owner 的测试数据库和容器。

首次全量隔离回归用于发现兼容问题，不是通过证明。最终交付须分别记录静态/单元、三语言契约、模板生成、空库初始化、现有数据升级、业务端到端和部署后复验的实际结果。失败、未运行和依赖条件跳过均不计作通过；本文件不预设最终通过结论。
