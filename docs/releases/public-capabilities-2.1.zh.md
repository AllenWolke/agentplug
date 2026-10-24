# 公共能力、SDK 2.1 与示例 Agent 更新

[项目首页](../../README.md) · [开发者路线](../developer/zh/README.md) · [English](public-capabilities-2.1.en.md)

本次更新把模型治理、知识与工具、持久化工作流、授权和取消恢复收敛到公共平台与三语言 SDK。业务 Agent 通过受信客户端调用公共能力，继续负责自己的业务输入、流程和输出。本文介绍功能变化、接入方式和兼容边界，不包含具体部署的账号、凭据或运行记录。

## 新增和完善的公共能力

| 领域 | 更新内容 | 开发者接入要点 |
| --- | --- | --- |
| 模型选择与调用 | 自动路由、候选质量准入、可用性检查、有限故障切换、物理尝试记录及供应商协议适配 | 默认沿用已配置模型；自动选择由已发布策略显式启用，Agent 不自行替换供应商 |
| 结构化输出与费用 | JSON Schema 输出、前缀缓存、缓存 Token 价格及实际模型/路由/计费元数据 | 结构化最终生成与 Function Calling 分开请求；字段缺失或费用未知不能解释为零 |
| 工作流与恢复 | 扩展 Harness、步骤工作流、持久化阶段调用、原批处理窗口、截止预算、有界并发和受控重试 | 恢复沿用原输入、窗口、操作身份及截止时间；已提交但结果未知的调用只查询原回执 |
| 检查点 | 容量协商、额度预留、CAS 游标、恢复引用分页及跨作用域校验 | 使用 SDK 的游标和分页接口；CAS 冲突后读取当前头，不覆盖为进程内旧状态 |
| 知识与引用 | 受控多来源融合、持久化搜索/回答、只读检索恢复、索引回执、缓存及冻结引用的当前权限复核 | 来源和日期纳入幂等身份；已有引用或缓存命中不替代当前用户与工作负载授权 |
| 远端工具 | 操作身份绑定、幂等有效期及原操作只读收据契约 | 丢响应后查询同一操作，不用新身份重发；工具接受请求不代表副作用已经完成 |
| 组织治理 | 部门 Agent 使用审批包、工作负载版本集合、本人增权限制与持续授权检查 | 保留公司、部门、成员和批量授权接口；成员关系或管理角色不自动授予运行权 |
| 通知与取消 | Kafka 通知投递、本人收件箱、已送达通知撤回、取消补偿、持久化停止确认和预算关闭证明 | 按部署配置启用；分别确认发布、投递和送达，取消完成需要停止、补偿及预算证据 |
| 观测与评测 | 阶段性能观测、评测案例复用及独立审核验证 | 保留实际归属与阶段信息；Agent 不读取金标准或自行声明质量通过 |

连接复用、发送边界限流、纯解码缓存及已确认回滚事务重试同步到公共实现。授权决定不作为解码缓存；未知提交不能进入自动重试。

## 三语言 SDK 与六种模板

仓库 SDK 公共能力版本为 **2.1.0**，六种模板为 **1.1.0**。Go、Java 补齐 Python 已有的模型对话、Embedding、Prompt、知识搜索/回答/回放及记忆便捷接口；三语言共同支持结构化输出、执行策略读取、持久化知识流程、引用授权、检查点游标和分页恢复。

| 能力 | Python | Go | Java |
| --- | --- | --- | --- |
| 模型与向量 | `client.chat` / `embed` | `client.Chat` / `Embed` | `client.capabilities().chat` / `embed` |
| Prompt 与记忆 | `resolve_prompt` / `memory_load` / `memory_save` | `ResolvePrompt` / `MemoryLoad` / `MemorySave` | `resolvePrompt` / `memoryLoad` / `memorySave` |
| 知识搜索、回答及回放 | `search_knowledge` / `answer_knowledge` / `replay_knowledge` | `SearchKnowledge` / `AnswerKnowledge` / `ReplayKnowledge` | `searchKnowledge` / `answerKnowledge` / `replayKnowledge` |
| 引用权限 | `authorize_references` / `authorize_cached_result` | `AuthorizeReferences` / `AuthorizeCachedResult` | `authorizeReferences` / `authorizeCachedResult` |
| 阶段和步骤编排 | `DurableStageClient` / `run_step_workflow` | `DurableStageClient` / `RunStepWorkflow` | `DurableStageClient` / `StepWorkflow.run` |
| 检查点进度 | `CheckpointCursor` | `OpenCheckpointCursor` | `CheckpointCursor.open` |

Go 方法位于 `CapabilityClient` 或其公共能力门面；Java 便捷方法由 `client.capabilities()` 提供。Python 引用授权是 `reference_authorization` 模块的辅助函数，调用时传入已有客户端。客户端必须来自 SDK 已验证的执行上下文，不能用浏览器传来的身份字段直接构造。LangGraph 专用适配保留在 Python，通用恢复隔离和状态保护由三语言各自实现。

模板包括 `go-generic`、`go-eino`、`python-generic`、`python-langgraph`、`java-generic` 和 `java-spring-ai`。从当前 `agentctl` 生成工程，保留对应的 `template.lock`、SDK 副本及依赖版本；升级 SDK 后同步模板，不单独替换受管理的入口文件。Go 保留原模块路径，Java/Python 按仓库构建与安装说明使用。

接口用法见[公共能力指南](../developer/zh/capabilities.md)和[三语言 SDK 指南](../开发者指南/三语言SDK业务Agent开发指南.md)。

## 三个示例 Agent 的调整

三个示例当前均为 **0.3.0**，主输入和输出 Schema 为 **v3**，执行协议仍为 `agent-execution/v2`。

| 示例 | 调整内容 | 保留的业务行为 |
| --- | --- | --- |
| [Go 运维诊断](../../examples/go-operations/README.md) | 公共调用改用 SDK 便捷接口；使用和返回冻结知识证据前复核当前权限；保留模型归属元数据，并接入统一恢复、限流与阶段观测 | 根据服务、症状和观察生成只读诊断建议；原工具开关及固定文档协作计划保持有效 |
| [Java 工单助手](../../examples/java-tickets/README.md) | 公共能力调用收敛到 SDK；冻结引用重新鉴权；按统一协议处理审批续接、回执恢复及模型元数据 | 生成工单回复草稿和建议；工单正文作为数据处理，协作目标由固定计划确定 |
| [Python 文档问答](../../examples/python-documents/README.md) | 增加 v3 可选 `as_of`、`source_ids`；来源和日期绑定幂等与恢复指纹；接入统一引用校验和治理元数据 | `direct` 仍为默认流程，`tool_loop` 仍显式选择；通知、沙箱和协作按原开关及授权启用 |

v3 输出新增 `model_metadata`，保留平台实际返回的模型、路由、缓存和计费信息。历史 v2 Schema、Manifest 和恢复读取能力保留；Java 另保留原 v1 路径。历史请求沿用对应的旧输出契约和指纹，不原地改写 Catalog 或检查点。

## 缺陷修复与兼容处理

- 修复运行权限与历史读取权限版本独立变化时，合法本人事件读取被误拒的问题；撤权和跨用户读取仍被拒绝。
- 修复浏览器取消的修订冲突处理：仅对明确的版本冲突有界重新读取并复核授权，业务操作和模型请求不随之重发。
- 增加历史自动恢复隔离与 Kafka 消费起点保护，避免启用通知和取消补偿时自动推进历史未知工具、取消任务或未确认费用。
- 为代理 DNS 返回假 IP 的环境提供可选模型域名 DoH 配置。仅解析显式允许的公共域名，保留 TLS 和地址安全校验。
- 统一 CI 与活动镜像的 Go 1.26.10 工具链，升级 `klauspost/compress` 至 1.18.7，修复相关安全依赖问题。
- 完善 GitHub Actions 手动触发、SDK/模板同步及隐藏目录报告上传配置；补齐 Python ASGI 启动依赖，修正辅助进程临时目录执行权限。

## 配置与升级

新增能力不会自动创建模型资产、知识绑定、工具映射或组织授权。先发布对应策略及资源，再将新 Agent 版本部署到目标安装。

| 场景 | 配置或操作 |
| --- | --- |
| 自动模型选择、结构化输出、缓存价格 | 在模型、价格及安装策略中发布相应能力；业务输入不覆盖供应商或价格 |
| 通知和取消补偿 | 核对 `PLATFORM_EVENT_BUS_MODE`、Kafka 投递配置及 `PLATFORM_CANCELLATION_COMPENSATION_ENABLED`；补偿默认 `false`，事件总线沿用部署配置 |
| 已有数据环境启用后台恢复 | 先备份并配置 SHA 绑定的历史恢复保护及消费起点，保留原消费组与未知记录；按[运行说明](../developer/zh/notification-cancellation-operations.md)办理 |
| 外部知识服务 | 独立配置 `PLATFORM_EXTERNAL_KNOWLEDGE_URL`、`PLATFORM_EXTERNAL_KNOWLEDGE_BASE_IDS` 及密钥文件；留空使用平台原生知识路径 |
| 可选模型 DNS | `PLATFORM_MODEL_DNS_OVER_HTTPS_HOSTS_JSON` 显式指定域名；留空沿用普通 DNS，`[]` 禁用此扩展 |
| 调用耗时观测 | Agent 可使用 `AGENT_PLATFORM_CAPABILITY_TIMING=1`，日志不包含正文或凭据 |

迁移沿本项目已发布版本追加，保留原编号和校验和。公司、部门、成员、批量授权和前端入口保持兼容；显式空工具或空知识列表继续表示不使用这些能力。未知费用、工具结果及提交结果继续保留未知，不按零结算或自动重放。

部署与数据版本处理见[部署指南](../developer/zh/deployment.md)、[配置参考](../developer/zh/configuration.md)及[升级说明](../developer/zh/public-capabilities-upgrade.md)。已有环境保留现有账号、授权和历史数据，新功能通过版本化资产接入。
