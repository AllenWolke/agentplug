# 公共通用能力：应该复用什么

[入门路线](README.md) · [English](../en/capabilities.md)

当前仓库 SDK 公共能力版本为 **2.1.0**，六种模板为 **1.1.0**，三个业务示例为 **0.3.0 / v3 Schema**。本次功能、示例调整及缺陷修复见[公共能力更新说明](../../releases/public-capabilities-2.1.zh.md)；升级与历史兼容细节见[升级指南](public-capabilities-upgrade.md)。

业务 Agent 写领域判断、工作流和业务输出。身份验证、模型路由、知识检索、运行生命周期等使用平台和 SDK。以下接入点使用 [Python CapabilityGatewayClient](../../../sdk/python/agent_platform_sdk/capability_client.py)及 SDK 公共辅助函数；Go / Java 对应实现见 [Go SDK](../../../sdk/go/)和 [Java SDK](../../../sdk/java/)。Python 能力方法是异步调用，要 `await`。

## 能力选择表

| 需求 | 接入点 | 前置条件与影响 |
| --- | --- | --- |
| 模型对话、Embedding | `chat`、`embed` | 批准的 ModelVersion、PriceVersion、模型策略和两类主体授权；产生模型用量与内部计价 |
| 结构化最终生成 | `chat(..., require_json=True, response_schema=...)` | 模型与发布策略支持对应格式；与 Function Calling 分开请求 |
| 平台工具驱动的多轮推理 | `generate_with_functions`、`run_harness` | Runtime / 工具策略限定函数和轮次，不能直接传供应商 SDK 绕开 |
| 版本化 Prompt | `resolve_prompt` | 当前已发布 Prompt 资产；不把任意浏览器文本作为受信策略 |
| 执行业务工具 | `invoke_tool` | 已批准工具、参数约束、风险和确认规则；可能修改外部系统 |
| 查询企业知识 | `search_knowledge`、`run_knowledge_harness`、`answer_knowledge` | 可用源和索引、Embedding、知识策略、当前用户与机器 ACL；返回来源与检索证据 |
| 读取 / 保存记忆 | `memory_load`、`memory_save` | 受控 namespace、key、Schema 和作用域，不能跨租户共享裸缓存 |
| 检查点与恢复 | `load_checkpoint`、`save_checkpoint`、`load_recovery_checkpoint` | 匹配安装 / 运行 / Schema 的权限和恢复引用，不能只存一个无归属字符串 |
| 检查点容量与进度 | `CheckpointCursor`、SDK 恢复引用分页 | 容量协商、配额及 CAS；恢复先读取原进度和回执 |
| 持久化阶段与步骤 | `DurableStageClient`、`run_step_workflow` | 绑定原操作身份、批处理窗口和截止时间，只有已确认安全的调用才能重试 |
| 当前引用权限 | `authorize_references`、`authorize_cached_result` | 在使用和返回缓存、冻结知识前重新核验当前用户及工作负载权限 |
| 运行策略 | `load_execution_policy`、`load_harness_policy` | 读取平台已发布的执行边界，不由业务输入扩大工具、预算或并发 |
| 检查执行仍然有效 | `validate_current_execution` | 当前安装、绑定、运行及授权有效；长流程中不能永远依赖开始时的 Token |
| 加载 Skill | `load_skill`、`load_skill_bindings` | 已发布 Skill、Runtime 允许范围、Skill 资源权限 |
| 委派和协作 | `run_agent_group` 及协调接口 | 委派、子安装和资源授权、父子预算与取消协议 |

是否需要某能力由业务决定。例如确定性规则 Agent 不需要为了“复用充分”强行调用模型。验收应要求所有**实际需要的基础能力**复用正确，并解释未使用的能力。

## 三语言接口对应

Go 方法由已验证的 `CapabilityClient` 及其 `PublicCapabilities()` 门面提供；Java 通过 `client.capabilities()` 调用；Python 保留异步客户端接口。三语言使用相同的身份、预算、错误和恢复语义，具体参数保留各语言惯用形式。

| 能力 | Python | Go | Java 公共门面 |
| --- | --- | --- | --- |
| 对话 / Embedding | `chat` / `embed` | `Chat` / `Embed` | `chat` / `embed` |
| Prompt | `resolve_prompt` | `ResolvePrompt` | `resolvePrompt` |
| 记忆 | `memory_load` / `memory_save` | `MemoryLoad` / `MemorySave` | `memoryLoad` / `memorySave` |
| 知识搜索 / 回答 / 回放 | `search_knowledge` / `answer_knowledge` / `replay_knowledge` | `SearchKnowledge` / `AnswerKnowledge` / `ReplayKnowledge` | `searchKnowledge` / `answerKnowledge` / `replayKnowledge` |
| 当前引用授权 | `authorize_references` / `authorize_cached_result` | `AuthorizeReferences` / `AuthorizeCachedResult` | `authorizeReferences` / `authorizeCachedResult` |
| 持久化知识流程 | `run_knowledge_search` / `run_knowledge_harness` | `RunKnowledgeSearch` / `RunKnowledgeHarness` | `KnowledgeWorkflow.search` / `answer` |
| 执行策略 | `load_execution_policy` | `LoadExecutionPolicy` | `loadExecutionPolicy` |

这些接口补齐 Go/Java 对 Python 公共能力的支持，不要求为每种语言各写一份模型或知识网关。结构化输出示例和恢复约束见[SDK 2.1 接入说明](../../开发者指南/三语言SDK业务Agent开发指南.md#sdk-21-公共能力接入)。

Python 的引用授权是 [reference_authorization](../../../sdk/python/agent_platform_sdk/reference_authorization.py) 模块中的辅助函数，例如 `await authorize_cached_result(client, result, knowledge_scope)`，传入已有受信客户端，不是 `client` 的同名方法。

## 模型路由、格式和元数据

模型自动选择、候选质量准入和故障切换由发布策略控制，默认继续使用配置好的模型。显式 JSON Schema 使用 `required` 模式，或在业务允许时选择 `prefer_supported`；后者按平台兼容规则处理，业务仍须校验最终内容。最终 JSON 生成与请求函数列表分成不同调用，不在同一请求叠加不兼容约束。

保留响应中实际存在的 `model_version_id`、`routing`、`route_execution`、`context_cache` 和 `billing` 字段。缓存 Token 采用已发布价格，未知费用与缺失元数据不补为零。业务不能通过模型偏好绕过安装允许的版本集合。

## 可信上下文的正确来源

完整例子的接线见 [Python server.py](../../../examples/python-documents/document_assistant/server.py)：先由 SDK 验证执行上下文，再从验证结果构造 `CapabilityContext.from_verified` 和能力客户端。具体构造参数以当前 SDK 为准；不要用客户端传来的租户 ID 拼一个“已验证”上下文。

模型供应商凭据只挂载到平台。业务 Agent 使用自己的工作负载凭据、平台公钥、能力网关地址和安装绑定。**不复制平台 `.env` 到 Agent，不向 Agent 发平台数据库 DSN 或私钥。**

## 知识检索并非 Agent 自查数据库

公共知识流程管理源版本、解析 / 分块、索引代次和发布投影；检索可以结合向量、关键词、融合及相应检索策略。Agent 提供业务问题、获准 Scope、Top K 和缓存模式，使用检索结果与引用。

参考 [document_assistant/business.py](../../../examples/python-documents/document_assistant/business.py)。同样的调用代码是否真正有效，取决于目标安装绑定、实际文档、Embedding 和当前 ACL；空绑定不会因为示例运行过就自动获得可检索内容。

`as_of`、`source_ids` 纳入持久化检索的幂等身份与恢复指纹；恢复使用相同日期、来源和输入。使用冻结结果前调用当前引用授权接口，返回给用户之前再次复核。检索回放只读原操作及其回执，不重新发送未知模型调用。外部知识服务使用独立配置，留空仍走原生 PostgreSQL 知识路径。

## 副作用、超时和费用

`invoke_tool(..., confirmed=True)` 不等于取得平台审批。对于有副作用的工具，遵守平台确认、提交和收据协议。请求超时且结果未知时先查询原操作收据，不能无条件重试转账、发信或其他外部写入。

平台模型价格是内部计价参数，不是供应商账单保证。超时结果和历史预留按原证据对账，不能用重新发送模型请求来“补账”。父子 Agent 共享运行树预算，业务工作流仍须约束轮数和委派规模。

## 通知、审批与取消

三个示例的本人通知、沙箱和固定协作仍由输入开关及发布授权决定。高风险工具审批暂停时，SDK 退出当前处理器；续接核验原任务、检查点、当前授权和新的执行租约。业务不自行构造批准凭证。

Kafka 通知的 Outbox 发布、投递和本人收件箱送达是独立状态。取消补偿可将已送达通知标记为撤回并保留原文与收据；取消完成还要求实际停止证明及预算关闭。恢复保护与消费组起点的配置见[通知和取消运行说明](notification-cancellation-operations.md)。新环境的开关、配置和资源均须独立准备，不复制其他部署的身份或消费位置。

## 复用验收

交付报告记录“业务需求 → SDK 方法 / 公共组件 → 资源策略和授权 → 实际测试证据”。检查有没有自行实现 JWT 校验、角色表、模型网关、向量库直连、运行状态机、工具审批或跨租户记忆缓存；发现重复实现时，用平台接口替换，或明确需要新增的扩展端口。

仓库内 `python scripts/check_agent_code_ownership.py` 检查已登记目录，**不会自动覆盖外部业务仓库**。新业务 Agent 还需按上述映射审查实际源码与依赖；不能把该脚本成功当作完整复用验收。
