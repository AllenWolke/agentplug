# 公共通用能力：应该复用什么

[入门路线](README.md) · [English](../en/capabilities.md)

业务 Agent 写领域判断、工作流和业务输出。身份验证、模型路由、知识检索、运行生命周期等使用平台和 SDK。以下方法名来自 [Python CapabilityGatewayClient](../../../sdk/python/agent_platform_sdk/capability_client.py)；Go / Java 对应实现见 [Go SDK](../../../sdk/go/)和 [Java SDK](../../../sdk/java/)。Python 能力方法是异步调用，要 `await`。

## 能力选择表

| 需求 | 接入点 | 前置条件与影响 |
| --- | --- | --- |
| 模型对话、Embedding | `chat`、`embed` | 批准的 ModelVersion、PriceVersion、模型策略和两类主体授权；产生模型用量与内部计价 |
| 平台工具驱动的多轮推理 | `generate_with_functions`、`run_harness` | Runtime / 工具策略限定函数和轮次，不能直接传供应商 SDK 绕开 |
| 版本化 Prompt | `resolve_prompt` | 当前已发布 Prompt 资产；不把任意浏览器文本作为受信策略 |
| 执行业务工具 | `invoke_tool` | 已批准工具、参数约束、风险和确认规则；可能修改外部系统 |
| 查询企业知识 | `search_knowledge`、`run_knowledge_harness`、`answer_knowledge` | 可用源和索引、Embedding、知识策略、当前用户与机器 ACL；返回来源与检索证据 |
| 读取 / 保存记忆 | `memory_load`、`memory_save` | 受控 namespace、key、Schema 和作用域，不能跨租户共享裸缓存 |
| 检查点与恢复 | `load_checkpoint`、`save_checkpoint`、`load_recovery_checkpoint` | 匹配安装 / 运行 / Schema 的权限和恢复引用，不能只存一个无归属字符串 |
| 检查执行仍然有效 | `validate_current_execution` | 当前安装、绑定、运行及授权有效；长流程中不能永远依赖开始时的 Token |
| 加载 Skill | `load_skill`、`load_skill_bindings` | 已发布 Skill、Runtime 允许范围、Skill 资源权限 |
| 委派和协作 | `run_agent_group` 及协调接口 | 委派、子安装和资源授权、父子预算与取消协议 |

是否需要某能力由业务决定。例如确定性规则 Agent 不需要为了“复用充分”强行调用模型。验收应要求所有**实际需要的基础能力**复用正确，并解释未使用的能力。

## 可信上下文的正确来源

完整例子的接线见 [Python server.py](../../../examples/python-documents/document_assistant/server.py)：先由 SDK 验证执行上下文，再从验证结果构造 `CapabilityContext.from_verified` 和能力客户端。具体构造参数以当前 SDK 为准；不要用客户端传来的租户 ID 拼一个“已验证”上下文。

模型供应商凭据只挂载到平台。业务 Agent 使用自己的工作负载凭据、平台公钥、能力网关地址和安装绑定。**不复制平台 `.env` 到 Agent，不向 Agent 发平台数据库 DSN 或私钥。**

## 知识检索并非 Agent 自查数据库

公共知识流程管理源版本、解析 / 分块、索引代次和发布投影；检索可以结合向量、关键词、融合及相应检索策略。Agent 提供业务问题、获准 Scope、Top K 和缓存模式，使用检索结果与引用。

参考 [document_assistant/business.py](../../../examples/python-documents/document_assistant/business.py)。同样的调用代码是否真正有效，取决于目标安装绑定、实际文档、Embedding 和当前 ACL；空绑定不会因为示例运行过就自动获得可检索内容。

## 副作用、超时和费用

`invoke_tool(..., confirmed=True)` 不等于取得平台审批。对于有副作用的工具，遵守平台确认、提交和收据协议。请求超时且结果未知时先查询原操作收据，不能无条件重试转账、发信或其他外部写入。

平台模型价格是内部计价参数，不是供应商账单保证。超时结果和历史预留按原证据对账，不能用重新发送模型请求来“补账”。父子 Agent 共享运行树预算，业务工作流仍须约束轮数和委派规模。

## 复用验收

交付报告记录“业务需求 → SDK 方法 / 公共组件 → 资源策略和授权 → 实际测试证据”。检查有没有自行实现 JWT 校验、角色表、模型网关、向量库直连、运行状态机、工具审批或跨租户记忆缓存；发现重复实现时，用平台接口替换，或明确需要新增的扩展端口。

仓库内 `python scripts/check_agent_code_ownership.py` 检查已登记目录，**不会自动覆盖外部业务仓库**。新业务 Agent 还需按上述映射审查实际源码与依赖；不能把该脚本成功当作完整复用验收。
