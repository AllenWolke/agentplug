# Python 文档助手

当前 Agent 为 **0.3.0**，直接安装仓库 **2.1.0** SDK，业务入口位于 `document_assistant/business.py`。Manifest 使用 `schema://example-python-documents/input/v3` 和 `schema://example-python-documents/output/v3`。v3 输出增加平台实际返回的 `model_metadata`；v2 Schema、历史 Manifest 及恢复指纹保留，v1 文件与对应历史 Catalog 也保留。当前业务输入示例：

```json
{"question":"文档增量更新如何保持一致性？","top_k":3,"cache_mode":"use","collaborate":false}
```

v3 可选 `as_of`（规范 `YYYY-MM-DD` 日期）和 `source_ids`（获准来源 ID 列表），用于约束公共知识检索：

```json
{"question":"指定日期前的文档有哪些更新要求？","top_k":3,"cache_mode":"use","as_of":"2026-10-01","source_ids":["python-documents"]}
```

来源和日期必须符合当前知识策略，并参与幂等身份与恢复指纹；续接时沿用原值。业务使用和返回缓存或冻结引用前执行当前权限复核，治理及模型元数据原样保留。接口和兼容规则见[公共能力更新说明](../../docs/releases/public-capabilities-2.1.zh.md)。

`workflow_mode` 可选值为 `direct` 或 `tool_loop`，省略时默认为 `direct`。`direct` 保持现有RAG路径，不增加Function模型循环；`tool_loop` 是显式选择的前置Function流程，会增加模型调用和可能的工具调用用量。`sandbox_check` 与 `notify_me` 默认均为 `false`，显式开启任一选项都要求 `workflow_mode=tool_loop`。最终Token与成本以平台账本为准，输出中的 `tool_loop_usage` 不代表整轮汇总。

`collaborate` 默认 `false`。显式设为 `true` 时，业务在完成原答案工作后，只能通过 SDK `run_agent_group` 请求固定的 `operations.diagnosis` 任务，目标、端点和子输入不能由调用人选择；子请求的 `notify_me`、`sandbox_check`、`collaborate` 均固定为 `false`。组暂停使用实际 handler 退出证明，恢复先读取同一个 gather 并检查当前权限，再按公共 KnowledgeHarness 只读恢复原答案；终态输出前重新读取当前组结果。子输出只作为有界不可信诊断支持，不缓存到业务检查点或问答记忆。五个账号不会自动获得跨 Agent 授权，安装、用户和机器权限仍须分别配置。

知识范围固定为 `python-documents`，用户不能通过业务输入选择模型、知识库、身份或发布策略。平台注入签名策略快照；SDK验签后构建能力上下文，负责HMAC、机器身份头、上下文续期、HTTP边界及协作式取消。平台持久化运行负责查询、幂等、审计、追踪、预算与计费。SDK本地监督为L1，重启缺少退出证明时不确认旧运行停止，不能当成L2/L3恢复。

业务流程复用平台记忆、已发布Prompt、`runtime.inspect`工具及公共 `knowledge/answer`。改写、embedding、Metadata Filter、BM25+pgvector混合检索、Top-K、重排、引用回答及五层Cache全部由平台执行。Agent不连接模型供应商、关系型数据库或Vector DB，也不重新实现索引与权限规则。`runtime.inspect`仅核验执行上下文。

返回完整答案、规范引用和 `evaluation_citations` / `evaluation_claims`，供平台Evaluation运行冻结的检索、引用和接地指标。Agent不计算自己的“正确”结论，也不接收金标准。内置词面蕴含是确定性基线，不能当作完整语义正确性；评测配置、真实数据与最终报告仍由平台管理。

`use`使用平台缓存，`cold`使用独立冷缓存，`bypass`绕过共享缓存；均仍执行当前双身份权限与预算检查。答案生成usage与节省估计分开输出；全运行Token和成本读取平台账本。记忆记录上一条问答，不将历史文本拼进当前知识查询。

自主知识资料位于 `knowledge/handbook.md`。文档负责人通过前端 `/api/modules/knowledge/sources/python-documents` 读取当前源版本，通过 `PUT /api/modules/knowledge/sources/python-documents/documents/{document}` 提交带源版本/文档版本CAS及幂等键的规范源变更；索引由 `/api/modules/knowledge/indexes/python-documents/tasks` 的 `full` / `incremental`任务构建。删除使用版本化墓碑，源及Outbox同事务，连续检查点和发布CAS由平台负责。具体权限、工作空间和安装实例需要管理员显式配置，示例不自行签发管理身份或使用数据库密码。

本目录运行 `python -B -m pytest -p no:cacheprovider tests`；开发安装顺序为 `python -m pip install ../../sdk/python .`。从仓库根构建：

```powershell
docker build -f examples/python-documents/Dockerfile -t agentplug:example-python .
```

`deploy/compose/compose.examples.yaml` 使用独立 `EXAMPLE_PYTHON_CLIENT_ID` / `EXAMPLE_PYTHON_CLIENT_SECRET`，平台公钥及能力网关，无宿主端口；同项目内访问 `http://example-python:8080`。缺少平台校验或机器凭据时拒绝启动，容器以非root运行。部署前须注册并发布不可变 Manifest 版本、创建并部署安装、通过规范知识源接口提交文档并构建索引，再分别配置用户与机器的能力权限。机器凭据由 Identity 工作负载绑定签发，不能复用其他 Agent 的凭据。

## Prompt 绑定、Skill 与公共 RAG

当前 0.3.0 继续保留已发布 Prompt 和 Skill 的接入方式。Tool Loop 将已发布 Prompt 原样保留为唯一 system 消息；业务和安全指引与问题放在第一条 user 消息中，供平台按已发布上下文策略处理。

源码调用SDK run_knowledge_harness，在公共State固定example.documents.guidance版本与citations章节、输入指纹和发送边界。首次进入正常answer_knowledge公共RAG，恢复和完成回放使用原请求的只读恢复入口；ModelCall只查已有改写/Embedding/重排/答案回执，未知或输入/索引变化导致回执无法确认时停止协调，不重新调用供应商。公共五层缓存、引用和独立评测字段继续复用，没有追加第二个模型循环。

skills/guidance.v1.json须由有权人注册、另一有权人审核并发布；实际安装Runtime allowed_skills、用户skill_user/v2绑定及本安装Skill Grant、机器Skill Grant和知识/模型权限须明确配置。该角色和预设从目录 v2 起提供；已有数据库中的 v1 定义及绑定由显式迁移保留。示例能否执行仍须核验实际安装、策略、授权和平台运行结果。

知识Harness检查点不保存答案正文，每次恢复重新按当前模型、Skill、知识文档和执行权限读取结果；恢复用量标注为原调用回执，恢复入口不新发送模型请求。检查点需要明确state.checkpoint授权和公共State配置。此为RAG专用持久边界。五个执行入口及事件实时鉴权的用法见[三语言SDK开发指南](../../docs/开发者指南/三语言SDK业务Agent开发指南.md)。`tool_loop` 是本示例显式选择的 Function 流程；其工具策略、批准配置、预算和授权仍由平台发布与执行，不能由源码分支代替。

## 可选 tool_loop

将输入显式设为 `"workflow_mode":"tool_loop"` 可启用前置Function循环，例如：

```json
{"question":"文档增量更新如何保持一致性？","top_k":3,"cache_mode":"use","workflow_mode":"tool_loop"}
```

该分支使用平台已发布Prompt、`example.documents.guidance` Skill的 `citations` 章节，以及Function别名 `inspect`（映射到 `runtime.inspect`）。它先将Prompt正文/哈希和原始Run输入指纹保存到Run作用域公共检查点 `documents/document-tool-evidence`（schema `schema://example-python-documents/tool-evidence/v1`），再调用SDK `run_harness`（Harness key `document-tools`）。首次Run和批准恢复必须重建相同Harness输入；恢复令牌只从平台签名的 `request.resume_input.confirmation_token` 传给SDK，不能放入业务输入或检查点。

公共Harness每次入口读取当前发布的循环策略，将轮次、工具数、相同工具语义调用次数和绝对运行时限持久绑定到检查点。`incomplete` 的 `termination_reason=MODEL_BUDGET_EXCEEDED` 保持预算错误，`HARNESS_LIMIT_EXCEEDED` 保持运行限额错误；其他不完整或截断输出映射为非重试 `HARNESS_INCOMPLETE`，不伪装成模型预算耗尽。未知派发仍需先查询原回执并进入协调，不会自动降级为部分成功。

如果Function需要批准，SDK `HarnessPause` 只向执行生命周期提交受限的工具名、call ID与Harness key；该次业务调用在等待时不会进入RAG，也不会读写问答记忆。批准恢复后完成原Harness循环，再调用独立的公共 `knowledge/answer` 和 `KnowledgeHarness`，继续使用平台缓存、规范引用与Evaluation字段。前置Function流程可能调用模型选择 `inspect`，业务还会执行一次显式 `runtime.inspect` 来填充 `context_checks`；即使模型已选择该函数，也可能有重复检查。`direct` 路径仍是默认值，不经过额外Function模型循环。

源码将Prompt正文及哈希、原Run输入指纹写入Run作用域检查点；Harness每次准备模型上下文时会校验平台返回的Prompt哈希与该冻结值一致，不一致即停止。批准恢复使用相同Harness输入和检查点，确认令牌只从签名的 `resume_input.confirmation_token` 传入，不保存到检查点。RAG阶段由独立KnowledgeHarness管理自己的Skill、输入与回执，不宣称与前置Function Prompt共用同一版本。

部署该流程前，应将输入/输出Schema随不可变Catalog版本发布，并配置 Function 别名 `inspect` 到 `runtime.inspect` 的映射、工具与模型策略、Skill绑定、Run checkpoint权限及平台批准/恢复路径。证据检查点的Schema ID由公共State核验谱系，没有独立Schema注册API。源码检查点不等同于策略发布、批准凭证或用户/机器授权。

## 可选本人通知与独立批准

`notify_me`默认false。显式请求通知时同时设置`workflow_mode=tool_loop`：

```json
{"question":"文档增量更新如何保持一致性？","workflow_mode":"tool_loop","notify_me":true}
```

Function `notify_self`映射公共写工具`notify.self`，参数仅title/text，平台从可信人类Scope选定当前调用人，拒绝业务或模型提供收件人。通知描述本次检索请求，不冒充尚未生成的引用答案；工具返回Outbox受理事实，不宣称已送达。模型不保证选择该工具，输出`notify_me`仅回显请求，不能当作通知执行证明。

工具进入原Harness FIFO后，需要本人在独立控制面执行pending→preview→再次认证→approve→显式resume，业务不生成批准Token，也不把Token放入业务input或检查点。等待阶段不进入RAG、不保存问答记忆，恢复继续原输入、原模型/工具回执。启用前须将 `notify_self` 参数Schema、`notify.self` 工具和强制确认配置发布到不可变 ToolPolicy，并分别授予调用人和绑定机器 `tool.invoke` 权限；缺少配置时平台应拒绝操作。

## 可选 Code Runtime 检查

显式设置 `sandbox_check=true` 并同时设置 `workflow_mode=tool_loop`，可让公共 Function Harness 提供 `sandbox_python`：

```json
{"question":"文档中的金额合计是多少？","workflow_mode":"tool_loop","sandbox_check":true}
```

`sandbox_python` 映射到平台 `code.python`，函数参数只有 `code` 字符串。系统提示只允许提交短小、只读的 Python 分析，禁止访问文件、网络、环境变量、凭据或密钥，也不允许副作用。业务只通过公共 Harness 请求该函数，不直连 Code Runtime 控制器。若平台要求确认，沿原 FIFO 批准暂停；令牌只从签名恢复请求的 `resume_input.confirmation_token` 瞬时传入，工具恢复使用平台只读回执。Skill 中的 `code_runtime` 章节仅在显式开启时披露。

模型不保证会选择 `sandbox_python`；返回的 `sandbox_check` 只是用户选项回显，不是函数已调用或执行成功的证明。沙箱输出在 Harness 中作为不可信工具观察值使用，最终文档回答仍由公共 RAG 和引用流程生成。Manifest 声明 `tool.invoke:code.python`，release-bundle 可生成 `sandbox_python` 到 `code.python` 的策略片段和仅含 `code` 参数的独立确认草案；启用时须按实际安装发布 ToolPolicy、Code Runtime Profile/控制器绑定，以及用户与机器权限。片段本身不创建授权。

## 可选固定 AgentGroup 协作

```json
{"question":"文档增量更新如何保持一致性？","collaborate":true}
```

此选项复用平台固定路由 `operations.diagnosis`，并将 `service=python-documents`、固定的诊断支持请求、有界上游问题观察（最多 600 字符）及三个禁用子选项写入有序计划检查点。该 route 是此 Agent 的出站子任务；Manifest 对外接收类型仍只有 `documents.answer`。子请求固定要求“最多三点可引用的只读诊断支持要点”：`operations.diagnosis` 任务类型的模型输出预算由已发布模型配置固定，把整段上游问题原样转发会让诊断答案超出该有限预算，而 Go 业务会正确拒绝被截断的诊断，因此子输入必须保持有界。平台仍需为当前用户和绑定机器分别配置路由、Agent invoke、State 与知识读取权限；业务不签发跨 Agent 授权、不接受调用者指定目标或 endpoint。若子 Agent 未完成，SDK 只保存固定 gather 引用并在实际 handler 退出后暂停；继续时必须消费原 gather，重建答案仅通过已有 RAG 回执与当前 ACL 进行，不重跑已不确定的模型/工具副作用。每次最终返回前都会重新读取组结果，子结果作为不可信支持披露。

当前 `input.schema.json` / `output.schema.json` 与 Manifest 指向 v3，旧 v2 和 v1 文件及对应历史 Catalog 保留。启用协作前须发布匹配的 Catalog 版本与固定路由：新 v3 请求使用 v3 子契约，历史 v2 续接保留 v2 子契约。调用人、父机器和目标机器分别配置 AgentGroup、State 和知识权限；Schema 文件本身不发布 Catalog、路由或授权。

## Python 执行生命周期与事件读取

`document_assistant/server.py` 当前通过共享的 `ExecutionTaskRegistry` 将 invoke、run、resume、cancel、events 五个 Hook 接入 SDK FastAPI 工厂，`manifest.json` 也声明这五项能力。events 在本地验证签名后，每次披露前向平台私有事件守卫核对当前权限；仅返回最多 256 条受限元数据，不披露原业务输出、工具参数或令牌。终态事件要求本进程持有该世代的实际退出证明。

浏览器认证的 `POST /platform/runs/{id}/event-capability` 从实际 Run 派生 events-only `EventRequest`，并检查当前用户与绑定机器的 `history.read` 权限。它只返回事件请求与短时 events 令牌，不提供任意 Agent 端点或工作负载密钥。

事件代理、批准/继续/撤销及原Run状态读取须在部署环境配置可达的Agent端点、平台签名材料和对应身份权限；事件列表每次读取都重新检查当前授权。运行状态与退出证明仍为 `process-local-L1`，因此进程重启不会恢复本地处理器或事件投影；跨进程继续必须依赖平台持久Run、真实停止证明、当前检查点和重新核验的授权。本文中的 `tool_loop` 需发布对应不可变Schema、策略与机器绑定后才能使用。操作步骤见[三语言SDK开发指南](../../docs/开发者指南/三语言SDK业务Agent开发指南.md)与[安装授权指南](../../docs/开发者指南/业务Agent挂载与已有用户授权指南.md)，事件序号边界见[SDK执行世代事件协议](../../contracts/sdk-event-ranges.md)。
