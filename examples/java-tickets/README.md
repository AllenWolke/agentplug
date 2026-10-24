# Java 工单助手

直接依赖仓库 `sdk/java/agent-platform-sdk`。业务仅生成带知识引用的工单回复草稿和建议，不连接工单系统、不提交或关闭工单，也不连接模型厂商或平台数据库。

当前 Agent 为 **0.3.0**，使用仓库 **2.1.0** SDK。Manifest 选择 `schema://example-java-tickets/input/v3` 与 `schema://example-java-tickets/output/v3`；`input.schema.json` / `output.schema.json` 是当前 v3 文件。v3 输出增加 `model_metadata`，保留实际模型、路由、缓存与计费归属。旧 v2 和 v1 契约分别保存在对应版本文件，原输入沿用对应输出和恢复指纹，不覆盖历史 Catalog。业务输入保留工单字段及可选 `notify_me`、`sandbox_check`、`collaborate`，三个开关默认均为 false。输入 Schema 的字符长度是外层约束；Java 业务还检查 UTF-8 字节上限和不完整 Unicode。用户不能通过输入更换模型、身份、工具、知识库或协作目标。

公共调用收敛到 `CapabilityClient.capabilities()` 及 SDK 工作流。使用冻结知识和最终返回引用前分别调用 `authorizeCachedResult` 复核当前权限；审批续接、未知调用的原收据恢复、限流和阶段观测使用公共语义。完整变化和配置见[公共能力更新说明](../../docs/releases/public-capabilities-2.1.zh.md)。

业务依次复用公共记忆读取、已发布 Prompt、`runtime.inspect` 工具、`java-tickets` 知识检索、模型生成和记忆保存。SDK 负责上下文验签、请求绑定、HMAC、机器凭据、能力续期及运行生命周期；平台负责双身份与数据范围授权、模型幂等、预算、账本、审计和追踪。工具只检查可信执行上下文，不代表任何宿主或外部工单系统健康。

在仓库根使用 JDK 21 和 Maven 执行：

```sh
mvn -f sdk/java/pom.xml -pl :example-java-tickets -am package
java -cp 'examples/java-tickets/target/*:examples/java-tickets/target/lib/*' com.lexagent.examples.tickets.TicketAgent
```

Windows 的 Java classpath 分隔符使用 `;`。运行前配置 `AGENT_PLATFORM_PUBLIC_KEY_BASE64`、`PLATFORM_CAPABILITY_URL`、`INTERNAL_TOKEN`、`INTERNAL_SIGNING_SECRET`、`AGENT_CLIENT_ID` 和 `AGENT_CLIENT_SECRET`，可用 SDK 支持的对应 `_FILE` 挂载配置代替凭据环境变量。缺少平台公钥、网关或机器身份时拒绝启动；配置错误不打印密钥。

签发者默认 `platform`，audience 默认 `agent-runtime`，必须与平台一致。Agent ID 独立固定为 `example-java-tickets`，SDK 校验签名绑定的 Agent ID，其他 Agent 的合法凭据不能进入本助手。

从仓库根构建 `docker build -f examples/java-tickets/Dockerfile -t agentplug:example-java .`。`deploy/compose/compose.examples.yaml` 中的 Java 服务使用独立 `EXAMPLE_JAVA_CLIENT_ID`、`EXAMPLE_JAVA_CLIENT_SECRET`，通过同项目网络 `http://example-java:8080` 访问，没有宿主端口。启动前须使用实际镜像摘要注册并发布不可变 Manifest 版本，创建并部署目标安装，再将该安装签发的机器身份配置到服务；授权按[挂载与授权指南](../../docs/开发者指南/业务Agent挂载与已有用户授权指南.md)分别配置。

本目录 `knowledge/handbook.md` 为自主教学资料，通过平台知识源和索引管理接口发布后，需要在知识策略绑定文档，并分别授予调用用户和 Agent 机器身份检索权限。

SDK `MemoryRunStore` 是进程内 L1，进程重启不保留 Agent 本地事件。平台持久化的业务运行、模型幂等和记忆不等同于 Agent 本地运行恢复。业务在每次公共能力请求前后检查取消；取消请求不证明发送中的模型请求已停止或账本已结清，应结合平台运行状态和用量账本判断，不能将协作取消直接作为模型停止或结算的证明。

## 公共 Harness 与 Skill 工作流

工作流先加载本Run的tickets/draft-evidence公共检查点，不存在时收集记忆、Prompt、runtime.inspect和授权知识，以expected_revision=0和稳定操作键冻结。Schema为schema://example-java-tickets/evidence/v1；业务摘要绑定ticket_id/summary/details及幂等键。恢复复用首次JSON证据与Prompt，不因记忆或检索变化改写模型输入。单份冻结对象最多240KiB，证据JSON最多128KiB。

模型步骤直接调用仓库SDK runHarness，使用ticket-model检查点、最多四轮/八次工具，先加载example.tickets.guidance摘要和draft章节。模型Function别名inspect要求发布策略显式映射到runtime.inspect及固定参数Schema；SDK解析模型调用，公共Runtime执行并返回不可信Observation。缺少发布配置时平台拒绝。

只有completed输出继续保存草稿记忆；approval_required使用SDK HarnessPause停在waiting并退出当前处理器。平台批准后的签名resume_input.confirmation_token仅供当前恢复使用，SDK核验同一业务输入、真实退出的waiting世代和新的修订/租约，再注入新客户端继续原检查点；批准Token/完整工具参数不进入生命周期事件。已有恢复请求回放不新建处理器，未知或其他未完成状态停止。`MemoryRunStore`是L1；进程重启后仅有检查点不足以证明旧处理器停止。该Agent只返回回复草稿和建议，不会提交、转派或关闭工单。平台在模型发送、返回及回执恢复时复查Skill依赖和当前授权，账本记录真实用量。

skills/guidance.v1.json需人工注册、另一有权人审核，再发布稳定/灰度版本。Runtime allowed_skills、用户skill_user/v2绑定和本安装Skill Grant、机器身份Skill Grant，以及现有知识/工具权限都需明确配置。公共State读写、TTL/配额和上下文窗口须随正式发布配置。仅有Skill资料不授予能力。

发布前将 release-bundle 输出的 Function/策略片段合并到完整六类策略资产，审核后发布不可变策略版本；需要 Code 时另行配置目标安装的 Code binding/Profile，并为当前用户和机器身份分别授予所需资源权限。片段不会创建授权或形成完整策略。进程内 L1 RunStore 不提供跨进程的 Agent 运行恢复。

## 可选当前调用人通知请求

输入可选 notify_me 布尔值，缺省为 false；旧请求仍只启用只读 inspect。设为 true 时，冻结业务指纹绑定该动作，Harness只申请 inspect 与 notify_self，并用可信系统指令限制通知为当前调用人，不接受其他收件人。notify_self 需要发布策略映射至 notify.self 的固定 title/text 参数Schema，并由独立的人类批准；业务不签发Token、不直连数据库或通知服务。

输出 notify_me 只回显请求值，不表示通知已提交、发送或送达。缺少已发布工具映射、独立批准配置或任一主体的授权时，平台应拒绝该请求。

## 可选 Code Runtime 只读分析

输入可选 `sandbox_check` 布尔值，缺省为 `false`。默认请求继续只选择 `inspect`；只有设为 `true` 时，公共 Harness 才会选择发布函数别名 `sandbox_javascript`（平台策略映射到运维注册的 `code.javascript`）。冻结业务摘要会绑定此选择，恢复时不能切换该选项。

可信系统提示要求模型最多申请一次短只读 JavaScript 分析，只使用当前工单摘要和详情作为字面数据，不读写文件、不访问网络、环境、凭据或宿主，也不修改工单。Code 执行须经过公共 Tool Runtime、当前身份/Agent授权和独立人工批准；业务不连接控制器。批准前 Harness 暂停并退出当前处理器；批准后的原操作沿签名恢复继续，SDK 使用公共只读回执恢复，不把未知结果重新执行。返回的标准 Observation 按非可信数据处理。

Manifest 声明 `tool.invoke:code.javascript`。`example-release-bundle` 可准备 `sandbox_javascript` 到 `code.javascript` 的固定 `code` 字符串函数定义及 `require_confirmation` 策略片段；它只是合并到完整六策略资产的准备资料，不授予权限、不注册或发布 Function。实际运行仍要求运维为目标租户/应用/Agent配置匹配的 Code binding/Profile、平台隔离控制器，以及当前调用人和机器身份的资源授权；首次调用需要人类批准。

输出 `sandbox_check` 只回显请求值，不表示代码已获批准、执行或通过。默认 false 不请求 Code Function，也不增加 Code 工具执行。

## 可选 Documents 协作

v2 输入可选 `collaborate`，缺省为 `false`。关闭时沿现有工单流程运行，不启动 AgentGroup。打开时，业务先冻结自身已有的工单证据，再保存固定协作计划，然后只请求一个 `documents.answer` 子任务。子输入由工单编号和摘要构成，并固定为 `workflow_mode:"direct"`、`collaborate:false`、`notify_me:false`、`sandbox_check:false`；调用者不能指定 Agent、任务类型、endpoint、递归协作或子选项。Java SDK 将路由返回的输入/输出 Schema 固定为 Python Documents v2。

协作由平台 AgentGroup route/prepare/admit/gather 公共接口执行。等待时由 SDK 仅返回受控 group handoff；恢复须复读原 group 检查点并在当前权限下 fresh gather，未完成或未知的 child 不会释放工单 Harness。最终 `document_support` 只保留有界的子回答和引用 ID，按不可信支持材料呈现，不放入原工单 Harness 输入，也不作为工单已提交或变更的证明。平台需对当前用户与 Agent 机器身份分别配置 `documents.answer` 的允许目标、AgentGroup/跨 Agent 授权和数据范围；示例不会自动授予 crossGrant。

默认 `collaborate:false` 不增加 AgentGroup 或 Documents 子任务用量。设为 `true` 会产生额外子 Agent/RAG 用量，由平台账本结算。启用协作需要已发布匹配的 Documents Schema/版本、固定路由、目标安装及调用用户和两台机器各自的授权；新 v3 请求使用 v3 子契约，历史输入保留对应 v2 子契约，原 v1/v2 Catalog 均保留。
