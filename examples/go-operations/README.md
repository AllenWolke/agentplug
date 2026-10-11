# Go 运维诊断助手

业务输入使用 `schema://example-go-operations/input/v2`，包含 `service`、`symptom` 和可选的 `observations` 字符串；`notify_me`、`sandbox_check` 与 `collaborate` 默认均为 `false`。平台注入的 `policy_snapshot` 不由业务用户选择。

原已发布版本的不可变 input/output v1 契约分别保存在 `input.v1.schema.json` 与 `output.v1.schema.json`；当前 Manifest 单独引用 v2 Schema，不覆盖已发布 Catalog。

可选输入 `notify_me` 是严格布尔值，省略时默认为 `false`。默认模式只向 Harness 暴露只读 `inspect`。只有调用人明确设置 `notify_me: true`，模型才会额外看到 `notify_self`；该别名映射到平台 `notify.self` 工具，只接受 `title` 和 `text`，收件人由平台限制为当前认证调用人。每次通知都需要独立人工批准。批准或工具响应不表示通知已发送或送达；输出中的 `notify_me` 只是原请求回显，没有发送状态。用户文本、诊断证据都不能指定收件人。

可选输入 `sandbox_check` 也是严格布尔值，省略时默认为 `false`。只有设为 `true` 时，公共 Harness 才会暴露 `sandbox_python`，它映射到已注册的 `code.python`。固定系统提示和Skill只允许提交短小、确定性的只读分析程序；工具使用一次性隔离环境，不连接宿主或业务服务。每次执行都须独立人工批准，并沿公共 Tool Observation 与只读回执恢复路径处理。代码、参数、权限、镜像和资源上限不由业务用户选择；输出中的 `sandbox_check` 仅回显选择，不表示代码执行或成功。该选项参与冻结证据指纹，恢复时不能切换。

可选输入 `collaborate` 默认 `false`。显式设为 `true` 后，助手仍先冻结自己的诊断证据，再用固定 `documents.answer` 任务类型和单个固定子输入调用 SDK `RunAgentGroup`；用户不能选择目标 Agent、安装或端点，子请求固定使用 Python 文档助手 v2 的 direct 流程，并关闭其协作、通知与沙箱选项。协作计划 marker 在任何路由/准入副作用前持久化；SDK协调检查点保存计划与child引用，不缓存child输出。等待使用独立 AgentGroupPause/Handoff，恢复先按当前权限重新 Gather 原 child，不重新路由或重派发；Harness仍只读取本业务已冻结的证据。最终返回前会再查询一次当前 Group，`collaboration` 只含受限的文档回答/引用与摘要，并标注为不可信数据；此信息不写入 `last-diagnosis`。跨 Agent 的 human/machine `agent.delegate`、目标安装 `run` 权限以及完整 Runtime delegation/预算策略必须由管理员另行发布和授权，`collaborate` 不是授权。启用前须发布匹配的不可变 Agent/策略版本，并为调用用户、父机器和目标机器配置所需委托、安装与状态权限。

助手直接依赖仓库 `sdk/go`：首次收集公共记忆、已发布 Prompt、`runtime.inspect` 和 `go-operations` 知识证据，将其冻结到公共检查点，再经SDK Harness、渐进Skill加载及受治理模型生成，最后保存记忆。可选Code调用同样经Harness和平台工具网关，不直连控制器；恢复复用原证据和公共工具回执。SDK负责上下文验签、能力请求签名、续期、运行事件和取消；平台负责双身份授权、模型幂等、预算、用量、审计和追踪。助手不持有模型厂商凭据，也不连接平台数据库。

`runtime.inspect` 检查当前受信执行上下文，不能证明宿主或业务服务健康。`sandbox_python` 只可按提示处理少量已提供证据，不访问宿主、业务服务、网络或文件，不执行修复；其Observation仍是不可信数据。

在本目录运行 `go test ./...`。从仓库根构建 `docker build -f examples/go-operations/Dockerfile -t agentplug:example-go .`。启动需要 SDK 的平台公钥、能力网关和 Identity 签发的机器身份配置；缺少验证配置时拒绝启动。将 Manifest 与实际镜像摘要用于平台目录的注册、审核和不可变版本发布，再创建安装、部署并核验控制器就绪；用户与机器资源授权分别按[挂载与授权指南](../../docs/开发者指南/业务Agent挂载与已有用户授权指南.md)办理。Compose 环境变量和机器密钥应来自该安装的工作负载绑定，不能复用其他 Agent 的凭据。

部署覆盖配置位于 `deploy/compose/compose.examples.yaml`。在平台已配置的环境中额外提供 Identity 签发的 `EXAMPLE_GO_CLIENT_ID`、`EXAMPLE_GO_CLIENT_SECRET`，使用 `docker compose -f compose.yaml -f deploy/compose/compose.examples.yaml --profile full up -d example-go`。该服务无宿主端口，平台经同项目网络访问 `http://example-go:8080`。镜像不包含 shell、数据库客户端或模型厂商凭据。

准备注册与发布请求时，从仓库 `platform` 目录运行以下命令。摘要来自实际已构建镜像，不能填镜像标签；输出只生成请求草案，不会注册、发布或授权：

```powershell
$exampleDigest = docker image inspect agentplug:example-go --format '{{.Id}}'
go run ./cmd/example-release-bundle --example ../examples/go-operations --artifact-digest $exampleDigest --publisher system.admin
```

草案使用前端 `/api/modules/catalog`，按提交、评测、审批、安装、部署和激活分组。使用登录会话和选定工作空间执行，审批遵守人员分离，部署就绪由真实控制器观测。出现 CAS 冲突时读取当前版本，不猜测版本或伪造就绪。`knowledge/runbook.md` 是自主知识资料，需要通过公共知识源管理及索引接口入库，随后在发布知识策略绑定明确文档与权限。

当前异步运行使用 SDK 的进程内 L1 RunStore；进程重启不会保留业务运行事件。公共能力的持久化幂等和平台运行记录并不等同于 Agent 本地运行恢复，不能将本示例用于需要 L2/L3 持久化恢复的流程。

平台与 Agent 的 `AGENT_PLATFORM_AUDIENCE` 必须使用同一个执行服务 audience（默认 `agent-runtime`），签发者默认 `platform`。Agent 标识独立固定为 `example-go-operations`；SDK 同时校验签名绑定的 `scope.agent_id`，其他 Agent 的合法凭证也不能进入本助手。

## Harness 与 Skill 工作流

公开策略模板 `deploy/local/example-go-operations.policy-input.template.json` 为诊断提供有界的公共Prompt：四段简短中文，优先输出结论与不确定性、证据缺口、至多三项只读排查和回滚判断条件。正文目标为300字，另保留一个实际知识来源引用；证据已包含的执行上下文检查不重复调用。单次模型上限为1024 tokens，总Run预算仍由平台独立限制。Agent每次从平台解析发布的Prompt和摘要，修改Prompt应通过策略资产的版本/CAS发布及新快照生效，不能通过请求覆盖模型或预算。模型若仍返回截断，继续拒绝不完整答案并保留实际费用；不要自动追加模型调用来掩盖截断。

演示模板的日模型额度为 `budget_cents=1000`，由平台转换为10,000,000微额的UTC日窗口，便于进行多用例重复评估。该额度仍是硬上限，每个Run另受较小的Token/费用预算约束；历史失败调用同样消耗日额度，不能清除账本来重新测试。部署者应按已批准的模型价格、实际需求和当前窗口剩余用量设置额度，不以模型输出上限或CLI批次预算替代日额度。

工作流先通过公共State加载本Run的operations/diagnosis-evidence；首次收集记忆、Prompt、上下文检查和知识证据后，以expected_revision=0及稳定操作键冻结。证据Schema为schema://example-go-operations/evidence/v1，绑定service/symptom/observations与业务幂等键。恢复复用原证据，不重新读取会变化的记忆或检索结果；权限仍由平台逐次检查。

模型步骤调用仓库SDK RunHarness，使用diagnosis-model检查点、最多四轮/八次工具，并逐步加载example.operations.guidance摘要与diagnosis章节。`inspect` 始终映射到批准的 `runtime.inspect`；显式启用通知时，`notify_self` 必须映射到正式注册的 `notify.self` Function，参数仅含 `title`、`text` 且不含 recipient。该工具还需要独立人工批准、当前调用人的 IAM 授权及已发布部署策略。显式启用`sandbox_check`时，`sandbox_python`映射到正式注册的`code.python` Function，仅参数`code`，经隔离控制器执行并要求独立批准；正式策略/IAM和控制器绑定缺一不可。两类工具响应都经SDK作为不可信Observation加入上下文，Harness恢复只读查询已提交回执，不自动重复未知执行。

只有completed时继续写业务记忆。approval_required通过SDK PauseHarness进入waiting并退出处理器，事件仅保存Harness key/工具名/call ID。平台批准后发送签名resume_input.confirmation_token；SDK要求原业务输入、已退出waiting世代及新的执行修订/租约，重新注入逐运行客户端并从公共检查点继续，不把批准Token写入事件。通知和`sandbox_check`选择都绑定在冻结业务 evidence 指纹中，不能在恢复时更改。未知或其他未完成结果停止，不自动重复模型。启用通知或Code前，须完成工具与Function注册、不可变策略发布、独立批准配置、调用用户/机器授权及Code binding；缺少任一条件时，平台应拒绝该能力请求。

skills/guidance.v1.json需通过人工控制面注册、由其他有权人审核，再发布稳定/灰度版本。安装的Runtime allowed_skills需包含该Skill，用户需skill_user/v2角色和本安装Skill Grant，Agent机器身份亦需该Grant；工具/知识依赖不能靠Skill授予。部署策略须开放公共检查点读写、足够Task TTL/MaxEntries和上下文窗口。每次发布后按当前安装、身份和策略版本核验有效配置；发布草案或 Skill 文件本身不创建授权。

业务模型检查点可保留模型与工具边界，但 SDK 的 `MemoryRunStore` 是进程内 L1，进程重启后不保留 Agent 本地运行事件。平台持久运行记录、模型幂等和记忆不能代替 Agent 本地恢复；需要跨进程恢复时，部署的平台必须提供持久 Run、真实停止证明、当前检查点和重新核验的授权。
