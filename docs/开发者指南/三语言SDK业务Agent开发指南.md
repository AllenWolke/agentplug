# 三语言 SDK 业务 Agent 开发指南

> 初次接触项目请先读[开发者入门路线](../developer/zh/README.md)和[第一个业务 Agent](../developer/zh/first-agent.md)。本页是完整 SDK 和复杂场景参考；公共能力分工见[能力复用说明](../developer/zh/capabilities.md)，交付见[部署与绑定](../developer/zh/delivery.md)。

本文介绍仓库执行 v2 协议和三个独立部署示例的开发、公共能力调用与发布流程。发布前构建实际镜像并取得不可变摘要，按照真实权限和部署状态完成注册；生成请求草案后仍须逐步提交和验证。

公开 Compose、`.env.example` 和独立复现工具默认启用 `PLATFORM_RUN_TREE_BUDGET_ENABLED=true`。完成显式数据库迁移、SQL模型治理和有限 `runtime.run_budget` 发布后再提交业务 Run；启动依赖缺失时平台拒绝启动。不要关闭该开关来绕过预算验收。旧部署升级时保留实际未知计费记录，只按原供应商回执办理核账。

干净环境需要显式配置 `KNOWLEDGE_DATABASE_DSN`，指向该 Compose 项目自己的 PostgreSQL 知识投影库。公开复现脚本会使用本环境的 `platform_runtime` 账号生成此配置，业务 Agent 仍通过 SDK 访问知识能力。索引成功之后，还应核验运行平台已加载该 Provider；遗漏 DSN 会让内置演示引用被正常文档权限过滤拒绝。

使用 `https://api.deepseek.com` 时，应明确发布思考配置。本教程的短输出演示使用 `reasoning_mode: "disabled"`；公开复现脚本对该正式端点自动生成此字段。需要推理时，模型资产可发布 `reasoning_mode: "enabled"` 和 `reasoning_effort: "low" | "high" | "max"`，平台按审核后的资产传递，业务 Agent 不能覆盖。强度为空时由厂商使用默认值；强度必须与开启思考同时配置，Embedding 不携带这些字段。查询改写与 Function Calling 预检仍受既定输出和预算限制，思考输出也会消耗厂商计量的输出额度。首次接入先做有界连通性检查，再验证实际业务。已发布资产通过新 Draft 修订、独立管理员发布和快照 CAS 更新；保留原修订、预算和 `max_tokens` 上限。[DeepSeek 思考模式与参数](https://api-docs.deepseek.com/guides/thinking_mode/)。

## SDK 2.1 公共能力接入

当前仓库公共 SDK 为 **2.1.0**、六种模板为 **1.1.0**、三个示例为 **0.3.0**。完整功能变化见[更新说明](../releases/public-capabilities-2.1.zh.md)，方法对应见[三语言公共接口](../developer/zh/capabilities.md#三语言接口对应)。Go/Java 现在提供与 Python 对应的模型、Embedding、Prompt、记忆和知识便捷接口，统一处理签名、幂等身份和元数据，不再要求业务代码手工拼接公共请求。

下面是业务处理器中的结构化最终生成片段。`client` 已由 SDK 校验执行上下文并注入；Go 的导入别名 `sdk` 指向 `github.com/lexagent/agent-platform-sdk-go/agentplatform`，Java 导入 `com.lexagent.sdk.PublicCapabilities`、`java.util.Map` 和 `java.util.List`。示例输出限制仍须在已发布策略和剩余预算允许范围内。

Python：

```python
schema = {"type": "object", "properties": {"summary": {"type": "string"}},
          "required": ["summary"], "additionalProperties": False}
result = await client.chat(
    [{"role": "user", "content": "根据已提供证据生成摘要。"}],
    max_tokens=256, step_name="answer.final", require_json=True,
    response_schema=schema, response_schema_mode="required",
)
```

Go：

```go
schema := map[string]any{
    "type": "object", "properties": map[string]any{"summary": map[string]any{"type": "string"}},
    "required": []string{"summary"}, "additionalProperties": false,
}
result, err := client.Chat(ctx, []map[string]any{
    {"role": "user", "content": "根据已提供证据生成摘要。"},
}, sdk.ChatOptions{
    MaxTokens: 256, StepName: "answer.final", RequireJSON: true,
    ResponseSchema: schema, ResponseSchemaMode: "required",
})
// 在处理 result 前按业务入口约定返回或分类处理 err。
```

Java：

```java
Map<String, Object> schema = Map.of(
    "type", "object", "properties", Map.of("summary", Map.of("type", "string")),
    "required", List.of("summary"), "additionalProperties", false);
Map<String, Object> result = client.capabilities().chat(
    List.of(Map.of("role", "user", "content", "根据已提供证据生成摘要。")),
    new PublicCapabilities.ChatOptions(0.3, 256, "answer.final", true, schema, "required"));
```

三个片段均调用普通生成接口；Function Calling 阶段应独立执行。按各语言惯用方式处理失败、解析返回正文并保留平台实际提供的模型、路由、缓存和计费元数据。`required` 需要模型与发布策略支持；业务允许兼容输出时才使用 `prefer_supported`，仍须校验返回内容。

持久化知识流程的 `as_of`、`source_ids`、查询和检查点键一起绑定操作身份；恢复不能更换筛选参数。使用和返回缓存或冻结知识前调用 `AuthorizeCachedResult` / `authorize_cached_result` / `authorizeCachedResult`。Python 使用 `from agent_platform_sdk.reference_authorization import authorize_cached_result` 并执行 `await authorize_cached_result(client, result, knowledge_scope)`。步骤工作流、`DurableStageClient` 和检查点游标恢复时读取原回执，保留原截止时间、批处理窗口和作用域；已提交或结果未知不等于允许重试。

Python FastAPI 入口按需安装 `python -m pip install -e './sdk/python[grpc,asgi]' fastapi`；命令从仓库根执行。`asgi` 提供 Uvicorn 启动依赖，gRPC 仅对应相应传输。LangGraph 专用集成继续使用 Python 模板的依赖文件，通用工作流接口不要求 Go/Java 使用 LangGraph。

## 1. 选择示例与开发环境

| 语言 | 业务目录 | 仓库 SDK | 开发环境 | 固定 Agent ID |
|---|---|---|---|---|
| Go | `examples/go-operations` | `sdk/go` | Go 1.26.10（仓库构建工具链） | `example-go-operations` |
| Python | `examples/python-documents` | `sdk/python` | Python 3.12 及以上 | `example-python-documents` |
| Java | `examples/java-tickets` | `sdk/java/agent-platform-sdk` | JDK 21、Maven | `example-java-tickets` |

Go 的 `go.mod` 使用 `replace` 指向仓库 SDK；Python 先安装仓库 SDK，再安装业务包；Java 通过仓库 Maven reactor 构建。不要把平台数据库驱动、数据库密码或模型供应商 Key 加入业务 Agent。

## 2. 先定义业务协议

每个示例目录包含 `manifest.json`、`input.schema.json` 和 `output.schema.json`。当前三个示例的业务输入输出使用独立的 `schema://<agent_id>/input/v3` 和 `schema://<agent_id>/output/v3` 标识，v3 输出增加 `model_metadata`；执行协议保持 `agent-execution/v2`。旧 v2 文件、历史 Manifest 和对应恢复指纹保留，Java 另保留原 v1 路径。修改不兼容字段时发布新的 Schema 和不可变 Agent 版本，不原地覆盖历史 Catalog 或策略。业务输入仅包括业务参数，身份、模型、工具、知识库及策略版本由平台发布的策略快照决定。

三个有效业务输入如下：

```json
{"service":"orders","symptom":"响应延迟升高","observations":"最近部署后出现"}
```

```json
{"question":"文档增量更新如何保持一致性？","top_k":3,"cache_mode":"use"}
```

```json
{"ticket_id":"DEMO-001","summary":"客户端请求超时","details":"需要排查建议"}
```

这些是平台运行请求中的业务 `input`，不能直接作为完整执行 v2 请求发送给 Agent。平台负责生成完整签名上下文和执行凭证。

## 3. Go：组织运维诊断业务

在 `examples/go-operations` 中阅读业务处理器及入口，保留 SDK 的验签、续期和运行生命周期，只修改诊断业务与版本化 Schema。示例依次读取公共记忆、解析已发布 Prompt、调用 `runtime.inspect`、检索 `go-operations` 知识、调用受治理模型、保存记忆。

```powershell
Set-Location examples/go-operations
go test ./...
Set-Location ../..
docker build -f examples/go-operations/Dockerfile -t agentplug:example-go .
```

`runtime.inspect` 核验可信执行上下文，不检查真实宿主或业务服务健康。当前示例输出排查建议，不执行修复。

## 4. Python：组织文档业务与 RAG

业务入口为 `examples/python-documents/document_assistant/business.py` 的 `answer_document`；服务入口为 `document_assistant.server`。`CapabilityGatewayClient` 接收经过 SDK 校验的上下文，当前文档业务通过公共 `memory_load`、`resolve_prompt`、`invoke_tool`、`run_knowledge_harness` 和 `memory_save` 组织流程，并在业务前后调用 `validate_current_execution`。`run_knowledge_harness` 复用 SDK 的知识状态、恢复与公共回答能力；底层 `answer_knowledge` 仍可用于自定义组合，不应在业务里复制平台检索或计费逻辑。

```powershell
Set-Location examples/python-documents
python -m pip install ../../sdk/python .
python -B -m pytest -p no:cacheprovider tests
Set-Location ../..
docker build -f examples/python-documents/Dockerfile -t agentplug:example-python .
```

公共知识能力在平台 PostgreSQL + pgvector 内执行查询改写、Embedding、双身份权限与 Metadata Filter、BM25 + Vector Search、融合 Top-K、重排和引用回答。文档助手只请求固定的 `python-documents` 知识范围，不访问向量数据库。

`cache_mode` 可取 `use`、`cold`、`bypass`。缓存命中仍须检查当前权限、源版本、索引代际与预算；查看平台账本核实整个运行的 Token 和费用，不能只把答案生成的 `saved_usage` 当成全运行节省。

文档示例 v3 另外接受可选 `as_of`（规范 `YYYY-MM-DD` 日期）和 `source_ids`（获准来源标识列表）。这两个字段参与业务幂等与恢复指纹，不能在续接时更换。默认 `direct` 流程保持不变；显式选择 `tool_loop` 才进入前置工具循环，通知和沙箱仍需对应工具策略、人工批准及双身份授权。

`use` 支持同一用户、同一会话中不同运行的重复提问复用，缓存键保留安装、Agent版本、权限版本、策略和知识版本。不同用户或会话不共享缓存。当前完整运行上下文每次仍通过校验，旧签名或撤权不能因缓存命中而放行。普通模型账本使用实际执行 Run ID。评测子运行保留可信产品父 Run 归属，以每个 Case 的实际执行 Run 作为有限预算根和计费主体，再汇总实际用量；实际评测已验证执行、结算及制品归属。执行成功与质量门禁分别判断：教学样本的 Recall/MRR/NDCG/Citation 已通过，但 Grounding 仍按实际评分返回 blocked，不应降低阈值或将其写成质量通过。

RAG Evaluation 配置位于该示例的 [evaluation/README.md](../../examples/python-documents/evaluation/README.md) 和 [metrics.json](../../examples/python-documents/evaluation/metrics.json)。使用独立人工确认的 `expected.relevant_ids`、`expected.citation_ids` 和冻结正文 `expected.citations`，计算 Recall、Precision、MRR、NDCG、引用准确率与接地指标。金标准只传给评测器；业务 Agent 不接收金标准，也不自评。内置接地算法是词面基线，不能解释为完整语义正确性。

知识更新通过平台规范源接口和 `full` / `incremental` 索引任务办理：源记录及 Outbox 同事务，文档及源版本采用 CAS，删除保留墓碑，索引发布切换版本和连续检查点。全量替换、增量更新、失败重试与新版本发布由公共模块处理，不在 Python 业务里复制实现。

索引任务的发起人须同时具备目标知识范围的维护权限和已发布模型策略的 `model.embed` 权限；机器身份也须获得对应 Embedding 资源授权及工作负载绑定。管理身份不默认拥有业务模型调用权，不能只用超级管理员身份启动索引。开发环境可给已有操作员临时维护身份，完成后撤销；维护授权变更应在任务提交前完成，避免改变运行中的权限版本。

平台索引工作进程从安装作用域的私有文件读取机器凭据。配置 `PLATFORM_WORKLOAD_SECRET_DIR` 挂载目录和 `PLATFORM_INDEX_WORKLOAD_SECRET_ROOT` 容器路径；每个安装文件名为紧凑 JSON 数组 `[tenant_id, department_id, application_id, installation_id]` 的 UTF-8 SHA-256 加 `.json`，内容为 `client_id`、`client_secret`。这些文件不进入 Git。机器凭据网络白名单使用平台实际观测到的该 Agent 来源地址 `/32` 或 `/128`；平台进程内能力调用另需明确允许 `127.0.0.1/32`，不要授权整个共享网段。

重建 Agent 容器可能改变其动态 IP。使用来源地址白名单时，应固定该服务在独立项目网络中的地址，并在重建后核对地址、机器凭据和安装绑定，再启用索引工作负载文件。凭据轮换时先保存私有回执，同步 Agent 配置并核验正在运行的进程，最后将新凭据提供给平台索引工作进程。若部署结果不确定，先读回容器和授权状态；不要重复轮换、扩大 CIDR 或重复提交同一索引来绕过问题。

真实维护登录会话提交：

```http
POST /api/modules/knowledge/indexes/python-documents/tasks
Content-Type: application/json

{"installation_id":"example-python-documents-installation","idempotency_key":"handbook-full-v1","mode":"full","config":{"dimensions":1024,"window_runes":400,"overlap_runes":80,"maximum_documents":16,"maximum_chunks":128}}
```

使用响应中的运行 ID 查询 `GET /api/modules/knowledge/indexes/python-documents/tasks/{run_id}`，确认成功和活动生成版本后再提供检索。重放相同任务必须保持相同维护身份及授权版本；使用新的源版本启动新更新任务。

规范源快照可通过 `GET /api/modules/knowledge/sources/python-documents` 读取当前 `revision` 和各文档 `version`。修改文档时，`PUT /api/modules/knowledge/sources/python-documents/documents/{document_id}` 同时提交 `expected_source_revision`、`expected_document_version`、新幂等键、正文、metadata及ACL。旧修订不能覆盖新变更；写入后提交新的 `mode: incremental` 索引任务，完成后核对源版本和索引发布回执。未变化分块复用已有向量，新增或变化分块才请求Embedding。

删除使用同一PUT接口，携带两个当前期望版本和新幂等键，设置 `deleted: true`，并清空正文、metadata和ACL。快照保留空正文墓碑，不能把墓碑误读为仍可检索的文档。只有对应增量任务成功发布、活动投影不再包含其分块后，同步检查点才完成；检索仍实时检查源权限和删除状态。新活动代际同时使旧RAG缓存失效。

## 5. Java：组织工单业务

入口为 `com.lexagent.examples.tickets.TicketAgent`。保留 SDK 签名与作用域验证，在业务中依次读取记忆、解析 Prompt、调用上下文工具、检索 `java-tickets`、生成回复草稿并保存记忆。示例不提交、关闭或修改外部工单。

```powershell
mvn -f sdk/java/pom.xml -pl :example-java-tickets -am package
docker build -f examples/java-tickets/Dockerfile -t agentplug:example-java .
```

本地启动时 Windows classpath 分隔符为 `;`：

```powershell
java -cp 'examples/java-tickets/target/example-java-tickets-0.2.6.jar;examples/java-tickets/target/lib/*' com.lexagent.examples.tickets.TicketAgent
```

启动前提供平台公钥、能力网关地址、签名配置及独立机器凭据，参见 [Java 示例说明](../../examples/java-tickets/README.md)。不要将凭据写入代码或公共文档。

## 6. 接入公共能力与生命周期

三个服务统一使用平台公钥，签发者 `platform`、audience `agent-runtime`，Agent ID 各自固定；其他 Agent 的合法凭证也不能混用。机器身份拥有明确工作负载绑定；调用人和机器均须通过当前资源与数据范围权限检查。

平台提供持久化运行查询、幂等、审计、追踪、用量和预算。保持 SDK 的错误码传递和协作取消，不吞掉撤权、预算不足或签名错误，不擅自重新发送不确定是否结算的模型请求。进程内 `MemoryRunStore` 仍只是 L1 投影；普通进程故障恢复另走平台签发的 `runtime-recovery/v1`，不能把本地 Store 本身当作持久恢复机制。

Java SDK同步`invoke`与异步`run`共用执行登记和退出屏障。取消控制绑定原执行作用域、版本与租约；业务线程未退出时返回`cancelling`，真正退出后才确认`cancelled`。业务代码应让`InterruptedException`或SDK取消错误向外传播，不忽略中断继续访问公共能力。取消接口不返回业务结果，重放结果仍验证授权；进程重启后不能仅凭RunStore终态推断旧处理器已经停止。

普通运行故障恢复使用 `runtime-recovery/v1`：平台只有在确认旧处理世代实际停止后，才把该命令放入新的、已签名的执行 v2 `resume_input`；SDK核验原Run/旧修订与租约摘要、策略摘要、原输入和停止引用，再逐项读取引用所指的当前公共检查点并复核当前权限，随后通过 `RecoveryGenerationRunStore` 建立新世代投影并沿原业务 `invoke` 路径继续。Go入口为`ExecutionServer.resumeRuntimeRecovery`，Java入口为`ExecutionServer.handleRuntimeRecoveryResume`，Python入口为`ExecutionLifecycle.resume`→`_resume_runtime_recovery`。停止引用本身不是可由业务用户提交的凭据，调用方不得拼造reference、伪造旧处理器退出或用新的普通Run替代恢复；详细协议见[受控执行恢复](../RUNTIME-RECOVERY.md)与[协议字段](../../contracts/runtime-recovery.md)。启用该流程需要部署平台持久Run和停止证明接口、SDK匹配版本、检查点权限及当前运行授权；`MemoryRunStore`本身不提供跨进程恢复。

## 7. 注册、发布和部署

先登记模型与规范知识源，构建 Agent 镜像，再从仓库 `platform` 目录生成请求草案。开发者必须在目标工作空间获得 `agent_developer` 提交身份；审批账号须为不同主体。示例中的 `developer.account` 应替换为实际已登录的开发者主体 ID，初始业务用户默认没有开发提交身份。

```powershell
$exampleDigest = docker image inspect agentplug:example-python --format '{{.Id}}'
Set-Location platform
go run ./cmd/example-release-bundle --example ../examples/python-documents --artifact-digest $exampleDigest --publisher developer.account --endpoint http://example-python:8080
Set-Location ..
```

另两个示例替换目录、镜像及 endpoint。摘要必须来自实际构建镜像。生成器只在标准输出打印可审阅的 JSON 请求计划，不登录、不提交、不评测、不发布，也不伪造部署就绪。默认 Definition ID 为 `<agent_id>-definition`；Version ID 根据 Manifest 语义版本生成安全、带版本区分的 ID，Installation 和 Deployment ID 也随版本生成。需要重跑草案时可显式传入 `--version-id`、`--installation-id`、`--deployment-id`，三者都必须是安全标识。

若已有已发布 Definition，可改用其真实 ID，生成新的不可变版本计划：

```powershell
Set-Location platform
go run ./cmd/example-release-bundle --example ../examples/python-documents --artifact-digest $exampleDigest --publisher developer.account --endpoint http://example-python:8080 --existing-definition replace-with-verified-definition-id --version-id replace-with-new-version-id
Set-Location ..
```

此模式先输出对现有 Definition 的 GET 检查步骤；必须用当前登录提交人确认它已发布、Agent ID 与 Manifest 一致且归该提交人所有。随后计划只创建、评测和发布新的 Version，不再创建/评测/发布 Definition。计划仍创建版本专属的新 Installation 和 Deployment；`--installation-id` 指定新安装 ID，不是升级现有安装。保持原安装并升级须走单独的安装升级流程。

输出的 `skill_publications` 附带示例 Skill 的规范 bundle、摘要及 `/api/modules/skills/inspect`、`register`、`review`、`publish` 请求草案。它们不是自动执行结果：Skill API 提供 inspect 而没有 preview；每次写入前都要重新检查当前权限、实际目标命名空间和修订，并按最新状态提交 CAS。登记作者与审批人必须是不同主体，不能用草案中的默认修订值替代实际读取值。

`policy_fragments` 将 `allowed_skills` 与 `inspect` Function 示例合并进现有策略；Manifest声明`tool.invoke:notify.self`时，生成`notify_self`映射、title/text参数Schema及`require_confirmation:["notify.self"]`片段；声明`tool.invoke:code.python`或`tool.invoke:code.javascript`时，分别生成`sandbox_python`或`sandbox_javascript`到相应`code.*`工具的`code`字符串函数定义和独立确认片段。它们不是六类完整的可发布策略，也不会创建人类或机器授权。发布前仍须核实实际镜像摘要、评测证据、当前授权、策略版本和Code Runtime Profile/控制器观测，并将片段合并到完整策略后审核发布。

通过 Identity 为各 Agent 创建独立机器身份；将平台校验材料和机器凭据放入私有部署配置，启动独立服务：

```powershell
docker compose -f compose.yaml -f deploy/compose/compose.examples.yaml --profile modular up -d example-go example-python example-java
```

服务仅暴露项目网络端口；平台从网络内连接三个 endpoint。实际控制器确认镜像摘要、Manifest 和就绪后，才能激活实例。随后发布安装范围的六策略快照，绑定机器身份，分别授予用户与机器所需公共能力资源权限，再办理模型部署就绪和全量索引发布。只有这些依赖实际有效，业务调用才会放行；服务探针通过不能代替公共能力授权。

Go、Java 示例将发布 Manifest 内嵌在构建产物中，SDK 启动时核对身份、版本、协议、能力及存储类型。修改声明或产物后发布新的不可变版本，不能修改已发布版本的内容。同一应用下同一 Agent 已有安装时，保留安装 ID，通过 `POST /api/modules/catalog/installations/{id}/upgrade` 提交 `version_id` 和当前 `expected_revision`。实例须为 `provisioning` 或 `suspended`；运行中的实例先按生命周期处理在途执行并暂停。升级后需创建更高部署修订并重新观测，才能激活。已有用户授权参见 [挂载与授权指南](业务Agent挂载与已有用户授权指南.md)。

### 已委派子执行的停止控制

调用子执行取消时，沿用原已记录的 operation key、ordinal 和 child key，并提交正整数 `expected_execution_revision`。父执行的签名上下文、当前处理世代、机器凭据和绑定仍须有效；收回业务运行或委派权限后，平台允许对原精确子执行提交停止意图，这不授予新执行、业务输出或历史读取权。父世代已经到期或释放租约时，由平台协调器按持久记录接管停止，业务代码不自行续造租约。

子执行修订已改变时，专用 HTTP 409 `AGENT_STOP_REVISION_CONFLICT` 仅返回 `stop_control`，包含 `version: agent-child-stop-control-conflict/v1`、当前 `status` 和正整数 `execution_revision`。三语言 SDK 仅保留这个严格字段集合，不接收附加正文或敏感字段。业务可核对原任务与控制状态后，用该修订显式再提交取消；SDK 不自动重试，不能用零修订跳过 CAS。一般 409、403 或不完整响应不提供此控制权限。受理取消不等于处理器已退出，最终停止仍以实际退出屏障和平台终态为依据。

### 共享实例并发

同一安装实例可服务多个已授权用户，平台 Execution 模块统一负责调度、会话顺序、租约、幂等与取消。Go HTTP、Java HTTP 执行器和 Python FastAPI 异步适配器处理独立请求，业务仅实现 SDK 回调。每次调用建立自己的已验证上下文和公共能力客户端，不在全局变量中保存用户、会话或运行状态。

不同用户、不同会话可并发；同一用户同一完整会话作用域按顺序推进。`PLATFORM_RUN_WORKERS` 是平台执行池线程数，默认4、可配置1～32；模型部署的 `capacity.max_concurrent_requests` 是共享模型容量。两个限制的层级不同，不代表每个 Agent 自动拥有对应数量的专用线程。用户、历史、记忆、知识权限、取消、用量和预算仍按可信作用域隔离。上线前应验证共享实例并发时间线及数据隔离。

将第二个已有用户挂到同一安装时，分别办理其运行权限及模型、工具、知识、记忆资源权限。公共知识策略还必须绑定第二个用户可读的规范文档：只有资源Grant而缺少文档绑定、规范源ACL或机器检索权限时，检索仍会拒绝。参见[挂载与授权指南](业务Agent挂载与已有用户授权指南.md)。无需为第二个用户复制Agent服务，不把任何用户上下文存入全局变量。

SDK确认取消时以实际处理器退出为依据。平台公共模型能力对已经发出的请求有界收取真实计费回执，同时禁止向已结束的调用人披露答案；进程或网络故障导致的未知用量保留待协调状态。业务Agent不自行重跑模型、释放预算或改写运行结果，运维恢复流程见[执行恢复](../RUNTIME-RECOVERY.md)。

共享实例上线验收应逐项保存实际证据，准备计划或离线测试通过不能代替执行结果：

1. 为两个用户分别办理同一安装及其所需公共能力的最小权限，并确认各自知识文档绑定与源 ACL。
2. 两个用户使用不同 Session、Run 和幂等键同时执行，保存同一安装的实际开始/结束时间，确认执行窗口重叠。
3. 分别核对会话、消息、知识引用、记忆和 Usage 归属；请求另一用户历史应被拒绝。
4. 对一个用户执行撤权并读回当前权限，确认后续调用被拒绝，另一用户仍可正常使用。
5. 验证取消时分别保存平台受理回执、远端执行退出与最终账本结果；结束后撤销测试新增的授权，保留原有授权。

## 8. 交付前检查

使用已登录且拥有目标安装运行权的业务账号创建会话，例如：

```http
POST /api/modules/conversation/sessions
Content-Type: application/json

{"id":"document-session-001","kind":"qa","agent_id":"example-python-documents","agent_version_id":"example-python-documents-v0.2.8","title":"文档检索示例"}
```

再提交版本化业务输入。Agent endpoint、安装实例、当前权限和六策略快照由平台解析及注入，不由浏览器签发：

```http
POST /api/modules/conversation/sessions/document-session-001/runs
Content-Type: application/json

{"run_id":"document-run-001","idempotency_key":"document-run-001","request":{"question":"全量索引与增量同步如何保证数据一致？","top_k":3,"cache_mode":"use"}}
```

查询 `GET /api/modules/execution/platform/runs/document-run-001` 和 `GET /api/modules/conversation/sessions/document-session-001/messages`。Go 输入的 `observations` 是字符串，Java 输入须包含 `ticket_id` 和 `summary`。运行查询成功不代表已有结果，应等待终态并检查输出。用量明细由具备审计权限的账号读取，查询必须附 RFC3339 格式的 `from`、`to` 时间范围。

部署后用对应业务用户执行完整链路，检查运行、审计、追踪、账本和知识引用，并验证跨用户、跨 Agent、撤权、幂等、取消、预算与供应商故障。Python 另检查独立金标评测、冷/热缓存和全量/增量索引同步。清理本次创建的临时测试文件、容器及镜像，并记录目标环境的运行证据；镜像构建成功本身不证明业务能力已部署可用。


## 原生Function Calling与MCP公共工具

平台模型网关支持原生函数调用及工具结果往返；业务Agent通过SDK调用平台模型和工具网关，不持有模型或MCP服务凭据。模型只能建议已发布Function，实际工具执行仍受调用人与机器身份的双重授权、工具策略、审批、运行租约、取消和幂等账本控制。

先按本指南已有策略注册、审批、发布流程，在工具策略中加入Function定义。例如：

```json
{
  "allowed_tools": ["runtime.inspect"],
  "require_confirmation": [],
  "functions": [
    {
      "name": "runtime_inspect",
      "tool_name": "runtime.inspect",
      "description": "Read the current execution runtime status",
      "parameters": {"type": "object", "properties": {}, "additionalProperties": false}
    }
  ]
}
```

上例的`require_confirmation`为空，说明它仅展示Function映射，不会自行触发人工批准。要验证批准恢复，必须另行发布实际已注册、Schema固定且策略标明需要确认的工具，并为调用人和机器配置相应资源授权。

函数名是模型协议名称，工具名是平台授权资源名称；定义及Schema来自不可变发布策略。Agent的`function_names`只选择已发布名称，不能附带自定义Schema或新增工具。未批准定义、非法参数、孤立/重复工具结果被拒绝；模型返回非法调用时保存真实用量并返回`MODEL_FUNCTION_INVALID`，不会执行指令。实际输出达到Token上限返回`MODEL_OUTPUT_INCOMPLETE`。

以下输入的`prompt_template_hash`取自当前SDK解析到的已发布Prompt，`idempotency_key`是业务操作的稳定标识，重试时复用。SDK按轮次及工具调用ID生成独立稳定账本键，不对未知副作用进行自动重试，也不把模型建议作为敏感工具确认。

```json
{
  "messages": [{"role": "user", "content": "Inspect this execution runtime before answering."}],
  "prompt_template_hash": "<current published prompt hash>",
  "function_names": ["runtime_inspect"],
  "idempotency_key": "diagnosis-step-1",
  "max_tokens": 256
}
```

```go
// client is injected by the execution SDK, input is the object above.
result, err := client.GenerateWithFunctions(ctx, input, 4)
```

```python
# client is the current execution's CapabilityGatewayClient.
result = await client.generate_with_functions(input, max_rounds=4)
```

```java
// client is the current execution's injected CapabilityClient.
Map<String, Object> result = client.generateWithFunctions(input, 4);
```

轮次范围为1～8，包含最终模型回答轮次；最后允许轮次仍提出工具调用时，SDK返回`FUNCTION_ROUND_LIMIT`，不继续执行工具。SDK仅使用平台返回的已发布`function_bindings`映射，将assistant/tool消息带入下一模型轮次；工具Schema、调用参数和结果消息均计入平台保守输入预算。

MCP服务由平台运维装配，配置方法见[MCP部署说明](../../deploy/mcp/README.md)。将配置的平台工具名加入已发布工具策略，再按普通工具资源分别授予调用人与机器身份。远端工具发现不会自动注册权限，Schema变化先拒绝调用再由运维核验更新。SDK调用方式与内置平台工具一致，不需要业务Agent导入MCP厂商客户端。

使用这些接口时，先确认平台API版本、策略快照、所需State权限和目标Agent安装均匹配；新能力的运行范围由这些已发布资源及当前用户/机器授权共同决定。仅调用SDK接口不会创建策略、权限或安装。

## 公共业务检查点与CAS

三语言SDK的公共检查点接口使用当前运行的能力客户端；Agent不连接平台数据库。部署前先用迁移身份应用仓库提供的平台迁移，并部署包含相应检查点API的后端版本；运行身份仅获得公共State所需权限。迁移和后端版本必须配套，Agent不应直接读写数据库。

状态按用户、Agent、安装、不可变版本、会话及运行隔离。`revision=0`读取当前版本；历史版本从1开始。Schema使用稳定版本标识，例如`schema://operations/diagnosis-state/v1`；它是状态谱系标识，不等于自动注册了内容JSON Schema。Agent自行校验业务结构，平台执行对象大小、版本和摘要校验。

```go
saved, err := client.SaveCheckpoint(ctx, "diagnosis", "loop", "schema://operations/diagnosis-state/v1", "step-1", 0, map[string]any{"phase": "retrieved"})
restored, err := client.LoadCheckpoint(ctx, "diagnosis", "loop", "schema://operations/diagnosis-state/v1", 0)
// State numbers decode to json.Number so large integer identifiers remain exact.
```

```python
saved = await client.save_checkpoint("documents", "loop", "schema://documents/state/v1", {"phase": "retrieved"}, expected_revision=0, idempotency_key="step-1")
restored = await client.load_checkpoint("documents", "loop", "schema://documents/state/v1")
```

```java
Map<String, Object> saved = client.saveCheckpoint("tickets", "loop", "schema://tickets/state/v1", Map.of("phase", "retrieved"), 0, "step-1");
Map<String, Object> restored = client.loadCheckpoint("tickets", "loop", "schema://tickets/state/v1", 0);
```

成功读取结果的`checkpoint`包含`revision/schema_id/value/content_hash/expires_at/execution_revision`。平台以状态head与检查点记录区分状态谱系：只有从未创建才返回null；已有谱系的当前检查点已到期，或指定历史版本正文已不可用时，返回`409 STATE_CONTINUITY_LOST`，不降级成“首次运行”。三语言SDK的Go `LoadCheckpoint`、Python `load_checkpoint`和Java `loadCheckpoint`均透传平台错误；公共Harness不会吞掉该错误。处理该错误时应保留失败状态，检查原操作副作用后再由调用方决定是否创建新的Run。

成功Load/Save结果还带`state_key`：它由可信运行Scope与namespace/key派生，用来匹配平台停止事务保存的检查点引用，不是额外授权。停止事务引用至多保存128个最新检查点的修订、摘要、执行代次和到期时间，不保存业务正文；这些元数据只有随平台签名恢复命令到达SDK后才有意义，不能自行拼成执行凭证或绕过批准恢复。

三语言已提供只读引用核验方法：Python `CapabilityGatewayClient.load_recovery_checkpoint(reference)`、Go `CapabilityClient.LoadRecoveryCheckpoint(ctx, reference)`、Java `CapabilityClient.loadRecoveryCheckpoint(reference)`。引用需精确包含`state_key/revision/schema_id/content_hash/execution_revision/expires_at`六字段；平台要求其仍是当前运行的最新head并逐项匹配，不允许读别人的状态或以旧版正文恢复。该方法复用当前签名、续期和`memory.read`授权，读取不授予业务执行权。

### 普通故障恢复 `runtime-recovery/v1`

这条路径与人工批准暂停/恢复不同。平台签名的 `resume_input` 固定为 `version=runtime-recovery/v1`、`origin_operation=invoke`、平台保存的 `reference`，仅在确实需要继续原批准时附带瞬时`confirmation_token`。reference绑定旧处理器确实退出、旧执行修订/租约、原请求与策略摘要，以及最多128条检查点的六字段引用；SDK读取每条引用对应的**当前**State并逐项匹配，再次检查当前权限后才创建新的执行世代。没有当前检查点、检查点过期/丢失、引用不匹配或权限被撤销均失败关闭，不会把旧Run当新请求冷启动。`STATE_CONTINUITY_LOST`表示已有State谱系不能继续复用；如决定重新提交，核对原副作用后创建新Run。

示例SDK实际实现分别位于[Go runtime_recovery.go](../../sdk/go/agentplatform/runtime_recovery.go)、[Java ExecutionServer.java](../../sdk/java/agent-platform-sdk/src/main/java/com/lexagent/sdk/ExecutionServer.java)和[Python execution_lifecycle.py](../../sdk/python/agent_platform_sdk/execution_lifecycle.py)。三者都要求显式 `RecoveryGenerationRunStore` 能力；Store只收到Scope、幂等键和修订，不接收令牌。无本地执行时也只有在平台签名命令、当前State和权限都匹配后才能导入新投影。同一世代的只读重放先验证完整签名绑定与当前执行权限，再确认Registry中仍是同一个私有处理器：运行中只返回 `202`，不重建处理器、Run投影或事件；只有处理器真实退出后，才可披露等待/终态结果。新世代恢复仍必须证明旧处理器实际退出，并重新核验当前State及权限。旧模型/工具派发通过只读回执对账；回执未知时保持未知并停止，不能再次派发。`MemoryRunStore`和本地事件仍是L1，不保存跨进程历史。

### 有序业务检查点计划

普通 `runtime-recovery/v1` 在业务Handler之前调用显式检查点选择器。选择器只列出该业务工作流所需的固定步骤；SDK先核验平台签名的停止引用，再逐项按原Scope读取其引用的**当前**公共State，并对照revision、schema、摘要、执行修订和有效期。计划之外合法的Skill/Context等附属检查点可以同时存在，但不能替代业务证据或Harness步骤。selector缺省时普通恢复拒绝。人工批准恢复走pending/批准/显式resume路径，不使用这个普通故障计划。

每一步必须有当前且结构有效的业务检查点，或由业务明确允许的首次步骤。允许首次开始时，签名引用内必须没有该检查点，SDK还要对同一Scope/key重新Load并确认精确响应`checkpoint:null`；随后只接受与冻结输入摘要一致的首次开始。后续步骤的摘要可根据此前已由SDK实际读取并验证为完成的检查点计算。下一步仅在真实Save/Load回执表明当前持久检查点已完成后开放，并再次确认该步骤当前没有head；任意业务返回字典或Harness结果不能推进计划。处理中断后沿用已有模型/工具只读回执，未知回执不会自动重发。

示例普通故障恢复使用以下固定顺序。Go运维要求既有证据检查点，然后运行Harness；Java工单同样要求既有工单证据后才可能开始Harness；Python direct只走Knowledge步骤，`tool_loop`则按证据→Harness→Knowledge顺序推进。Go/Java证据检查点不允许缺失后冷启动；Python证据首次写入只冻结已发布Prompt/输入指纹，Harness与Knowledge的首次有价派发仍须先持久化各自的开始阶段。

| 示例 | 顺序与固定检查点 |
|---|---|
| Go 运维 | `operations/diagnosis-evidence`，`schema://example-go-operations/evidence/v1` → `harness/diagnosis-model`，`schema://agentplug/harness-loop/v1` |
| Python 文档 direct | `knowledge-harness/document-answer`，`schema://agentplug/knowledge-harness/v1` |
| Python 文档 `tool_loop` | `documents/document-tool-evidence`，`schema://example-python-documents/tool-evidence/v1` → `harness/document-tools`，`schema://agentplug/harness-loop/v1` → `knowledge-harness/document-answer`，`schema://agentplug/knowledge-harness/v1` |
| Java 工单 | `tickets/draft-evidence`，`schema://example-java-tickets/evidence/v1` → `harness/ticket-model`，`schema://agentplug/harness-loop/v1` |

选择器的最小配置形状如下；各业务必须保留源码中的校验器、完成谓词和输入摘要生成，不要把示例缩写直接作为可跳过检查的实现：

```go
agentplatform.ServerConfig{
    RecoveryCheckpointSelector: recoveryCheckpointSelector,
}
```

```java
ServerConfig.builder()
    .recoveryCheckpointSelector(business::recoveryPlan)
    .build();
```

```python
ExecutionLifecycle(
    ..., load_checkpoint=load_checkpoint,
    load_recovery_checkpoint=load_recovery_checkpoint,
    recovery_checkpoint_selector=document_recovery_checkpoint_selector,
)
```

业务实现分别见[Go recovery.go](../../examples/go-operations/recovery.go)、[Java TicketAssistant.java](../../examples/java-tickets/src/main/java/com/lexagent/examples/tickets/TicketAssistant.java)和[Python business.py](../../examples/python-documents/document_assistant/business.py)。Go接口类型为`RecoveryCheckpointSelector`/`RecoveryCheckpointStep`，Java为`RecoveryPlan.Selector`/`RecoveryPlan.Step`，Python selector与步骤定义位于SDK公共模块`agent_platform_sdk.recovery_context`，顶层也导出`RecoveryPlan`、`RecoveryCheckpointStep`及相关类型。SDK同一进程中收到相同签名恢复命令时，先复查当前授权并确认其私有活动世代已真实退出，再只读返回该世代已有结果，不再次调用业务Handler；新进程或新世代仍完整执行当前引用及有序计划核验。

没有配置业务selector的Agent会因selector缺省而拒绝普通恢复。部署前为目标工作流配置固定计划，并在目标平台验证停止证明、当前检查点和授权核验均有效；固定计划和安全边界详见[恢复协议](../../contracts/runtime-recovery.md)。

三个计划各自使用示例内的业务校验器、SDK公开Capability/State接口和公共Harness或Knowledge能力，不直连平台数据库，也不依赖其他示例代码；Python文档的RAG步骤仍由公共Knowledge接口执行。

业务调用方只提交原业务输入，不直接请求Agent的内部`resume`路由，也不生成`runtime-recovery-stop/v1`、停止证明或`confirmation_token`。恢复请求由平台控制器依据持久Run和真实停止证据签发，原Scope、input/schema及幂等键保持一致。恢复能否继续还取决于平台是否可证明旧处理器已退出、当前State仍有效且当前授权仍成立。

## 公共Context准备与输入限额

检查点到期后，平台后台分批删除业务正文并保留Schema/CAS版本头，防止相同状态键被重新初始化。不要用新操作键绕过到期限制；需要新业务状态时使用新的状态键，并遵守平台条目配额。正文清理不等于状态版本元数据或审计事件全部删除。若状态加载返回`STATE_CONTINUITY_LOST`，Harness/业务应保留错误并停止，不能当成新阶段从头运行。用户确认要重新发起时，应先核验原请求是否存在未确定的模型/工具副作用，再创建新Run；新Run代表新的业务操作，不是原Run恢复。平台不能证明旧退出、核验当前检查点或确认当前授权时，不得恢复。

通过现有资产审批发布流程，将模型策略的`max_input_tokens`及运行策略的`context`固定到不可变版本。例如批准如下上下文设置：

```json
{"max_messages":64,"mode":"summary","summary_max_bytes":1024}
```

`mode`可为window、summary、reject；窗口按完整用户轮次裁剪，系统Prompt和当前轮次不截断。summary是有来源摘要的非可信对话摘录，不是LLM语义总结；若当前轮次仍超限则拒绝。输入估计包含消息和Tool Schema，实际Token与费用取模型回执。

调用时提供从user开始的对话，平台插入批准的系统Prompt。若传入system，它必须为首条且正文完全等于批准模板，否则拒绝。不能给准备接口传入任意system指令或自行改变模式、限额。尚未配置上下文策略时，准备接口默认64条消息和16384的保守输入估计上限；模型直接调用的输入上限由明确发布的`max_input_tokens`控制，0保留旧策略兼容行为。

```go
prepared, err := client.PrepareContext(ctx, []map[string]any{{"role":"user", "content":"diagnose this incident"}}, []string{"runtime_inspect"})
```

```python
prepared = await client.prepare_context([{"role":"user", "content":"find the document answer"}], ["runtime_inspect"])
```

```java
Map<String, Object> prepared = client.prepareContext(List.of(Map.of("role", "user", "content", "classify this ticket")), List.of("runtime_inspect"));
```

Function名称必须已在当前工具策略发布，文本模型请求可传空列表。准备结果包括`messages/function_names/prompt_template_hash/policy_snapshot_hash/source_hash/dropped_messages/strategy/estimated_input_tokens`；有摘录时还包括`summary_source_hash`。仅把模型请求字段加稳定`idempotency_key`后提交正常模型接口，其他字段保留作状态/追踪证据。准备不调用厂商，也不产生模型费用；模型生成入口会再次检查批准的输入限额，不允许绕过准备接口提交超限消息。

部署公共Context和模型接口时，应为对应Agent发布上下文策略、模型策略及授权，并在目标环境检查预算、工具Schema和费用账本；接口准备或单项请求成功不能替代业务流程的授权与端到端核验。

首次写入`expected_revision=0`，后续写入使用刚读取的版本。相同步骤重试复用操作键及完全相同输入；`STATE_REVISION_CONFLICT`要求业务重新检查冲突，SDK不会自动换版本重试。Schema谱系变化返回`STATE_SCHEMA_CONFLICT`；当前权限、执行世代或租约不成立返回`STATE_AUTHORITY_DENIED`。已有状态到期或历史正文不可用时，平台以`STATE_CONTINUITY_LOST`失败关闭，不能从旧Run冷启动。普通异常停止使用独立的`runtime-recovery/v1`受控恢复路径（见前文），无停止证据或当前检查点时会拒绝。保存检查点不证明外部副作用已提交，恢复时仍需使用平台工具幂等及真实回执。

## 批准暂停、签名恢复和固定计划协作

SDK提供公共编排，业务Agent只整理输入和处理领域结果。使用本节能力前，发布包含相应接口的不可变SDK/Agent版本，并配置完整ToolPolicy、State权限、身份授权和平台签名材料；运行行为仍以目标平台的当前资源为准。

Go/Java示例已为模型选择工具指定Function别名inspect。必须把如下ToolPolicy片段合并到完整、经审核发布的策略；还需用户/机器的工具资源授权。此片段不能单独当成完整发布请求，也不会自动创建Grant：

```json
{
  "allowed_tools": ["runtime.inspect"],
  "require_confirmation": [],
  "functions": [{
    "name": "inspect",
    "tool_name": "runtime.inspect",
    "description": "Read verified execution context; does not inspect host health",
    "parameters": {"type": "object", "properties": {}, "additionalProperties": false}
  }]
}
```

只有已注册工具、不可变ToolPolicy允许该工具、发布策略将其标为需要确认，且调用人和Agent机器身份都通过当前`tool.invoke`与检查点读取授权时，SDK才会得到`approval_required`。它只表示当前FIFO队首需要人类批准；不能用示例里的只读`runtime.inspect`代替需要确认的实际工具，也不能靠`business.review`放行。

```go
if loop.Status == "approval_required" {
    return nil, agentplatform.PauseHarness(loop, "diagnosis-model")
}
```

```java
if ("approval_required".equals(loop.get("status"))) {
    throw HarnessPause.from(loop, "ticket-model");
}
```

Go `PauseHarness`、Java `HarnessPause.from`和Python `HarnessPause.from_result`只传递有界的key/name/call_id标识；业务参数留在原公共Harness检查点。生命周期将暂停作为waiting记录并退出当前执行世代，不会把参数、Token或完整pending对象写进事件。

人类批准使用浏览器控制面完成，而不是要求Agent提交完整参数。实际接口按此顺序调用，所有请求都沿用当前登录的用户会话：

| 动作 | 方法与路径 | 请求关键字段 |
|---|---|---|
| 读取当前等待的FIFO队首 | `POST /api/modules/tool-approvals/pending` | `operation: {run_id, pending_key}` |
| 生成限时预览 | `POST /api/modules/tool-approvals/preview` | `operation`为pending返回的引用 |
| 再次认证 | `POST /api/modules/tool-approvals/step-up` | 同一`operation`和预览`claims`、动作名、当前密码 |
| 提交批准 | `POST /api/modules/tool-approvals/approve` | 同一`operation`和`claims`、刚取得的`step_up_token` |
| 撤销批准 | `POST /api/modules/tool-approvals/step-up`后`POST /api/modules/tool-approvals/revoke` | `tool.approval.revoke`再次认证、同一引用/claims及短期proof |
| 显式继续 | `POST /api/modules/tool-approvals/resume` | 仅同一`operation`引用和服务器原样返回的`claims` |

pending请求体仅含运行ID和Harness key：

```json
{"operation":{"run_id":"run-example","pending_key":"diagnosis-model"}}
```

响应的`operation`由服务器从`harness-loop/v1`当前检查点重读得到，包含`name`、`call_id`、`pending_key`、`checkpoint_revision`，且`payload`为`null`。浏览器不能补参数或替换FIFO队首。preview会重新核对本人会话、运行/策略、函数Schema及用户和机器权限，并返回绑定相同引用的`claims`和经脱敏的预览字段；客户端必须原样保留`operation`和`claims`，不能重算claims或根据事件拼造它们。

`step-up`用当前密码为`tool.approval.approve`或`tool.approval.revoke`创建短期证明；密码在提交前从输入框清除。批准返回的`confirmation_token`只短暂经过当前前端调用栈，组件会丢弃响应正文，只把批准编号和到期时间交给宿主。step-up proof和确认Token都不得写入localStorage、sessionStorage、业务input、运行事件、日志或检查点。工具批准不授予资源权限；平台仍按当前版本策略、当前用户和机器授权重新检查。

批准后，用户显式点击“继续运行”，浏览器只发pending引用和预览claims，不发送完整参数、密码、step-up proof或`confirmation_token`。平台事务使用本人当前会话和已提交批准记录将原Run切到恢复请求状态；生产Gateway在实际派发前重新读取原检查点及FIFO队首、复查当前权限和策略，再为同一仍有效批准瞬时重签。SDK接收的是平台签名的`resume_input.confirmation_token`，恢复同一业务输入、Schema和幂等键，并要求原waiting世代确已退出以及新执行修订/租约成立。恢复请求若超时或响应不明，不能自动重发：查询原Run的`GET /api/modules/execution/platform/runs/{runID}`（前端对应`api.executionRunStatus(runID, signal)`），继续核对原运行状态。撤销也必须对同一批准再次认证，不能改变待批准参数。

Go业务调用`RunHarness`并用`PauseHarness`将批准结果变成安全暂停；恢复Token只从平台签名的`request.ResumeInput`取出，作为一次性的Harness选项传入：

```go
loop, err := runner.RunHarness(ctx, input, agentplatform.HarnessOptions{
    Key: "diagnosis-model", MaxRounds: 4, MaxToolCalls: 8,
    ConfirmationToken: confirmationToken,
})
if err != nil { return nil, err }
if loop.Status == "approval_required" {
    return nil, agentplatform.PauseHarness(loop, "diagnosis-model")
}
```

Java使用`CapabilityClient.runHarness`和SDK的`HarnessPause.from`：

```java
var loop = client.runHarness(input, new HarnessRunner.Options("ticket-model", 4, 8, confirmationToken));
if ("approval_required".equals(loop.get("status"))) {
    throw HarnessPause.from(loop, "ticket-model");
}
```

Python SDK源码公开`CapabilityGatewayClient.run_harness`和`HarnessPause.from_result`；完成结果原样返回，批准结果只生成仅含key、name、call_id的暂停对象，未知/无效状态失败关闭：

```python
from agent_platform_sdk import HarnessPause

loop = await client.run_harness(
    input, key="document-model", confirmation_token=confirmation_token
)
result_or_pause = HarnessPause.from_result(loop, "document-model")
if isinstance(result_or_pause, HarnessPause):
    raise result_or_pause
return result_or_pause
```

`confirmation_token`只能来自本次平台签名的`request.resume_input`，不可从浏览器请求、业务input或持久存储取值。Python文档助手默认`workflow_mode="direct"`；可选`tool_loop`显式增加Function Harness模型流程，默认路径不会增加Harness模型调用。启用工具需要不可变版本发布、权限策略配置、部署和端到端检查。`MemoryRunStore`仍是进程内L1，受控恢复依赖平台持久Run、停止证据、当前检查点和当前授权。

Java Harness每次入口都会读取平台当前`harness-policy/v1`，将SDK选项限制在平台发布的轮次/工具额度内，并把策略摘要、原始限制、绝对截止时间和重复调用计数保存在公共State。重复摘要仅服务于同一Java Harness检查点恢复，不能当作业务幂等键、旧输入摘要或请求签名；大整数与字符串转义有稳定编码，但各语言对浮点数的JSON表示不同，因此不承诺Java、Go、Python之间重复摘要相同，也不要跨语言移交或重建Harness检查点。统一浮点编码若成为跨语言持久化协议，需另行版本化后再实施。

### 三语言共享的Harness策略与期限

Go、Python、Java SDK每次Harness入口都会通过受签名保护的能力网关读取`POST /internal/runtime/harness-policy`，请求体必须是空对象`{}`。平台只披露当前已绑定Runtime策略中的限额，不接受业务调用方传入策略ID或自行提高限制。响应包含`version="harness-policy/v1"`、64个十六进制字符的`policy_hash`、正整数`server_time_ms`和`limits`。Runtime资产的`harness`字段可设置`max_rounds`（1..8）、`max_tool_calls`（1..16）、`max_repeated_calls`（1..4）、`max_elapsed_seconds`（10..3600）与`limit_behavior`（`error`或`incomplete`）；未设置时源码默认值分别为8、16、1、300秒和`error`。SDK可配置的`max_rounds`和`max_tool_calls`与发布值取较小值；重复调用数、绝对期限及超限行为由SDK按发布值执行。调用方只能进一步收紧可配置项，不能覆盖管理员策略。

限额由有权管理员在浏览器策略控制面按具体租户、部门、应用、Agent和版本范围维护`runtime`资产。读取当前资产和快照后，保留原Runtime内容，只更新其中的`harness`字段；按返回的真实`revision`使用`PUT /modules/policyasset/assets/runtime/{id}`更新，再以`POST /modules/policyasset/assets/runtime/{id}/publish`发布资产，最后通过`POST /modules/policyasset/snapshots/publish`把该Runtime版本与其他当前策略资产引用一起发布为新快照。所有写入都带实际`scope`和`expected_revision`，冲突时重新读取并复核，不猜版本号，也不要只发布Runtime资产而遗漏快照。需要当前身份在目标范围拥有`policy.manage`；下例的数值仅供说明，不能直接视作已发布配置：

```json
"harness": {
  "max_rounds": 4,
  "max_tool_calls": 8,
  "max_repeated_calls": 2,
  "max_elapsed_seconds": 180,
  "limit_behavior": "incomplete"
}
```

Harness从`server_time_ms`建立绝对截止时间，并保存在其公共State中。模型调用、工具调用、暂停后的人工审批等待以及进程停机时间都计入同一期限；恢复或继续不会重置计时。SDK会把下游请求超时收紧到剩余期限，期限过后不会开启新模型/工具派发；恢复未决操作时只允许按原Run查询只读回执，未知回执仍保持未知。

三个业务适配器都区分平台Run预算与Harness循环限额：模型预算耗尽报告`MODEL_BUDGET_EXCEEDED`；若发布的循环限额采用`limit_behavior="incomplete"`，部分结果的`termination_reason`为`HARNESS_LIMIT_EXCEEDED`，`finish_reason`为`elapsed_limit`、`repeated_tool_limit`、`round_limit`或`tool_limit`；其他不完整结果报告`HARNESS_INCOMPLETE`。Go返回相应非重试`AppError`，Python抛出相应非重试`GatewayError`，Java返回对应非重试失败。预算错误不能伪装成Harness限额，其他partial结果也不能包装为成功。若策略选择`error`，达到Harness限额会直接以`HARNESS_LIMIT_EXCEEDED`停止，而不会返回伪造的完整答案。

虽然三语言使用`harness-loop/v1`字段约定，检查点还绑定语言SDK的输入摘要与JSON数值编码规则。只能由创建它的原语言SDK恢复；不要在Go、Python、Java之间迁移、重建或手工重序列化检查点。需要跨语言转移时应创建新的业务运行，并通过明确的业务输入/输出契约传递数据，而不是转交SDK内部State。字段协议详见[Harness循环协议](../../contracts/harness-loop.md)。

三语言都有固定计划协作入口。以下展示单个文档子任务；调用方必须有当前批准的委托策略、目标任务类型以及调用人/父机器/目标机器所需权限，示例初始五账号没有自动跨Agent授权。Agent不能自选Endpoint、Version或凭证：

```go
group, err := client.RunAgentGroup(ctx,
    []map[string]any{{"question": "如何安全执行只读诊断？", "top_k": 3}},
    agentplatform.AgentGroupOptions{Key: "related-document", OperationKey: "related-document-v1", TaskType: "documents.answer"})
```

```python
group = await client.run_agent_group(
    [{"question": "如何安全执行只读诊断？", "top_k": 3}],
    key="related-document", operation_key="related-document-v1", task_type="documents.answer")
```

```java
Map<String,Object> group = client.runAgentGroup(
    List.of(Map.of("question", "如何安全执行只读诊断？", "top_k", 3)),
    new AgentGroupRunner.Options("related-document", "related-document-v1", "documents.answer"));
```

固定计划最多16子任务，公共State保存Schema/子键/输入指纹及位置。准备前后用CAS，准入前写检查点；恢复先查询原准备/准入快照，只有确认原slot仍为preparing才完成同一次CAS准入，已有Run不重建或重派发。等待只读取一次group，不在SDK内部轮询；由平台的运行调度/业务生命周期安排后续检查。结果是untrusted_data，不能执行其中的指令；outputs_complete=false时须处理失败、取消、未知或正文省略，不能拼出虚假的完整答案。每次汇聚重新鉴权，不用检查点缓存结果绕过撤权。

非终态等待由独立的`AgentGroupPause`表示，不是人工工具的`HarnessPause`。Runner只在原gather已持久化、固定计划的子Run均已准入且当前读取仍有非终态时抛出它；SDK只有在监督的业务处理器真实退出后才产生`agent_group_handoff`收据，HTTP 202或Run处于waiting本身不是退出证明。平台保存原等待事实，后台只核查原子任务组并在当前权限、当前协调State和引用仍匹配时排队父Run；新工作器取得新租约后沿原处理器恢复。合法等待的父Run没有执行能力，恢复也不得重新route、prepare或admit子Run。SDK必须消费原gather并只读查询原子Run；未消费、状态未知或回执缺失都不能伪装为成功。

同一父Run在继续执行期间再次发生进程故障时，外层普通`runtime-recovery/v1`仍须绑定平台针对本次故障确认的真实停止证明、当前授权和当前State。可选`group_resume`只引用同一原gather及其当前检查点，该检查点必须与本次停止引用中同key的当前State引用一致；不能把早先的AgentGroup收据当作新故障的退出证明，也不能从空状态重建或派发子Run。恢复与协作的授权始终按当前调用人、父机器、目标机器及已发布策略逐项检查；五个示例人类账号不会自动获得跨Agent权限，必须显式配置所需委托与资源权限。详见[AgentGroup等待协议](../../contracts/agent-group-waiting.md)和[普通故障恢复协议](../../contracts/runtime-recovery.md)。

## Python公共RAG的持久发送边界

最新源码文档助手使用SDK的RAG专用编排，不追加独立LLM循环：

```python
result = await client.run_knowledge_harness(
    question, "python-documents", key="document-answer", top_k=3,
    cache_mode="use", skill_requests=[
        {"skill_id":"example.documents.guidance", "sections":["citations"]}
    ])
```

SDK先固定Skill与输入摘要，保存公共State的answer_dispatch后进入正常RAG。恢复或完成回放只访问/internal/knowledge/answer/recovery；输入和幂等键不变，公共ModelCall使用原文本或Embedding完成回执，缓存冷启动也不会自动重发模型。缺失/未知/漂移停止，须从平台原操作协调，不能换key重做。答案不保存到检查点，每次重新核验当前文档、Skill、模型和执行权限。引用、Cache、Evaluation仍由原公共管线提供，恢复用量代表原调用，零新模型请求不表示原供应商费用已撤销。

需显式公共State授权与策略、Skill双Grant及知识/模型/Embedding权限。该专用RAG编排与后文可选Function Harness/Code Runtime是不同路径；各路径的策略、权限和资源配置应分别发布，不会因启用其中一种而自动获得其他能力。

## 三示例的可选本人通知

源码新增`notify_me`布尔输入，默认false。Go诊断助手与Java工单助手在原Harness中选择`inspect/notify_self`；Python须同时选择`workflow_mode=tool_loop`，默认direct保持原RAG调用路径。三个示例只回显通知意图，不将该字段当作实际送达证明。

| 示例 | 业务请求示例 |
|---|---|
| Go | `{"service":"api","symptom":"响应缓慢","notify_me":true}` |
| Python | `{"question":"索引增量更新如何保持一致性？","workflow_mode":"tool_loop","notify_me":true}` |
| Java | `{"ticket_id":"DEMO-1","summary":"排查服务超时","notify_me":true}` |

`notify_self`是模型协议名称，映射平台写工具`notify.self`；参数仅title/text，平台从可信人类执行Scope选择当前调用人，拒绝指定任意收件人。发布参数Schema仍需满足字节限制title≤256、text≤4096；JSON Schema的字符计数不替代运行期字节校验。实际写操作复用公共Outbox、幂等账本、执行租约、提交前权限/批准检查及Observation。受理不等于送达，模型也不保证选择工具。

模型选择写工具后，Harness保存原FIFO操作并返回批准等待，SDK监督退出才交接给平台。本人必须在独立控制面预览、再次认证、批准并显式继续；模型和业务代码不能批准自己。需要当前人类及Agent机器tool.invoke:notify.self授权、检查点读取/写入权限、已发布Function/强制确认策略及平台签名配置。默认配置不自动授予上述权限；部署时验证批准、撤权和幂等行为，并以平台运行状态与Outbox回执判定操作结果。

## 三示例的可选 Code Runtime 分析

三个示例的业务输入都提供可选布尔值`sandbox_check`，默认`false`；它只是允许公共Function Harness选择对应的Code Function，不是代码或执行凭据。实际业务输入如下：

| 示例 | `request`输入 | Function/工具映射 |
|---|---|---|
| Go运维 | `{"service":"api","symptom":"响应缓慢","sandbox_check":true}` | `sandbox_python` → `code.python` |
| Python文档 | `{"question":"文档中的金额合计是多少？","workflow_mode":"tool_loop","sandbox_check":true}` | `sandbox_python` → `code.python` |
| Java工单 | `{"ticket_id":"DEMO-1","summary":"检查工单事实","sandbox_check":true}` | `sandbox_javascript` → `code.javascript` |

Python schema规定`sandbox_check=true`必须同时设置`workflow_mode="tool_loop"`；Go与Java使用原有业务Harness，无需额外模式字段。三个业务指纹都绑定该选择，恢复时不能切换。只有选择启用时，Harness的`function_names`才包含Code Function；业务只提交布尔选项，不接受调用方直接传入`code`。模型建议的函数参数由发布Function schema限制为仅`code`字符串（长度1..65536），示例指示它只对已提供的事实做短小只读分析，不访问文件、网络、环境、凭据或密钥、不做副作用。沙箱Profile及其隔离仍由平台运维配置，提示词本身不替代运行隔离。

Manifest相应声明`tool.invoke:code.python`或`tool.invoke:code.javascript`；[`example-release-bundle`](../../platform/cmd/example-release-bundle/main.go)据此生成`sandbox_python`/`sandbox_javascript`到`code.*`的Function草案、仅含`code`参数的封闭Schema及`require_confirmation`策略片段。它只是合并提示，不是六类完整可发布策略，不会注册Function、绑定Code Profile或授权。正式运行需要发布匹配当前版本的ToolPolicy/Code配置，并分别为当前调用人与绑定机器授予对应`tool.invoke:code.*`资源权限。每次实际调用还需独立人工批准。

批准遵循原FIFO `pending → preview → step-up → approve → 显式resume`，确认令牌只从平台签名恢复请求中瞬时传入；已派发操作在恢复时走只读工具回执查询，未知或未完成回执保持未知并停止，不自动重新执行代码。`sandbox_check`输出字段仅回显用户的选择，不证明函数被选择、批准、运行或成功。Code Runtime是否执行及其结果应由已核验的工具Observation和平台回执确认。

Code运行时使用仓库自建的三个多阶段镜像目标，构建上下文为仓库根目录：

```powershell
docker build --target python -t agentplug:code-python -f workers/code-runtime/images/Dockerfile .
docker build --target javascript -t agentplug:code-javascript -f workers/code-runtime/images/Dockerfile .
docker build --target shell -t agentplug:code-shell -f workers/code-runtime/images/Dockerfile .
docker image inspect agentplug:code-python --format '{{.Id}}'
```

对三种镜像分别执行`docker image inspect`，把返回的实际`sha256:<64位小写十六进制>`镜像ID填入私有控制器配置`code-runtime.json`的`images.python`、`images.javascript`、`images.shell`，不要把可变Tag当成ID。`platform/cmd/prepare-code-runtime`也要求这三个实际ID，并生成`.local-secrets`下的私有配置；重建镜像后必须重新核对ID和配置。镜像启动入口是`code-sandbox-guard`，以UID/GID `65532:65532`运行，并带`landlock-v3`标签。Linux运行内核必须支持Landlock ABI 3；守卫无法启用Landlock时会失败关闭，不会退回无文件隔离执行。

守卫仅允许固定系统目录只读，将写入限制在容器内的临时`/workspace`、`/tmp`和`/dev/shm`；没有宿主机文件挂载。控制器还以Docker `--network none`、只读根文件系统、非root、移除全部capabilities、`no-new-privileges`及seccomp运行代码。此隔离只适用于平台Code Runtime，不意味着普通业务进程或外部API已获访问权。若业务需要查询外部系统，改用已注册的平台只读API Tool，并为Agent版本配置固定HTTPS端点和查询参数白名单；不可把网络打开给代码执行器。操作说明见[Code Runtime运行手册](../../workers/code-runtime/README.md)。

## 运行事件与三语言读取边界

平台持久Run事件和Agent SDK元数据事件使用不同的序号。平台历史流通过`GET /api/modules/execution/platform/runs/{run_id}/events?after_seq=0`读取；Agent快照通过`GET /api/modules/execution/platform/runs/{run_id}/agent-events?after_seq=0`读取。后一入口仅供原Run本人使用，其他有权审核历史的用户走平台历史接口。浏览器使用已登录的同源会话，不传入Agent端点或context_token。

平台代理选择当前就绪的安装版本及端点并签发events-only请求；Go、Python、Java SDK在披露前通过公共私有事件鉴权接口重新检查当前调用人与绑定机器读取权。部署必须配置SDK公共能力客户端的机器身份和内部签名凭据，并为绑定机器显式授予对应安装的history.read，不能由run或模型调用权隐式推导。缺少公共鉴权配置的旧本地模式不具备这个实时IAM边界，不应用作生产部署。

Agent事件仅含operation、reason、harness_key、tool_name、call_id、code等有界标识元数据，不能作为业务答案、工具参数或批准凭据。前端提供独立的手动读取入口，游标以十进制字符串保存；不可将JavaScript解析出的不精确大整数作为下一次游标，也不可把Agent游标用于平台历史流。新Run应从零开始，不跨Run复用游标。

三语言SDK源码已接入共同的[执行世代事件区间协议](../../contracts/sdk-event-ranges.md)：由已验签执行修订分配互不重叠的序号区间，内存投影的新进程事件因此不会重新从1遮挡旧游标。自定义Store需明确实现GenerationRunStore对应语言SPI，不能从业务input自行选修订；批准恢复仍使用原真实交接收据，新区间空缺不表示已有历史事件。此能力不使MemoryRunStore成为持久存储，也不替代普通故障恢复的停止/检查点/权限核验。部署前应实际验证批准继续、浏览器游标跨执行世代读取及撤权拒绝，不能用本地投影证明持久恢复。

Agent代理一次最多15秒和256条。断开、当前授权撤销、安装修订或端点变化会终止读取；未知结果不能转换成运行成功。SDK本地事件记录不等于跨进程持久事件恢复。部署和授权配置见[业务Agent挂载与已有用户授权指南](业务Agent挂载与已有用户授权指南.md)。上线前应分别验证平台历史事件、本人Agent事件和撤权后的拒绝，不能以本地事件缓存代替这些检查。
