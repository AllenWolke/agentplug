# agent-eval

独立 Go CLI，使用智能体中台公开网关执行和分析评估。镜像名称为 `agentplug:agent-eval`，平台默认 Compose 不启动它，也不需要工具专属数据库。

工具提供独立CLI、九维规则评分、可选模型评审、人工校准及隔离仿真。测量结果附带证据和改进建议；缺少必需证据时保留UNKNOWN，不把Agent运行成功直接算成业务目标完成。

## 构建与独立启动

在仓库根目录执行：

```powershell
./scripts/agent-eval-build.ps1
docker build -f cli/agent-eval/Dockerfile -t agentplug:agent-eval .
docker run --rm agentplug:agent-eval help
```

Linux/macOS 使用 `sh scripts/agent-eval-build.sh`。生成 Linux、macOS、Windows 的 amd64/arm64 二进制。macOS 交叉构建不代表已经在 macOS 实机验证；CI 配置包含三种系统的原生测试入口。

```sh
python scripts/compose.py run --stack eval --env-file .env --service agent-eval
```

交互启动会隐藏输入密码，选择工作空间，发现当前有权查看的在线实例，并支持输入一个序号、逗号分隔的多个序号或 `all`。无已发布评估配置时，生成可编辑的 `evaluation.json`；先确认业务金标再提交审核。

Linux 主机的报告绑定目录须允许容器 UID 10001 写入。Docker Desktop 可通过 `host.docker.internal` 连接宿主平台；其他部署可设置 `AGENT_EVAL_PLATFORM_URL`。远程网关应使用 HTTPS。输入与凭证放在只读目录，报告放在单独可写目录。

## 认证与权限

凭证文件格式为 `{"username":"<account>","password":"<password>"}`，保存在仓库忽略的私有目录，限制本机文件权限。禁止把密码或 Token 写进命令参数、Dockerfile 或评估报告。CLI 只持有内存 Cookie，支持 Access Token 到期后的 Refresh，退出时注销会话。

`discover` 的 Agent 可见性和业务执行权分别校验。执行评估需要 `evaluation.run` 和被评估安装实例的 `run`。读取轨迹需要当前 Run 的 `history.read`；所有者只能取得该Run的脱敏工具和费用摘要，读取其他用户数据仍需对应数据范围及审计、用量权限。子Run逐项鉴权，未确认费用及缺失证据显示未知。管理员不默认拥有业务运行权。

发布金标与指标复用平台审核流程。数据集审核者必须与创建者不同，并具备发布审批权限；CLI 不绕过人员分离和 CAS。

## 离线用例流程

以下命令在三种系统使用相同参数；Windows 二进制名称以 `.exe` 结尾。凭证、实例与资源 ID 用实际值替换。

```sh
agent-eval discover --platform http://127.0.0.1:38080 --credentials-file <private.json> --workspace <tenant>/<department>/<application>
agent-eval init --credentials-file <private.json> --workspace <tenant>/<department>/<application> --agent <installation> --out <private-dir>
agent-eval prepare --credentials-file <creator.json> --config <private-dir>/evaluation.json --out <private-dir>
agent-eval review --credentials-file <reviewer.json> --workspace <tenant>/<department>/<application> --kind datasets --id <dataset> --decision approved --reason '<review reason>'
agent-eval publish --credentials-file <reviewer.json> --workspace <tenant>/<department>/<application> --kind datasets --id <dataset>
agent-eval publish --credentials-file <reviewer.json> --workspace <tenant>/<department>/<application> --kind metrics --id agent-assertions.1.0.0
agent-eval bind --credentials-file <creator.json> --config <private-dir>/prepared.json --out <private-dir>
agent-eval run --credentials-file <creator.json> --config <private-dir>/bound.json --id <stable-batch> --out <private-dir>
```

配置冻结安装实例、版本与安装修订号。平台冻结数据集和评分指标；标准答案不会传给业务 Agent。实例更新后须重新发现并创建评估套件。默认并发 1、重复 3 次；配置中的总 Token/费用限额按用例试验分配，只能降低平台既有预算。

`run` 每个实例生成一份 JSON 和 Markdown 报告，并保存批次状态。连接中断后使用相同配置、选择范围、目录和 `--id`，读取原评估 Run；未知请求不自动重复。取消使用 `agent-eval cancel --id <product-evaluation-run>`；实际停止以平台执行及子 Run 的确认记录为准。

内嵌 Go 运维、Python 文档、Java 工单用例是教学起点。仅验证字段、关键词或成功状态，不能证明完整业务目标、安全或事实准确；开发者应补全目标约束、相关知识 ID、工具允许集合、依赖关系与独立审核证据。

## 历史分析与报告

```sh
agent-eval analyze --credentials-file <private.json> --workspace <tenant>/<department>/<application> --run <execution-run> --expected <gold.json> --out <private-dir>
agent-eval report --input <report.json>
agent-eval compare --baseline <baseline.json> --candidate <candidate.json>
```

历史分析只读取记录，不重放 Agent。`analyze --input <trials.json>` 是本地导入分析，明确标为导入来源，不能授予平台发布资格。基线比较要求相同 Agent、冻结金标、模式、重复数、并发、预算、超时、评分协议及仿真配置；版本允许不同。未知币种的费用不可直接比较。

九维指标区分 `measured`、`missing`、`not_applicable`、`blocked`。未知费用、TTFT、人工接受与安全证据均不记零。P95 至少 20 个不同 Run，P99 至少 100 个；不足时不输出可靠性能结论。安全指标独立判定，违规优先失败，必要证据不足保持未知。

建议包含问题、Run/Case 证据引用、可能原因、建议修改及复验方法。报告不含原始业务输出，不自动修改代码、授权或策略。

## 仿真开发入口

```sh
agent-eval fixture serve --listen 127.0.0.1:8787 --scenario failure
```

fixture 提供成功、失败、超时和未知结果的只读测试 API；`--scenario selectable` 允许固定的场景查询枚举。它不拦截或修改生产 Provider。仿真运行要求管理员配置的测试工作空间、已发布fixture Agent、明确安装修订号、冻结策略以及专用测试Provider全部匹配。完整部署与指标说明见[独立工具开发者指南](../../docs/开发者指南/独立AgentEvaluation工具使用指南.md)。

## 可选模型评审与人工校准

同一工具镜像提供 `judge serve`，它必须作为独立评分Agent完成注册、发布、安装和机器身份绑定。默认CLI不启动评分服务。评分服务只调用平台 `context.prepare` 和 `model.generate`；模型、Prompt、思考配置和计价由发布策略决定，不接受厂商凭证或请求级模型覆盖。

```sh
agent-eval judge manifest
agent-eval judge bundle --out <private-registration-dir>
agent-eval judge serve --listen 0.0.0.0:8080
agent-eval model-prepare --credentials-file <creator.json> --workspace <tenant>/<department>/<application> --agent <grading-installation> --run <source-execution-run> --rubric cli/agent-eval/examples/rubric.v1.json --limit-tokens 30000 --limit-micros 1000000 --out <private-grading-dir>
```

`model-prepare` 冻结有权读取的原Run输出、摘要和Rubric，生成 `grading.json`。按前述 prepare → 另一位审核者review/publish → bind → run 流程执行；评分数据源为 `imported_redacted`，不会把业务标准答案交给业务Agent。读取、审核、发布和执行评分数据都继承原Run的实时权限，不可通过评估管理权限扩大数据访问范围。

```sh
agent-eval analyze --credentials-file <private.json> --workspace <tenant>/<department>/<application> --run <source-execution-run> --judgement-run <grading-execution-run> --expected <gold.json> --out <private-dir>
agent-eval review --credentials-file <reviewer.json> --workspace <tenant>/<department>/<application> --kind feedback --input <feedback.json>
agent-eval analyze --credentials-file <private.json> --workspace <tenant>/<department>/<application> --run <source-execution-run> --judgement-run <grading-execution-run> --feedback <feedback-id> --out <private-dir>
```

模型只能评估有明确Rubric的语义指标，不能证明不存在越权、泄漏，也不能填充费用、TTFT和人工接受率。未知、调用失败或无有效证据引用时不生成虚假分数。确定性业务断言优先；有证据的人工判定优先于模型判定，并保留校准分歧。报告记录原Run、评分Run、模型和版本、Rubric摘要及实际费用；未获取的信息保持未知。

`*.trials.private.json` 保存受保护的脱敏执行证据，供本地开发排查；它与认证文件、评分配置和批次状态均应保存在私有目录，不能放入公开交付包。JSON/Markdown报告不包含这些原始输出。
