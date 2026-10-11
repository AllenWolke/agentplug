# 独立 Agent Evaluation 工具使用指南

本工具评估任务成功、工具、规划、上下文、状态与记忆、安全、可靠性、成本延迟和可观测性。它输出证据与改进建议，不自动修改业务Agent代码、策略、权限或线上流量。没有足够证据的指标保持未知，不能以运行完成代替业务质量或安全结论。

## 1. 独立安装与启动

工具源码在[cli/agent-eval](../../cli/agent-eval/README.md)，运行时只连接平台公开认证网关，无专属数据库。普通CLI运行无需启动fixture或评分Agent。平台默认Compose不包含本工具。

在仓库根目录执行：

```powershell
./scripts/agent-eval-build.ps1
$AgentEval = './.local-secrets/agent-eval/bin/agent-eval-windows-amd64.exe'
& $AgentEval help
docker build -f cli/agent-eval/Dockerfile -t agentplug:agent-eval .
docker run --rm agentplug:agent-eval version
```

Linux/macOS使用`sh scripts/agent-eval-build.sh`，选择对应系统和架构的二进制。macOS本机验证入口是`sh scripts/agent-eval-native-check.sh`；交叉构建不能作为macOS实机执行证据。

创建两个私有目录：输入目录保存配置及只读凭证；报告目录保存状态与报告。设置`AGENT_EVAL_INPUT_DIR`、`AGENT_EVAL_REPORT_DIR`、`AGENT_EVAL_PLATFORM_URL`后单独启动：

```sh
python scripts/compose.py run --stack eval --env-file .env --service agent-eval
```

该文件只用于手动启动，退出时移除本次CLI容器。Linux的报告目录须允许UID10001写入；输入目录只读。Docker Desktop默认经`host.docker.internal:38080`访问本机网关。其他部署填写实际网关；远程使用HTTPS。

## 2. 认证、工作空间与选择

不传命令时，CLI隐藏输入密码，选择已有工作空间，显示在线Agent数、安装实例数和可评估数。输入`1`单选、`1,3`多选、`all`选择全部当前可评估实例。在线要求活动安装、已发布版本、最新部署就绪且即时健康探测成功；旧部署记录不能证明在线。运行数仅统计当前用户有权读取的本人活跃Run，无权限显示“不可读取”。

脚本凭证格式是`{"username":"已有账号","password":"该账号密码"}`，保存在`.local-secrets/agent-eval`，POSIX设置0600，Windows限制ACL。不要放入镜像、环境日志或命令参数。CLI只在内存保存Access/Refresh Cookie；退出注销，令牌不落盘。

每条远程CLI命令建立并注销一个认证会话。平台当前开发配置对同一账号实施每10分钟10次登录限制；达到限制会明确返回HTTP429 `RATE_LIMITED`，请等待下一时间窗口后继续，不要反复重试或重置密码。本地`report`、`compare`、`metrics`等命令不登录。频繁自动化评估应在工作流中合理安排认证与批次数量，不能通过关闭限流绕过保护。

以下变量中的工作空间与安装ID必须替换为`discover`实际返回值：

```powershell
$Scope = 'tenant-demo/dept-demo/app-demo'
$Creator = './.local-secrets/agent-eval/creator.json'
$Reviewer = './.local-secrets/agent-eval/reviewer.json'
$Output = './.local-secrets/agent-eval/example-batch'
$Installation = 'replace-with-discovered-installation'
& $AgentEval discover --credentials-file $Creator --workspace $Scope
& $AgentEval init --credentials-file $Creator --workspace $Scope --agent $Installation --out $Output
```

Linux/macOS参数相同，使用对应二进制和shell变量。可重复传`--agent`选多个实例。`init`保存当前发布版本及安装修订，不覆盖既有配置；版本/安装变化后重新发现并创建新配置。

执行需`evaluation.run`和目标安装的`run`；管理需对应评估资产权限。历史需当前`history.read`及数据范围。本人Run只返回该Run的脱敏工具及用量摘要；其他用户的数据还需独立审计/用量权限。子Run逐项鉴权，权限不完整时不报告完整树总费用。管理身份不默认获得业务运行权。

已有用户的授权预览、CAS提交与撤权参考[业务Agent挂载与已有用户授权指南](业务Agent挂载与已有用户授权指南.md)。新工具复用现有权限体系，不增加永久人类演示账号。

## 3. 固定用例、发布与执行

`evaluation.json`使用`agent-eval-suite/v1`，配置契约见[CLI suite schema](../../contracts/agent-evaluation/v1/cli-suite.schema.json)。默认并发1、每用例3次，明确总Token/费用预算。平台可进一步收紧预算。预算按选定实例、用例和试验次数分配，不因CLI配置扩大调用人或机器权限。

`init`内置Go运维、Python文档、Java工单教学用例，未知业务生成通用待填模板。修改业务输入和`expected.assertions`，人工确认目标结果、关键约束及引用；业务Agent只收到`input`。字段路径支持对象和数组索引；操作为`equals`、`exists`、`contains`、`gte`、`lte`。执行终态成功与业务目标成功分别统计。

工具配置支持`allowed`、`required`、`forbidden`、`parameters`、`maximum_calls`和`dependencies`。依赖是工具对的偏序，可表达多种正确路径；只在有可信开始/结束时间或同Run序列时判断。平台审计未保存参数正文时，参数正确率保持未知。不要在`reviewed_checks`静态填写“安全通过”或“恢复成功”。

```powershell
& $AgentEval prepare --credentials-file $Creator --config "$Output/evaluation.json" --out $Output
```

命令返回数据集ID，保存到`prepared.json`。由另一位有权读取金标的审核者执行以下命令（`$Dataset`替换实际ID）：

```powershell
$Dataset = 'replace-with-created-dataset-id'
& $AgentEval review --credentials-file $Reviewer --workspace $Scope --kind datasets --id $Dataset --decision approved --reason '已核对业务金标与证据要求'
& $AgentEval publish --credentials-file $Reviewer --workspace $Scope --kind datasets --id $Dataset
& $AgentEval publish --credentials-file $Reviewer --workspace $Scope --kind metrics --id agent-assertions.1.0.0
& $AgentEval bind --credentials-file $Creator --config "$Output/prepared.json" --out $Output
& $AgentEval run --credentials-file $Creator --config "$Output/bound.json" --id example-eval-v1 --agent $Installation --out $Output
```

已发布指标无需再次发布。失败的审核或CAS必须按返回状态修订，不用伪造第二身份或可信网关Header。`bind`冻结明确的实例、版本、修订、数据集与指标。

批次`--id`固定配置及选择范围，状态保存为私有`*.state.json`。重连使用相同配置、ID和目录；已记录Run只读取现有状态，即使Agent当前离线也不重新执行。尚未提交的新试验仍需要在线检查。断线或未知结果不能用新ID自动重放副作用；保留原Run并查询回执。取消使用评估产品RunID，终止以平台和下游确认记录为准：

```powershell
$ProductRun = 'replace-with-product-evaluation-run-id'
& $AgentEval cancel --credentials-file $Creator --workspace $Scope --id $ProductRun
```

## 4. 指标、阈值与报告

`agent-eval metrics`列出九维指标及口径。报告契约是[agent-evaluation-report/v1](../../contracts/agent-evaluation/v1/report.schema.json)。JSON/Markdown只包含汇总、版本、Run引用、指标、评审元数据和建议；`*.trials.private.json`含受保护的脱敏输出，仍应放私有目录并排除公开交付。

| 状态 | 含义 |
|---|---|
| measured | 已取得适用证据，显示样本、分子、分母和引用 |
| missing | 缺金标、授权、账本、实际测量或可信结果 |
| not_applicable | 金标明确登记该指标不适用；不据此证明安全 |
| blocked | 样本不足等条件阻止给出有效数值 |

费用来自已确认账本；有未结/UNKNOWN模型账单时不得把部分和当成完整费用。未知币种不能比较金额；工具未定价、无TTFT、无人工反馈不能填0。树总用量只在所有已授权节点证据完整时求和；根Run延迟是端到端耗时，不与子Run延迟相加。

P95至少20个不同Run，P99至少100个；重复试验不等于更多独立业务用例。置信区间仅对符合独立计数条件的二项比例计算，不为连续步骤效率或同一用例重复试验制造统计把握。

可在配置添加明确阈值，例如：

```json
{"thresholds":[
  {"metric_id":"task_success","minimum":0.95,"minimum_samples":20,"maximum_missing":0},
  {"metric_id":"p95_latency","maximum":10000,"minimum_samples":20,"maximum_missing":0}
]}
```

`threshold_gate`与独立`safety_gate`分别显示。安全违规直接FAIL，安全必要证据缺失为UNKNOWN；阈值通过不能替代安全准出。默认任务与安全门禁要求任务断言全部满足且安全证据完整；该保守结论不等同业务方自定义发布策略。

改进建议包含问题、引用、可能原因/已确认原因、建议修改、复验方法。不取得轨迹就不能确认是Router、检索、工具、状态还是模型导致；建议明确保留推断。

## 5. 可选模型评审与人工校准

默认规则评分不启用LLM评审。需要时使用同一独立镜像的`judge serve`作为评分Agent，按[SDK开发指南](三语言SDK业务Agent开发指南.md)注册、发布、安装，并绑定独立机器身份。读取`agent-eval judge manifest`获取声明；为该实例发布Context、Prompt和Model策略、审核计价和模型访问政策。Prompt教学样例在[judge-prompt.txt](../../cli/agent-eval/examples/judge-prompt.txt)。服务只调用平台公共Context/Model，不接受模型厂商凭据或输入覆盖模型配置。

可选部署入口为[deploy/compose/compose.eval-services.yaml](../../deploy/compose/compose.eval-services.yaml)的`judge` profile，不随平台启动。按[services.env.example](../../cli/agent-eval/examples/services.env.example)配置实际网络、内部能力地址和私有凭证目录；目录包含`judge-client-secret`、`internal-token`、`internal-signing-secret`和`platform-public-key`，分别只读挂载。镜像默认用户10001，各秘密文件需可被该进程读取。

```sh
python scripts/compose.py up --stack eval-services --profile judge --env-file .local-secrets/agent-eval/services.env
```

定义[Rubric模板](../../cli/agent-eval/examples/rubric.v1.json)的版本、指标和明确评审规则，再冻结有权读取的原Run：

```powershell
$SourceRun = 'replace-with-business-execution-run-id'
$JudgeInstallation = 'replace-with-grading-installation-id'
$Grading = './.local-secrets/agent-eval/grading-batch'
& $AgentEval model-prepare --credentials-file $Creator --workspace $Scope --agent $JudgeInstallation --run $SourceRun --rubric cli/agent-eval/examples/rubric.v1.json --limit-tokens 30000 --limit-micros 1000000 --out $Grading
```

生成`grading.json`后按prepare→另一位审核者review/publish→bind→run执行。数据源必须为`imported_redacted`，读取、审核、执行、继续执行及评分输出都继承原Run当前权限。撤权后不得借评分数据继续读取结果。评分服务的模型版本、Rubric摘要、原输出摘要、评分Run及真实用量可追溯；模型失败、格式错误或虚构引用均不产生分数。

派生评分用例只冻结原Run自己的输出和事件，不复制子Run事件。需要评审子Run时，将子Run作为独立`--run`来源冻结并鉴权；子Run撤权后，关联评分材料同时受保护。规则报告仍可对当前逐项授权的运行树聚合。

模型仅评审语义指标，不证明安全无违规，不填写计费、TTFT或人工接受。确定性断言优先；有证据的人工校准优先于模型。人工记录通过认证API写入，不能把本地伪造评分JSON当平台证明：

```powershell
$JudgeRun = 'replace-with-grading-execution-run-id'
& $AgentEval analyze --credentials-file $Creator --workspace $Scope --run $SourceRun --judgement-run $JudgeRun --expected './.local-secrets/agent-eval/gold.json' --out $Output
& $AgentEval rubric-hash --input './.local-secrets/agent-eval/human-rubric.json'
& $AgentEval review --credentials-file $Reviewer --workspace $Scope --kind feedback --input './.local-secrets/agent-eval/feedback.json'
```

反馈格式参考[feedback.template.json](../../cli/agent-eval/examples/feedback.template.json)，替换原Run、原输出摘要、Rubric及其真实摘要。判定需引用`output`或当前授权轨迹的有效事件/步骤引用；不确定用`null`。`human_acceptance`只由人类反馈填写。人工也可复核明确安全、状态及可靠性测试机会，不能填写实际时间、Token或费用计数；安全指标的`true`表示发生违规。没有完整拒绝/攻击用例及独立证据，不应给出“无违规”的`false`。再通过`analyze --feedback`关联返回的反馈ID；报告保留评分者、Rubric和校准分歧，不公开自由文本业务证据。

## 6. 隔离仿真

仿真必须在明确测试工作空间内运行。新建专用测试应用/安装和机器身份，不改变生产Provider绑定或原五个人类初始化数据。选用原有授权用户的临时测试工作空间权限，按平台管理流程预览、提交，验收后撤回。

镜像提供`fixture serve`只读API和`fixture agent serve`执行v2服务。按前述方式分别挂载fixture机器凭据，启动`fixture` profile；fixture与judge看不到彼此机器凭据：

```sh
python scripts/compose.py up --stack eval-services --profile fixture --env-file .local-secrets/agent-eval/services.env
```

先导出与镜像内服务相同的注册资料，再通过平台目录完成定义/版本提交、独立审核、发布、安装和机器身份绑定。`bundle`仅生成文件，不申请权限或发布服务，不覆盖已有资料：

```sh
agent-eval fixture agent bundle --out .local-secrets/agent-eval/fixture-registration
agent-eval judge bundle --out .local-secrets/agent-eval/judge-registration
```

每份资料包含`manifest.json`、`input.schema.json`和`output.schema.json`。将三份JSON对象分别传入目录版本接口的`manifest`、`input_schema`、`output_schema`；`artifact_digest`填写实际`agentplug:agent-eval`镜像摘要。输入Schema允许平台注入冻结的`policy_snapshot`，开发者用例禁止自行提供该字段。平台计算内容摘要，部署使用其返回的`manifest_hash`；不能用文件字节摘要代替。fixture与judge无需创建业务Skill，不能套用要求Skill声明的业务示例发布包。

fixture实际部署地址为`http://fixture-agent:8080`，judge为`http://judge-agent:8080`。就绪探测成功后才确认部署状态；安装与策略均发布后绑定各自测试机器。fixture策略允许`api.eval_fixture`及Checkpoint能力，明确预算；不授予无关模型/知识/写操作能力。judge独立发布Prompt/Context/Model策略和预算，不获得fixture工具权限。

管理员合并[fixture Provider模板](../../cli/agent-eval/examples/fixture-api-bindings.template.json)到独立测试Provider配置，保留所有现有生产绑定。Endpoint固定、GET只读、2秒超时、无SecretRef，仅允许场景枚举。开发环境夹具API仅共享已运行平台的网络命名空间，以`127.0.0.1:8787`满足现有HTTP仅允许开发回环地址的守卫；不共享平台文件或凭据，不开放宿主端口。`AGENT_EVAL_PLATFORM_CONTAINER`填写实际平台容器名。端口占用时启动报错。正式环境需使用受控HTTPS测试Provider；不得为仿真放宽全局网络守卫。

按[仿真Profile模板](../../cli/agent-eval/examples/simulation-profile.template.json)填写真实测试工作空间、发布版本ID、安装ID/修订、冻结策略摘要和API绑定文件的准确字节SHA256。平台设置`PLATFORM_EVALUATION_SIMULATION_PROFILES_FILE`与`PLATFORM_API_BINDINGS_FILE`，重新发布平台配置；禁用Profile时仿真明确阻塞，不回退生产。

在测试工作空间`init`选择`agent-eval-simulation`，得到11个教学用例，填写真实`simulation_profile`，先核对金标再走审核/绑定/执行流程。默认模板中的长上下文是待替换教学文本，需准备有界长样本；不得把模板占位文本当长上下文验收。

| 场景 | 本夹具提供的能力 | 仍需独立业务证据 |
|---|---|---|
| 正常/多步骤 | 公共Tool API、可信Observation、两个幂等调用 | 真实业务目标及工具路径 |
| 失败/超时 | 专用Provider失败/延迟、验证错误码、安全Handoff | 实际超时审计、重试预算和业务降级 |
| 权限边界 | 禁止工具真实拒绝，重新核验当前执行权限 | 用户/租户/机器各自边界 |
| 注入/长上下文 | 不可信样本不作为指令 | 真实Context/RAG事实及引用 |
| Checkpoint | CAS保存与读取往返 | 容器终止后新进程真实恢复、无重复步骤 |
| UNKNOWN | 只读API的202不确定教学响应，不自动重放 | 写副作用独立回执、真实UNKNOWN账本 |
| 模糊/低置信 | 显式澄清/Handoff教学结果 | 真实Router低置信、人工接管记录 |

该夹具使用SDK进程内RunStore，不声称提供进程重启恢复。仿真报告标记来源，不能代替真实三语言Agent恢复/安全验收。进程恢复及副作用用例须作用于专门隔离的业务Agent，由受控故障注入和平台账本确认；不得重放既有失败Run或清理UNKNOWN账本来制造通过。

## 7. 线上只读分析与基线比较

`analyze --run`只读取当前授权历史及关联子Run，不提交业务执行。新执行只能由`run`显式建立新Run。第一版不分配线上流量；分析已有版本和灰度结果、反馈及人工审核。

```powershell
& $AgentEval analyze --credentials-file $Creator --workspace $Scope --run $SourceRun --expected './.local-secrets/agent-eval/gold.json' --out $Output
& $AgentEval compare --baseline './.local-secrets/agent-eval/baseline.json' --candidate './.local-secrets/agent-eval/candidate.json'
& $AgentEval report --input "$Output/analysis.json"
```

离线比较要求相同用例金标、模式、并发、次数、预算、超时、评分/阈值协议；版本可以不同。历史比较要求相同业务输入摘要集合、金标和评审协议，不比较未知并发/负载/冷热缓存下的性能因果。币种未知或P95/P99样本不足时金额/分位值不可比较。

`analyze --input`用于固定轨迹验证规则，明确标记导入证据，不能得到平台发布资格。分析目录与批次状态都应私有；清理本轮临时容器及镜像时只删本轮登记的资源，不运行全局prune，不删除正式项目数据库、卷、历史失败Run或不确定账本。

## 8. 开发与验收入口

配置、报告、Rubric、判定和轨迹契约位于[contracts/agent-evaluation/v1](../../contracts/agent-evaluation/v1/cli-suite.schema.json)。开发完成后集中执行工具与共享包全量测试、相关平台/SDK回归，并在实际平台完成三语言业务、拒绝/撤权、预算/取消/幂等/重连、模型失败及人工校准、隔离仿真与教程复现。

证据按场景保存实际版本、命令、Run和结果。缺少macOS实机时单独标明交叉构建及可复现原生入口，不能写“Mac实机通过”。macOS开发者可使用[原生验证入口](../../scripts/agent-eval-native-check.sh)复核本机CLI；报告必须保留未测量或缺少证据的指标。

## 独立领域复核与金标隔离

金标正文只交给评分器，业务Agent通过获准的知识检索完成任务。金标不是业务Agent的输入。规则词面接地与独立语义复核分别记录；不能降低词面阈值来掩盖失败。

需要领域正确性时，在Rubric中显式配置`domain_correctness`，在`--expected`文件提供`domain_facts`和`gold_references`（每条含id、revision、source、content）。冻结原文必须来自独立可核验来源，不能用本次Agent回答作为金标。领域结论同时引用冻结证据的顶层`output`和`expected`；answer/chunk等嵌套ID不是评分证据ID。

`model-prepare ... --rubric <rubric.json> --expected <gold.json> --limit-tokens <total> --limit-micros <total> --out <private-dir>`生成独立评分配置，再依次prepare、另一位审核者review/publish、bind、run。分析时`analyze --run <original-run> --judgement-run <grading-run> --expected <same-gold.json> ...`必须使用相同金标，摘要不符会被拒绝。评分器需已发布1.0.6或后续兼容版本；旧非领域评分保留兼容。

预算按全部用例分配。平台采用UTF-8字节数的保守输入估算，再预留最大输出Token；同时受发布的模型输入上限和Runtime预算约束。先根据冻结输入与公开策略设置有界预算，不能只根据模型实际计量估算准入。未知费用、缺证据或无效模型输出保持未知/失败。

语义复核不替代安全测试、统计性能测试或银行业务人工审核；缺少安全证据时总体门禁仍为UNKNOWN。
