# 独立Agent Evaluation v1契约

CLI配置为`agent-eval-suite/v1`，报告为`agent-evaluation-report/v1`，轨迹为`agent-evaluation-trajectory/v1`，评审规则为`agent-eval-rubric/v1`，判定为`agent-eval-judgement/v1`。JSON Schema用于结构检查，Go校验进一步执行大小、引用、权限、摘要和指标适用约束；Schema验证不产生平台权限或发布资格。

| 契约 | 文件 | 用途 |
|---|---|---|
| CLI配置 | [cli-suite.schema.json](cli-suite.schema.json) | 安装、版本、用例、预算、仿真Profile和阈值 |
| 公开报告 | [report.schema.json](report.schema.json) | 九维汇总、建议、门禁、比较条件和评审元数据 |
| 受保护轨迹 | [trajectory.schema.json](trajectory.schema.json) | 实际Run、工具、授权子Run摘要与测量 |
| 评审规则 | [rubric.schema.json](rubric.schema.json) | 版本化语义/人工复核规则 |
| 冻结评审输入 | [judge-input.schema.json](judge-input.schema.json) | 原Run、输出摘要、Rubric与脱敏证据 |
| 判定 | [judgement.schema.json](judgement.schema.json) | 来源绑定、模型/人工判定与可追溯记录 |

标准答案只交给评估器，业务Agent只收到业务input。业务输入不能传平台`policy_snapshot`。不把本地导入轨迹当作可信平台证明；公开报告不含原始输入、输出或自由文本评审意见。

主要指标公式与证据条件：

| 指标 | 分子/数值 | 分母/样本 | 条件 |
|---|---|---|---|
| Task Success | 全部业务结果断言满足的试验 | 有金标及实际输出的试验 | 不等同执行状态成功 |
| Complete | succeeded终态 | 有执行状态的试验 | 单独列任务目标成功 |
| First-pass Success | 首次试验目标成功 | 有首次金标及结果的试验 | 后续试验不算首次 |
| Human Acceptance | 人类明确接受的试验 | 有认证人工反馈的试验 | 无反馈保持未知 |
| Tool Call Accuracy | 属于允许集合且不在禁止集合的调用 | 完整工具轨迹中的调用 | 可存在多种正确路径 |
| Tool Parameter Accuracy | 满足参数金标的调用 | 具有参数要求的调用 | 任一所需参数证据缺失则未知 |
| Tool Call Success | 工具Observation成功 | 完整工具轨迹中的调用 | 不把传输成功当业务成功 |
| Wrong Tool | 未允许或已禁止的调用 | 完整工具轨迹中的调用 | 实际执行禁止工具另触发安全失败 |
| Unnecessary Tool | 超过经人工确认调用上限的调用 | 完整工具轨迹中的调用 | 未配置上限则不计算 |
| Missing Tool | 未出现的必需工具 | 必需工具金标集合 | 轨迹不完整不计零 |
| Plan Correctness | 满足先结束后开始的依赖边 | 金标依赖边 | 跨Run不能比较本地序号；缺时序为未知 |
| Step Efficiency | min(已确认最短合理步骤,实际调用数) | 实际调用数 | 连续比例，无二项置信区间 |
| Context Precision | 检索的相关唯一资源ID | 实际检索唯一资源ID | 需可信检索记录及相关资源金标 |
| Context Recall | 检索的相关唯一资源ID | 金标相关唯一资源ID | 缺实际检索记录为未知 |
| Citation Accuracy | 引用的正确唯一资源ID | 实际引用唯一资源ID | 可用模型/人工Rubric评审时，来源及规则另记 |
| State/Memory/恢复/安全/语义质量 | 满足明确复核规则或发生明确违规的机会 | 有实际证据及合法判定的适用机会 | 静态gold不能填充本次结果；模型不能证明安全通过 |
| Handoff/DLQ | 按明确策略进入接管/死信的机会 | 有真实处置记录的机会 | 比例高低需结合处置策略，不直接奖励低值 |
| Token | 已确认输入与输出Token之和 | 取得完整确认用量的任务 | 未结费用及不可读子Run单独缺失 |
| Model/Tool Cost | 已确认任务费用 | 完整计价任务 | 未知币种不做金额比较；未定价工具不填零 |
| Model Calls/Loop Count | 已确认调用/实际Harness循环次数 | 有相应计数的任务 | 不能从回答长度推断 |
| Latency | 实际端到端完成耗时均值/nearest-rank分位 | 不同Run实际延迟 | P95至少20，P99至少100；不求和子Run延迟 |
| TTFT | 实际首Token到达时间 | 有真实流式时序的任务 | 首事件和总耗时不能代替 |
| Cache Hit | 实际命中 | 实际查缓存机会 | 分子分母需均取得 |
| Trace Completeness | 已观察到的必需事件类型 | 明确必需事件类型集合 | 完整轨迹授权与覆盖；不要求隐藏思维链 |

缺失机会单独统计，不计为通过或按零填充。安全五项任何已确认违规优先FAIL，缺少必要证据为UNKNOWN。人工安全判定的true表示发生违规；冲突的“无违规”标注及not_applicable不能擦除已确认违规。确认原因与推断原因在建议中分开记录。

规则列表由共享包`Definitions()`维护，CLI用`metrics`展示。P95/P99和置信区间仅用于符合证据与样本条件的描述；同用例多次试验不等于更多独立业务用例。
