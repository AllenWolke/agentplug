# 父子 Agent 等待与继续协议

开发协议，平台等待/门禁/唤醒/签名派发/取消已接线，三 SDK 已有独立等待恢复源码，普通故障恢复组合仍在开发；尚未整体验收。用于 T3-16，不增加任务总数。

## 已确认的缺口

当前三语言 AgentGroup Runner 在 gather 阶段返回 in_progress，业务普通返回会完成父 Run；子 Run 随后被孤儿回收。单纯设置父 Run 为 waiting 也不够：祖先鉴权和孤儿回收仍要求 running/有效租约，且没有 child 终态唤醒父 Run 的队列。不能用人工工具批准暂停伪装子任务等待。

## SDK 实际退出收据

新增独立 `agent_group_handoff` 响应字段（Proto tag 8，不改变原人工批准 handoff tag 7），严格使用以下12字段：

- version：`sdk-agent-group-exit/v1`。
- run_id、execution_revision、body_hash、lease_token_hash：原实际签名派发与旧租约。
- input_fingerprint：SDK原业务输入指纹；不放输入正文。
- origin_operation：invoke 或 run；202本身不构成退出证明。正式工作器继续使用同步invoke。异步run仅在同代重复run请求的当前鉴权只读回放中取回已实际退出的收据，不重新执行或追加事件；未退出仍返回202，不通过SSE夹带收据。
- group_key、operation_key：当前持久协调检查点及固定计划标识。
- last_event_seq：本次真实 waiting 事件序号，符合 sdk-event-range/v1。
- checkpoint：公共 State 的六字段引用，schema_id 必须为 `schema://agentplug/agent-group/v1`。
- child_keys：1～16个已准入子任务键，按原固定计划顺序，无重复。

Runner 只在已持久化 gather、所有计划槽均已准入且当前真实读取结果为非终态时抛出独立 AgentGroupPause。SDK监督层把它转换成 waiting；具体处理器真正退出后才能返回收据。不得使用 HarnessPause、tool_name、call_id 或确认令牌模拟该暂停，不缓存子输出，不在等待时轮询。

## 平台等待事务

沿已有 Run/Session/dispatch 租约锁验证原派发与SDK退出事实，再验证当前协调检查点、固定计划和全部child绑定。用同一事务捕获全部当前公共State六字段引用（至多128条，必须包含协调检查点），保存独立 group_wait_reference 和 waiting outcome，保留原输入与历史归属。State正文、Token、批准令牌不进入等待引用。

只有具备上述已提交凭证、匹配当前waiting修订、有效检查点与实际child归属的父 Run，才能作为合法等待祖先。新prepare/admit仍要求父Run实际运行租约；合法等待不放开父Run执行能力。子Run每次操作继续复查调用人、机器、祖先授权和累计预算。孤儿回收保留合法当前group内的子Run；凭证缺失、过期、撤权或取消仍进入受控停止。

## 唤醒与签名继续

后台只读核实当前group真正终态，不披露子输出、不创建或重派发child。再次复核当前授权和全部State引用后，以当前waiting修订CAS排队父Run；检查点/计划漂移、未知child状态或账本不确定不能被当成功。

持久恢复输入为 `agent-group-resume/v1`：version、origin_operation、waiting_revision、handoff、checkpoints，均不含Token或业务正文。handoff是原已提交12字段收据；checkpoints是同一等待事务捕获的引用列表。waiting_revision=handoff.execution_revision+1。排队和新租约领取各增加一次修订，当前签名execution_revision=waiting_revision+2。整个resume_input受当前执行签名正文摘要保护，旧租约摘要必须不同。

三SDK恢复入口逐条读取当前State并复核授权；验证协调State仍为原gather、原parent/child_keys及原输入。旧本地执行须实际退出，新进程只可通过明确HandoffRunStore导入无冲突waiting投影，再通过GenerationRunStore继续到新的事件区间。不伪造旧历史；业务沿原invoke/run处理器进入gather，只读重新查询既有child结果，不重复prepare/admit。重复同代命令只读回放。

取消需使用已提交group退出事实证明父处理器停止，并复用现有模型账本/子树停止门禁；不依赖已消失进程的内存，也不把State过期当成子任务停止证明。

实现补充：等待事务先取得 IAM 读取连续性和根到叶祖先围栏，再取得当前 Run/Session、路由及 State 围栏。实际派发结果没有 HTTP capability 上下文，使用专用系统权限端口核实际活租约、原冻结策略和当前双主体权限，不在公共准入接口放开 token 校验。后台对撤权/状态失效记录受控停止意图；最终取消仍重核旧退出收据、真实 child 终态和对应模型结算，未知不释放。

继续执行中再次故障时，使用 runtime-recovery/v1 的可选 group_resume 绑定，参见[普通恢复协议](runtime-recovery.md)。新的真实 runtime 停止来源优先；旧等待不能冒充本次停止。

## 准出范围

平台持久等待、祖先/预算/孤儿门禁、唤醒CAS、签名派发、三SDK/六模板、取消与业务/教程均接线后，集中验证真实多进程、父子并发、撤权、自然到期、取消、重启及无重复child。初始五账号仍只保留各自业务权限；协作场景的跨Agent授权必须显式办理，不能为演示扩大默认权限。

