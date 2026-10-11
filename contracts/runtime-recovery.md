# 平台签名运行恢复命令

协议：`runtime-recovery/v1`。仅由平台在旧执行已实际停止、停止事务已提交且新租约已领取后签发。它与人工批准交接恢复是不同入口，不把停止引用当作独立数字签名。

平台通过执行 v2 的 `operation=resume`、原 Scope、原 input_schema/input/idempotency_key 发送恢复命令，整个 resume_input 仍受当前执行令牌正文摘要保护。原 Run 的 RequestJSON 和持久 ResumeInputJSON 不改写。当前工作器业务执行方式为同步 invoke。

resume_input 严格对象：

```json
{
  "version": "runtime-recovery/v1",
  "origin_operation": "invoke",
  "reference": {"version": "runtime-recovery-stop/v1"},
  "confirmation_token": "仅确实仍需原批准时瞬时加入"
}
```

前三字段必需，confirmation_token 可选；另允许可选 group_resume，其值为原已提交 agent-group-resume/v1 五字段引用，不能与 confirmation_token 同时出现。示意 reference 必须替换成已提交停止引用的完整字段，不能直接使用示例。Token 不持久化、不进入事件或日志。

父运行继续原子任务组时再次故障，必须使用本次真实 runtime stop 来源及 ready+1 新代；原 group handoff 不是上一失败代的退出证明。group_resume.waiting_revision+2 不晚于 reference.stopped_revision；其协调检查点六字段须精确等于本次 reference.checkpoints 中同 key 的当前引用。仅复读本次 runtime 引用，旧 group 的其他引用只作历史。恢复处理器绑定并消费原 gather，不能从空 key 重建 child。此时外层 origin_operation 与 group_resume.origin_operation 相同，可为 invoke 或 run；无 group_resume 仍为 invoke。平台已接线，三 SDK 增量与整体验证尚在进行。

reference 的必需字段为 version、run_id、stopped_revision、ready_revision、operation、body_hash、policy_hash、lease_token_hash、request_hash、resume_input_hash、source、checkpoints；仅 proof_digest/runtime_id 可选。revision 满足 ready=stopped+2、当前已验签 execution revision=ready+1，均在事件区间协议上限内。旧租约摘要不同于当前租约摘要，策略摘要等于当前原冻结 policy_snapshot.content_hash。source 为 sdk-cancel-exit/v1 时没有proof字段，为runtime-process-stop/v1时要求两个小写SHA256摘要。

checkpoints 为1..128条按state_key严格递增的引用，每条仅六字段：state_key、revision、schema_id、content_hash、execution_revision、expires_at。State revision为1..64，execution revision不晚于stopped revision，摘要为小写SHA256，到期必须可解析且尚未到期。

## SDK 处理器前核验

1. 只在已验签resume入口识别命令；验证Run/修订/租约/原策略与严格字段形状。不从业务input读取证明或Token。
2. 使用当前执行客户端逐条调用LoadRecoveryCheckpoint，公共平台核当前Scope、最新head、真实正文摘要和数据库到期；SDK复核返回的state_key及六字段，不能读历史正文替代当前状态。
3. 再次检查当前执行权限。网络/权限/缺失/过期/冲突均拒绝，不能新建检查点或重复模型/工具。
4. 受控投影SPI只接收Scope、幂等键、stopped revision、新revision，不传完整请求或Token。创建/恢复投影使用新修订的事件区间；只有此次真实started事件，不伪造旧事件、旧结果或最后序号。
5. SDK无本地执行时可导入；有本地旧执行时必须匹配旧修订/租约/稳定Scope/原输入且具体处理器已退出。有同代本地执行则只读回放，不再次进入业务。自定义Store缺少明确恢复SPI拒绝。
6. 业务由同一个invoke处理器继续，沿原业务/Harness公共State恢复；model_dispatch/tool_dispatch只查询真实回执，未知保持未知。下一个尚未派发的新步骤仍受当前权限、确认、预算和幂等限制。

新 handler 导入前还要求服务端显式有序 RecoveryPlan：固定业务 namespace/key/schema、完整检查点业务验证、真实持久完成顺序；附属 Skill/Context 不能替代业务进度。只允许完整快照和当前公共 load 均证实从未创建的下一步骤首次开始，且其实际输入摘要与计划一致。未来步骤可以从已核验完成的前序值计算摘要，不猜输出。私有上下文仅在已验签恢复入口创建；完成推进必须读取真实公共 State。普通批准继续不建立此上下文。

相同执行世代已有 SDK 私有 Active 时，严格核原签名命令和当前执行权限后只读已有执行，不创建新投影或 handler。旧检查点头可能已被该 handler 合法推进，不要求其继续停留在旧快照；跨进程或新世代导入仍需全部当前引用和业务计划准入。

## 投影 SPI

RecoveryGenerationRunStore 扩展GenerationRunStore，RecoverGeneration(scope, idempotency_key, stopped_revision, execution_revision)原子导入运行投影并追加started(operation=resume,reason=runtime_recovery)。方法名遵循各语言习惯。已存在投影必须为终态、Scope/幂等键一致，已知旧generation须等于stopped revision；其旧真实事件保留，结果/错误不作为新代结果，取消/恢复信号重新初始化。SDK监督层先证明旧处理器退出，再允许此状态替换。无本地执行证明但有冲突投影拒绝。

普通平台停止引用不包含SDK最后事件序号，不推算或伪造该值。新发布的SDK从首次执行起采用世代事件区间；本地旧事件存在时额外检查新base不小于实际末序号。旧进程历史丢失时仍通过平台SQL历史读取，不能宣称恢复了SDK历史正文。

## 批准与初始状态边界

若持久批准引用对应的Harness仍处于原approval_required且当前head/操作匹配，平台复核原批准后才加入瞬时confirmation_token；head已经推进时不得重放旧批准。已派发写工具沿只读回执恢复，新写工具必须重新走其独立批准。

没有任何可信检查点时不得签发继续请求或冷重放业务。生产停止事务已增加不可恢复的失败处置：只有原实际派发与真实退出来源已验证、全部已准入后代已停止、模型结算和工具回执账本均已静止，且 State 明确缺失或过期时，才原子记录 `recovery_unavailable_stop_confirmed` 与 `RECOVERY_STATE_UNAVAILABLE` 失败结果并释放会话。这不是 `recovery_stop_confirmed` 续跑证明，不生成恢复请求；未知工具、待结算费用或瞬态数据库错误继续等待。

首次未派发安全排队已补源码：显式2026100408迁移增加不可变 claim/dispatch journal，所有 Gateway 和兼容HTTP发送前写入。仅当前协议唯一 accepted1→claim2、recovering4、原输入/租约摘要一致且所有派发及结果均不存在时，按真实 Session/过期时间、后代和账本静止门禁 CAS 重新排队原 Run，记录 `undispatched_requeued`。缺正面 claim 的旧运行、任何已派发或未知状态均不适用。该分支不冒充远程退出或 SDK resume，也不释放预算。实际迁移、故障和跨进程验收尚未执行；SDK bootstrap 仍不能替代业务证据。
