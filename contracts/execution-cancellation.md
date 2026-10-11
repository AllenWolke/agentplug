# 两阶段执行取消契约 / Two-phase execution cancellation

平台取消接口先以 CAS 将 Run 写为 `cancelling` 并保存 `cancel_requested` 事件。该状态拒绝新公共能力调用/续签/迟到成功，并继续占有会话 FIFO；租约过期不构成远程停止证明。

- 无在执行世代的 accepted/waiting 可直接保存取消终态。
- 有租约的 Run：平台从持久化原请求派生 `operation=cancel`，重新签发短期控制令牌，绑定原执行 revision、lease token 摘要及完整 Scope/策略/正文。
- 取消控制不要求被撤销的业务 grant 重新放行；调用方的取消权限仍由平台入口验证，控制签名只能由平台生成。
- SDK 在验签之后按完整 Scope、Run、签名执行世代登记/取消业务协程，等待任务清理后再确认。抑制取消返回 `CANCELLATION_NOT_CONFIRMED`。取消墓碑阻止先到 Cancel、后到 Invoke 的世代执行，不能取消新世代。
- 远程未知/失败：平台返回 HTTP 202、`status=cancelling`，不清理会话锁。持久化待取消项由补偿循环重投停止命令，不重跑 Agent/模型/工具。
- 同步 Invoke 的超时、网络错误、坏响应、空状态或非法 accepted/running 状态也进入停止待确认；不能直接释放会话或再投递业务。原错误分类与 cancel_requested 意图原子保存。只有类型化已完成 SDK AppError 可按重试策略重试；未知结果不重试。停止确认后终态为 cancelled，原失败原因保留在取消意图审计中，不将安全停止伪报业务成功。
- 确认响应必须协议、Run ID、`status=cancelled` 全匹配且无错误，之后平台原子保存终态、最终结果、状态与取消事件、释放会话锁；返回 HTTP 200。

租约过期恢复采用独立的 `recovering` 状态，并保存 `recovery_stop_requested`，继续占有同一会话。平台签名停止旧 revision/token 世代；仅在远程停止确认后，事务保存 `recovery_stop_confirmed`，清空旧租约，保留原请求和 `resume_input`，重新派发原 Run。不得生成取消 Outcome，不得释放 FIFO 给下一 Run。停止失败保持 `recovering`；重启扫描包含该状态和无租约的待恢复 running 命令。用户在恢复屏障期间取消可能返回状态冲突，需要待屏障完成后重试；本批不声称已实现合并两种控制意图。

当前回归证明仓储及 SDK 路由行为；隔离真实 MySQL 已验证取消意图事件、终态结果、取消事件故障全回滚、八并发 CAS 与重连恢复，Linux race 连续三次无跳过。SDK真实 FastAPI ASGI 路由验证 http.disconnect 会停止业务任务。另有真实 Ed25519 平台签名器→HTTP Transport→独立 Python/FastAPI 进程的 TCP 回归连续三次通过：Invoke 超时且业务抑制取消时保留锁，实际清理后才确认停止；这不是三应用完整 Docker E2E，也不是代理故障或 SDK 进程重启验证。

SDK 进程真正重启、代理断连、跨语言 SDK、持久化取消监督、公平重试及真实双 Agent Docker 端到端仍需复验；此文档不声称这些项目已经通过。
