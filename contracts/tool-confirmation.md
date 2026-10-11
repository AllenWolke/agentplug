# 操作绑定工具确认协议

版本：`tool-confirmation/v1`。此协议验证独立人类控制面批准的具体操作；不能替代资源授权、运行权限或机器身份验证。

工具网关对已发布`require_confirmation`中的工具，在创建执行回执前校验输入顶层`confirmation_token`。单独`confirmed=true`无效。未装配验证器时拒绝需要确认的操作；当前普通只读工具不新增确认要求。

凭据格式为`base64url(payload).base64url(signature)`，不使用padding。签名为Ed25519，签名输入是`agentplug/tool-confirmation/v1`加NUL字节，再拼接原始JSON载荷。载荷绑定批准记录ID、用户主体、完整工具回执作用域摘要、授权版本、发布策略摘要、工具名、调用ID、参数指纹、签发与到期时间。有效期不得超过300秒；同一凭据只能对应相同运行和相同幂等调用，不能用于其他调用或改动后的参数。

网关只持有公钥。启动变量`PLATFORM_TOOL_CONFIRMATION_PUBLIC_KEY_FILE`指向base64编码32字节公钥文件；禁止与运行上下文公钥相同。批准私钥不得放入业务Agent、模型请求或SDK配置。凭据不写入工具结果、日志或审计正文。批准事件应记录批准ID及摘要，而非完整token。

幂等回放也校验凭据及当前IAM；到期后须重新确认同一操作，账本仍负责禁止重复副作用。策略或授权版本变化须重新确认。撤权、停用和取消不因确认凭据而放行。

当前已实现执行端验证、启动装配、批准记录SQL持久化、批准/撤销与Audit/Outbox同事务。网关在首次调用、执行租约检查和最终结果返回前查询当前批准有效性；记录缺失、撤销或摘要不一致时拒绝。显式迁移`2026100402`新增批准表并保留`2026100401`校验和；运行期使用DML身份。

人类登录、再次认证、具体操作预览、批准签发/撤销的用户入口及SDK/界面交接仍待开发。SQL写入口需要启动层装配事务授权器，未装配时拒绝；当前正式控制面尚未装配该授权器，测试回调不是人类批准。测试签名仅由专用夹具生成，不作为完整用户批准流程验收。已知写工具风险分类也必须接入强制确认，不能只依赖可选发布配置。

Identity已新增工具动作的本地密码再次认证与事务内单次证明消费，独立控制面签发器在批准/Audit/Outbox提交后签名。上述公共接口已有实际SQL阶段验证；真实浏览器会话、预览与批准入口、运行/资源双身份事务授权器和SDK交接尚未接通，不代表用户批准流程已完成。

HTTP控制面已新增POST `/tool-approvals/{preview,step-up,approve,revoke}`，请求中的`operation`包含`run_id/name/call_id/payload`。预览返回操作绑定`claims`、再次认证用`request_digest`及有界脱敏展示；后续请求携带原操作和claims，修改参数或作用域拒绝。`step-up`另带动作和当前密码；`approve/revoke`携带单次证明。所有接口禁止缓存，不输出原始密码、证明或业务参数到日志。

上述入口只能从独立浏览器网关经过会话检查后使用；Agent内部监听器明确拒绝这些路由。当前启动层尚未装配完整`ToolApprovalControl`，因此正式访问返回服务不可用；预览/认证/批准端口的真实Run、策略和双身份资源权限适配、前端别名和SDK交接仍待接通。网关/会话边界阶段测试使用受控授权回调，不能作为真实用户审批验收。

最新源码已接入真实会话、Run所有者、固定策略和调用人/机器资源权限适配；配置`PLATFORM_TOOL_CONFIRMATION_PRIVATE_KEY_FILE`后装配控制面，签发密钥与上下文密钥必须不同。浏览器网关别名为`/api/modules/tool-approvals/{preview,step-up,approve,revoke}`且仅POST。正式部署仍未开启；当前待验证真实SQL用户流程、事务锁与故障组合，并补齐SDK和业务界面，不声明整体验收。
# 三语言SDK显式交接

业务代码使用平台人类控制面签发的令牌，保留预览中的同一工具名、参数和调用ID：Go `CapabilityClient.InvokeTool(ctx, name, callID, payload, token)`；Python `CapabilityGatewayClient.invoke_tool(name, payload, call_id=callID, confirmation_token=token)`；Java `CapabilityClient.invokeTool(name, callID, payload, token)`。令牌最大8192字节，调用ID最大128字节；实际密码认证、签发、绑定校验、到期及撤销由平台负责。

Python既有不带令牌调用保持原有调用ID生成方式；携带令牌必须显式给出批准的调用ID，不能从包含令牌的请求重新生成ID。三SDK公共Function循环仍不自动确认敏感工具，业务流程必须先取得具体批准。当前新增显式接口不代表已经完成循环暂停/恢复、界面批准和三示例整体交接验收。

