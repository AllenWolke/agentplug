# 策略快照规则包发布绑定

六类公共策略资产仍通过现有浏览器管理端口创建、发布；规则包是可选领域绑定，不新建另一套运行时策略服务。

`POST /modules/policyasset/snapshots/publish` 在现有 `scope`、`expected_revision`、`assets` 之外接受：

```json
{"rule":{"version":"0.2.0","checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
```

- 使用真实 Identity 管理权限；内部 Token 本身不能调用浏览器管理接口。
- 非空绑定要求非空、无两端空白且不超过128字符的版本，以及64字符小写十六进制 SHA-256。版本或摘要单独缺失均拒绝。
- 六类资产须完整、已发布且与完整策略 Scope 一致；坏绑定不写快照。
- 绑定进入原有快照事务、CAS、hash 和历史保存，不依赖启动 Bootstrap；规则执行仍核对实际规则包摘要。
- API 管理授权不等于监管专家审批或业务金标认证。演示规则必须继续标注合成来源。

## 恢复授权边界

两个 Agent 恢复 LangGraph 时使用 `Command(resume=decision, update={"context": verified_context})`。context 来自已校验的签名派发请求，不从审核用户输入取值；其 checkpoint 命名空间不变。更新仅替换执行上下文，不重跑已完成模型、工具和业务节点。公共能力仍校验当前 Run、IAM、策略、取消及租约，旧 checkpoint Token 不得作为恢复授权使用。

本契约新增规则绑定已通过策略控制面负向单测；完整发布、执行和生产准出仍以总体验收记录为准。
