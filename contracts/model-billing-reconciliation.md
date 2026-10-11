# 模型计费人工对账契约

本契约对应 MM-AUD-13 的人工处理部分，不代表该缺陷已完整关闭。

## 身份与边界

浏览器只通过同源 HttpOnly 会话访问 `/api/modules/model-billing/reconciliations`。BFF 将该唯一白名单路径投影到平台 capability 模块的 `/billing/reconciliations`，注入内部服务凭据及真实登录主体。平台再次使用 Identity 全局治理审批权限授权；租户普通用户、部门/应用管理员不能因此管理全局计费。

不得将内部模型、工具入口通过此公共别名暴露。浏览器不得提交 `actor_id`、`actor_tenant`；服务端从可信会话确定审计主体。

## 查询

`GET` 返回标准平台封装，`data.items` 最多 100 条，按最近更新时间排序。记录包含 `scope_hash`、`idempotency_key`、`fingerprint`、`state`、`tenant_id`、`application_id`、`agent_id`、`reservation_id`、`reserve_micros` 和可选 `decision`。

不返回模型请求、Prompt、原始响应或 Secret。查询错误明确失败，不能显示为成功的空列表。该接口不是全历史分页审计接口。

## 提交

`POST` 请求正文最多 8192 字节；未知字段、额外 JSON、错误类型和伪造主体拒绝。

```json
{
  "scope_hash": "完整64位作用域哈希",
  "idempotency_key": "原模型调用幂等键",
  "fingerprint": "完整64位请求摘要",
  "decision": {
    "id": "本次人工决策的稳定ID",
    "reservation_id": "当前预占ID",
    "outcome": "no_charge",
    "reason": "管理员核实原因",
    "provider_ref": "厂商回执引用，不填写密钥"
  }
}
```

`charged` 还要求 `provider`、`model`、非负整数 `input_tokens`、`output_tokens`、`cost_micros`。费用沿用原调用 USD 微单位；不接受临时更换原价格版本或预算作用域。`no_charge` 的 Token/费用必须为零。

返回 `data.status=accepted` 只表示决策和审计已持久化，不表示补偿已完成。相同完整决策重复提交是幂等重试；不同主体/回执/决策/预占或请求摘要返回 409。数据库故障返回明确 503，不能当作业务冲突吞掉。

## 状态及补偿

- `preparing`：治理预占使用随机尝试 nonce 与两分钟期限。最多16条有界恢复只处理明确未发送且已到期的准备记录；新尝试使用新 nonce，旧生产者不能覆盖。数据库重连测试不是完整进程 kill/restart 证据。
- 明确未发送：先以固定系统身份持久化 no_charge 决策及 accepted 审计，再通过预算 Port 的幂等回执释放，最后提交 applied。中途失败保留 decision_pending，由 Worker 继续补偿。
- 损坏恢复意图：SQL 按记录返回安全诊断标志，不返回损坏内容；Worker 保留预算、记录失败并退避该记录，不阻断同页有效记录。人工修复与规模化公平性仍待验证。
- 服务内部 `/billing/metrics` 校验服务令牌且拒绝浏览器别名，只输出固定 Worker runs/completed/failed 计数，无请求、主体和密钥标签。生产采集装配尚未验证。

- `inflight`：发送前已持久化的恢复意图。预算转为不可按 TTL 自动释放的保留状态后，才允许调用厂商；厂商 RPC 使用一分钟超时，恢复意图截止时间两分钟。执行中的记录不进入人工列表，人工决策拒绝。过截止时间的持久化尝试只由补偿 Port 条件迁移到 manual，不直接重新调用厂商。截止时间不是“厂商未计费”的证据。
- 上述两阶段中任何失败均不得发送模型请求；恢复意图和预算保留使用各自模块 Port，不跨模块直接写表。需要进一步证明预占与恢复意图之间的进程崩溃窗口、原进程 kill/restart、真实 HTTP 取消和双 Worker 行为，不能仅凭单测宣布全部关闭。

- `manual`：结果未知，预算保留。只有授权管理员核实厂商回执后可决策。
- `decision_pending`：决策与 accepted 审计同事务保存，后台 Worker 执行。
- `resolved`：账本和 applied 审计同事务终结；中间故障只恢复持久化补偿，不重跑模型。
- 未计费：完整回执哈希与预算释放同事务，释放后该调用可重新尝试。新尝试不能复用旧预占决策。
- 已计费：幂等结算原预算/用量。未获取模型响应时继续禁止自动生成，不伪造可回放答案。

程序不自动证明厂商回执真实性，管理员须核对外部账单。前端数字校验不替代服务端授权和数据校验。

## 验证证据及限制

正式回归位于 `platform/internal/capability/billing_decision_test.go`：普通主体拒绝、坏请求零副作用、审计写入失败事务回滚、八并发精确决策仅一条审计、补偿审计更新失败后新模块恢复、已计费不重跑、未计费新尝试拒绝旧决策。真实数据库必须使用隔离测试 DSN；未配置跳过不得算真实 SQL 通过。

客户端契约测试为 `frontend/tests/model-billing.test.mjs`，BFF 路由限制测试为 `frontend/server/main_test.go`。这些不是浏览器交互或当前业务镜像 E2E。

当前源码 capability 全包 Linux race/隔离 MySQL 三轮通过，包含准备过期 nonce、未发送审计补偿和损坏行隔离。仍需验证实际进程中止、双 Worker、规模化公平性、指标生产采集、管理页及完整 Docker 链路，才能整体关闭 MM-AUD-13。
