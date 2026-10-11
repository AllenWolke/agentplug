# AgentPlug 前端与同源网关

React、React Router 和 Vite 提供平台管理及业务工作空间，Go 网关提供静态页面和同源 API。公开版改造中，三个 SDK 示例和最终业务界面仍待补齐，当前阶段见[当前开发状态](../README.md#当前状态)。

登录采用短期 access token 与可撤销 refresh 会话，令牌保存在 HttpOnly Cookie。请求经过当前身份、工作空间和权限验证；网关删除客户端伪造的身份/内部令牌头。生产使用可信 OIDC、Secure Cookie、TLS 和再次认证，不能把开发登录当作生产身份来源。

权限界面支持工作空间、权限详情、身份预设、授权差异预览、版本冲突处理、申请审批与委托。管理员的管理权不自动变成业务 Agent 运行权；真实目录中的安装实例与当前 Grant 决定业务入口。

从本目录执行 `npm ci`、`npm test`、`npm run build`、`go test ./...`。根 Compose 入口为 `python scripts/compose.py`；当前原开发库和三个示例尚待改造验收，请依[根说明](../README.md)核对状态后启动。

同源模块通过 `/api/modules/<模块名>` 白名单映射，`usage` 是 `usage-cost` 的浏览器别名。授权依赖可信服务器上下文，浏览器 Scope、隐藏菜单或目录展示不能替代服务器判断。原业务页面和专用模块已移除，通用运行、会话、模型、评测、审计和通知能力保留。
