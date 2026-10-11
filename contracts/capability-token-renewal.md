# Platform capability token renewal / 平台公共能力短令牌续签

Private endpoint: `POST /internal/context/renew`. This is not a browser or external-system API.

请求体使用与其他公共能力相同的信封：`{"context": <HarnessContext>, "input": {}}`。
`context.platform_context_token` 必须与 `X-Platform-Context: Bearer <token>` 一致。
同时要求 `X-Internal-Token` 与操作绑定的 `X-Context-Signature`，禁止重定向。

HMAC 正文是 UTF-8 规范 JSON 数组：

```text
["platform-capability/v2", "POST", "/internal/context/renew", SHA256(exact_request_body)]
```

JWT 仍须满足 EdDSA、issuer/audience、完整租户/部门/应用/安装/实例/Agent/version/
主体/会话/Run/Trace、授权 epoch、operation、命令正文摘要及策略摘要绑定。
派发令牌还包含平台签发的 `execution_revision` 和 `lease_token_hash`；后者是当前
私有 Worker 租约的 SHA256，原始租约密钥绝不下发。无这两个声明不能调用公共能力或续签。

只有本续签接口允许读取已过期的签名身份凭据；正常能力入口仍拒绝过期令牌。
续签不依赖旧凭据授权：必须重查 running Run、当前命令、有效 Run/会话租约、执行世代、
当前 IAM epoch 与安装状态。撤权、取消、替换执行者、正文/操作/策略或 Scope 变更均拒绝。
成功时按数据库保留的原命令重新签发短令牌，不采纳请求方提供的新命令或新策略。

成功响应：`{"code":0, "message":"ok", "data":{"context_token":"<new signed token>"}, ...}`。
调用方以 HTTP 状态和 `data` 为准。
失败使用既有错误信封：401 `INVALID_SIGNATURE`；403 `CAPABILITY_DENIED`/`RENEWAL_DENIED`；
未装配续签 Port 时 503 `RENEWAL_UNAVAILABLE`。不回显凭据、租约和请求正文。

Python SDK Model/Knowledge/Memory/Prompt 与 Tool 客户端在过期前 15 秒续签，
同一上下文并发续签单飞；确认新令牌 Scope/命令/策略/世代绑定不变才替换。
续签授权拒绝映射 403、不可重试；网络或格式故障映射能力不可用，禁止先执行业务副作用。
Go SDK 的 CapabilityClient 在每次 Post 前采用同一续签协议，逐运行互斥续签，
拒绝重定向，并限制续签响应为 32 KiB、能力响应为 1 MiB。同步 Invoke 和异步 Run
都通过 ServerConfig.Capability 注入独立客户端；generic/Eino 模板已装配该字段。
业务节点通过 CapabilityFromContext(ctx) 复用客户端，不能从模型厂商自行直连。
部署参数为 PLATFORM_CAPABILITY_URL、INTERNAL_TOKEN、INTERNAL_SIGNING_SECRET；
两项内部凭据支持 _FILE 挂载。未配置公共能力 URL 时不注入，不代表允许模型直连；
已配置 URL 但凭据缺失或为开发占位值时拒绝模板启动。
Java SDK CapabilityClient 使用等价绑定检查与逐运行互斥续签；响应订阅器在缓冲前
限制大小，拒绝跳转。ServerConfig 的 InvokeHandler/RunHandler 显式接收客户端，
generic/Spring AI 两套模板及 Spring starter 已装配，禁止静态全局或 ThreadLocal
跨运行持有客户端。此接口变更已同步当前模板，不保留旧处理器兼容入口。
这些语言客户端完成不等于整个 27 项修复或真实部署 E2E 已通过。

验证入口：`internal/execution/capability_renewal_test.go`、
`internal/capability/context_renewal_test.go`、`sdk/python/tests/test_token_renewal.py`。
这些定向证据不替代长任务、撤权、重启及 HTTP/gRPC 当前源码 Docker E2E。

Go 验证入口：sdk/go/agentplatform/capability_client_test.go，覆盖真实已签 SDK
Invoke/Run 业务调用、八并发单次续签、撤权/身份替换/坏 JSON/超大响应/跳转零能力调用、
稳定 HTTP 状态和可重试属性。模板 sdk_sync_test.go 也校验客户端与权威 SDK 同步。

Java 验证入口：sdk/java/agent-platform-sdk/src/test/java/com/lexagent/sdk/CapabilityClientTest.java。
