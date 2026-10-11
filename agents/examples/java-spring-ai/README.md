# Java Spring AI Agent Example

该示例是可独立启动的 `agent-execution/v2` HTTP 服务，而不是 Controller 伪代码。它使用
`sdk/java/agent-platform-sdk` 的 `ExecuteRequest`、`ContextVerifier` 与语言无关 Manifest；Spring AI
只位于业务编排内部。每个请求均先验证 Bearer JWS、完整 Scope、BodyHash、Action 和时效，再调用
Spring AI Workflow。平台不会识别 Java 类名，也不会为 Java Agent 增加 Agent ID 分支。

先用 Maven 聚合工程构建：

```bash
mvn -f sdk/java/pom.xml package
AGENT_PLATFORM_PUBLIC_KEY_X509_BASE64="<gateway-ed25519-x509-public-key>" \
  java -jar agents/examples/java-spring-ai/target/example-java-spring-ai-agent-2.0.0.jar
```

服务公开 Manifest 以及 `invoke/run/resume/cancel/events` 五类 v2 HTTP 端点；运行状态示例在内存中，
生产 Adapter 必须替换为按 `ScopeKey` 分区的持久化 checkpoint/事件存储，才可横向扩展。
