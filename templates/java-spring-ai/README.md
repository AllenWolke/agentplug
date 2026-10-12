# Spring AI Agent

This template provides a Spring Boot `agent-execution/v2` service. The reviewed
`platform_entry/` vendors the platform Java SDK: its `ExecutionServer` is the
only HTTP surface (manifest, readiness and the five execution entries —
`invoke`, `run`, `resume`, `cancel`, `events`), while Spring provides DI for a
Spring AI domain workflow with `@Tool` extension points. Authentication,
Scope, idempotency and audit remain platform concerns owned by the PEP.

The security baseline is Spring Boot 4.0.8 with Spring AI 2.0.1, Java 17 or
later, and Maven. The vendored platform SDK uses Jackson 2 for its wire
contract; Spring AI uses Jackson 3. The template imports aligned Jackson
2.21.7 and 3.1.7 BOMs before Boot's BOM to manage their shared annotations.
Keep that ordering when adding application dependencies.
Existing Spring Boot 3 applications must migrate their Spring integration
before adopting this template; the standalone platform SDK remains separate.

The execution boundary injects a fresh SDK `CapabilityClient` per Invoke/Run.
Model generation uses `PLATFORM_CAPABILITY_URL`, `INTERNAL_TOKEN` and
`INTERNAL_SIGNING_SECRET` (credentials also support `_FILE`). Renewal, scope,
policy, budget and provider selection remain platform-owned. A configured
direct `ChatClient` without this gateway is rejected, not used as a fallback.
Without a gateway or direct model, the deterministic echo is only a transport
conformance example; it is not a generated model answer or production proof.

Build locally with `mvn --batch-mode --no-transfer-progress package` and run
`java -jar target/agent-0.1.0.jar`. The Dockerfile uses a multi-stage Maven build
and a non-root runtime. Release CI must pin both base images and publish only
the resulting image digest through an approved overlay.

The runtime installs Ubuntu security updates with signature verification.
If the ARM package server is unreachable, Docker builds accept
`--build-arg UBUNTU_PORTS_MIRROR=https://mirror.sjtu.edu.cn/ubuntu-ports`.
The default uses Ubuntu's official HTTPS server; do not disable APT signatures.

运行时构建会安装 Ubuntu 安全更新并核验包签名。ARM 软件源无法访问时，可通过上述
构建参数选择镜像站；默认使用 Ubuntu 官方 HTTPS 源，不应关闭 APT 签名校验。
