# Java Generic Agent

This template provides a framework-free `agent-execution/v2` service. The
reviewed `platform_entry/` vendors the platform Java SDK (transport, PEP and the
run state machine) and starts its `ExecutionServer`, which serves the manifest,
the readiness probe and the five execution entries (`invoke`, `run`, `resume`,
`cancel`, `events`). Business code belongs under `domain/`.

Build locally with `mvn --batch-mode --no-transfer-progress package` and run
`java --add-modules jdk.httpserver -cp target/agent-0.1.0.jar:target/lib/* generated.GenericAgent`.
The process refuses to start unless the platform injects
`AGENT_PLATFORM_PUBLIC_KEY_BASE64`. The bundled memory run store is
development-only; production must supply a scoped durable `RunStore`.

`CapabilitySelfCheck` is a runnable check that verifies the shared
Go-SDK-signed capability fixture against the vendored SDK and proves forged,
tampered and mis-scoped capabilities are rejected:

```bash
java -cp "target/agent-0.1.0.jar:target/lib/*" generated.CapabilitySelfCheck
```

The runtime installs Ubuntu security updates with signature verification.
If the ARM package server is unreachable, Docker builds accept
`--build-arg UBUNTU_PORTS_MIRROR=https://mirror.sjtu.edu.cn/ubuntu-ports`.
The default uses Ubuntu's official HTTPS server; do not disable APT signatures.

运行时构建会安装 Ubuntu 安全更新并核验包签名。ARM 软件源无法访问时，可通过上述
构建参数选择镜像站；默认使用 Ubuntu 官方 HTTPS 源，不应关闭 APT 签名校验。
