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
