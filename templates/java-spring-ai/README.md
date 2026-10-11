# Spring AI Agent

This template provides a Spring Boot `agent-execution/v2` service. The reviewed
`platform_entry/` vendors the platform Java SDK: its `ExecutionServer` is the
only HTTP surface (manifest, readiness and the five execution entries —
`invoke`, `run`, `resume`, `cancel`, `events`), while Spring provides DI for a
Spring AI domain workflow with `@Tool` extension points. Authentication,
Scope, idempotency and audit remain platform concerns owned by the PEP.

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
