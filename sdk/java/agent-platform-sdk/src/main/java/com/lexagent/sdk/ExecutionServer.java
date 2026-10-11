package com.lexagent.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.lexagent.sdk.ExecutionContract.AppError;
import com.lexagent.sdk.ExecutionContract.EventRequest;
import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.ExecutionContract.ExecuteResponse;
import com.lexagent.sdk.ExecutionContract.ExecutionEvent;
import com.lexagent.sdk.ExecutionContract.AgentGroupHandoff;
import com.lexagent.sdk.ExecutionContract.HandlerHandoff;
import com.lexagent.sdk.Lifecycle.EventSink;
import com.lexagent.sdk.Lifecycle.IdempotencyConflictException;
import com.lexagent.sdk.Lifecycle.InvalidTransitionException;
import com.lexagent.sdk.Lifecycle.RunRecord;
import com.lexagent.sdk.Lifecycle.RunSignals;
import com.lexagent.sdk.Lifecycle.RunUnknownException;
import com.lexagent.sdk.Lifecycle.StartResult;
import com.lexagent.sdk.Tracing.Attribute;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/** ExecutionServer: the SDK's transport for the full Execution v2 surface.
 *
 * It mounts invoke plus the run/resume/cancel/events lifecycle entries,
 * verifies every caller through the platform PEP and keeps the business seams
 * behind the verified boundary. Generated Agents configure it instead of
 * re-implementing transport, verification or the run state machine.
 *
 * ExecutionServer 是 SDK 的传输封装：挂载完整 Execution v2 入口（invoke 与
 * run/resume/cancel/events 生命周期入口），所有调用先经平台 PEP 校验，业务接缝
 * 保持在已验证边界之后。生成 Agent 只做配置，不重复实现传输、校验与状态机。
 */
public final class ExecutionServer {
    public static final String INVOKE_PATH = "/internal/agent-execution/v2/invoke";
    public static final String RUNS_PATH = "/internal/agent-execution/v2/runs";
    private static final String RUNS_PREFIX = RUNS_PATH + "/";
    private static final int BODY_LIMIT = 1 << 20;
    private static final String HANDOFF_VERSION = "sdk-handler-exit/v1";
    private static final String AGENT_GROUP_HANDOFF_VERSION = "sdk-agent-group-exit/v1";
    private static final String AGENT_GROUP_RESUME_VERSION = "agent-group-resume/v1";
    private static final String HARNESS_SCHEMA = "schema://agentplug/harness-loop/v1";
    private static final String AGENT_GROUP_SCHEMA = "schema://agentplug/agent-group/v1";
    private static final Pattern HANDOFF_DIGEST = Pattern.compile("[a-f0-9]{64}");
    private static final Pattern HANDOFF_KEY = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}");
    private static final Pattern HANDOFF_IDENTIFIER = Pattern.compile("[A-Za-z0-9_.:-]{1,128}");

    private record HandoffResume(HandlerHandoff receipt, String checkpointKey, long checkpointRevision,
            String checkpointHash, long checkpointExecutionRevision) {}

    private record RecoveryCheckpoint(Map<String, Object> reference, String stateKey, long revision,
            String schemaId, String contentHash, long executionRevision, Instant expiresAt) {}

    private record RuntimeRecovery(long stoppedRevision, long readyRevision, String operation,
            String bodyHash, String policyHash, String leaseHash, List<RecoveryCheckpoint> checkpoints,
            String originOperation, AgentGroupResume groupResume) {}

    private record AgentGroupResume(AgentGroupHandoff handoff, long waitingRevision,
            List<RecoveryCheckpoint> checkpoints) {}

    private final ServerConfig config;
    private final ContextVerifier verifier;
    private final com.fasterxml.jackson.databind.JsonNode declaredManifest;
    private final ObjectMapper json = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .findAndRegisterModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final ExecutorService runExecutor = Executors.newCachedThreadPool(task -> {
        Thread thread = new Thread(task, "agentplatform-run");
        thread.setDaemon(true);
        return thread;
    });
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final ExecutionTracker executions = new ExecutionTracker();

    public ExecutionServer(ServerConfig config) {
        this.config = config;
        this.declaredManifest = validateManifest();
        // The configuration's clock (when present) drives the PEP too, so a
        // pinned clock verifies gateway tokens deterministically.
        // 配置里的时钟（若提供）同时驱动 PEP，使钉住的时钟能确定性校验网关令牌。
        this.verifier = config.now() == null
                ? new ContextVerifier()
                : new ContextVerifier(config.now());
    }

    /** Bind and start serving the Execution v2 surface on the given address.
     * 在给定地址绑定并开始服务 Execution v2 接口。
     */
    public HttpServer start(InetSocketAddress address) throws IOException {
        HttpServer server = HttpServer.create(address, 0);
        server.setExecutor(Executors.newCachedThreadPool(task -> {
            Thread thread = new Thread(task, "agentplatform-http");
            thread.setDaemon(true);
            return thread;
        }));
        server.createContext("/", this::route);
        server.start();
        return server;
    }

    /** Stop the run executor; in-flight business handlers observe their cancel
     * signals. / 停止运行执行器；在途业务处理器观察各自的取消信号。
     */
    public void stop() {
        if (closed.compareAndSet(false, true)) {
            runExecutor.shutdownNow();
        }
    }

    // -- routing ---------------------------------------------------------

    private void route(HttpExchange exchange) throws IOException {
        String path = path(exchange);
        try (var ignored = config.tracer().startSpan("agentplatform.request",
                new Attribute("agentplatform.path", path))) {
            if ("GET".equals(exchange.getRequestMethod())) {
                if ("/health/ready".equals(path)) {
                    exchange.sendResponseHeaders(200, -1);
                    exchange.close();
                    return;
                }
                if ("/.well-known/agent-manifest.json".equals(path)) {
                    writeJson(exchange, 200, manifest());
                    return;
                }
                notFound(exchange);
                return;
            }
            if (INVOKE_PATH.equals(path)) {
                execute(exchange, "invoke", null);
                return;
            }
            if (RUNS_PATH.equals(path)) {
                execute(exchange, "run", null);
                return;
            }
            if (path.startsWith(RUNS_PREFIX)) {
                String[] parts = path.substring(RUNS_PREFIX.length()).split("/");
                if (parts.length == 2 && !parts[0].isBlank()) {
                    String action = parts[1];
                    if ("events".equals(action)) {
                        events(exchange, parts[0]);
                        return;
                    }
                    if ("resume".equals(action) || "cancel".equals(action) || "checkpoint".equals(action)) {
                        execute(exchange, action, parts[0]);
                        return;
                    }
                }
            }
            notFound(exchange);
        }
    }

    private Object manifest() {
        if (declaredManifest != null) return declaredManifest;
        return Map.of(
                "manifest_version", "agent-manifest/v1",
                "agent_id", config.agentId(),
                "version", config.agentVersion(),
                "execution_protocols", new String[]{ExecutionContract.PROTOCOL_VERSION},
                "capabilities", config.capabilities().stream().sorted().toArray(String[]::new),
                "schemas", Map.of(
                        "input", "schema://" + config.agentId() + "/input/v1",
                        "output", "schema://" + config.agentId() + "/output/v1"),
                "runtime", Map.of(
                        "transport", "http",
                        "isolation", "container",
                        "run_store", storeLabel()));
    }

    private String storeLabel() {
        return config.store() instanceof MemoryRunStore ? MemoryRunStore.LABEL : "durable";
    }

    private com.fasterxml.jackson.databind.JsonNode validateManifest() {
        if (config.manifest() == null) return null;
        try {
            var root = json.readTree(config.manifest());
            var runtime = root.path("runtime");
            var schemas = root.path("schemas");
            var protocols = root.path("execution_protocols");
            var capabilities = root.path("capabilities");
            if (!root.path("manifest_version").asText().equals("agent-manifest/v1")
                    || !root.path("agent_id").asText().equals(config.agentId())
                    || !root.path("version").asText().equals(config.agentVersion())
                    || !protocols.isArray() || protocols.size() != 1
                    || !protocols.get(0).asText().equals(ExecutionContract.PROTOCOL_VERSION)
                    || !runtime.path("transport").asText().equals("http")
                    || !runtime.path("isolation").asText().equals("container")
                    || !runtime.path("health_path").asText().equals("/health/ready")
                    || !runtime.path("run_store").asText().equals(storeLabel())
                    || !capabilities.isArray()) throw new IllegalArgumentException();
            var seen = new java.util.HashSet<String>();
            for (var item : capabilities) {
                if (!item.isTextual() || !config.advertised().containsKey(item.asText()) || !seen.add(item.asText()))
                    throw new IllegalArgumentException();
            }
            if (!seen.equals(config.advertised().keySet())) throw new IllegalArgumentException();
            for (String name : List.of("input", "output")) {
                if (!schemas.path(name).isTextual() || !isDeclaredSchemaReference(schemas.path(name).asText(), name))
                    throw new IllegalArgumentException();
            }
            return root;
        } catch (Exception ignored) {
            throw new ServerConfig.ServerConfigError("published manifest differs from execution configuration");
        }
    }

    private boolean isDeclaredSchemaReference(String value, String name) {
        try {
            var uri = new java.net.URI(value);
            var path = uri.getRawPath();
            return "schema".equals(uri.getScheme())
                    && config.agentId().equals(uri.getRawAuthority())
                    && uri.getRawUserInfo() == null
                    && uri.getPort() == -1
                    && uri.getRawQuery() == null
                    && uri.getRawFragment() == null
                    && path != null
                    && path.matches("/" + java.util.regex.Pattern.quote(name) + "/v[1-9][0-9]*");
        } catch (java.net.URISyntaxException | IllegalArgumentException ignored) {
            return false;
        }
    }

    // -- execution entries -------------------------------------------------

    private void execute(HttpExchange exchange, String operation, String runId) throws IOException {
        try (var ignored = config.tracer().startSpan("agentplatform." + operation,
                new Attribute("agentplatform.operation", operation))) {
            if (!"POST".equals(exchange.getRequestMethod())) {
                writeError(exchange, 405, "METHOD_NOT_ALLOWED", "operation requires POST");
                return;
            }
            if (!config.advertised().getOrDefault(operation, false)) {
                writeError(exchange, 404, "UNSUPPORTED_CAPABILITY", "capability is not advertised by this agent");
                return;
            }
            ExecuteRequest request = readJson(exchange, ExecuteRequest.class);
            if (request == null) {
                return;
            }
            if (requireEnvelope(exchange, request)) {
                return;
            }
            if (!operation.equals(request.operation())) {
                writeError(exchange, 400, "REQUEST_INVALID", "unexpected operation for this entry");
                return;
            }
            if (!config.agentId().equals(request.scope().agentId()) || !boundBearer(exchange, request.contextToken())) {
                writeError(exchange, 401, "CAPABILITY_INVALID", "execution capability is invalid");
                return;
            }
            ExecutionContract.CapabilityClaims claims;
            try {
                claims = verifier.verify(request, config.publicKey(), config.issuer(), config.audience());
            } catch (RuntimeException exception) {
                // The failure reason is never echoed back; it may reveal tenant
                // or claim details. / 不回显失败原因，避免泄漏租户或声明细节。
                writeError(exchange, 401, "CAPABILITY_INVALID", "execution capability is invalid");
                return;
            }
            switch (operation) {
                case "invoke" -> handleInvoke(exchange, request, claims);
                case "run" -> handleRun(exchange, request, claims);
                case "resume" -> handleResume(exchange, request, runId, claims);
                default -> handleCancel(exchange, request, runId, claims);
            }
        }
    }

    private void handleInvoke(HttpExchange exchange, ExecuteRequest request, ExecutionContract.CapabilityClaims claims) throws IOException {
        ExecutionTracker.Admission admission;
        try { admission = executions.admit(request, claims, config.store()); }
        catch (RuntimeException error) { writeAppFailure(exchange, request.scope().runId(), error); return; }
        if (!admission.created()) { replay(exchange, request, admission.active()); return; }
        var active = admission.active();
        executeInvocation(exchange, request, active);
    }

    private CapabilityClient newCapabilityClient(ExecuteRequest request, ExecutionTracker.Active active) {
        if (config.capability() == null) return null;
        CapabilityClient client = new CapabilityClient(config.capability(), request);
        if (active.groupResumeBinding != null) client.bindAgentGroupResume(active.groupResumeBinding);
        if (active.runtimeRecoveryBinding != null) client.bindRuntimeRecovery(active.runtimeRecoveryBinding);
        return client;
    }

    /** Persist only a safe terminal failure, while respecting any concurrent terminal transition. */
    private Lifecycle.RunRecord settleUnexpectedFailure(String runId, Throwable failure) {
        try {
            config.store().fail(runId, safeExecutionFailure(failure));
        } catch (RuntimeException ignored) {
            // A concurrent cancel or terminal transition owns the outcome.
        }
        try {
            return config.store().getRun(runId);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static AppError safeExecutionFailure(Throwable failure) {
        if (failure instanceof CapabilityClient.Failure capabilityFailure) return capabilityFailure.appError();
        return new AppError("INTERNAL", "the agent failed to process the request", true, Map.of());
    }

    private static int safeExecutionStatus(Throwable failure) {
        if (failure instanceof CapabilityClient.Failure capabilityFailure) return capabilityFailure.status();
        return 500;
    }

    private void executeInvocation(HttpExchange exchange, ExecuteRequest request, ExecutionTracker.Active active) throws IOException {
        var exitRecorded = new AtomicBoolean(false);
        Runnable recordExit = () -> {
            if (exitRecorded.compareAndSet(false, true)) active.leave();
        };
        active.enter();
        CapabilityClient capability = null;
        try {
        capability = newCapabilityClient(request, active);
        Map<String, Object> output;
        try {
            if (config.store().signals(request.scope().runId()).isCancelled()) {
                recordExit.run();
                writeJson(exchange, 200, envelope(request.scope().runId(), "cancelled", null, null)); return;
            }
            output = config.invoke().invoke(request, capability);
        } catch (HarnessPause pause) {
            if (capability != null && !capability.agentGroupResumeSatisfied()) {
                config.store().fail(request.scope().runId(), new AppError("AGENT_GROUP_RESUME_REQUIRED", "the original AgentGroup gather was not consumed", false, Map.of()));
                recordExit.run();
                writeError(exchange, 409, "AGENT_GROUP_RESUME_REQUIRED", "the original AgentGroup gather was not consumed"); return;
            }
            try { executions.park(request.scope().runId(), active, config.store(), pause); }
            catch (RuntimeException error) { recordExit.run(); writeAppFailure(exchange, request.scope().runId(), error); return; }
            recordExit.run();
            HandlerHandoff handoff = executions.handoff(request.scope().runId(), active, config.store());
            writeJson(exchange, 200, envelope(request.scope().runId(), "waiting", null, null, handoff)); return;
        } catch (AgentGroupPause pause) {
            if (capability != null && !capability.agentGroupResumeSatisfied()) {
                config.store().fail(request.scope().runId(), new AppError("AGENT_GROUP_RESUME_REQUIRED", "the original AgentGroup gather was not consumed", false, Map.of()));
                recordExit.run();
                writeError(exchange, 409, "AGENT_GROUP_RESUME_REQUIRED", "the original AgentGroup gather was not consumed"); return;
            }
            try { executions.parkAgentGroup(request.scope().runId(), active, config.store(), pause); }
            catch (RuntimeException error) { recordExit.run(); writeAppFailure(exchange, request.scope().runId(), error); return; }
            recordExit.run();
            AgentGroupHandoff handoff = executions.agentGroupHandoff(request.scope().runId(), active, config.store());
            if (handoff == null) {
                writeError(exchange, 500, "INVALID_TRANSITION", "AgentGroup wait exit cannot be verified");
                return;
            }
            writeJson(exchange, 200, envelope(request.scope().runId(), "waiting", null, null, null, handoff)); return;
        } catch (CapabilityClient.Failure failure) {
            if (config.store().signals(request.scope().runId()).isCancelled()) {
                recordExit.run();
                writeJson(exchange, 200, envelope(request.scope().runId(), "cancelled", null, null)); return;
            }
            config.store().fail(request.scope().runId(), failure.appError());
            recordExit.run();
            writeJson(exchange, failure.status(), envelope(request.scope().runId(), "failed", null, failure.appError()));
            return;
        } catch (Exception exception) {
            if (config.store().signals(request.scope().runId()).isCancelled()) {
                recordExit.run();
                writeJson(exchange, 200, envelope(request.scope().runId(), "cancelled", null, null)); return;
            }
            config.store().fail(request.scope().runId(), new AppError("INTERNAL", "the agent failed to process the request", true, Map.of()));
            recordExit.run();
            writeJson(exchange, 500, envelope(request.scope().runId(), "failed", null, new AppError(
                    "INTERNAL", "the agent failed to process the request", true, Map.of())));
            return;
        }
        if (capability != null && !capability.agentGroupResumeSatisfied()) {
            config.store().fail(request.scope().runId(), new AppError("AGENT_GROUP_RESUME_REQUIRED", "the original AgentGroup gather was not consumed", false, Map.of()));
            recordExit.run();
            writeError(exchange, 409, "AGENT_GROUP_RESUME_REQUIRED", "the original AgentGroup gather was not consumed"); return;
        }
        try { config.store().complete(request.scope().runId(), output); }
        catch (InvalidTransitionException concurrent) {
            if (config.store().signals(request.scope().runId()).isCancelled()) {
                recordExit.run();
                writeJson(exchange, 200, envelope(request.scope().runId(), "cancelled", null, null)); return;
            }
            throw concurrent;
        }
        recordExit.run();
        writeJson(exchange, 200, envelope(request.scope().runId(), "succeeded", output, null));
        } catch (RuntimeException failure) {
            Lifecycle.RunRecord settled = settleUnexpectedFailure(request.scope().runId(), failure);
            if (settled != null && Lifecycle.CANCELLED.equals(settled.status())) {
                writeJson(exchange, 200, envelope(request.scope().runId(), Lifecycle.CANCELLED, null, null));
            } else if (settled != null && Lifecycle.SUCCEEDED.equals(settled.status())) {
                writeJson(exchange, 200, envelope(request.scope().runId(), Lifecycle.SUCCEEDED, settled.output(), null));
            } else if (settled != null && Lifecycle.FAILED.equals(settled.status())) {
                AppError terminalError = settled.error() == null
                        ? safeExecutionFailure(failure) : settled.error();
                writeJson(exchange, safeExecutionStatus(failure),
                        envelope(request.scope().runId(), Lifecycle.FAILED, null, terminalError));
            } else {
                writeError(exchange, 503, "RUN_OUTCOME_UNCONFIRMED", "execution outcome cannot be verified");
            }
        } finally { recordExit.run(); }
    }

    private void replay(HttpExchange exchange, ExecuteRequest request, ExecutionTracker.Active active) throws IOException {
        if (config.capability() != null) {
            try { new CapabilityClient(config.capability(), request).authorizeReplay(); }
            catch (CapabilityClient.Failure failure) {
                writeJson(exchange, failure.status(), envelope(request.scope().runId(), "failed", null, failure.appError())); return;
            }
        }
        if (active.exited.getCount() != 0) {
            writeJson(exchange, 202, envelope(request.scope().runId(), "running", null, null)); return;
        }
        RunRecord record = config.store().getRun(request.scope().runId());
        HandlerHandoff handoff = executions.handoff(request.scope().runId(), active, config.store());
        AgentGroupHandoff groupHandoff = executions.agentGroupHandoff(request.scope().runId(), active, config.store());
        writeJson(exchange, 200, envelope(request.scope().runId(), record.status(), record.output(), record.error(), handoff, groupHandoff));
    }

    private void handleRun(HttpExchange exchange, ExecuteRequest request, ExecutionContract.CapabilityClaims claims) throws IOException {
        ExecutionTracker.Admission started;
        try {
            started = executions.admit(request, claims, config.store());
        } catch (RuntimeException exception) {
            writeAppFailure(exchange, request.scope().runId(), exception);
            return;
        }
        if (started.created()) {
            runExecutor.submit(() -> executeRun(request, started.active()));
            writeJson(exchange, 202, envelope(request.scope().runId(), "running", null, null));
            return;
        }
        replay(exchange, request, started.active());
    }

    private void executeRun(ExecuteRequest request, ExecutionTracker.Active active) {
        String runId = request.scope().runId();
        active.enter();
        try (var span = config.tracer().startSpan("agentplatform.run.execute",
                new Attribute("agentplatform.run_id", runId))) {
            CapabilityClient capability = newCapabilityClient(request, active);
            RunSignals signals = config.store().signals(runId);
            if (signals.isCancelled()) return;
            if (!active.resumed) {
                // A fresh generation has only its accepted event at admission.
                // Resume, handoff adoption and recovery atomically append and
                // verify their own started event before this handler is queued.
                try {
                    config.store().appendEvent(runId, Lifecycle.EVENT_STARTED, Map.of());
                } catch (RunUnknownException | InvalidTransitionException exception) {
                    return;
                }
            }
            EventSink sink = (eventType, payload) -> config.store().appendEvent(runId, eventType, payload);
            Map<String, Object> output;
            try {
                output = config.run().run(request, sink, signals, capability);
            } catch (HarnessPause pause) {
                if (capability != null && !capability.agentGroupResumeSatisfied()) {
                    config.store().fail(runId, new AppError("AGENT_GROUP_RESUME_REQUIRED", "the original AgentGroup gather was not consumed", false, Map.of()));
                    return;
                }
                try { executions.park(runId, active, config.store(), pause); }
                catch (RuntimeException ignored) { /* Cancel/transition races remain unconfirmed. */ }
                return;
            } catch (AgentGroupPause pause) {
                if (capability != null && !capability.agentGroupResumeSatisfied()) {
                    config.store().fail(runId, new AppError("AGENT_GROUP_RESUME_REQUIRED", "the original AgentGroup gather was not consumed", false, Map.of()));
                    return;
                }
                try { executions.parkAgentGroup(runId, active, config.store(), pause); }
                catch (RuntimeException ignored) { /* Cancel/transition races remain unconfirmed. */ }
                return;
            } catch (Exception exception) {
                try {
                    config.store().fail(runId, exception instanceof CapabilityClient.Failure failure ? failure.appError() : new AppError(
                            "INTERNAL", "the agent failed to process the request", true, Map.of()));
                } catch (RunUnknownException | InvalidTransitionException terminal) {
                    // the run already reached a terminal state / 运行已到达终态
                }
                return;
            }
            if (capability != null && !capability.agentGroupResumeSatisfied()) {
                config.store().fail(runId, new AppError("AGENT_GROUP_RESUME_REQUIRED", "the original AgentGroup gather was not consumed", false, Map.of()));
                return;
            }
            try {
                config.store().complete(runId, output);
            } catch (RunUnknownException | InvalidTransitionException concurrent) {
                // a concurrent cancel already finished the run / 并发取消已收尾
            }
        } catch (RuntimeException failure) {
            settleUnexpectedFailure(runId, failure);
        } finally { active.leave(); }
    }

    private void handleResume(HttpExchange exchange, ExecuteRequest request, String runId, ExecutionContract.CapabilityClaims claims) throws IOException {
        if (runId == null || !runId.equals(request.scope().runId())) {
            writeError(exchange, 400, "REQUEST_INVALID", "path run id must match the verified scope");
            return;
        }
        if (request.resumeInput() == null) {
            writeError(exchange, 400, "REQUEST_INVALID", "signed resume_input is required");
            return;
        }
        if (config.capability() == null) {
            writeError(exchange, 503, "CAPABILITY_CONFIG_INVALID", "controlled resume requires current platform authorization");
            return;
        }
        CapabilityClient capability;
        try {
            capability = new CapabilityClient(config.capability(), request);
            capability.validateCurrentExecution();
        } catch (CapabilityClient.Failure failure) {
            writeJson(exchange, failure.status(), envelope(runId, "failed", null, failure.appError()));
            return;
        } catch (RuntimeException rejected) {
            writeError(exchange, 503, "CAPABILITY_CONFIG_INVALID", "controlled resume requires current platform authorization");
            return;
        }

        if (isAgentGroupResume(request.resumeInput())) {
            handleAgentGroupResume(exchange, request, claims, capability);
            return;
        }

        if (isRuntimeRecovery(request.resumeInput())) {
            handleRuntimeRecoveryResume(exchange, request, claims, capability);
            return;
        }

        if (executions.hasRun(runId)) {
            if (!executions.owns(request.scope())) {
                writeError(exchange, 404, "RUN_UNKNOWN", "run is unavailable in this scope"); return;
            }
            if (!executions.managedPause(runId)) {
                writeError(exchange, 409, "RUN_RESUME_UNCONFIRMED", "an active generation cannot be replaced");
                return;
            }
            ExecutionTracker.Admission admission;
            try { admission = executions.resume(request, claims, config.store()); }
            catch (RuntimeException error) { writeAppFailure(exchange, runId, error); return; }
            if (!admission.created()) { replay(exchange, request, admission.active()); return; }
            if ("invoke".equals(admission.active().originOperation)) { executeInvocation(exchange, request, admission.active()); return; }
            runExecutor.submit(() -> executeRun(request, admission.active()));
            writeJson(exchange, 202, envelope(runId, "running", null, null)); return;
        }
        try {
            // Network authorization and public State reads happen before entering
            // ExecutionTracker's monitor. The monitor rechecks all local conflicts.
            HandoffResume handoff = parseHandoffResume(request, claims);
            Map<String, Object> state = capability.loadCheckpoint("harness", handoff.checkpointKey(), HARNESS_SCHEMA, 0);
            verifyCurrentCheckpoint(state, handoff);
            capability.validateCurrentExecution();
            Map<String, Object> pauseMetadata = Map.of("reason", "approval_required",
                    "harness_key", handoff.receipt().harnessKey(), "tool_name", handoff.receipt().toolName(),
                    "call_id", handoff.receipt().callId());
            ExecutionTracker.Admission admission = executions.adoptWaiting(request, claims, config.store(),
                    handoff.receipt(), pauseMetadata);
            if ("invoke".equals(admission.active().originOperation)) {
                executeInvocation(exchange, request, admission.active());
                return;
            }
            runExecutor.submit(() -> executeRun(request, admission.active()));
            writeJson(exchange, 202, envelope(runId, "running", null, null));
        } catch (CapabilityClient.Failure failure) {
            writeJson(exchange, failure.status(), envelope(runId, "failed", null, failure.appError()));
        } catch (RuntimeException rejected) {
            // Keep receipt, checkpoint, policy and token details out of errors.
            writeError(exchange, 409, "RESUME_HANDOFF_REJECTED", "verified waiting handoff cannot be adopted");
        }
    }

    private void handleRuntimeRecoveryResume(HttpExchange exchange, ExecuteRequest request,
            ExecutionContract.CapabilityClaims claims, CapabilityClient capability) throws IOException {
        RuntimeRecovery recovery;
        ExecutionTracker.RecoveryCandidate expected;
        try {
            recovery = parseRuntimeRecovery(request, claims, capability.nowEpochSeconds());
            expected = executions.inspectRecovery(request, claims, recovery.stoppedRevision(),
                    recovery.bodyHash(), recovery.leaseHash(), recovery.originOperation(),
                    recovery.groupResume() == null ? null : recovery.groupResume().handoff());
        } catch (RuntimeException rejected) {
            writeError(exchange, 409, "RESUME_RECOVERY_REJECTED", "verified recovery reference cannot be applied");
            return;
        }
        if (expected.replay()) {
            try {
                capability.validateCurrentExecution();
                ExecutionTracker.Active active = executions.confirmRecoveryReplay(request, claims,
                        recovery.stoppedRevision(), recovery.bodyHash(), recovery.leaseHash(),
                        recovery.originOperation(), recovery.groupResume() == null ? null : recovery.groupResume().handoff(),
                        expected);
                replay(exchange, request, active);
            } catch (CapabilityClient.Failure failure) {
                writeError(exchange, failure.status(), "RESUME_RECOVERY_REJECTED", "verified recovery reference cannot be applied");
            } catch (RuntimeException rejected) {
                writeError(exchange, 409, "RESUME_RECOVERY_REJECTED", "verified recovery reference cannot be applied");
            }
            return;
        }
        try {
            Map<String, Object> groupState = null;
            List<RecoveryPlan.Snapshot> snapshots = new ArrayList<>(recovery.checkpoints().size());
            RecoveryPlan.Snapshot groupSnapshot = null;
            for (RecoveryCheckpoint checkpoint : recovery.checkpoints()) {
                Map<String, Object> loaded = capability.loadRecoveryCheckpoint(checkpoint.reference());
                verifyRecoveryCheckpoint(loaded, checkpoint, capability.nowEpochSeconds());
                RecoveryPlan.Snapshot snapshot = new RecoveryPlan.Snapshot(checkpoint.reference(), checkpoint.stateKey(), loaded);
                snapshots.add(snapshot);
                if (recovery.groupResume() != null && checkpoint.stateKey().equals(
                        recovery.groupResume().handoff().checkpoint().get("state_key"))) {
                    groupState = loaded;
                    groupSnapshot = snapshot;
                }
            }
            RecoveryPlan.RuntimeRecoveryBinding recoveryBinding = validateRuntimeRecoveryPlan(
                    request, claims.executionRevision(), List.copyOf(snapshots), groupSnapshot, capability, recovery);
            AgentGroupResumeBinding groupResumeBinding = null;
            if (recovery.groupResume() != null) {
                if (groupState == null) throw new IllegalArgumentException();
                String inputHash = verifyAgentGroupStateCheckpoint(groupState, recovery.groupResume().handoff());
                groupResumeBinding = new AgentGroupResumeBinding(recovery.groupResume().handoff(), inputHash);
            }
            capability.validateCurrentExecution();
            ExecutionTracker.Admission admission = executions.recoverGeneration(request, claims,
                    config.store(), recovery.stoppedRevision(), recovery.bodyHash(), recovery.leaseHash(), expected,
                    groupResumeBinding, recoveryBinding, recovery.originOperation());
            if (!admission.created()) {
                replay(exchange, request, admission.active());
                return;
            }
            if ("invoke".equals(admission.active().originOperation)) {
                executeInvocation(exchange, request, admission.active());
                return;
            }
            runExecutor.submit(() -> executeRun(request, admission.active()));
            writeJson(exchange, 202, envelope(request.scope().runId(), "running", null, null));
        } catch (CapabilityClient.Failure failure) {
            writeJson(exchange, failure.status(), envelope(request.scope().runId(), "failed", null, failure.appError()));
        } catch (RuntimeException rejected) {
            writeError(exchange, 409, "RESUME_RECOVERY_REJECTED", "verified recovery reference cannot be applied");
        }
    }

    /** Validate a business-owned ordered checkpoint plan before installing the
     * recovered handler generation. All network reads happen outside tracker locks. */
    private RecoveryPlan.RuntimeRecoveryBinding validateRuntimeRecoveryPlan(ExecuteRequest request,
            long executionRevision, List<RecoveryPlan.Snapshot> snapshots, RecoveryPlan.Snapshot groupSnapshot,
            CapabilityClient capability, RuntimeRecovery recovery) throws CapabilityClient.Failure {
        RecoveryPlan.Selector selector = config.recoveryCheckpointSelector();
        if (selector == null) throw new IllegalArgumentException();
        RecoveryPlan plan;
        try {
            plan = selector.select(request, snapshots, groupSnapshot);
        } catch (Exception rejected) {
            throw new IllegalArgumentException();
        }
        if (plan == null || (recovery.groupResume() != null && (!plan.allowGroupResume()
                || !plan.allowedAgentGroupKey().equals(recovery.groupResume().handoff().groupKey()))))
            throw new IllegalArgumentException();
        if (plan.allowGroupResume() && plan.allowedAgentGroupKey().isEmpty()) throw new IllegalArgumentException();
        if (!plan.allowedAgentGroupKey().isEmpty()) {
            if (!AgentGroupRunner.validKey(plan.allowedAgentGroupKey())) throw new IllegalArgumentException();
            long groupSteps = plan.steps().stream().filter(step -> "coordination".equals(step.namespace())
                    && plan.allowedAgentGroupKey().equals(step.key())
                    && AgentGroupRunner.STATE_SCHEMA.equals(step.schemaId())).count();
            if (groupSteps != 1) throw new IllegalArgumentException();
        }

        Map<String, RecoveryPlan.Snapshot> captured = new LinkedHashMap<>();
        Map<String, RecoveryCheckpoint> capturedReferences = new LinkedHashMap<>();
        for (int i = 0; i < snapshots.size(); i++) {
            RecoveryPlan.Snapshot snapshot = snapshots.get(i);
            RecoveryCheckpoint checkpoint = recovery.checkpoints().get(i);
            if (captured.putIfAbsent(snapshot.stateKey(), snapshot) != null
                    || capturedReferences.putIfAbsent(snapshot.stateKey(), checkpoint) != null)
                throw new IllegalArgumentException();
        }

        Map<RecoveryPlan.CheckpointKey, Object> priorValues = new LinkedHashMap<>();
        boolean stageBlocked = false;
        List<RecoveryPlan.PlannedStep> plannedSteps = new ArrayList<>();
        long now = capability.nowEpochSeconds();
        for (RecoveryPlan.Step step : plan.steps()) {
            if (!validRecoveryStep(step)) throw new IllegalArgumentException();
            if ("coordination".equals(step.namespace()) && AgentGroupRunner.STATE_SCHEMA.equals(step.schemaId())
                    && !step.key().equals(plan.allowedAgentGroupKey())) throw new IllegalArgumentException();
            Map<String, Object> loaded = capability.loadCheckpoint(step.namespace(), step.key(), step.schemaId(), 0);
            if (loaded == null || !loaded.keySet().equals(Set.of("state_key", "checkpoint"))
                    || !(loaded.get("state_key") instanceof String stateKey)
                    || !HANDOFF_DIGEST.matcher(stateKey).matches()) throw new IllegalArgumentException();
            Object checkpointValue = loaded.get("checkpoint");
            RecoveryPlan.Snapshot referenceSnapshot = captured.get(stateKey);
            if (checkpointValue == null) {
                if (referenceSnapshot != null || (!stageBlocked && !step.allowInitialStart()))
                    throw new IllegalArgumentException();
                plannedSteps.add(new RecoveryPlan.PlannedStep(step, stateKey, false,
                        loaded, null, false));
                stageBlocked = true;
                continue;
            }
            if (stageBlocked || referenceSnapshot == null
                    || !loaded.equals(referenceSnapshot.response())) throw new IllegalArgumentException();
            RecoveryCheckpoint expected = capturedReferences.get(stateKey);
            if (expected == null || !step.schemaId().equals(expected.schemaId())) throw new IllegalArgumentException();
            verifyRecoveryCheckpoint(loaded, expected, now);
            Map<String, Object> checkpoint = stringMap(checkpointValue);
            Map<String, Object> value = stringMap(checkpoint.get("value"));
            try {
                step.validateCheckpoint().validate(request, checkpoint, Map.copyOf(priorValues));
                boolean complete = step.isComplete().isComplete(value);
                plannedSteps.add(new RecoveryPlan.PlannedStep(step, stateKey, true,
                        loaded, checkpoint, complete));
                if (complete) priorValues.put(step.checkpointKey(), value);
                else stageBlocked = true;
            } catch (Exception rejected) {
                throw new IllegalArgumentException();
            }
        }
        return new RecoveryPlan.RuntimeRecoveryBinding(request, executionRevision,
                plannedSteps, priorValues, snapshots,
                recovery.groupResume() != null && plan.allowGroupResume(), plan.allowedAgentGroupKey());
    }

    private static boolean validRecoveryStep(RecoveryPlan.Step step) {
        return validRecoveryPart(step.namespace(), 128) && validRecoveryPart(step.key(), 128)
                && step.schemaId().startsWith("schema://") && step.schemaId().length() > "schema://".length()
                && step.schemaId().getBytes(StandardCharsets.UTF_8).length <= 256
                && step.schemaId().chars().noneMatch(ch -> "*\u0000\r\n\t ".indexOf(ch) >= 0);
    }

    private static boolean validRecoveryPart(String value, int maxBytes) {
        return value != null && !value.isBlank() && value.equals(value.trim())
                && value.getBytes(StandardCharsets.UTF_8).length <= maxBytes
                && value.chars().noneMatch(ch -> "*\u0000\r\n".indexOf(ch) >= 0);
    }

    private static Map<String, Object> stringMap(Object value) {
        if (!(value instanceof Map<?, ?> raw)) throw new IllegalArgumentException();
        Map<String, Object> result = new LinkedHashMap<>();
        raw.forEach((key, nested) -> {
            if (!(key instanceof String text)) throw new IllegalArgumentException();
            result.put(text, nested);
        });
        return result;
    }

    private void handleAgentGroupResume(HttpExchange exchange, ExecuteRequest request,
            ExecutionContract.CapabilityClaims claims, CapabilityClient capability) throws IOException {
        AgentGroupResume resume;
        ExecutionTracker.AgentGroupCandidate expected;
        try {
            resume = parseAgentGroupResume(request, claims, capability.nowEpochSeconds());
            expected = executions.inspectAgentGroupResume(request, claims, config.store(), resume.handoff());
        } catch (RuntimeException rejected) {
            writeError(exchange, 409, "RESUME_AGENT_GROUP_REJECTED", "verified AgentGroup handoff cannot be applied");
            return;
        }
        try {
            Map<String, Object> groupState = null;
            for (RecoveryCheckpoint checkpoint : resume.checkpoints()) {
                Map<String, Object> loaded = capability.loadRecoveryCheckpoint(checkpoint.reference());
                verifyRecoveryCheckpoint(loaded, checkpoint, capability.nowEpochSeconds());
                if (checkpoint.stateKey().equals(resume.handoff().checkpoint().get("state_key")))
                    groupState = loaded;
            }
            if (groupState == null) throw new IllegalArgumentException();
            String groupInputHash = verifyAgentGroupStateCheckpoint(groupState, resume.handoff());
            capability.validateCurrentExecution();
            for (RecoveryCheckpoint checkpoint : resume.checkpoints())
                if (!checkpoint.expiresAt().isAfter(Instant.ofEpochSecond(capability.nowEpochSeconds())))
                    throw new IllegalArgumentException();

            ExecutionTracker.Admission admission = executions.resumeAgentGroup(request, claims, config.store(),
                    resume.handoff(), groupInputHash, expected);
            if (!admission.created()) {
                replay(exchange, request, admission.active());
                return;
            }
            if ("invoke".equals(admission.active().originOperation)) {
                executeInvocation(exchange, request, admission.active());
                return;
            }
            runExecutor.submit(() -> executeRun(request, admission.active()));
            writeJson(exchange, 202, envelope(request.scope().runId(), "running", null, null));
        } catch (CapabilityClient.Failure failure) {
            writeJson(exchange, failure.status(), envelope(request.scope().runId(), "failed", null, failure.appError()));
        } catch (RuntimeException rejected) {
            writeError(exchange, 409, "RESUME_AGENT_GROUP_REJECTED", "verified AgentGroup handoff cannot be applied");
        }
    }

    private static boolean isAgentGroupResume(Map<String, Object> resumeInput) {
        return resumeInput != null && AGENT_GROUP_RESUME_VERSION.equals(resumeInput.get("version"));
    }

    private AgentGroupResume parseAgentGroupResume(ExecuteRequest request,
            ExecutionContract.CapabilityClaims claims, long nowEpochSeconds) {
        Map<?, ?> marker = request.resumeInput();
        if (!"resume".equals(request.operation())
                || !marker.keySet().equals(Set.of("version", "origin_operation", "waiting_revision", "handoff", "checkpoints"))
                || !AGENT_GROUP_RESUME_VERSION.equals(text(marker.get("version")))) throw new IllegalArgumentException();

        Map<?, ?> raw = object(marker.get("handoff"));
        Set<String> handoffFields = Set.of("version", "run_id", "execution_revision", "body_hash", "lease_token_hash",
                "input_fingerprint", "origin_operation", "group_key", "operation_key", "last_event_seq", "checkpoint", "child_keys");
        if (!raw.keySet().equals(handoffFields)) throw new IllegalArgumentException();
        Map<?, ?> rawCheckpoint = object(raw.get("checkpoint"));
        Set<String> checkpointFields = Set.of("state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at");
        if (!rawCheckpoint.keySet().equals(checkpointFields)) throw new IllegalArgumentException();

        String runId = text(raw.get("run_id"));
        long stoppedRevision = exactLong(raw.get("execution_revision"));
        long lastEventSeq = exactLong(raw.get("last_event_seq"));
        String bodyHash = text(raw.get("body_hash"));
        String oldLeaseHash = text(raw.get("lease_token_hash"));
        String inputFingerprint = text(raw.get("input_fingerprint"));
        String originOperation = text(raw.get("origin_operation"));
        String groupKey = text(raw.get("group_key"));
        String operationKey = text(raw.get("operation_key"));
        String checkpointStateKey = text(rawCheckpoint.get("state_key"));
        long checkpointRevision = exactLong(rawCheckpoint.get("revision"));
        String checkpointSchema = text(rawCheckpoint.get("schema_id"));
        String checkpointHash = text(rawCheckpoint.get("content_hash"));
        long checkpointExecutionRevision = exactLong(rawCheckpoint.get("execution_revision"));
        String checkpointExpiresText = text(rawCheckpoint.get("expires_at"));
        Instant checkpointExpiresAt = Instant.parse(checkpointExpiresText);
        Map<String, Object> checkpointReference = new LinkedHashMap<>();
        checkpointReference.put("state_key", checkpointStateKey);
        checkpointReference.put("revision", checkpointRevision);
        checkpointReference.put("schema_id", checkpointSchema);
        checkpointReference.put("content_hash", checkpointHash);
        checkpointReference.put("execution_revision", checkpointExecutionRevision);
        checkpointReference.put("expires_at", checkpointExpiresText);

        Object rawChildKeys = raw.get("child_keys");
        if (!(rawChildKeys instanceof List<?> values) || values.isEmpty() || values.size() > 16)
            throw new IllegalArgumentException();
        List<String> childKeys = new ArrayList<>(values.size());
        Set<String> seenChildKeys = new HashSet<>();
        for (Object value : values) {
            if (!(value instanceof String key) || !HANDOFF_DIGEST.matcher(key).matches() || !seenChildKeys.add(key))
                throw new IllegalArgumentException();
            childKeys.add(key);
        }

        long waitingRevision = exactLong(marker.get("waiting_revision"));
        long currentRevision = claims.executionRevision() == null ? 0 : claims.executionRevision();
        long oldBase = Lifecycle.eventSequenceBase(stoppedRevision);
        long oldMaximum = Lifecycle.maxEventSequence(stoppedRevision);
        long currentBase = Lifecycle.eventSequenceBase(currentRevision);
        if (!AGENT_GROUP_HANDOFF_VERSION.equals(text(raw.get("version")))
                || !request.scope().runId().equals(runId) || !HANDOFF_IDENTIFIER.matcher(runId).matches()
                || !HANDOFF_DIGEST.matcher(bodyHash).matches() || !HANDOFF_DIGEST.matcher(oldLeaseHash).matches()
                || !HANDOFF_DIGEST.matcher(inputFingerprint).matches()
                || !inputFingerprint.equals(ExecutionTracker.businessHash(request))
                || !("invoke".equals(originOperation) || "run".equals(originOperation))
                || !HANDOFF_KEY.matcher(groupKey).matches() || !HarnessRunner.skillIdentifier(operationKey)
                || stoppedRevision < 1 || stoppedRevision > Lifecycle.MAX_GENERATION_REVISION - 3
                || lastEventSeq <= oldBase || lastEventSeq > oldMaximum
                || stoppedRevision + 1 != waitingRevision || currentRevision != waitingRevision + 2
                || currentRevision > Lifecycle.MAX_GENERATION_REVISION || currentBase < lastEventSeq
                || !AGENT_GROUP_SCHEMA.equals(checkpointSchema) || checkpointRevision < 1 || checkpointRevision > 64
                || !HANDOFF_DIGEST.matcher(checkpointStateKey).matches()
                || !HANDOFF_DIGEST.matcher(checkpointHash).matches()
                || checkpointExecutionRevision != stoppedRevision
                || !checkpointExpiresAt.isAfter(Instant.ofEpochSecond(nowEpochSeconds))
                || !Objects.equals(marker.get("origin_operation"), originOperation)
                || claims.leaseTokenHash() == null || !HANDOFF_DIGEST.matcher(claims.leaseTokenHash()).matches()
                || claims.leaseTokenHash().equals(oldLeaseHash)) throw new IllegalArgumentException();

        String expectedStateKey = expectedAgentGroupStateKey(request.scope(), groupKey);
        if (!checkpointStateKey.equals(expectedStateKey)) throw new IllegalArgumentException();

        Object rawCheckpoints = marker.get("checkpoints");
        if (!(rawCheckpoints instanceof List<?> checkpointValues) || checkpointValues.isEmpty() || checkpointValues.size() > 128)
            throw new IllegalArgumentException();
        List<RecoveryCheckpoint> checkpoints = new ArrayList<>(checkpointValues.size());
        String previousKey = "";
        int groupReferences = 0;
        for (Object value : checkpointValues) {
            Map<?, ?> reference = object(value);
            if (!reference.keySet().equals(checkpointFields)) throw new IllegalArgumentException();
            String stateKey = text(reference.get("state_key"));
            long revision = exactLong(reference.get("revision"));
            String schemaId = text(reference.get("schema_id"));
            String contentHash = text(reference.get("content_hash"));
            long executionRevision = exactLong(reference.get("execution_revision"));
            String expiresAtText = text(reference.get("expires_at"));
            Instant expiresAt = Instant.parse(expiresAtText);
            if (!HANDOFF_DIGEST.matcher(stateKey).matches() || stateKey.compareTo(previousKey) <= 0
                    || revision < 1 || revision > 64 || !validStateSchema(schemaId)
                    || !HANDOFF_DIGEST.matcher(contentHash).matches() || executionRevision < 1
                    || executionRevision > stoppedRevision || !expiresAt.isAfter(Instant.ofEpochSecond(nowEpochSeconds)))
                throw new IllegalArgumentException();
            Map<String, Object> snapshot = new LinkedHashMap<>();
            snapshot.put("state_key", stateKey); snapshot.put("revision", revision);
            snapshot.put("schema_id", schemaId); snapshot.put("content_hash", contentHash);
            snapshot.put("execution_revision", executionRevision); snapshot.put("expires_at", expiresAtText);
            checkpoints.add(new RecoveryCheckpoint(Map.copyOf(snapshot), stateKey, revision, schemaId,
                    contentHash, executionRevision, expiresAt));
            if (stateKey.equals(checkpointStateKey)) {
                if (!snapshot.equals(checkpointReference)) throw new IllegalArgumentException();
                groupReferences++;
            }
            previousKey = stateKey;
        }
        if (groupReferences != 1) throw new IllegalArgumentException();
        AgentGroupHandoff handoff = new AgentGroupHandoff(text(raw.get("version")), runId, stoppedRevision,
                bodyHash, oldLeaseHash, inputFingerprint, originOperation, groupKey, operationKey,
                lastEventSeq, checkpointReference, childKeys);
        return new AgentGroupResume(handoff, waitingRevision, List.copyOf(checkpoints));
    }

    private static boolean validStateSchema(String value) {
        return value != null && value.startsWith("schema://") && value.length() > "schema://".length()
                && value.getBytes(StandardCharsets.UTF_8).length <= 256
                && value.chars().noneMatch(ch -> "\u0000\r\n\t* ".indexOf(ch) >= 0);
    }

    private static String expectedAgentGroupStateKey(ExecutionContract.ScopeKey scope, String groupKey) {
        try {
            byte[] identity = new ObjectMapper().writeValueAsBytes(List.of(scope.tenantId(), scope.departmentId(),
                    scope.applicationId(), scope.agentId(), scope.agentInstanceId(), scope.principalType(), scope.principalId(),
                    scope.installationId(), scope.agentVersionId(), scope.sessionId(), scope.runId()));
            String prefix = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(identity));
            byte[] state = new ObjectMapper().writeValueAsBytes(List.of(prefix, "coordination", groupKey));
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(state));
        } catch (Exception ignored) { throw new IllegalArgumentException(); }
    }

    private static String verifyAgentGroupStateCheckpoint(Map<String, Object> response, AgentGroupHandoff handoff) {
        if (response == null || !response.keySet().equals(Set.of("checkpoint", "state_key"))
                || !handoff.checkpoint().get("state_key").equals(response.get("state_key")))
            throw new IllegalArgumentException();
        Map<?, ?> checkpoint = object(response.get("checkpoint"));
        Map<?, ?> state = object(checkpoint.get("value"));
        Set<String> stateFields = Set.of("version", "parent_run_id", "input_hash", "group_key", "operation_key",
                "input_fingerprint", "phase", "ordinal", "targets", "bindings", "child_keys");
        if (!state.keySet().equals(stateFields) || !"agent-group/v1".equals(state.get("version"))
                || !handoff.runId().equals(state.get("parent_run_id"))
                || !handoff.groupKey().equals(state.get("group_key"))
                || !handoff.operationKey().equals(state.get("operation_key"))
                || !handoff.inputFingerprint().equals(state.get("input_fingerprint"))
                || !"gather".equals(state.get("phase"))
                || !HANDOFF_DIGEST.matcher(text(state.get("input_hash"))).matches()
                || exactLong(state.get("ordinal")) != handoff.childKeys().size()
                || !(state.get("targets") instanceof List<?> targets)
                || !(state.get("bindings") instanceof List<?> bindings)
                || !(state.get("child_keys") instanceof List<?> childKeys)
                || targets.size() != handoff.childKeys().size() || bindings.size() != targets.size()
                || childKeys.size() != targets.size()) throw new IllegalArgumentException();
        for (int index = 0; index < targets.size(); index++) {
            Map<?, ?> target = object(targets.get(index));
            Map<?, ?> binding = object(bindings.get(index));
            Set<String> targetFields = Set.of("input_schema", "output_schema");
            Set<String> bindingFields = Set.of("child_key", "input_fingerprint", "output_schema");
            String childKey = handoff.childKeys().get(index);
            if (!target.keySet().equals(targetFields) || !binding.keySet().equals(bindingFields)
                    || !childKey.equals(childKeys.get(index)) || !childKey.equals(binding.get("child_key"))
                    || !HANDOFF_DIGEST.matcher(text(binding.get("input_fingerprint"))).matches()
                    || !Objects.equals(binding.get("output_schema"), target.get("output_schema"))
                    || !validStateSchema(text(target.get("input_schema")))
                    || !validStateSchema(text(target.get("output_schema")))) throw new IllegalArgumentException();
        }
        return text(state.get("input_hash"));
    }

    private static boolean isRuntimeRecovery(Map<String, Object> resumeInput) {
        return resumeInput != null && "runtime-recovery/v1".equals(resumeInput.get("version"));
    }

    private RuntimeRecovery parseRuntimeRecovery(ExecuteRequest request,
            ExecutionContract.CapabilityClaims claims, long nowEpochSeconds) {
        Map<?, ?> marker = request.resumeInput();
        Set<String> markerFields = Set.of("version", "origin_operation", "reference");
        Set<String> markerWithToken = Set.of("version", "origin_operation", "reference", "confirmation_token");
        Set<String> markerWithGroup = Set.of("version", "origin_operation", "reference", "group_resume");
        Set<String> markerWithReview = Set.of("version", "origin_operation", "reference", "business_review");
        if (!marker.keySet().equals(markerFields) && !marker.keySet().equals(markerWithToken)
                && !marker.keySet().equals(markerWithGroup) && !marker.keySet().equals(markerWithReview))
            throw new IllegalArgumentException();
        String originOperation = text(marker.get("origin_operation"));
        boolean composedGroupResume = marker.containsKey("group_resume");
        if (!"runtime-recovery/v1".equals(text(marker.get("version")))
                || !("invoke".equals(originOperation) || (composedGroupResume && "run".equals(originOperation))))
            throw new IllegalArgumentException();
        if (marker.containsKey("confirmation_token")) {
            String confirmation = text(marker.get("confirmation_token"));
            if (confirmation.isBlank() || confirmation.getBytes(StandardCharsets.UTF_8).length > 8192)
                throw new IllegalArgumentException();
        }

        Map<?, ?> raw = object(marker.get("reference"));
        Set<String> baseFields = Set.of("version", "run_id", "stopped_revision", "ready_revision", "operation",
                "body_hash", "policy_hash", "lease_token_hash", "request_hash", "resume_input_hash", "source", "checkpoints");
        Set<String> fullFields = Set.of("version", "run_id", "stopped_revision", "ready_revision", "operation",
                "body_hash", "policy_hash", "lease_token_hash", "request_hash", "resume_input_hash", "source",
                "checkpoints", "proof_digest", "runtime_id");
        if (!raw.keySet().equals(baseFields) && !raw.keySet().equals(fullFields))
            throw new IllegalArgumentException();
        String runId = text(raw.get("run_id"));
        long stoppedRevision = exactLong(raw.get("stopped_revision"));
        long readyRevision = exactLong(raw.get("ready_revision"));
        String operation = text(raw.get("operation"));
        if (marker.containsKey("business_review")) {
            Map<?, ?> review = object(marker.get("business_review"));
            String reviewer = text(review.get("reviewer_id"));
            if (!review.keySet().equals(Set.of("decision", "reviewer_id")) || !"resume".equals(operation)
                    || !Set.of("approve", "reject").contains(text(review.get("decision")))
                    || !reviewer.matches("[A-Za-z0-9_.:-]{1,128}")
                    || reviewer.equals(request.scope().principalId())) throw new IllegalArgumentException();
        }
        String bodyHash = text(raw.get("body_hash"));
        String policyHash = text(raw.get("policy_hash"));
        String oldLeaseHash = text(raw.get("lease_token_hash"));
        String source = text(raw.get("source"));
        if (!"runtime-recovery-stop/v1".equals(text(raw.get("version")))
                || !request.scope().runId().equals(runId) || stoppedRevision < 1
                || stoppedRevision > Lifecycle.MAX_GENERATION_REVISION - 3
                || readyRevision != stoppedRevision + 2
                || claims.executionRevision() == null || claims.executionRevision() != readyRevision + 1
                || claims.executionRevision() > Lifecycle.MAX_GENERATION_REVISION
                || !Set.of("invoke", "run", "resume").contains(operation)
                || !HANDOFF_DIGEST.matcher(bodyHash).matches()
                || !HANDOFF_DIGEST.matcher(policyHash).matches()
                || !HANDOFF_DIGEST.matcher(oldLeaseHash).matches()
                || !HANDOFF_DIGEST.matcher(text(raw.get("request_hash"))).matches()
                || !HANDOFF_DIGEST.matcher(text(raw.get("resume_input_hash"))).matches()
                || claims.leaseTokenHash() == null || !HANDOFF_DIGEST.matcher(claims.leaseTokenHash()).matches()
                || Objects.equals(oldLeaseHash, claims.leaseTokenHash())
                || claims.bodyHash() == null || !HANDOFF_DIGEST.matcher(claims.bodyHash()).matches())
            throw new IllegalArgumentException();
        Lifecycle.eventSequenceBase(claims.executionRevision());

        Object policyValue = request.input() == null ? null : request.input().get("policy_snapshot");
        Map<?, ?> policy = object(policyValue);
        String originalPolicyHash = text(policy.get("content_hash"));
        if (!HANDOFF_DIGEST.matcher(originalPolicyHash).matches() || !policyHash.equals(originalPolicyHash))
            throw new IllegalArgumentException();

        if ("sdk-cancel-exit/v1".equals(source)) {
            if (raw.containsKey("proof_digest") || raw.containsKey("runtime_id")) throw new IllegalArgumentException();
        } else if ("runtime-process-stop/v1".equals(source)) {
            if (!raw.containsKey("proof_digest") || !raw.containsKey("runtime_id")
                    || !HANDOFF_DIGEST.matcher(text(raw.get("proof_digest"))).matches()
                    || !HANDOFF_DIGEST.matcher(text(raw.get("runtime_id"))).matches()) throw new IllegalArgumentException();
        } else throw new IllegalArgumentException();

        if (!(raw.get("checkpoints") instanceof List<?> checkpointValues)
                || checkpointValues.isEmpty() || checkpointValues.size() > 128) throw new IllegalArgumentException();
        List<RecoveryCheckpoint> checkpoints = new ArrayList<>(checkpointValues.size());
        String previousKey = "";
        for (Object value : checkpointValues) {
            Map<?, ?> checkpoint = object(value);
            Set<String> fields = Set.of("state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at");
            if (!checkpoint.keySet().equals(fields)) throw new IllegalArgumentException();
            String stateKey = text(checkpoint.get("state_key"));
            long revision = exactLong(checkpoint.get("revision"));
            String schemaId = text(checkpoint.get("schema_id"));
            String contentHash = text(checkpoint.get("content_hash"));
            long executionRevision = exactLong(checkpoint.get("execution_revision"));
            String expiresAtText = text(checkpoint.get("expires_at"));
            Instant expiresAt = Instant.parse(expiresAtText);
            if (!HANDOFF_DIGEST.matcher(stateKey).matches() || stateKey.compareTo(previousKey) <= 0
                    || revision < 1 || revision > 64
                    || schemaId.length() <= "schema://".length() || schemaId.getBytes(StandardCharsets.UTF_8).length > 256
                    || !schemaId.startsWith("schema://") || schemaId.chars().anyMatch(ch -> "\u0000\r\n\t* ".indexOf(ch) >= 0)
                    || !HANDOFF_DIGEST.matcher(contentHash).matches() || executionRevision < 1
                    || executionRevision > stoppedRevision || !expiresAt.isAfter(Instant.ofEpochSecond(nowEpochSeconds)))
                throw new IllegalArgumentException();
            Map<String, Object> reference = new LinkedHashMap<>();
            reference.put("state_key", stateKey);
            reference.put("revision", revision);
            reference.put("schema_id", schemaId);
            reference.put("content_hash", contentHash);
            reference.put("execution_revision", executionRevision);
            reference.put("expires_at", expiresAtText);
            checkpoints.add(new RecoveryCheckpoint(Map.copyOf(reference), stateKey, revision,
                    schemaId, contentHash, executionRevision, expiresAt));
            previousKey = stateKey;
        }
        AgentGroupResume groupResume = null;
        if (composedGroupResume) {
            groupResume = parseRuntimeGroupResume(request, claims, marker.get("group_resume"),
                    originOperation, stoppedRevision, checkpoints);
        }
        return new RuntimeRecovery(stoppedRevision, readyRevision, operation, bodyHash, policyHash,
                oldLeaseHash, List.copyOf(checkpoints), originOperation, groupResume);
    }

    /** Parse the previously committed AgentGroup waiting reference carried
     * alongside a new runtime-stop proof. Its checkpoint list is historical;
     * only matching current runtime references are loaded from public State. */
    private AgentGroupResume parseRuntimeGroupResume(ExecuteRequest request,
            ExecutionContract.CapabilityClaims claims, Object rawGroupResume, String originOperation,
            long runtimeStoppedRevision, List<RecoveryCheckpoint> runtimeCheckpoints) {
        Map<?, ?> marker = object(rawGroupResume);
        Set<String> markerFields = Set.of("version", "origin_operation", "waiting_revision", "handoff", "checkpoints");
        if (!marker.keySet().equals(markerFields)
                || !AGENT_GROUP_RESUME_VERSION.equals(text(marker.get("version")))
                || !originOperation.equals(text(marker.get("origin_operation")))) throw new IllegalArgumentException();

        Map<?, ?> raw = object(marker.get("handoff"));
        Set<String> handoffFields = Set.of("version", "run_id", "execution_revision", "body_hash", "lease_token_hash",
                "input_fingerprint", "origin_operation", "group_key", "operation_key", "last_event_seq", "checkpoint", "child_keys");
        Set<String> checkpointFields = Set.of("state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at");
        if (!raw.keySet().equals(handoffFields)) throw new IllegalArgumentException();
        Map<?, ?> rawCheckpoint = object(raw.get("checkpoint"));
        if (!rawCheckpoint.keySet().equals(checkpointFields)) throw new IllegalArgumentException();

        String runId = text(raw.get("run_id"));
        long groupExecutionRevision = exactLong(raw.get("execution_revision"));
        long waitingRevision = exactLong(marker.get("waiting_revision"));
        long lastEventSeq = exactLong(raw.get("last_event_seq"));
        String bodyHash = text(raw.get("body_hash"));
        String oldLeaseHash = text(raw.get("lease_token_hash"));
        String inputFingerprint = text(raw.get("input_fingerprint"));
        String groupOrigin = text(raw.get("origin_operation"));
        String groupKey = text(raw.get("group_key"));
        String operationKey = text(raw.get("operation_key"));
        String checkpointStateKey = text(rawCheckpoint.get("state_key"));
        long checkpointRevision = exactLong(rawCheckpoint.get("revision"));
        String checkpointSchema = text(rawCheckpoint.get("schema_id"));
        String checkpointHash = text(rawCheckpoint.get("content_hash"));
        long checkpointExecutionRevision = exactLong(rawCheckpoint.get("execution_revision"));
        String checkpointExpiresText = text(rawCheckpoint.get("expires_at"));
        Instant checkpointExpiresAt = Instant.parse(checkpointExpiresText);
        Map<String, Object> checkpointReference = new LinkedHashMap<>();
        checkpointReference.put("state_key", checkpointStateKey);
        checkpointReference.put("revision", checkpointRevision);
        checkpointReference.put("schema_id", checkpointSchema);
        checkpointReference.put("content_hash", checkpointHash);
        checkpointReference.put("execution_revision", checkpointExecutionRevision);
        checkpointReference.put("expires_at", checkpointExpiresText);

        Object rawChildKeys = raw.get("child_keys");
        if (!(rawChildKeys instanceof List<?> values) || values.isEmpty() || values.size() > 16)
            throw new IllegalArgumentException();
        List<String> childKeys = new ArrayList<>(values.size());
        Set<String> seenChildKeys = new HashSet<>();
        for (Object value : values) {
            if (!(value instanceof String key) || !HANDOFF_DIGEST.matcher(key).matches() || !seenChildKeys.add(key))
                throw new IllegalArgumentException();
            childKeys.add(key);
        }

        long oldBase = Lifecycle.eventSequenceBase(groupExecutionRevision);
        long oldMaximum = Lifecycle.maxEventSequence(groupExecutionRevision);
        if (!AGENT_GROUP_HANDOFF_VERSION.equals(text(raw.get("version")))
                || !request.scope().runId().equals(runId) || !HANDOFF_IDENTIFIER.matcher(runId).matches()
                || !HANDOFF_DIGEST.matcher(bodyHash).matches() || !HANDOFF_DIGEST.matcher(oldLeaseHash).matches()
                || !HANDOFF_DIGEST.matcher(inputFingerprint).matches()
                || !inputFingerprint.equals(ExecutionTracker.businessHash(request))
                || !Set.of("invoke", "run").contains(groupOrigin) || !groupOrigin.equals(originOperation)
                || !HANDOFF_KEY.matcher(groupKey).matches() || !HarnessRunner.skillIdentifier(operationKey)
                || groupExecutionRevision < 1 || groupExecutionRevision > Lifecycle.MAX_GENERATION_REVISION - 3
                || lastEventSeq <= oldBase || lastEventSeq > oldMaximum
                || waitingRevision != groupExecutionRevision + 1
                || waitingRevision + 2 > runtimeStoppedRevision
                || !AGENT_GROUP_SCHEMA.equals(checkpointSchema) || checkpointRevision < 1 || checkpointRevision > 64
                || !HANDOFF_DIGEST.matcher(checkpointStateKey).matches()
                || !HANDOFF_DIGEST.matcher(checkpointHash).matches()
                || checkpointExecutionRevision != groupExecutionRevision
                || claims.leaseTokenHash() == null || !HANDOFF_DIGEST.matcher(claims.leaseTokenHash()).matches()
                || claims.leaseTokenHash().equals(oldLeaseHash)) throw new IllegalArgumentException();

        String expectedStateKey = expectedAgentGroupStateKey(request.scope(), groupKey);
        if (!checkpointStateKey.equals(expectedStateKey)) throw new IllegalArgumentException();

        Object rawCheckpoints = marker.get("checkpoints");
        if (!(rawCheckpoints instanceof List<?> checkpointValues) || checkpointValues.isEmpty() || checkpointValues.size() > 128)
            throw new IllegalArgumentException();
        List<RecoveryCheckpoint> checkpoints = new ArrayList<>(checkpointValues.size());
        String previousKey = "";
        int groupReferences = 0;
        for (Object value : checkpointValues) {
            Map<?, ?> reference = object(value);
            if (!reference.keySet().equals(checkpointFields)) throw new IllegalArgumentException();
            String stateKey = text(reference.get("state_key"));
            long revision = exactLong(reference.get("revision"));
            String schemaId = text(reference.get("schema_id"));
            String contentHash = text(reference.get("content_hash"));
            long executionRevision = exactLong(reference.get("execution_revision"));
            String expiresAtText = text(reference.get("expires_at"));
            Instant expiresAt = Instant.parse(expiresAtText);
            if (!HANDOFF_DIGEST.matcher(stateKey).matches() || stateKey.compareTo(previousKey) <= 0
                    || revision < 1 || revision > 64 || !validStateSchema(schemaId)
                    || !HANDOFF_DIGEST.matcher(contentHash).matches() || executionRevision < 1
                    || executionRevision > groupExecutionRevision) throw new IllegalArgumentException();
            Map<String, Object> snapshot = new LinkedHashMap<>();
            snapshot.put("state_key", stateKey); snapshot.put("revision", revision);
            snapshot.put("schema_id", schemaId); snapshot.put("content_hash", contentHash);
            snapshot.put("execution_revision", executionRevision); snapshot.put("expires_at", expiresAtText);
            Map<String, Object> immutableSnapshot = Map.copyOf(snapshot);
            checkpoints.add(new RecoveryCheckpoint(immutableSnapshot, stateKey, revision, schemaId,
                    contentHash, executionRevision, expiresAt));
            if (stateKey.equals(checkpointStateKey)) {
                if (!immutableSnapshot.equals(checkpointReference)) throw new IllegalArgumentException();
                groupReferences++;
            }
            previousKey = stateKey;
        }
        if (groupReferences != 1) throw new IllegalArgumentException();

        boolean currentReferenceMatches = false;
        for (RecoveryCheckpoint checkpoint : runtimeCheckpoints) {
            if (checkpoint.stateKey().equals(checkpointStateKey)) {
                if (!checkpoint.reference().equals(checkpointReference)) throw new IllegalArgumentException();
                if (currentReferenceMatches) throw new IllegalArgumentException();
                currentReferenceMatches = true;
            }
        }
        if (!currentReferenceMatches) throw new IllegalArgumentException();

        AgentGroupHandoff handoff = new AgentGroupHandoff(text(raw.get("version")), runId,
                groupExecutionRevision, bodyHash, oldLeaseHash, inputFingerprint, groupOrigin,
                groupKey, operationKey, lastEventSeq, Map.copyOf(checkpointReference), childKeys);
        return new AgentGroupResume(handoff, waitingRevision, List.copyOf(checkpoints));
    }

    private static void verifyRecoveryCheckpoint(Map<String, Object> response, RecoveryCheckpoint expected,
            long nowEpochSeconds) {
        if (response == null || !response.keySet().equals(Set.of("checkpoint", "state_key"))
                || !expected.stateKey().equals(response.get("state_key"))
                || !expected.expiresAt().isAfter(Instant.ofEpochSecond(nowEpochSeconds)))
            throw new IllegalArgumentException();
        Map<?, ?> checkpoint = object(response.get("checkpoint"));
        Set<String> fields = Set.of("revision", "schema_id", "value", "content_hash", "expires_at", "execution_revision");
        if (!checkpoint.keySet().equals(fields)
                || exactLong(checkpoint.get("revision")) != expected.revision()
                || !expected.schemaId().equals(text(checkpoint.get("schema_id")))
                || !expected.contentHash().equals(text(checkpoint.get("content_hash")))
                || exactLong(checkpoint.get("execution_revision")) != expected.executionRevision()
                || !expected.expiresAt().equals(Instant.parse(text(checkpoint.get("expires_at")))))
            throw new IllegalArgumentException();
        object(checkpoint.get("value"));
    }

    private HandoffResume parseHandoffResume(ExecuteRequest request, ExecutionContract.CapabilityClaims claims) {
        Map<?, ?> resume = request.resumeInput();
        if (!resume.keySet().equals(Set.of("confirmation_token", "handoff", "checkpoint"))) throw new IllegalArgumentException();
        String confirmationToken = text(resume.get("confirmation_token"));
        if (confirmationToken.isBlank() || confirmationToken.getBytes(StandardCharsets.UTF_8).length > 8192) throw new IllegalArgumentException();

        Map<?, ?> raw = object(resume.get("handoff"));
        if (!raw.keySet().equals(Set.of("version", "run_id", "execution_revision", "body_hash", "lease_token_hash",
                "input_fingerprint", "origin_operation", "harness_key", "tool_name", "call_id", "last_event_seq"))) throw new IllegalArgumentException();
        HandlerHandoff receipt = new HandlerHandoff(text(raw.get("version")), text(raw.get("run_id")),
                exactLong(raw.get("execution_revision")), text(raw.get("body_hash")), text(raw.get("lease_token_hash")),
                text(raw.get("input_fingerprint")), text(raw.get("origin_operation")), text(raw.get("harness_key")),
                text(raw.get("tool_name")), text(raw.get("call_id")), exactLong(raw.get("last_event_seq")));
        if (!HANDOFF_VERSION.equals(receipt.version()) || !request.scope().runId().equals(receipt.runId())
                || !HANDOFF_DIGEST.matcher(receipt.bodyHash()).matches()
                || !HANDOFF_DIGEST.matcher(receipt.leaseTokenHash()).matches()
                || !HANDOFF_DIGEST.matcher(receipt.inputFingerprint()).matches()
                || !receipt.inputFingerprint().equals(ExecutionTracker.businessHash(request))
                || !Set.of("invoke", "run").contains(receipt.originOperation())
                || !HANDOFF_KEY.matcher(receipt.harnessKey()).matches()
                || !HANDOFF_IDENTIFIER.matcher(receipt.toolName()).matches()
                || !HANDOFF_IDENTIFIER.matcher(receipt.callId()).matches()
                || receipt.executionRevision() < 1 || receipt.executionRevision() >= (1L << 53)
                || receipt.lastEventSeq() < 1 || receipt.lastEventSeq() >= (1L << 53)
                || claims.executionRevision() == null || claims.executionRevision() <= receipt.executionRevision()
                || !HANDOFF_DIGEST.matcher(claims.leaseTokenHash()).matches()
                || claims.leaseTokenHash().equals(receipt.leaseTokenHash())) throw new IllegalArgumentException();

        Map<?, ?> checkpoint = object(resume.get("checkpoint"));
        if (!checkpoint.keySet().equals(Set.of("namespace", "key", "schema_id", "revision", "content_hash", "execution_revision"))) throw new IllegalArgumentException();
        String namespace = text(checkpoint.get("namespace"));
        String key = text(checkpoint.get("key"));
        String schema = text(checkpoint.get("schema_id"));
        long revision = exactLong(checkpoint.get("revision"));
        String hash = text(checkpoint.get("content_hash"));
        long executionRevision = exactLong(checkpoint.get("execution_revision"));
        if (!"harness".equals(namespace) || !HANDOFF_KEY.matcher(key).matches() || !HARNESS_SCHEMA.equals(schema)
                || revision < 1 || revision > 64 || !HANDOFF_DIGEST.matcher(hash).matches()
                || executionRevision != receipt.executionRevision() || !key.equals(receipt.harnessKey())) throw new IllegalArgumentException();
        return new HandoffResume(receipt, key, revision, hash, executionRevision);
    }

    private void verifyCurrentCheckpoint(Map<String, Object> response, HandoffResume expected) {
        Map<?, ?> checkpoint = object(response.get("checkpoint"));
        if (exactLong(checkpoint.get("revision")) != expected.checkpointRevision()
                || !HARNESS_SCHEMA.equals(text(checkpoint.get("schema_id")))
                || !expected.checkpointHash().equals(text(checkpoint.get("content_hash")))
                || exactLong(checkpoint.get("execution_revision")) != expected.checkpointExecutionRevision()) throw new IllegalArgumentException();
        Map<?, ?> value = object(checkpoint.get("value"));
        if (!"harness-loop/v1".equals(text(value.get("version")))
                || !"approval_required".equals(text(value.get("phase")))
                || !(value.get("pending") instanceof List<?> pending) || pending.isEmpty()) throw new IllegalArgumentException();
        Map<?, ?> head = object(pending.get(0));
        if (!expected.receipt().toolName().equals(text(head.get("name")))
                || !expected.receipt().callId().equals(text(head.get("call_id")))) throw new IllegalArgumentException();
    }

    private static Map<?, ?> object(Object value) {
        if (!(value instanceof Map<?, ?> map)) throw new IllegalArgumentException();
        return map;
    }

    private static String text(Object value) {
        if (!(value instanceof String string)) throw new IllegalArgumentException();
        return string;
    }

    private static long exactLong(Object value) {
        if (!(value instanceof Number number)) throw new IllegalArgumentException();
        try { return new BigDecimal(number.toString()).longValueExact(); }
        catch (ArithmeticException | NumberFormatException ignored) { throw new IllegalArgumentException(); }
    }

    private void handleCancel(HttpExchange exchange, ExecuteRequest request, String runId, ExecutionContract.CapabilityClaims claims) throws IOException {
        if (runId == null || !runId.equals(request.scope().runId())) {
            writeError(exchange, 400, "REQUEST_INVALID", "path run id must match the verified scope");
            return;
        }
        var active = executions.control(request.scope(), claims);
        if (active == null) {
            writeError(exchange, 409, "REMOTE_STOP_UNCONFIRMED", "execution stop cannot be verified"); return;
        }
        Object value = request.input() == null ? null : request.input().get("reason");
        String reason = value instanceof String string ? string : "";
        RunRecord record;
        try {
            record = config.store().cancel(runId, reason);
        } catch (RuntimeException exception) {
            writeAppFailure(exchange, runId, exception);
            return;
        }
        active.interrupt();
        // Intent in RunStore is not proof that the handler has exited.
        writeJson(exchange, 202, envelope(runId, active.exited.getCount() == 0 ? "cancelled" : "cancelling", null, null));
    }

    // -- events -------------------------------------------------------------

    private void events(HttpExchange exchange, String runId) throws IOException {
        try (var ignored = config.tracer().startSpan("agentplatform.events",
                new Attribute("agentplatform.operation", "events"))) {
            if (!"POST".equals(exchange.getRequestMethod())) {
                writeError(exchange, 405, "METHOD_NOT_ALLOWED", "operation requires POST");
                return;
            }
            if (!config.advertised().getOrDefault("events", false)) {
                writeError(exchange, 404, "UNSUPPORTED_CAPABILITY", "capability is not advertised by this agent");
                return;
            }
            EventRequest request = readJson(exchange, EventRequest.class);
            if (request == null) {
                return;
            }
            if (request.afterSeq() < 0 || request.afterSeq() >= Lifecycle.MAX_EVENT_SEQUENCE_EXCLUSIVE) {
                writeError(exchange, 400, "REQUEST_INVALID", "event cursor is outside the safe integer range");
                return;
            }
            if (request.scope() == null || !config.agentId().equals(request.scope().agentId()) || !boundBearer(exchange, request.contextToken())) {
                writeError(exchange, 401, "CAPABILITY_INVALID", "execution capability is invalid");
                return;
            }
            try {
                verifier.verifyEvent(request, config.publicKey(), config.issuer(), config.audience());
            } catch (RuntimeException exception) {
                writeError(exchange, 401, "CAPABILITY_INVALID", "execution capability is invalid");
                return;
            }
            if (!runId.equals(request.scope().runId())) {
                writeError(exchange, 400, "REQUEST_INVALID", "path run id must match the verified scope");
                return;
            }
            if (!executions.owns(request.scope())) {
                writeError(exchange, 404, "RUN_UNKNOWN", "run is unavailable in this scope"); return;
            }
            List<ExecutionEvent> events;
            try {
                events = config.store().eventsAfter(runId, request.afterSeq());
            } catch (RuntimeException exception) {
                writeAppFailure(exchange, runId, exception);
                return;
            }
            if (events == null) {
                writeError(exchange, 409, "EVENT_READ_UNCONFIRMED", "event order cannot be verified");
                return;
            }
            // A bounded replay that closes the stream afterwards; this is not
            // an unbounded live tail. / 有界重放后关闭流；不是无限实时流。
            StringBuilder body = new StringBuilder();
            long cursor = request.afterSeq();
            for (ExecutionEvent event : events.subList(0, Math.min(events.size(), 256))) {
                if (event == null || event.seq() < 1 || event.seq() >= Lifecycle.MAX_EVENT_SEQUENCE_EXCLUSIVE
                        || !runId.equals(event.runId()) || event.seq() <= cursor || event.payload() == null) {
                    writeError(exchange, 409, "EVENT_READ_UNCONFIRMED", "event order cannot be verified"); return;
                }
                if (List.of("cancelled", "completed", "failed", "waiting").contains(event.eventType()) && !executions.exited(request.scope())) break;
                Map<String, Object> metadata = new java.util.LinkedHashMap<>();
                for (String key : List.of("operation", "reason", "harness_key", "tool_name", "call_id", "code", "group_key", "operation_key")) {
                    Object value = event.payload().get(key);
                    if (value instanceof String text && ("operation_key".equals(key)
                            ? HarnessRunner.skillIdentifier(text) : text.matches("[A-Za-z0-9_.:-]{1,128}"))) metadata.put(key, text);
                }
                Object childCount = event.payload().get("child_count");
                if (childCount instanceof Number number) {
                    try {
                        long count = new BigDecimal(number.toString()).longValueExact();
                        if (count >= 1 && count <= 16) metadata.put("child_count", count);
                    } catch (ArithmeticException | NumberFormatException invalidMetadata) { /* Drop malformed optional metadata. */ }
                }
                ExecutionEvent safe = new ExecutionEvent(event.runId(), event.seq(), event.eventType(), event.occurredAt(), metadata);
                body.append("id: ").append(event.seq())
                        .append("\nevent: ").append(event.eventType())
                        .append("\ndata: ").append(json.writeValueAsString(safe))
                        .append("\n\n");
                cursor = event.seq();
            }
            byte[] raw = body.toString().getBytes(StandardCharsets.UTF_8);
            // One bounded batch is disclosed atomically; validate immediately
            // before committing HTTP headers and any of its bytes.
            try {
                verifier.verifyEvent(request, config.publicKey(), config.issuer(), config.audience());
                if (config.capability() != null) CapabilityClient.checkEventAuthority(config.capability(), request);
            } catch (CapabilityClient.Failure failure) {
                writeJson(exchange, failure.status(), envelope(runId, "failed", null, failure.appError())); return;
            } catch (RuntimeException denied) {
                writeError(exchange, 403, "CAPABILITY_INVALID", "event capability denied"); return;
            }
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.sendResponseHeaders(200, raw.length == 0 ? -1 : raw.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(raw);
            }
        }
    }

    // -- helpers --------------------------------------------------------

    private boolean requireEnvelope(HttpExchange exchange, ExecuteRequest request) throws IOException {
        boolean invalid = !ExecutionContract.PROTOCOL_VERSION.equals(request.protocolVersion())
                || request.contextToken() == null
                || request.operation() == null
                || request.idempotencyKey() == null
                || request.inputSchema() == null
                || request.scope() == null
                || request.input() == null;
        if (invalid) {
            writeError(exchange, 400, "REQUEST_INVALID", "request must be one valid JSON object");
        }
        return invalid;
    }

    private <T> T readJson(HttpExchange exchange, Class<T> type) throws IOException {
        byte[] raw;
        try {
            raw = exchange.getRequestBody().readNBytes(BODY_LIMIT + 1);
            if (raw.length == 0 || raw.length > BODY_LIMIT) {
                throw new IllegalArgumentException("body limit");
            }
            return json.readValue(raw, type);
        } catch (IOException | IllegalArgumentException exception) {
            writeError(exchange, 400, "REQUEST_INVALID", "request must be one valid JSON object");
            return null;
        }
    }

    private boolean boundBearer(HttpExchange exchange, String token) {
        // Bind the envelope token to the request credential so a stolen header
        // cannot be paired with a different body.
        // 将信封令牌与请求凭证绑定，窃取的头部无法与别的正文配对。
        return token != null && ("Bearer " + token).equals(exchange.getRequestHeaders().getFirst("Authorization"));
    }

    private ExecuteResponse envelope(String runId, String status, Map<String, Object> output, AppError error) {
        return envelope(runId, status, output, error, null);
    }

    private ExecuteResponse envelope(String runId, String status, Map<String, Object> output, AppError error,
            HandlerHandoff handoff) {
        return envelope(runId, status, output, error, handoff, null);
    }

    private ExecuteResponse envelope(String runId, String status, Map<String, Object> output, AppError error,
            HandlerHandoff handoff, AgentGroupHandoff agentGroupHandoff) {
        return new ExecuteResponse(ExecutionContract.PROTOCOL_VERSION, runId, status,
                "", output == null ? Map.of() : output, error, handoff, agentGroupHandoff);
    }

    private void writeAppFailure(HttpExchange exchange, String runId, RuntimeException exception) throws IOException {
        int status;
        String code;
        String message;
        boolean retryable;
        if (exception instanceof IdempotencyConflictException) {
            status = 409;
            code = "IDEMPOTENCY_CONFLICT";
            message = "run id was reused with a different idempotency key";
            retryable = false;
        } else if (exception instanceof RunUnknownException) {
            status = 404;
            code = "RUN_UNKNOWN";
            message = "run is unknown";
            retryable = false;
        } else if (exception instanceof InvalidTransitionException) {
            status = 500;
            code = "INVALID_TRANSITION";
            message = "run state transition is invalid";
            retryable = false;
        } else {
            status = 500;
            code = "INTERNAL";
            message = "the agent failed to process the request";
            retryable = true;
        }
        writeJson(exchange, status, envelope(runId, "failed", null,
                new AppError(code, message, retryable, Map.of())));
    }

    private void writeError(HttpExchange exchange, int status, String code, String message) throws IOException {
        writeJson(exchange, status, new AppError(code, message, false, Map.of()));
    }

    private void writeJson(HttpExchange exchange, int status, Object payload) throws IOException {
        byte[] body = json.writeValueAsBytes(payload);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private void notFound(HttpExchange exchange) throws IOException {
        writeError(exchange, 404, "NOT_FOUND", "unknown path");
    }

    private String path(HttpExchange exchange) {
        String raw = exchange.getRequestURI().getPath();
        int query = raw.indexOf('?');
        return query < 0 ? raw : raw.substring(0, query);
    }
}
