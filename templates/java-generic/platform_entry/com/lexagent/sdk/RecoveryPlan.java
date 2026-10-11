package com.lexagent.sdk;

import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Business-declared ordered checkpoint stages for verified runtime recovery.
 * This plan is evaluated only after every signed checkpoint reference has been
 * re-read from the current public State head. It does not itself grant access
 * or authorize a handler to skip an earlier stage.
 */
public final class RecoveryPlan {
    public record CheckpointKey(String namespace, String key) {}

    /** A signed reference plus its freshly verified public State response. */
    public record Snapshot(Map<String, Object> reference, String stateKey,
            Map<String, Object> response) {
        public Snapshot {
            reference = immutableMap(reference);
            response = immutableMap(response);
            if (stateKey == null || stateKey.isBlank()) throw new IllegalArgumentException("checkpoint state key is required");
        }
    }

    @FunctionalInterface
    public interface CheckpointValidator {
        void validate(ExecuteRequest request, Map<String, Object> checkpoint,
                Map<CheckpointKey, Object> priorValues) throws Exception;
    }

    @FunctionalInterface
    public interface CompletionPredicate {
        boolean isComplete(Object value) throws Exception;
    }

    @FunctionalInterface
    public interface InitialInputHashSelector {
        String select(ExecuteRequest request, Map<CheckpointKey, Object> priorValues) throws Exception;
    }

    /** One fixed workflow checkpoint. */
    public record Step(String namespace, String key, String schemaId,
            CheckpointValidator validateCheckpoint, CompletionPredicate isComplete,
            boolean allowInitialStart, InitialInputHashSelector initialInputHashSelector) {
        public Step {
            if (namespace == null || namespace.isBlank() || key == null || key.isBlank()
                    || schemaId == null || schemaId.isBlank()
                    || validateCheckpoint == null || isComplete == null)
                throw new IllegalArgumentException("recovery checkpoint step is incomplete");
            if (allowInitialStart != (initialInputHashSelector != null))
                throw new IllegalArgumentException("initial recovery start selector does not match its policy");
        }

        /** Constant-hash compatibility constructor for existing integrations. */
        public Step(String namespace, String key, String schemaId,
                CheckpointValidator validateCheckpoint, CompletionPredicate isComplete,
                boolean allowInitialStart, String initialInputHash) {
            this(namespace, key, schemaId, validateCheckpoint, isComplete, allowInitialStart,
                    allowInitialStart ? (request, prior) -> initialInputHash : null);
            if (allowInitialStart && (initialInputHash == null || !initialInputHash.matches("[a-f0-9]{64}")))
                throw new IllegalArgumentException("initial recovery start requires a frozen input hash");
            if (!allowInitialStart && initialInputHash != null)
                throw new IllegalArgumentException("unexpected initial recovery input hash");
        }

        public CheckpointKey checkpointKey() { return new CheckpointKey(namespace, key); }
    }

    @FunctionalInterface
    public interface Selector {
        RecoveryPlan select(ExecuteRequest request, List<Snapshot> checkpoints,
                Snapshot groupCheckpoint) throws Exception;
    }

    private final List<Step> steps;
    private final boolean allowGroupResume;
    private final String allowedAgentGroupKey;

    public RecoveryPlan(List<Step> steps, boolean allowGroupResume) {
        this(steps, allowGroupResume, "");
    }

    /**
     * @param allowedAgentGroupKey exact fixed coordination checkpoint key which
     *        this business plan may run; empty disables AgentGroup recovery.
     */
    public RecoveryPlan(List<Step> steps, boolean allowGroupResume, String allowedAgentGroupKey) {
        if (steps == null || steps.isEmpty() || steps.size() > 16)
            throw new IllegalArgumentException("recovery plan requires ordered steps");
        if (allowedAgentGroupKey == null) throw new IllegalArgumentException("AgentGroup key is invalid");
        var seen = new java.util.HashSet<CheckpointKey>();
        for (Step step : steps) {
            if (step == null || !seen.add(step.checkpointKey()))
                throw new IllegalArgumentException("recovery plan contains duplicate steps");
        }
        this.steps = List.copyOf(steps);
        this.allowGroupResume = allowGroupResume;
        this.allowedAgentGroupKey = allowedAgentGroupKey;
    }

    public List<Step> steps() { return steps; }
    public boolean allowGroupResume() { return allowGroupResume; }
    public String allowedAgentGroupKey() { return allowedAgentGroupKey; }

    static final class PlannedStep {
        final Step step;
        final String stateKey;
        final boolean originallyCaptured;
        Map<String, Object> response;
        Map<String, Object> checkpoint;
        boolean complete;

        PlannedStep(Step step, String stateKey, boolean originallyCaptured,
                Map<String, Object> response, Map<String, Object> checkpoint, boolean complete) {
            this.step = step;
            this.stateKey = stateKey;
            this.originallyCaptured = originallyCaptured;
            this.response = immutableMap(response);
            this.checkpoint = checkpoint == null ? null : immutableMap(checkpoint);
            this.complete = complete;
        }
    }

    /** Private per-generation ordered state observation and one-use start permits. */
    static final class RuntimeRecoveryBinding {
        private final ExecuteRequest request;
        private final long executionRevision;
        private final List<PlannedStep> steps;
        private final Map<CheckpointKey, Object> priorValues = new LinkedHashMap<>();
        private final Map<String, Snapshot> capturedByStateKey = new LinkedHashMap<>();
        private final Map<Map<String, Object>, Snapshot> capturedByReference = new LinkedHashMap<>();
        private final boolean allowGroupResume;
        private final String allowedAgentGroupKey;
        private int currentIndex;
        private boolean currentOpened;
        private StartAuthorization start;
        private Thread agentGroupThread;
        private String agentGroupOperationKey;
        private String agentGroupInputHash;
        private boolean agentGroupCheckpointObserved;
        private boolean agentGroupGatherUsed;

        RuntimeRecoveryBinding(ExecuteRequest request, long executionRevision,
                List<PlannedStep> steps, Map<CheckpointKey, Object> priorValues,
                List<Snapshot> captured, boolean allowGroupResume, String allowedAgentGroupKey) {
            if (request == null || executionRevision < 1 || steps == null || steps.isEmpty())
                throw new IllegalArgumentException("runtime recovery binding is incomplete");
            this.request = request;
            this.executionRevision = executionRevision;
            this.steps = List.copyOf(steps);
            if (priorValues != null)
                priorValues.forEach((key, value) -> this.priorValues.put(key, immutableValue(value)));
            this.allowGroupResume = allowGroupResume;
            this.allowedAgentGroupKey = allowedAgentGroupKey == null ? "" : allowedAgentGroupKey;
            while (currentIndex < this.steps.size() && this.steps.get(currentIndex).complete) currentIndex++;
            if (captured != null) for (Snapshot snapshot : captured) {
                if (capturedByStateKey.putIfAbsent(snapshot.stateKey(), snapshot) != null)
                    throw new IllegalArgumentException("checkpoint state key is duplicated");
                capturedByReference.put(snapshot.reference(), snapshot);
            }
        }

        synchronized boolean isAgentGroupResume() { return allowGroupResume; }

        synchronized void authorizeAgentGroupInvocation(String groupKey, String operationKey,
                String inputHash) throws CapabilityClient.Failure {
            if (allowedAgentGroupKey.isEmpty() || !allowedAgentGroupKey.equals(groupKey)
                    || !HarnessRunner.skillIdentifier(operationKey) || inputHash == null
                    || !inputHash.matches("[a-f0-9]{64}")) throw rejected();
            int index = findStep("coordination", groupKey);
            if (index < 0 || !AgentGroupRunner.STATE_SCHEMA.equals(steps.get(index).step.schemaId())) throw rejected();
            for (int prior = 0; prior < index; prior++) if (!steps.get(prior).complete) throw rejected();
            PlannedStep planned = steps.get(index);
            String expected;
            if (planned.checkpoint != null) {
                try {
                    Map<String, Object> value = stringMap(planned.checkpoint.get("value"));
                    if (!"agent-group/v1".equals(value.get("version"))
                            || !groupKey.equals(value.get("group_key"))
                            || !operationKey.equals(value.get("operation_key"))) throw rejected();
                    expected = string(value.get("input_hash"));
                } catch (CapabilityClient.Failure failure) { throw failure; }
            } else {
                if (!planned.step.allowInitialStart() || planned.step.initialInputHashSelector() == null
                        || index != currentIndex) throw rejected();
                try { expected = planned.step.initialInputHashSelector().select(request, immutablePriorValues()); }
                catch (Exception invalid) { throw rejected(); }
            }
            if (!inputHash.equals(expected)) throw rejected();
            if (agentGroupThread != null && agentGroupThread != Thread.currentThread()) throw rejected();
            agentGroupThread = Thread.currentThread();
            agentGroupOperationKey = operationKey;
            agentGroupInputHash = inputHash;
            agentGroupCheckpointObserved = false;
            agentGroupGatherUsed = false;
        }

        synchronized void authorizeAgentGroupCheckpointLoaded(String groupKey,
                String operationKey, String inputHash) throws CapabilityClient.Failure {
            if (!allowedAgentGroupKey.equals(groupKey) || agentGroupThread != Thread.currentThread()
                    || !operationKey.equals(agentGroupOperationKey) || !inputHash.equals(agentGroupInputHash)
                    || !agentGroupCheckpointObserved) throw rejected();
            int index = findStep("coordination", groupKey);
            if (index < 0) throw rejected();
            PlannedStep planned = steps.get(index);
            if (planned.checkpoint == null) {
                if (index != currentIndex || !planned.originallyCaptured && !planned.step.allowInitialStart()
                        || start == null || !start.consume("coordination", groupKey,
                                AgentGroupRunner.STATE_SCHEMA, inputHash, planned.stateKey)) throw rejected();
                currentOpened = true;
                start = null;
            } else if (!planned.complete && index == currentIndex && !currentOpened) {
                throw rejected();
            }
        }

        synchronized void finishAgentGroupInvocation(String groupKey, String operationKey,
                String inputHash) throws CapabilityClient.Failure {
            if (!allowedAgentGroupKey.equals(groupKey) || agentGroupThread != Thread.currentThread()
                    || !operationKey.equals(agentGroupOperationKey) || !inputHash.equals(agentGroupInputHash)
                    || !agentGroupCheckpointObserved || !agentGroupGatherUsed) throw rejected();
            agentGroupThread = null;
            agentGroupOperationKey = null;
            agentGroupInputHash = null;
            agentGroupCheckpointObserved = false;
            agentGroupGatherUsed = false;
        }

        synchronized boolean consumeStart(String namespace, String key, String schemaId,
                String inputHash, String stateKey) {
            if (start == null || currentIndex >= steps.size()) return false;
            PlannedStep current = steps.get(currentIndex);
            if (!current.step.namespace().equals(namespace) || !current.step.key().equals(key)
                    || !current.step.schemaId().equals(schemaId) || !current.stateKey.equals(stateKey)) return false;
            if (!start.consume(namespace, key, schemaId, inputHash, stateKey)) return false;
            currentOpened = true;
            return true;
        }

        synchronized void authorizeInitialStart(String namespace, String key, String schemaId,
                String inputHash) throws CapabilityClient.Failure {
            if (currentIndex >= steps.size()) throw rejected();
            PlannedStep current = steps.get(currentIndex);
            if (!current.originallyCaptured && !current.step.allowInitialStart()
                    || !consumeStart(namespace, key, schemaId, inputHash, current.stateKey)) throw rejected();
        }

        synchronized void beforePost(String path, Map<String, Object> input) throws CapabilityClient.Failure {
            if (isAgentGroupPath(path)) {
                int groupIndex = findStep("coordination", allowedAgentGroupKey);
                if (allowedAgentGroupKey.isEmpty() || groupIndex < 0
                        || agentGroupThread != Thread.currentThread() || !agentGroupCheckpointObserved
                        || (!steps.get(groupIndex).complete && !currentOpened)
                        || input == null || !agentGroupOperationKey.equals(input.get("operation_key"))) throw rejected();
                if ("/internal/agent/gather".equals(path)) {
                    if (agentGroupGatherUsed) throw rejected();
                    agentGroupGatherUsed = true;
                }
                return;
            }
            if (currentIndex >= steps.size()) return;
            if (!"/internal/state/checkpoint".equals(path)) {
                if (!currentOpened) throw rejected();
                return;
            }
            if (input == null) throw rejected();
            Object reference = input.get("reference");
            if (reference instanceof Map<?, ?> rawReference) {
                Map<String, Object> ref = stringMap(rawReference);
                if (!capturedByReference.containsKey(ref) || !"load".equals(input.get("operation")))
                    throw rejected();
                return;
            }
            String namespace = string(input.get("namespace"));
            String key = string(input.get("key"));
            String schemaId = string(input.get("schema_id"));
            int index = findStep(namespace, key);
            String operation = string(input.get("operation"));
            if (index < 0) {
                if (!"load".equals(operation) && !currentOpened) throw rejected();
                if (!"load".equals(operation) && !"save".equals(operation)) throw rejected();
                if ("load".equals(operation) && !currentRevision(input)) throw rejected();
                return;
            }
            if (index > currentIndex || !steps.get(index).step.schemaId().equals(schemaId)) throw rejected();
            if (index < currentIndex) {
                if (!"load".equals(operation) || !currentRevision(input)) throw rejected();
                return;
            }
            if (!"load".equals(operation) && !"save".equals(operation)) throw rejected();
            if ("load".equals(operation) && !currentRevision(input)) throw rejected();
            if ("save".equals(operation) && !currentOpened) throw rejected();
        }

        synchronized void observePost(String path, Map<String, Object> input,
                Map<String, Object> response, long nowEpochSeconds) throws CapabilityClient.Failure {
            if (!"/internal/state/checkpoint".equals(path) || input == null) return;
            if (currentIndex >= steps.size()) return;
            Object reference = input.get("reference");
            if (reference instanceof Map<?, ?> rawReference) {
                Map<String, Object> ref = stringMap(rawReference);
                Snapshot expected = capturedByReference.get(ref);
                if (expected == null || !expected.response().equals(response)) throw rejected();
                return;
            }
            String namespace = string(input.get("namespace"));
            String key = string(input.get("key"));
            String schemaId = string(input.get("schema_id"));
            int index = findStep(namespace, key);
            String operation = string(input.get("operation"));
            if (index < 0) {
                observeSupplemental(operation, input, response, nowEpochSeconds);
                return;
            }
            if (index > currentIndex || !steps.get(index).step.schemaId().equals(schemaId)) throw rejected();
            PlannedStep planned = steps.get(index);
            if (index < currentIndex) {
                if (!"load".equals(operation) || !planned.response.equals(response)) throw rejected();
                if ("coordination".equals(namespace) && key.equals(allowedAgentGroupKey)
                        && agentGroupThread == Thread.currentThread()) agentGroupCheckpointObserved = true;
                return;
            }
            if ("load".equals(operation)) {
                observeLoad(planned, response, nowEpochSeconds);
                if ("coordination".equals(namespace) && key.equals(allowedAgentGroupKey)
                        && agentGroupThread == Thread.currentThread()) agentGroupCheckpointObserved = true;
                return;
            }
            if ("save".equals(operation)) {
                observeSave(planned, input, response, nowEpochSeconds);
                return;
            }
            throw rejected();
        }

        private void observeSupplemental(String operation, Map<String, Object> input,
                Map<String, Object> response, long nowEpochSeconds) throws CapabilityClient.Failure {
            if ("load".equals(operation)) {
                if (!currentRevision(input)) throw rejected();
                if (!(response.get("state_key") instanceof String stateKey)) throw rejected();
                Snapshot expected = capturedByStateKey.get(stateKey);
                if (expected == null || !expected.response().equals(response)) throw rejected();
                return;
            }
            if (!"save".equals(operation) || !currentOpened) throw rejected();
            validateCheckpointResponse(response, string(input.get("schema_id")), null,
                    nowEpochSeconds, input.get("expected_revision"), input.get("value"));
        }

        private void observeLoad(PlannedStep planned, Map<String, Object> response,
                long nowEpochSeconds) throws CapabilityClient.Failure {
            if (response == null || !response.keySet().equals(java.util.Set.of("checkpoint", "state_key"))
                    || !planned.stateKey.equals(response.get("state_key"))) throw rejected();
            Object rawCheckpoint = response.get("checkpoint");
            if (rawCheckpoint == null) {
                if (planned.originallyCaptured || planned.checkpoint != null || !planned.step.allowInitialStart()
                        || start != null) throw rejected();
                String inputHash;
                try { inputHash = planned.step.initialInputHashSelector().select(request, immutablePriorValues()); }
                catch (Exception failure) { throw rejected(); }
                if (inputHash == null || !inputHash.matches("[a-f0-9]{64}")) throw rejected();
                start = new StartAuthorization(planned.step.namespace(), planned.step.key(),
                        planned.step.schemaId(), inputHash, planned.stateKey);
                return;
            }
            if (planned.checkpoint == null || !planned.response.equals(response)) throw rejected();
            validateStepCheckpoint(planned, stringMap(rawCheckpoint), nowEpochSeconds);
            currentOpened = true;
            refreshCompletion(planned, response);
        }

        private void observeSave(PlannedStep planned, Map<String, Object> input,
                Map<String, Object> response, long nowEpochSeconds) throws CapabilityClient.Failure {
            Object expectedRevision = input.get("expected_revision");
            Map<String, Object> saved = validateCheckpointResponse(response, planned.step.schemaId(),
                    planned.stateKey, nowEpochSeconds, expectedRevision, input.get("value"));
            long requestedRevision = exactLong(expectedRevision);
            if (planned.checkpoint != null) {
                long priorRevision = exactLong(planned.checkpoint.get("revision"));
                if (requestedRevision != priorRevision || exactLong(saved.get("revision")) != priorRevision + 1) throw rejected();
            } else {
                if (planned.originallyCaptured || start == null || !start.consumed()
                        || requestedRevision != 0 || exactLong(saved.get("revision")) != 1) throw rejected();
            }
            Map<String, Object> nextResponse = Map.of("checkpoint", saved, "state_key", planned.stateKey);
            planned.response = immutableMap(nextResponse);
            planned.checkpoint = immutableMap(saved);
            validateStepCheckpoint(planned, planned.checkpoint, nowEpochSeconds);
            currentOpened = true;
            refreshCompletion(planned, planned.response);
        }

        private void validateStepCheckpoint(PlannedStep planned, Map<String, Object> checkpoint,
                long nowEpochSeconds) throws CapabilityClient.Failure {
            Map<String, Object> value = stringMap(checkpoint.get("value"));
            try { planned.step.validateCheckpoint().validate(request, checkpoint, immutablePriorValues()); }
            catch (Exception failure) { throw rejected(); }
            // Completion is evaluated only from the persisted State value.
            boolean complete;
            try { complete = planned.step.isComplete().isComplete(value); }
            catch (Exception failure) { throw rejected(); }
            planned.complete = complete;
        }

        private void refreshCompletion(PlannedStep planned, Map<String, Object> response)
                throws CapabilityClient.Failure {
            if (!planned.complete) return;
            Map<String, Object> checkpoint = stringMap(response.get("checkpoint"));
            Map<String, Object> value = stringMap(checkpoint.get("value"));
            priorValues.put(planned.step.checkpointKey(), immutableMap(value));
            currentIndex++;
            currentOpened = false;
            start = null;
        }

        private Map<String, Object> validateCheckpointResponse(Map<String, Object> response,
                String schemaId, String expectedStateKey, long nowEpochSeconds,
                Object expectedRevision, Object expectedValue) throws CapabilityClient.Failure {
            if (response == null || !response.keySet().equals(java.util.Set.of("checkpoint", "state_key"))
                    || !(response.get("state_key") instanceof String stateKey)
                    || !stateKey.matches("[a-f0-9]{64}")
                    || (expectedStateKey != null && !expectedStateKey.equals(stateKey))) throw rejected();
            Map<String, Object> checkpoint = stringMap(response.get("checkpoint"));
            if (!checkpoint.keySet().equals(java.util.Set.of("revision", "schema_id", "value", "content_hash", "expires_at", "execution_revision"))
                    || !schemaId.equals(checkpoint.get("schema_id"))
                    || !(checkpoint.get("content_hash") instanceof String hash) || !hash.matches("[a-f0-9]{64}")
                    || exactLong(checkpoint.get("execution_revision")) != executionRevision
                    || exactLong(checkpoint.get("revision")) < 1 || exactLong(checkpoint.get("revision")) > 64
                    || !Instant.parse(string(checkpoint.get("expires_at"))).isAfter(Instant.ofEpochSecond(nowEpochSeconds)))
                throw rejected();
            long expectedNext = exactLong(expectedRevision) + 1;
            if (exactLong(checkpoint.get("revision")) != expectedNext
                    || !stringMap(checkpoint.get("value")).equals(stringMap(expectedValue))) throw rejected();
            return immutableMap(checkpoint);
        }

        private int findStep(String namespace, String key) {
            for (int i = 0; i < steps.size(); i++) {
                Step step = steps.get(i).step;
                if (step.namespace().equals(namespace) && step.key().equals(key)) return i;
            }
            return -1;
        }

        private static boolean isAgentGroupPath(String path) {
            return "/internal/agent/route".equals(path) || "/internal/agent/prepare".equals(path)
                    || "/internal/agent/admission-state".equals(path) || "/internal/agent/admit".equals(path)
                    || "/internal/agent/gather".equals(path);
        }

        private static boolean currentRevision(Map<String, Object> input) throws CapabilityClient.Failure {
            if (!input.containsKey("revision")) return true;
            return exactLong(input.get("revision")) == 0;
        }

        private Map<CheckpointKey, Object> immutablePriorValues() {
            Map<CheckpointKey, Object> result = new LinkedHashMap<>();
            priorValues.forEach((key, value) -> result.put(key, immutableValue(value)));
            return Collections.unmodifiableMap(result);
        }

        private static long exactLong(Object value) throws CapabilityClient.Failure {
            try {
                if (value instanceof java.math.BigInteger number) return number.longValueExact();
                if (value instanceof java.math.BigDecimal number) return number.longValueExact();
                if (value instanceof Number number) return number.longValue();
            } catch (ArithmeticException ignored) { }
            throw rejected();
        }

        private static String string(Object value) { return value instanceof String text ? text : ""; }
        private static Map<String, Object> stringMap(Object value) throws CapabilityClient.Failure {
            if (!(value instanceof Map<?, ?> raw)) throw rejected();
            Map<String, Object> result = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : raw.entrySet()) {
                if (!(entry.getKey() instanceof String text)) throw rejected();
                result.put(text, entry.getValue());
            }
            return result;
        }
        private static CapabilityClient.Failure rejected() {
            return new CapabilityClient.Failure("RECOVERY_CHECKPOINT_REJECTED", 409, false);
        }
    }

    static final class StartAuthorization {
        private final String namespace, key, schemaId, inputHash, stateKey;
        private final AtomicBoolean consumed = new AtomicBoolean(false);
        StartAuthorization(String namespace, String key, String schemaId,
                String inputHash, String stateKey) {
            if (namespace == null || key == null || schemaId == null || inputHash == null || stateKey == null)
                throw new IllegalArgumentException("recovery start binding is incomplete");
            this.namespace = namespace;
            this.key = key;
            this.schemaId = schemaId;
            this.inputHash = inputHash;
            this.stateKey = stateKey;
        }
        boolean consume(String candidateNamespace, String candidateKey, String candidateSchema,
                String candidateInputHash, String candidateStateKey) {
            return namespace.equals(candidateNamespace) && key.equals(candidateKey)
                    && schemaId.equals(candidateSchema) && inputHash.equals(candidateInputHash)
                    && stateKey.equals(candidateStateKey) && consumed.compareAndSet(false, true);
        }
        boolean consumed() { return consumed.get(); }
    }

    private static Map<String, Object> immutableMap(Map<String, Object> source) {
        if (source == null) throw new IllegalArgumentException("checkpoint snapshot is required");
        Map<String, Object> result = new LinkedHashMap<>();
        source.forEach((key, value) -> {
            if (key == null) throw new IllegalArgumentException("checkpoint field is invalid");
            result.put(key, immutableValue(value));
        });
        return Collections.unmodifiableMap(result);
    }

    private static Object immutableValue(Object value) {
        if (value == null || value instanceof String || value instanceof Boolean || value instanceof Number)
            return value;
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            map.forEach((key, nested) -> {
                if (!(key instanceof String text)) throw new IllegalArgumentException("checkpoint field is invalid");
                result.put(text, immutableValue(nested));
            });
            return Collections.unmodifiableMap(result);
        }
        if (value instanceof List<?> list) {
            List<Object> result = new ArrayList<>(list.size());
            for (Object nested : list) result.add(immutableValue(nested));
            return Collections.unmodifiableList(result);
        }
        throw new IllegalArgumentException("checkpoint value is not JSON data");
    }
}
