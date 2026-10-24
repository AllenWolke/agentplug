package com.lexagent.sdk;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Durable ordered plans. Recovery reconciles the original receipt; it never
 * calls Execute for a persisted dispatch or treats unknown as unsent. */
public final class StepWorkflow {
    public static final String NAMESPACE = "step-workflow";
    public static final String SCHEMA = "schema://agentplug/step-workflow/v1";
    public record Step(String id, Map<String, Object> payload,
            @JsonProperty("depends_on") List<String> dependsOn,
            @JsonProperty("required_slots") List<String> requiredSlots) {}
    public record Options(String key, List<String> requiredSlots, int maxSteps, Map<String, Integer> maxCalls,
            Duration timeout, Long deadlineMs, List<Step> additionalSteps, int maxExtensions,
            boolean prepareOnly, boolean inspectOnly) {
        public static Options defaults(String key, List<String> slots) {
            return new Options(key, slots, 6, Map.of("model", 4, "knowledge", 4, "tool", 8), Duration.ofMinutes(1), null, null, 1, false, false);
        }
    }
    public interface Executor {
        Map<String, Object> execute(Step step, Runtime runtime, Map<String, Object> results) throws Exception;
        Map<String, Object> recover(Step step, Runtime runtime, Map<String, Object> results) throws Exception;
        default boolean revalidate(Step step, Map<String, Object> result) throws Exception { return true; }
    }
    public record Call(String kind, String key) {}
    public static final class Runtime {
        private final Session session;
        private final String operationKey;
        private final boolean recovering;
        Runtime(Session session, String operationKey, boolean recovering) { this.session = session; this.operationKey = operationKey; this.recovering = recovering; }
        public String operationKey() { return operationKey; }
        public long deadlineMs() throws CapabilityClient.Failure { return number(session.state.get("deadline_ms")); }
        public boolean recovering() { return recovering; }
        public long remainingMillis() throws CapabilityClient.Failure {
            long remaining = session.remainingMillis();
            if (remaining <= 0) throw stop("STEP_DEADLINE_EXCEEDED"); return remaining;
        }
        public void admitCall(String kind, String key) throws CapabilityClient.Failure { admitCalls(List.of(new Call(kind, key))); }
        public void admitCalls(List<Call> calls) throws CapabilityClient.Failure { session.admit(calls); }
    }
    private static CapabilityClient.Failure stop(String code) { return PublicCapabilities.stop(code); }
    private static long number(Object value) throws CapabilityClient.Failure { return PublicCapabilities.integer(value); }
    private static boolean name(String value) { return value != null && value.matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"); }
    private static boolean names(List<String> values) {
        return values != null && values.size() <= 32 && values.stream().allMatch(StepWorkflow::name) && new LinkedHashSet<>(values).size() == values.size();
    }
    static List<Step> normalize(List<Step> steps, List<String> slots, int maximum, List<Step> prior) throws CapabilityClient.Failure {
        if (steps == null || steps.isEmpty() || steps.size() > maximum || !names(slots)) throw stop("STEP_PLAN_REJECTED");
        Set<String> seen = new LinkedHashSet<>(); prior.forEach(step -> seen.add(step.id()));
        List<Step> result = new ArrayList<>();
        for (Step step : steps) {
            if (step == null || !name(step.id()) || seen.contains(step.id()) || step.payload() == null || !names(step.dependsOn())
                    || !seen.containsAll(step.dependsOn()) || !names(step.requiredSlots()) || !slots.containsAll(step.requiredSlots())) throw stop("STEP_PLAN_REJECTED");
            result.add(new Step(step.id(), PublicCapabilities.copy(step.payload()), List.copyOf(step.dependsOn()), List.copyOf(step.requiredSlots()))); seen.add(step.id());
        }
        return result;
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) throws CapabilityClient.Failure {
        if (!(value instanceof Map<?, ?>)) throw stop("STEP_STATE_REJECTED"); return (Map<String, Object>) value;
    }
    @SuppressWarnings("unchecked")
    private static List<String> strings(Object value) throws CapabilityClient.Failure {
        if (!(value instanceof List<?> list) || list.stream().anyMatch(item -> !(item instanceof String))) throw stop("STEP_STATE_REJECTED");
        return (List<String>) list;
    }
    private static List<Step> decodeSteps(Object raw, Options options) throws CapabilityClient.Failure {
        if (!(raw instanceof List<?> list)) throw stop("STEP_STATE_REJECTED"); List<Step> result = new ArrayList<>();
        for (Object item : list) {
            var value = object(item);
            if (!value.keySet().equals(Set.of("id", "payload", "depends_on", "required_slots")) || !(value.get("id") instanceof String id)) throw stop("STEP_STATE_REJECTED");
            result.add(new Step(id, object(value.get("payload")), strings(value.get("depends_on")), strings(value.get("required_slots"))));
        }
        return normalize(result, options.requiredSlots(), options.maxSteps(), List.of());
    }
    private static void validateResult(Map<String, Object> result, Step step) throws CapabilityClient.Failure {
        if (!(result.get("status") instanceof String status) || !Set.of("completed", "incomplete").contains(status) || !(result.get("output") instanceof Map<?, ?>)) throw stop("STEP_RESULT_REJECTED");
        var slots = strings(result.get("covered_slots"));
        if (!names(slots) || !step.requiredSlots().containsAll(slots) || !"completed".equals(result.get("status")) && !slots.isEmpty()) throw stop("STEP_RESULT_REJECTED");
    }
    public static Map<String, Object> run(CapabilityPort port, List<Step> steps, Executor executor, Options options) throws Exception {
        return new Session(port, steps, executor, options).run();
    }
    private static final class Session {
        final CapabilityPort port;
        final Executor executor;
        final Options options;
        final List<Step> initial;
        final Map<String, Integer> limits;
        final String digest;
        final long entered = System.nanoTime();
        final long serverTimeMs;
        final String policyHash;
        Map<String, Object> state;
        Map<String, Object> results;
        Map<String, Object> reservations;
        List<Step> steps;
        long revision;
        Session(CapabilityPort port, List<Step> initial, Executor executor, Options options) throws Exception {
            if (port == null || executor == null || options == null || !name(options.key()) || !names(options.requiredSlots()) || options.requiredSlots().isEmpty()
                    || options.maxSteps() < 1 || options.maxSteps() > 6 || options.maxExtensions() < 0 || options.maxExtensions() > 1
                    || options.timeout() == null || options.timeout().isNegative() || options.timeout().isZero() || options.timeout().compareTo(Duration.ofHours(1)) > 0
                    || options.prepareOnly() && options.additionalSteps() != null || options.inspectOnly() && (options.prepareOnly() || options.additionalSteps() != null)) throw stop("STEP_CONFIG_INVALID");
            this.port = port; this.executor = executor; this.options = options;
            this.initial = normalize(initial, options.requiredSlots(), options.maxSteps(), List.of());
            this.limits = options.maxCalls() == null ? Map.of("model", 4, "knowledge", 4, "tool", 8) : Map.copyOf(options.maxCalls());
            for (var entry : limits.entrySet()) if (!Set.of("model", "knowledge", "tool").contains(entry.getKey()) || entry.getValue() < 0 || entry.getValue() > 16) throw stop("STEP_CONFIG_INVALID");
            digest = PublicCapabilities.digest(List.of(this.initial, options.requiredSlots(), options.maxSteps(), limits, options.maxExtensions()));
            Map<String, Object> policy = port.post("/internal/runtime/harness-policy", Map.of());
            if (!"harness-policy/v1".equals(policy.get("version")) || !(policy.get("policy_hash") instanceof String hash) || !hash.matches("[a-f0-9]{64}")) throw stop("HARNESS_POLICY_REJECTED");
            policyHash = hash; serverTimeMs = number(policy.get("server_time_ms"));
            long elapsed = number(object(policy.get("limits")).get("max_elapsed_seconds"));
            if (serverTimeMs <= 0 || elapsed < 10 || elapsed > 3600) throw stop("HARNESS_POLICY_REJECTED");
            long deadline = Math.addExact(serverTimeMs, Math.min(options.timeout().toMillis(), elapsed * 1000));
            if (options.deadlineMs() != null) { if (options.deadlineMs() < 1 || options.deadlineMs() > 9_007_199_254_740_991L) throw stop("STEP_CONFIG_INVALID"); deadline = Math.min(deadline, options.deadlineMs()); }
            Map<String, Object> loaded = port.loadCheckpoint(NAMESPACE, options.key(), SCHEMA, 0);
            if (loaded.get("checkpoint") == null) {
                if (options.inspectOnly()) throw stop("STEP_RECONCILIATION_REQUIRED");
                if (port instanceof CapabilityClient client) client.authorizeRuntimeRecoveryStart(NAMESPACE, options.key(), SCHEMA, digest);
                state = new LinkedHashMap<>(); state.put("version", "step-workflow/v1"); state.put("input_hash", digest); state.put("phase", "running");
                state.put("steps", this.initial); state.put("required_slots", options.requiredSlots()); state.put("results", Map.of()); state.put("deadline_ms", deadline);
                state.put("call_limits", limits); state.put("reservations", Map.of()); state.put("extensions", 0); state.put("policy_hash", policyHash); state.put("pending", null);
                state = PublicCapabilities.copy(state);
            } else {
                Map<String, Object> checkpoint = object(loaded.get("checkpoint")); revision = number(checkpoint.get("revision")); state = PublicCapabilities.copy(object(checkpoint.get("value")));
                if (revision < 1 || revision > 63 || !"step-workflow/v1".equals(state.get("version")) || !digest.equals(state.get("input_hash"))) throw stop("STEP_STATE_REJECTED");
            }
            steps = decodeSteps(state.get("steps"), options);
            if (steps.size() < this.initial.size() || !PublicCapabilities.digest(steps.subList(0, this.initial.size())).equals(PublicCapabilities.digest(this.initial))
                    || !PublicCapabilities.digest(state.get("required_slots")).equals(PublicCapabilities.digest(options.requiredSlots()))
                    || !PublicCapabilities.digest(state.get("call_limits")).equals(PublicCapabilities.digest(limits))
                    || number(state.get("deadline_ms")) < 1 || number(state.get("deadline_ms")) > deadline
                    || number(state.get("extensions")) < 0 || number(state.get("extensions")) > options.maxExtensions()) throw stop("STEP_STATE_REJECTED");
            results = object(state.get("results")); reservations = object(state.get("reservations"));
            if (results.size() > steps.size() || reservations.size() > 32) throw stop("STEP_STATE_REJECTED");
            for (var entry : reservations.entrySet()) if (!name(entry.getKey()) || !limits.containsKey(entry.getValue()) || count(reservations, (String) entry.getValue()) > limits.get(entry.getValue())) throw stop("STEP_STATE_REJECTED");
            for (Step step : steps.subList(0, results.size())) {
                var result = object(results.get(step.id())); validateResult(result, step);
                if (!executor.revalidate(step, PublicCapabilities.copy(result))) throw stop("STEP_RESULT_AUTHORITY_DENIED");
            }
            String phase = String.valueOf(state.get("phase"));
            if (!Set.of("running", "dispatch", "awaiting_extension", "completed", "cancelled", "incomplete").contains(phase)
                    || phase.equals("dispatch") && (results.size() == steps.size() || !steps.get(results.size()).id().equals(state.get("pending")))
                    || !phase.equals("dispatch") && state.get("pending") != null) throw stop("STEP_STATE_REJECTED");
        }
        long remainingMillis() throws CapabilityClient.Failure { return number(state.get("deadline_ms")) - serverTimeMs - Math.max(0, System.nanoTime() - entered) / 1_000_000L; }
        static long count(Map<String, Object> values, String kind) { return values.values().stream().filter(kind::equals).count(); }
        void save() throws CapabilityClient.Failure {
            if (revision >= 63) throw stop("STEP_STATE_LIMIT");
            Map<String, Object> response = port.saveCheckpoint(NAMESPACE, options.key(), SCHEMA, PublicCapabilities.copy(state), revision, "steps-" + (revision + 1));
            if (number(object(response.get("checkpoint")).get("revision")) != revision + 1) throw stop("STEP_STATE_REJECTED"); revision++;
        }
        synchronized void admit(List<Call> calls) throws CapabilityClient.Failure {
            if (calls == null || calls.isEmpty() || calls.size() > 32) throw stop("STEP_CALL_REJECTED");
            Map<String, Object> next = PublicCapabilities.copy(reservations);
            for (Call call : calls) {
                if (call == null || !limits.containsKey(call.kind()) || !name(call.key())) throw stop("STEP_CALL_REJECTED");
                if (next.containsKey(call.key())) { if (!call.kind().equals(next.get(call.key()))) throw stop("STEP_CALL_REJECTED"); continue; }
                if (next.size() >= 32 || count(next, call.kind()) >= limits.get(call.kind())) throw stop("STEP_CALL_LIMIT_EXCEEDED"); next.put(call.key(), call.kind());
            }
            if (next.equals(reservations)) return;
            if (remainingMillis() <= 0) throw stop("STEP_DEADLINE_EXCEEDED");
            Map<String, Object> previous = reservations; state.put("reservations", next); reservations = next;
            try { save(); } catch (CapabilityClient.Failure error) { state.put("reservations", previous); reservations = previous; throw error; }
        }
        Set<String> covered() throws CapabilityClient.Failure {
            Set<String> slots = new LinkedHashSet<>(); for (Object result : results.values()) slots.addAll(strings(object(result).get("covered_slots"))); return slots;
        }
        Map<String, Object> output() throws CapabilityClient.Failure {
            Set<String> slots = covered(); List<String> missing = options.requiredSlots().stream().filter(slot -> !slots.contains(slot)).toList();
            Map<String, Object> value = new LinkedHashMap<>(); String phase = String.valueOf(state.get("phase"));
            value.put("status", Set.of("completed", "cancelled").contains(phase) ? phase : "incomplete"); value.put("version", state.get("version"));
            value.put("steps", steps); value.put("results", results); value.put("missing_slots", missing); value.put("covered_slots", options.requiredSlots().stream().filter(slots::contains).toList());
            value.put("deadline_ms", state.get("deadline_ms")); value.put("extensions", state.get("extensions"));
            Map<String, Long> calls = new LinkedHashMap<>(); limits.keySet().forEach(kind -> calls.put(kind, count(reservations, kind))); value.put("calls", calls);
            value.put("finish_reason", state.getOrDefault("finish_reason", phase)); return PublicCapabilities.copy(value);
        }
        void finish() throws CapabilityClient.Failure {
            boolean complete = covered().containsAll(options.requiredSlots());
            state.put("phase", complete ? "completed" : number(state.get("extensions")) < options.maxExtensions() ? "awaiting_extension" : "incomplete");
            state.put("finish_reason", complete ? "completed" : "required_slots_missing");
        }
        Map<String, Object> run() throws Exception {
            if (options.inspectOnly()) {
                if (!policyHash.equals(state.get("policy_hash"))) throw stop("STEP_POLICY_REJECTED");
                Map<String, Object> out = output(), inspection = new LinkedHashMap<>(); inspection.put("read_only", true); inspection.put("phase", state.get("phase"));
                inspection.put("pending_step", state.get("pending")); inspection.put("reconciliation_required", "dispatch".equals(state.get("phase"))); inspection.put("expired", remainingMillis() <= 0); out.put("inspection", inspection); return out;
            }
            if (revision == 0) save();
            if (options.prepareOnly()) { Map<String, Object> out = output(); out.put("admission", Map.of("phase", state.get("phase"), "remaining_seconds", Math.max(0, remainingMillis() / 1000.0))); return out; }
            if (options.additionalSteps() != null) {
                List<Step> appended = normalize(options.additionalSteps(), options.requiredSlots(), options.maxSteps() - initial.size(), initial);
                List<Step> combined = new ArrayList<>(initial); combined.addAll(appended);
                if (number(state.get("extensions")) > 0) { if (!PublicCapabilities.digest(combined).equals(PublicCapabilities.digest(steps))) throw stop("STEP_EXTENSION_REJECTED"); }
                else {
                    if (!"awaiting_extension".equals(state.get("phase")) || number(state.get("extensions")) >= options.maxExtensions()) throw stop("STEP_EXTENSION_REJECTED");
                    steps = combined; state.put("steps", combined); state.put("phase", "running"); state.put("extensions", 1); save();
                }
            }
            while (true) {
                String phase = String.valueOf(state.get("phase"));
                if (Set.of("completed", "cancelled", "incomplete", "awaiting_extension").contains(phase)) {
                    if (phase.equals("completed") && (results.size() != steps.size() || !covered().equals(new LinkedHashSet<>(options.requiredSlots())))) throw stop("STEP_STATE_REJECTED");
                    return output();
                }
                boolean recovering = phase.equals("dispatch");
                if (!recovering) {
                    if (!policyHash.equals(state.get("policy_hash"))) throw stop("STEP_POLICY_REJECTED");
                    if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
                    if (remainingMillis() <= 0) { state.put("phase", "incomplete"); state.put("finish_reason", "elapsed_limit"); save(); return output(); }
                }
                if (results.size() == steps.size()) { finish(); save(); continue; }
                Step step = steps.get(results.size());
                for (String dependency : step.dependsOn()) if (!"completed".equals(object(results.get(dependency)).get("status"))) {
                    state.put("phase", "incomplete"); state.put("pending", null); state.put("finish_reason", "dependency_incomplete"); save(); return output();
                }
                String operationKey = "step-" + PublicCapabilities.digest(List.of(options.key(), digest, step));
                if (!recovering) { port.validateCurrentExecution(); state.put("phase", "dispatch"); state.put("pending", step.id()); save(); }
                Runtime runtime = new Runtime(this, operationKey, recovering);
                Map<String, Object> result = recovering ? executor.recover(step, runtime, PublicCapabilities.copy(results)) : executor.execute(step, runtime, PublicCapabilities.copy(results));
                if (result == null || "unknown".equals(result.get("status"))) throw stop("STEP_RECONCILIATION_REQUIRED");
                result = PublicCapabilities.copy(result); validateResult(result, step); results.put(step.id(), result); state.put("phase", "running"); state.put("pending", null);
                if (results.size() == steps.size() && policyHash.equals(state.get("policy_hash"))) {
                    finish(); if (Thread.currentThread().isInterrupted()) { state.put("phase", "cancelled"); state.put("finish_reason", "cancelled"); }
                    else if (remainingMillis() <= 0) { state.put("phase", "incomplete"); state.put("finish_reason", "elapsed_limit"); }
                }
                save();
            }
        }
    }
}
