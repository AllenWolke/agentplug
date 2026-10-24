package com.lexagent.sdk;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Persistent public loop. Uncertain dispatch requires governed reconciliation. */
public final class HarnessRunner {
    public static final String STATE_SCHEMA = "schema://agentplug/harness-loop/v1";
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private HarnessRunner() {}

    @FunctionalInterface public interface ActionValidator { boolean allow(Map<String,Object> operation,Map<String,Object> view) throws CapabilityClient.Failure; }
    @FunctionalInterface public interface ProgressEvaluator { Map<String,Object> evaluate(Map<String,Object> observation,Map<String,Object> view) throws CapabilityClient.Failure; }
    public record Options(String key, int maxRounds, int maxToolCalls, String confirmationToken,
            String extensionId, Long deadlineMs, ActionValidator actionValidator, ProgressEvaluator progressEvaluator) {
        public Options(String key,int rounds,int tools,String token){this(key,rounds,tools,token,"",null,null,null);}
        boolean extended(){return (extensionId!=null&&!extensionId.isEmpty())||deadlineMs!=null||actionValidator!=null||progressEvaluator!=null;}
        String namespace(){return extended()?"harness-v2":"harness";}
        String schema(){return extended()?"schema://agentplug/harness-loop/v2":STATE_SCHEMA;}

        public Options(String key, int maxRounds, int maxToolCalls) { this(key, maxRounds, maxToolCalls, ""); }
        @Override public String toString() { return "HarnessRunner.Options[redacted]"; }
    }
    @FunctionalInterface interface Port {
        Map<String, Object> post(String path, Map<String, Object> input) throws CapabilityClient.Failure;
        default Map<String, Object> postWithin(String path, Map<String, Object> input, Duration timeout) throws CapabilityClient.Failure {
            return post(path, input);
        }
        default Map<String, Object> readHarnessPolicy() throws CapabilityClient.Failure {
            return postWithin("/internal/runtime/harness-policy", Map.of(), Duration.ofSeconds(5));
        }
        default long monotonicNanos() { return System.nanoTime(); }
    }

    private record PublishedPolicy(String hash, long serverTimeMs, int maxRounds, int maxToolCalls,
            int maxRepeatedCalls, int maxElapsedSeconds, String limitBehavior, ObjectNode limits) {}

    private static final class LoopClock {
        private final PublishedPolicy policy;
        private final long deadlineMs;
        private final long startedNanos;
        private LoopClock(PublishedPolicy policy, long deadlineMs, long startedNanos) {
            this.policy = policy; this.deadlineMs = deadlineMs; this.startedNanos = startedNanos;
        }
        long remainingNanos(Port port) {
            long elapsedNanos = Math.max(0, port.monotonicNanos() - startedNanos);
            long serviceRemainingMs = deadlineMs - policy.serverTimeMs();
            if (serviceRemainingMs <= 0) return 0;
            long serviceRemainingNanos = serviceRemainingMs > Long.MAX_VALUE / 1_000_000L
                    ? Long.MAX_VALUE : serviceRemainingMs * 1_000_000L;
            return Math.max(0, serviceRemainingNanos - elapsedNanos);
        }
        boolean expired(Port port) { return remainingNanos(port) <= 0; }
        Duration timeout(Port port) {
            long remaining = remainingNanos(port);
            long maximum = Duration.ofSeconds(310).toNanos();
            return Duration.ofNanos(Math.max(1L, Math.min(remaining, maximum)));
        }
    }

    private static PublishedPolicy loadPolicy(Port port) throws CapabilityClient.Failure {
        Map<String, Object> response = port.readHarnessPolicy();
        JsonNode value = JSON.valueToTree(response);
        if (!value.isObject() || !fieldNames(value).equals(Set.of("version", "policy_hash", "server_time_ms", "limits"))
                || !value.path("version").asText().equals("harness-policy/v1")
                || !value.path("policy_hash").asText().matches("[0-9a-f]{64}")
                || !exactLong(value.path("server_time_ms")) || value.path("server_time_ms").longValue() <= 0
                || value.path("server_time_ms").longValue() > 9_007_199_254_740_991L) {
            throw stop("HARNESS_POLICY_REJECTED");
        }
        JsonNode limits = value.path("limits");
        if (!limits.isObject() || !fieldNames(limits).equals(Set.of("max_rounds", "max_tool_calls", "max_repeated_calls", "max_elapsed_seconds", "limit_behavior"))
                || !boundedInt(limits.path("max_rounds"), 1, 8)
                || !boundedInt(limits.path("max_tool_calls"), 1, 16)
                || !boundedInt(limits.path("max_repeated_calls"), 1, 4)
                || !boundedInt(limits.path("max_elapsed_seconds"), 10, 3600)
                || !Set.of("error", "incomplete").contains(limits.path("limit_behavior").asText())) {
            throw stop("HARNESS_POLICY_REJECTED");
        }
        return new PublishedPolicy(value.path("policy_hash").asText(), value.path("server_time_ms").longValue(),
                limits.path("max_rounds").intValue(), limits.path("max_tool_calls").intValue(),
                limits.path("max_repeated_calls").intValue(), limits.path("max_elapsed_seconds").intValue(),
                limits.path("limit_behavior").asText(), (ObjectNode) limits.deepCopy());
    }

    private static boolean exactLong(JsonNode value) { return value.isIntegralNumber() && value.canConvertToLong(); }
    private static boolean boundedInt(JsonNode value, int minimum, int maximum) {
        return exactLong(value) && value.longValue() >= minimum && value.longValue() <= maximum;
    }

    private static LoopClock newClockWithStart(Port port, PublishedPolicy policy, long startedNanos) throws CapabilityClient.Failure {
        long deadline;
        try { deadline = Math.addExact(policy.serverTimeMs(), Math.multiplyExact((long) policy.maxElapsedSeconds(), 1000L)); }
        catch (ArithmeticException ignored) { throw stop("HARNESS_POLICY_REJECTED"); }
        if (deadline > 9_007_199_254_740_991L) throw stop("HARNESS_POLICY_REJECTED");
        return new LoopClock(policy, deadline, startedNanos);
    }

    private static LoopClock restoredClock(Port port, PublishedPolicy policy, JsonNode state, long startedNanos) throws CapabilityClient.Failure {
        JsonNode deadline = state.path("loop_deadline_ms");
        if (!exactLong(deadline) || deadline.longValue() <= 0 || deadline.longValue() > 9_007_199_254_740_991L) throw stop("HARNESS_STATE_REJECTED");
        return new LoopClock(policy, deadline.longValue(), startedNanos);
    }

    private static boolean hasAnyPolicyState(JsonNode state) {
        return List.of("loop_policy_hash", "loop_limits", "loop_deadline_ms", "tool_repeats", "repeat_counted_call_id")
                .stream().anyMatch(state::has);
    }

    private static boolean hasCompletePolicyState(JsonNode state) {
        return state.path("loop_policy_hash").isTextual() && state.path("loop_limits").isObject()
                && exactLong(state.path("loop_deadline_ms")) && state.path("tool_repeats").isObject()
                && state.path("repeat_counted_call_id").isTextual();
    }

    private static boolean matchesPolicy(JsonNode state, PublishedPolicy policy) {
        return state.path("loop_policy_hash").asText().equals(policy.hash())
                && state.path("loop_limits").equals(policy.limits());
    }

    private static void bindPolicy(ObjectNode state, PublishedPolicy policy, long deadlineMs, ObjectNode repeats) {
        state.put("loop_policy_hash", policy.hash()); state.set("loop_limits", policy.limits().deepCopy());
        state.put("loop_deadline_ms", deadlineMs); state.set("tool_repeats", repeats.deepCopy());
        state.put("repeat_counted_call_id", "");
    }

    private static void validatePolicyState(JsonNode state, PublishedPolicy policy) throws CapabilityClient.Failure {
        JsonNode repeats = state.path("tool_repeats");
        if (!matchesPolicy(state, policy) || !repeats.isObject() || repeats.size() > policy.maxToolCalls()) throw stop("HARNESS_POLICY_CHANGED");
        var fields = repeats.fields();
        while (fields.hasNext()) {
            var entry = fields.next();
            if (!entry.getKey().matches("[0-9a-f]{64}") || !boundedInt(entry.getValue(), 1, policy.maxRepeatedCalls())) throw stop("HARNESS_STATE_REJECTED");
        }
        String counted = state.path("repeat_counted_call_id").asText();
        if (counted.length() > 128) throw stop("HARNESS_STATE_REJECTED");
        if (!counted.isEmpty()) {
            JsonNode pending = state.path("pending");
            if (!pending.isArray() || pending.isEmpty() || !pending.get(0).path("call_id").asText().equals(counted)
                    || !Set.of("tool_dispatch", "approval_required").contains(state.path("phase").asText())) throw stop("HARNESS_STATE_REJECTED");
        }
        if (Set.of("tool_dispatch", "approval_required").contains(state.path("phase").asText())
                && state.path("pending").isArray() && !state.path("pending").isEmpty() && counted.isEmpty()) throw stop("HARNESS_STATE_REJECTED");
    }

    static String repeatedToolDigest(String name, JsonNode payload) throws CapabilityClient.Failure {
        try {
            String canonical = "[" + canonicalString(name) + "," + canonicalValue(payload) + "]";
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ignored) { throw stop("HARNESS_STATE_REJECTED"); }
    }

    private static String canonicalValue(JsonNode value) throws CapabilityClient.Failure {
        if (value.isObject()) {
            StringBuilder result = new StringBuilder("{");
            var names = new java.util.TreeSet<String>(); value.fieldNames().forEachRemaining(names::add);
            boolean first = true;
            for (String name : names) {
                if (!first) result.append(','); first = false;
                result.append(canonicalString(name)).append(':').append(canonicalValue(value.get(name)));
            }
            return result.append('}').toString();
        }
        if (value.isArray()) {
            StringBuilder result = new StringBuilder("[");
            for (int index = 0; index < value.size(); index++) {
                if (index > 0) result.append(',');
                result.append(canonicalValue(value.get(index)));
            }
            return result.append(']').toString();
        }
        if (value.isTextual()) return canonicalString(value.asText());
        if (value.isNumber()) return value.asText();
        if (value.isBoolean() || value.isNull()) return value.toString();
        throw stop("HARNESS_STATE_REJECTED");
    }

    private static String canonicalString(String value) {
        StringBuilder result = new StringBuilder(value.length() + 2).append('"');
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            switch (current) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\b' -> result.append("\\b");
                case '\f' -> result.append("\\f");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                case '<' -> result.append("\\u003c");
                case '>' -> result.append("\\u003e");
                case '&' -> result.append("\\u0026");
                case '\u2028' -> result.append("\\u2028");
                case '\u2029' -> result.append("\\u2029");
                default -> {
                    if (current < 0x20 || (Character.isSurrogate(current)
                            && !(Character.isHighSurrogate(current) && index + 1 < value.length() && Character.isLowSurrogate(value.charAt(index + 1))))) {
                        result.append(String.format("\\u%04x", (int) current));
                    } else {
                        result.append(current);
                        if (Character.isHighSurrogate(current)) result.append(value.charAt(++index));
                    }
                }
            }
        }
        return result.append('"').toString();
    }
    private static CapabilityClient.Failure stop(String code) { return new CapabilityClient.Failure(code, 409, false); }

    private static boolean budgetExhausted(JsonNode result) throws CapabilityClient.Failure {
        if (!result.has("run_budget")) return false;
        JsonNode budget = result.path("run_budget");
        if (!budget.isObject() || !budget.path("version").asText().equals("run-tree-budget/v1")
                || !budget.path("exhausted").isBoolean() || !budget.path("exceeded").isBoolean()
                || !budget.path("root_run_id").isTextual() || budget.path("root_run_id").asText().isBlank()) throw stop("HARNESS_BUDGET_REJECTED");
        return budget.path("exhausted").asBoolean() || budget.path("exceeded").asBoolean();
    }

    private static ObjectNode budgetOutput(JsonNode previous, String reason) {
        ObjectNode output = JSON.createObjectNode();
        output.put("completion_status", "incomplete"); output.put("finish_reason", reason);
        for (String field : List.of("text", "model", "usage", "billing", "run_budget", "prompt_template_hash", "routing", "route_execution", "context_cache", "response_schema", "model_version_id", "provider_id", "model_id", "step_id"))
            if (previous.has(field)) output.set(field, previous.get(field).deepCopy());
        if (reason.equals("budget_exhausted")) output.put("termination_reason", "MODEL_BUDGET_EXCEEDED");
        return output;
    }
    private static ObjectNode limitOutput(JsonNode previous, String reason) {
        ObjectNode output = JSON.createObjectNode();
        output.put("completion_status", "incomplete"); output.put("termination_reason", "HARNESS_LIMIT_EXCEEDED");
        output.put("finish_reason", reason);
        for (String field : List.of("text", "model", "usage", "billing", "run_budget", "prompt_template_hash", "routing", "route_execution", "context_cache", "response_schema", "model_version_id", "provider_id", "model_id", "step_id"))
            if (previous != null && previous.has(field)) output.set(field, previous.get(field).deepCopy());
        return output;
    }

    private static void finishForLimit(Port port, Options options, ObjectNode state, long revision,
            JsonNode previous, String reason, PublishedPolicy policy, LoopClock clock) throws CapabilityClient.Failure {
        state.remove("model_request"); state.remove("pending"); state.put("phase", "done"); state.put("repeat_counted_call_id", "");
        state.set("output", limitOutput(previous, reason));
        boolean throwError = policy.limitBehavior().equals("error");
        state.put("limit_error", throwError);
        save(port, options, revision, state, clock, true);
        if (throwError) throw stop("HARNESS_LIMIT_EXCEEDED");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(JsonNode value) { return JSON.convertValue(value, Map.class); }
    private static String digest(Object value) throws CapabilityClient.Failure {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(JSON.writeValueAsBytes(value))); }
        catch (Exception ignored) { throw stop("REQUEST_INVALID"); }
    }

    /** Stable fingerprint for a planned first Harness checkpoint. */
    public static String inputFingerprint(Map<String, Object> input, Options options) throws CapabilityClient.Failure {
        if (input == null || options == null) throw stop("HARNESS_CONFIG_INVALID");
        return options.extended()?digest(java.util.Arrays.asList(input,options.maxRounds(),options.maxToolCalls(),options.extensionId(),options.actionValidator()!=null,options.progressEvaluator()!=null,options.deadlineMs())):digest(List.of(input, options.maxRounds(), options.maxToolCalls()));
    }
    private static String stepKey(String key, int round, String phase) throws CapabilityClient.Failure {
        return "function-" + digest(List.of(key, round, phase));
    }

    static boolean skillIdentifier(String value) {
        if (value == null || value.isEmpty() || value.getBytes(StandardCharsets.UTF_8).length > 128
                || !StandardCharsets.UTF_8.newEncoder().canEncode(value)
                || value.indexOf('*') >= 0 || value.indexOf(0) >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) return false;
        String edges = " \t\n\r\u000B\f\u0085\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u2028\u2029\u202F\u205F\u3000";
        return edges.indexOf(value.charAt(0)) < 0 && edges.indexOf(value.charAt(value.length() - 1)) < 0;
    }
    private static ArrayNode skillRequests(JsonNode original) throws CapabilityClient.Failure {
        JsonNode values = original.path("skill_requests");
        if (values.isMissingNode()) return JSON.createArrayNode();
        if (!values.isArray() || values.size() > 4) throw stop("HARNESS_SKILL_REJECTED");
        Set<String> seen = new HashSet<>();
        for (JsonNode request : values) {
            if (!request.isObject() || !request.path("skill_id").isTextual() || !skillIdentifier(request.path("skill_id").asText())
                    || !seen.add(request.path("skill_id").asText())) throw stop("HARNESS_SKILL_REJECTED");
            var fields = request.fieldNames(); while (fields.hasNext()) if (!Set.of("skill_id", "sections").contains(fields.next())) throw stop("HARNESS_SKILL_REJECTED");
            JsonNode sections = request.path("sections");
            if (!sections.isMissingNode()) {
                if (!sections.isArray() || sections.size() > 4) throw stop("HARNESS_SKILL_REJECTED");
                Set<String> names = new HashSet<>();
                for (JsonNode section : sections) if (!section.isTextual() || !skillIdentifier(section.asText()) || !names.add(section.asText())) throw stop("HARNESS_SKILL_REJECTED");
            }
        }
        return (ArrayNode) values;
    }
    private static JsonNode skillDisclosure(Port port, String skill, String section, LoopClock clock) throws CapabilityClient.Failure {
        if (clock.expired(port)) throw stop("HARNESS_ELAPSED_LIMIT_LOCAL");
        JsonNode value = JSON.valueToTree(port.postWithin("/internal/skill/load", Map.of("skill_id", skill, "section", section), clock.timeout(port))).path("skill");
        if (!value.isObject() || !value.path("version").asText().equals("skill-disclosure/v1") || !value.path("skill_id").asText().equals(skill)
                || !value.path("instruction_trust").asText().equals("untrusted_data") || !value.path("version_id").isTextual()
                || !skillIdentifier(value.path("version_id").asText())
                || !value.path("digest").asText().matches("[0-9a-f]{64}")) throw stop("HARNESS_SKILL_REJECTED");
        if (!section.isEmpty() && (!value.path("section").asText().equals(section) || !value.path("content").isTextual()
                || value.path("content").asText().isEmpty() || value.path("content").asText().getBytes(StandardCharsets.UTF_8).length > 16384)) throw stop("HARNESS_SKILL_REJECTED");
        return value;
    }
    private static void resolveSkills(Port port, ArrayNode requests, ObjectNode state, boolean initial, LoopClock clock) throws CapabilityClient.Failure {
        JsonNode prior = state.path("skill_bindings");
        if (!initial && (!prior.isObject() || prior.size() != requests.size())) throw stop("HARNESS_SKILL_REJECTED");
        ObjectNode bindings = JSON.createObjectNode(); ArrayNode disclosures = JSON.createArrayNode();
        for (JsonNode request : requests) {
            String id = request.path("skill_id").asText(); JsonNode summary = skillDisclosure(port, id, "", clock);
            ObjectNode binding = JSON.createObjectNode(); binding.set("version_id", summary.get("version_id")); binding.set("digest", summary.get("digest"));
            if (!initial && !binding.equals(prior.path(id))) throw stop("HARNESS_SKILL_VERSION_CHANGED");
            bindings.set(id, binding);
            if (initial) {
                disclosures.add(summary);
                for (JsonNode section : request.path("sections")) {
                    JsonNode content = skillDisclosure(port, id, section.asText(), clock);
                    if (!content.path("version_id").equals(summary.path("version_id")) || !content.path("digest").equals(summary.path("digest"))) throw stop("HARNESS_SKILL_VERSION_CHANGED");
                    disclosures.add(content);
                }
            }
        }
        if (initial) {
            ObjectNode content = JSON.createObjectNode(); content.put("type", "skill_instructions"); content.put("instruction_trust", "untrusted_data"); content.set("skills", disclosures);
            try {
                byte[] encoded = JSON.writeValueAsBytes(content); if (encoded.length > 16384) throw stop("HARNESS_SKILL_CONTEXT_LIMIT");
                ObjectNode message = JSON.createObjectNode(); message.put("role", "user"); message.put("content", new String(encoded, StandardCharsets.UTF_8));
                state.set("skill_bindings", bindings); ((ArrayNode) state.path("messages")).add(message);
            } catch (CapabilityClient.Failure error) {throw error;}
            catch (Exception ignored) {throw stop("HARNESS_SKILL_REJECTED");}
        }
    }
    private static long save(Port port, Options options, long revision, ObjectNode state, LoopClock clock, boolean force) throws CapabilityClient.Failure {
        if (revision >= 63) throw stop("HARNESS_STATE_LIMIT");
        Duration timeout = clock.timeout(port);
        if (force && clock.expired(port)) timeout = Duration.ofSeconds(5);
        JsonNode receipt = JSON.valueToTree(port.postWithin("/internal/state/checkpoint", Map.of(
                "operation", "save", "namespace", options.namespace(), "key", options.key(), "schema_id", options.schema(),
                "idempotency_key", "loop-" + (revision + 1), "expected_revision", revision, "value", object(state)), timeout));
        JsonNode next = receipt.path("checkpoint").path("revision");
        if (!next.isIntegralNumber() || next.asLong() != revision + 1) throw stop("HARNESS_STATE_REJECTED");
        return revision + 1;
    }
    static Map<String, Object> run(Port port, String runId, Map<String, Object> input, Options options) throws CapabilityClient.Failure {
        return run(port, runId, input, options, false, null);
    }

    static Map<String, Object> run(Port port, String runId, Map<String, Object> input, Options options,
            boolean resumeRequest, RecoveryPlan.RuntimeRecoveryBinding recoveryBinding) throws CapabilityClient.Failure {
        if (options == null || options.key() == null || options.key().isBlank() || options.maxRounds() < 1 || options.maxRounds() > 8
                || options.maxToolCalls() < 1 || options.maxToolCalls() > 16 || options.confirmationToken() == null
                || options.confirmationToken().getBytes(StandardCharsets.UTF_8).length > 8192) throw stop("HARNESS_CONFIG_INVALID");
        if(options.extended()&&(options.extensionId()==null||!options.extensionId().matches("[A-Za-z0-9_.:/-]{1,128}")||options.deadlineMs()!=null&&(options.deadlineMs()<1||options.deadlineMs()>9_007_199_254_740_991L)))throw stop("HARNESS_CONFIG_INVALID");
        JsonNode original = JSON.valueToTree(input);
        if (!original.isObject() || !original.path("messages").isArray() || original.path("messages").isEmpty()
                || !original.path("idempotency_key").isTextual() || original.path("idempotency_key").asText().isBlank()) throw stop("REQUEST_INVALID");
        String key = original.path("idempotency_key").asText();
        ArrayNode skills = skillRequests(original);
        String inputHash = inputFingerprint(input, options);
        long policyClockStarted = port.monotonicNanos();
        PublishedPolicy policy = loadPolicy(port);
        ObjectNode state = JSON.createObjectNode();
        state.put("version", options.extended()?"harness-loop/v2":"harness-loop/v1"); state.put("input_hash", inputHash); state.put("phase", "model");
        state.put("round", 0); state.put("tool_count", 0); state.set("messages", original.path("messages").deepCopy()); state.putArray("pending");
        if(options.extended()){state.put("extension_id",options.extensionId());state.putArray("model_receipts");state.putArray("observations");}
        long revision = 0;
        JsonNode loaded = JSON.valueToTree(port.postWithin("/internal/state/checkpoint", Map.of(
                "operation", "load", "namespace", options.namespace(), "key", options.key(), "schema_id", options.schema(), "revision", 0), Duration.ofSeconds(5)));
        if (!loaded.isObject() || !(fieldNames(loaded).equals(Set.of("state_key", "checkpoint"))||fieldNames(loaded).equals(Set.of("state_key","checkpoint","checkpoint_history")))
                || !loaded.path("state_key").isTextual() || !loaded.path("state_key").asText().matches("[a-f0-9]{64}"))
            throw stop("HARNESS_STATE_REJECTED");
        JsonNode checkpoint = loaded.path("checkpoint");
        if ((checkpoint.isMissingNode() || checkpoint.isNull()) && resumeRequest
                && (recoveryBinding == null || !recoveryBinding.consumeStart(options.namespace(), options.key(), options.schema(),
                        inputHash, loaded.path("state_key").asText()))) throw stop("HARNESS_STATE_REJECTED");
        boolean restored = !checkpoint.isMissingNode() && !checkpoint.isNull();
        if (!checkpoint.isMissingNode() && !checkpoint.isNull()) {
            if (!checkpoint.path("revision").isIntegralNumber() || !checkpoint.path("revision").canConvertToLong()
                    || checkpoint.path("revision").asLong() < 1 || !checkpoint.path("value").isObject()
                    || !checkpoint.path("value").path("version").asText().equals(options.extended()?"harness-loop/v2":"harness-loop/v1")
                    || !checkpoint.path("value").path("input_hash").asText().equals(inputHash)) throw stop("HARNESS_STATE_REJECTED");
            revision = checkpoint.path("revision").asLong(); state = (ObjectNode) checkpoint.path("value").deepCopy();
        }
        if(options.extended()&&(!options.extensionId().equals(state.path("extension_id").asText())||!state.path("observations").isArray()||state.path("observations").size()>16||!state.path("model_receipts").isArray()||state.path("model_receipts").size()>8))throw stop("HARNESS_STATE_REJECTED");
        String phase = state.path("phase").asText();
        boolean dispatching = phase.equals("model_dispatch") || phase.equals("tool_dispatch");
        boolean legacyPolicyState = restored && !hasAnyPolicyState(state);
        if (restored && hasAnyPolicyState(state) && !hasCompletePolicyState(state)) throw stop("HARNESS_STATE_REJECTED");
        if (restored && hasCompletePolicyState(state) && !matchesPolicy(state, policy) && !dispatching) throw stop("HARNESS_POLICY_CHANGED");
        LoopClock clock;
        if (restored && hasCompletePolicyState(state)) {
            clock = restoredClock(port, policy, state, policyClockStarted);
            if (matchesPolicy(state, policy)) validatePolicyState(state, policy);
        } else {
            clock = newClockWithStart(port, policy, policyClockStarted);
            if(options.deadlineMs()!=null)clock=new LoopClock(policy,Math.min(clock.deadlineMs,options.deadlineMs()),policyClockStarted);
            if (!restored) bindPolicy(state, policy, clock.deadlineMs, JSON.createObjectNode());
        }
        if(options.deadlineMs()!=null&&clock.deadlineMs>options.deadlineMs())throw stop("HARNESS_STATE_REJECTED");
        boolean promptHashProvided = original.has("prompt_template_hash");
        JsonNode requestedPromptHash = original.get("prompt_template_hash");
        if (!state.path("round").isIntegralNumber() || !state.path("round").canConvertToInt() || state.path("round").asInt() < 0 || state.path("round").asInt() > 8
                || !state.path("tool_count").isIntegralNumber() || !state.path("tool_count").canConvertToInt()
                || state.path("tool_count").asInt() < 0 || state.path("tool_count").asInt() > 16
                || !state.path("pending").isArray() || state.path("pending").size() + state.path("tool_count").asInt() > 32
                || !state.path("messages").isArray() || state.path("messages").isEmpty()) throw stop("HARNESS_STATE_REJECTED");
        if (legacyPolicyState && state.path("tool_count").intValue() > 0 && !dispatching) throw stop("HARNESS_STATE_REJECTED");
        ObjectNode legacyRepeats = JSON.createObjectNode();
        if (promptHashProvided && (!requestedPromptHash.isTextual() || requestedPromptHash.asText().isEmpty()
                || (revision > 0 && state.has("prompt_hash") && (!state.path("prompt_hash").isTextual()
                || !state.path("prompt_hash").asText().equals(requestedPromptHash.asText()))))) throw stop("HARNESS_CONTEXT_REJECTED");
        String token = options.confirmationToken();
        if (restored && legacyPolicyState && !dispatching) {
            bindPolicy(state, policy, clock.deadlineMs, legacyRepeats);
            revision = save(port, options, revision, state, clock, false);
            legacyPolicyState = false;
        }
        int effectiveRounds = Math.min(options.maxRounds(), policy.maxRounds());
        int effectiveToolCalls = Math.min(options.maxToolCalls(), policy.maxToolCalls());
        while (true) {
            if (Thread.currentThread().isInterrupted()) throw stop("CANCELLED");
            int round = state.path("round").asInt();
            phase = state.path("phase").asText();
            if (phase.equals("done")) {
                if (hasCompletePolicyState(state) && !matchesPolicy(state, policy)) throw stop("HARNESS_POLICY_CHANGED");
                if (state.path("limit_error").asBoolean(false)) throw stop("HARNESS_LIMIT_EXCEEDED");
                Map<String,Object> finalResult=new LinkedHashMap<>();finalResult.put("status",state.path("output").path("completion_status").asText().equals("incomplete")?"incomplete":"completed");finalResult.put("output",object(state.path("output")));
                if(options.extended())finalResult.put("execution",Map.of("version","harness-execution/v2","extension_id",options.extensionId(),"deadline_ms",clock.deadlineMs,"decision_count",state.path("model_receipts").size(),"tool_count",state.path("tool_count").asInt(),"model_receipts",JSON.convertValue(state.path("model_receipts"),List.class),"observations",JSON.convertValue(state.path("observations"),List.class)));
                return finalResult;
            }
            boolean recoveringModel = phase.equals("model_dispatch");
            boolean recoveringTool = phase.equals("tool_dispatch");
            if (!recoveringModel && !recoveringTool && !skills.isEmpty()) {
                boolean initialDisclosure = revision == 0 && state.path("skill_bindings").size() == 0;
                try { resolveSkills(port, skills, state, initialDisclosure, clock); }
                catch (CapabilityClient.Failure failure) {
                    if (!failure.code().equals("HARNESS_ELAPSED_LIMIT_LOCAL")) throw failure;
                    finishForLimit(port, options, state, revision, state.path("output"), "elapsed_limit", policy, clock);
                    revision++; continue;
                }
            }
            if (!recoveringModel && !recoveringTool && clock.expired(port)) {
                finishForLimit(port, options, state, revision, state.path("output"), "elapsed_limit", policy, clock);
                revision++;
                continue;
            }
            if (phase.equals("model") || recoveringModel) {
                boolean recovering = recoveringModel;
                if (revision >= 62) throw stop("HARNESS_STATE_LIMIT");
                if (!recovering && round >= effectiveRounds) {
                    finishForLimit(port, options, state, revision, state.path("output"), "round_limit", policy, clock);
                    revision++; continue;
                }
                if (!recovering) {
                    Map<String, Object> prepare = new LinkedHashMap<>(); prepare.put("messages", JSON.convertValue(state.path("messages"), Object.class));
                    prepare.put("function_names", input.getOrDefault("function_names", List.of()));
                    JsonNode context = JSON.valueToTree(port.postWithin("/internal/context/prepare", prepare, clock.timeout(port)));
                    if (!context.path("messages").isArray() || context.path("messages").isEmpty()
                            || context.path("prompt_template_hash").asText().isBlank() || context.path("source_hash").asText().isBlank()
                            || (promptHashProvided && !requestedPromptHash.asText().equals(context.path("prompt_template_hash").asText()))
                            || (!state.path("prompt_hash").asText().isBlank() && !state.path("prompt_hash").asText().equals(context.path("prompt_template_hash").asText()))) throw stop("HARNESS_CONTEXT_REJECTED");
                    if (clock.expired(port)) {
                        finishForLimit(port, options, state, revision, state.path("output"), "elapsed_limit", policy, clock);
                        revision++; continue;
                    }
                    state.put("prompt_hash", context.path("prompt_template_hash").asText()); state.put("context_source_hash", context.path("source_hash").asText());
                    Map<String, Object> current = object(original); current.put("messages", JSON.convertValue(context.path("messages"), Object.class)); current.put("idempotency_key", stepKey(key, round, "model"));
                    current.remove("skill_requests"); current.remove("skill_bindings");
                    if (state.path("skill_bindings").size() > 0) current.put("skill_bindings", JSON.convertValue(state.path("skill_bindings"), Object.class));
                    current.put("prompt_template_hash", context.path("prompt_template_hash").asText());
                    current.remove("deadline_ms");if(options.extended())current.put("deadline_ms",clock.deadlineMs);
                    state.set("model_request", JSON.valueToTree(current)); state.put("phase", "model_dispatch"); revision = save(port, options, revision, state, clock, false);
                }
                JsonNode request = state.path("model_request");
                if (!request.isObject() || !request.path("idempotency_key").asText().equals(stepKey(key, round, "model"))
                        || state.path("prompt_hash").asText().isBlank() || !request.path("prompt_template_hash").asText().equals(state.path("prompt_hash").asText())) throw stop("HARNESS_STATE_REJECTED");
                JsonNode result;
                try { result = JSON.valueToTree(recovering
                        ? port.postWithin("/internal/model/receipt", object(request), Duration.ofSeconds(5))
                        : port.postWithin("/internal/model/generate", object(request), clock.timeout(port))); }
                catch (CapabilityClient.Failure error) {
                    if (!error.code().equals("MODEL_BUDGET_EXCEEDED")) throw error;
                    if (recovering && legacyPolicyState && state.path("tool_count").asInt() > 0) throw stop("HARNESS_RECONCILIATION_REQUIRED");
                    if (legacyPolicyState && recovering) { bindPolicy(state, policy, clock.deadlineMs, legacyRepeats); legacyPolicyState = false; }
                    state.remove("model_request"); state.remove("pending"); state.put("phase", "done"); state.put("repeat_counted_call_id", "");
                    state.set("output", budgetOutput(state.path("output"), "budget_exhausted"));
                    revision = save(port, options, revision, state, clock, true); continue;
                }
                if (recovering) {
                    if (!result.path("version").asText().equals("model-receipt/v1") || !result.path("idempotency_key").asText().equals(request.path("idempotency_key").asText())) throw stop("MODEL_RECEIPT_REJECTED");
                    if (!result.path("status").asText().equals("completed")) throw stop("HARNESS_RECONCILIATION_REQUIRED");
                    result = result.path("receipt"); if (!result.isObject()) throw stop("MODEL_RECEIPT_REJECTED");
                }
                state.remove("model_request");
                if (legacyPolicyState && recovering && state.path("tool_count").asInt() > 0) {
                    state.put("phase", "model"); state.set("output", result);
                    save(port, options, revision, state, clock, true);
                    throw stop("HARNESS_STATE_REJECTED");
                }
                if (legacyPolicyState && recovering) { bindPolicy(state, policy, clock.deadlineMs, legacyRepeats); legacyPolicyState = false; }
                if (restored && hasCompletePolicyState(state) && !matchesPolicy(state, policy)) {
                    state.put("phase", "done"); state.remove("pending"); state.put("repeat_counted_call_id", "");
                    state.set("output", budgetOutput(result, "tools_pending")); save(port, options, revision, state, clock, true);
                    throw stop("HARNESS_POLICY_CHANGED");
                }
                if (clock.expired(port)) {
                    finishForLimit(port, options, state, revision, result, "elapsed_limit", policy, clock);
                    revision++; continue;
                }
                if(options.extended()){ObjectNode entry=JSON.createObjectNode();entry.put("idempotency_key",request.path("idempotency_key").asText());entry.set("receipt",result.deepCopy());((ArrayNode)state.path("model_receipts")).add(entry);}
                JsonNode calls = result.path("tool_calls");
                if (budgetExhausted(result) && calls.isArray() && !calls.isEmpty()) {
                    state.put("phase", "done"); state.remove("pending"); state.put("repeat_counted_call_id", ""); state.set("output", budgetOutput(result, "budget_exhausted"));
                    revision = save(port, options, revision, state, clock, true); continue;
                }
                if (calls.isMissingNode() || calls.isNull() || (calls.isArray() && calls.isEmpty()) || result.path("completion_status").asText().equals("incomplete")) {
                    if (result.path("completion_status").asText().equals("tool_calls")) throw stop("FUNCTION_RESPONSE_INVALID");
                    state.put("phase", "done"); state.set("output", result); revision = save(port, options, revision, state, clock, true); continue;
                }
                if (!calls.isArray()) throw stop("FUNCTION_RESPONSE_INVALID");
                if (clock.expired(port)) {
                    finishForLimit(port, options, state, revision, result, "elapsed_limit", policy, clock);
                    revision++; continue;
                }
                if (round >= effectiveRounds - 1) {
                    finishForLimit(port, options, state, revision, result, "round_limit", policy, clock);
                    revision++; continue;
                }
                if (calls.size() + state.path("tool_count").asInt() > effectiveToolCalls) {
                    finishForLimit(port, options, state, revision, result, "tool_limit", policy, clock);
                    revision++; continue;
                }
                JsonNode bindings = result.path("function_bindings"); Set<String> seen = new HashSet<>(); ArrayNode pending = JSON.createArrayNode();
                for (JsonNode call : calls) {
                    JsonNode function = call.path("function"); String name = bindings.path(function.path("name").asText()).asText(); String id = call.path("id").asText();
                    JsonNode arguments;
                    try { arguments = JSON.readTree(function.path("arguments").asText()); }
                    catch (Exception ignored) { throw stop("FUNCTION_RESPONSE_INVALID"); }
                    if (name.isBlank() || name.getBytes(StandardCharsets.UTF_8).length > 128 || id.isBlank() || id.getBytes(StandardCharsets.UTF_8).length > 128
                            || !seen.add(id) || arguments == null || !arguments.isObject()) throw stop("FUNCTION_RESPONSE_INVALID");
                    ObjectNode operation = JSON.createObjectNode(); operation.put("name", name); operation.put("call_id", stepKey(key, round, id)); operation.put("model_call_id", id); operation.set("payload", arguments); pending.add(operation);
                }
                ObjectNode assistant = JSON.createObjectNode(); assistant.put("role", "assistant"); assistant.put("content", result.path("text").asText()); assistant.set("tool_calls", calls);
                if(options.actionValidator()!=null)for(JsonNode candidate:pending)if(!options.actionValidator().allow(object(candidate.deepCopy()),extensionView(state))){state.put("phase","done");state.putArray("pending");state.set("output",budgetOutput(result,"action_rejected"));save(port,options,revision,state,clock,true);throw stop("HARNESS_ACTION_REJECTED");}
                ((ArrayNode) state.path("messages")).add(assistant); state.set("pending", pending); state.put("phase", "tool");
                state.set("output", budgetOutput(result, "tools_pending")); revision = save(port, options, revision, state, clock, true);
                if (restored && hasCompletePolicyState(state) && !matchesPolicy(state, policy)) throw stop("HARNESS_POLICY_CHANGED");
            } else if (phase.equals("tool") || phase.equals("approval_required") || recoveringTool) {
                boolean recovering = recoveringTool;
                if (revision >= 62) throw stop("HARNESS_STATE_LIMIT");
                ArrayNode pending = (ArrayNode) state.path("pending"); if (pending.isEmpty()) throw stop("HARNESS_STATE_REJECTED");
                JsonNode operation = pending.get(0); Map<String, Object> view = object(operation); view.put("run_id", runId);
                if(!recovering&&options.actionValidator()!=null&&!options.actionValidator().allow(object(operation.deepCopy()),extensionView(state)))throw stop("HARNESS_ACTION_REJECTED");
                if (phase.equals("approval_required") && token.isEmpty()) return Map.of("status", "approval_required", "pending", view);
                if (!recovering) {
                    if (state.path("tool_count").asInt() >= effectiveToolCalls) {
                        finishForLimit(port, options, state, revision, state.path("output"), "tool_limit", policy, clock);
                        revision++; continue;
                    }
                    String callID = operation.path("call_id").asText();
                    String counted = state.path("repeat_counted_call_id").asText();
                    if (!counted.equals(callID)) {
                        String digest = repeatedToolDigest(operation.path("name").asText(), operation.path("payload"));
                        int repeated = state.path("tool_repeats").path(digest).asInt(0);
                        if (repeated >= policy.maxRepeatedCalls()) {
                            finishForLimit(port, options, state, revision, state.path("output"), "repeated_tool_limit", policy, clock);
                            revision++; continue;
                        }
                        ((ObjectNode) state.path("tool_repeats")).put(digest, repeated + 1);
                        state.put("repeat_counted_call_id", callID);
                    }
                    state.put("phase", "tool_dispatch"); revision = save(port, options, revision, state, clock, false);
                }
                Map<String, Object> command = new LinkedHashMap<>(); command.put("name", operation.path("name").asText()); command.put("call_id", operation.path("call_id").asText()); command.put("payload", object(operation.path("payload")));
                if (!token.isEmpty()) command.put("confirmation_token", token); token = "";
                JsonNode receipt;
                try { receipt = JSON.valueToTree(recovering
                        ? port.postWithin("/internal/tool/receipt", command, Duration.ofSeconds(5))
                        : port.postWithin("/internal/tool/invoke", command, clock.timeout(port))); }
                catch (CapabilityClient.Failure error) {
                    if (error.code().equals("MODEL_BUDGET_EXCEEDED")) {
                        if (recovering) throw stop("HARNESS_RECONCILIATION_REQUIRED");
                        state.put("phase", "done"); state.remove("pending"); state.put("repeat_counted_call_id", ""); state.set("output", budgetOutput(state.path("output"), "budget_exhausted"));
                        revision = save(port, options, revision, state, clock, true); continue;
                    }
                    if (!error.code().equals("TOOL_CONFIRMATION_REQUIRED")) throw error;
                    if (!recovering) { state.put("phase", "approval_required"); revision = save(port, options, revision, state, clock, true); }
                    return Map.of("status", "approval_required", "pending", view);
                }
                if (recovering) {
                    if (!receipt.path("version").asText().equals("tool-receipt/v1") || !receipt.path("tool_name").asText().equals(operation.path("name").asText())
                            || !receipt.path("call_id").asText().equals(operation.path("call_id").asText())) throw stop("TOOL_RECEIPT_REJECTED");
                    if (!receipt.path("status").asText().equals("completed")) throw stop("HARNESS_RECONCILIATION_REQUIRED");
                    receipt = receipt.path("receipt"); if (!receipt.isObject()) throw stop("TOOL_RECEIPT_REJECTED");
                }
                JsonNode observation = receipt.path("observation");
                try {
                    if (!observation.isObject() || !observation.path("version").asText().equals("runtime-observation/v1")
                            || !observation.path("tool_name").asText().equals(operation.path("name").asText()) || !observation.path("call_id").asText().equals(operation.path("call_id").asText())
                            || !Set.of("succeeded", "failed", "timeout", "cancelled").contains(observation.path("status").asText()) || !observation.path("effect").asText().equals("completed")
                            || !observation.path("instruction_trust").asText().equals("untrusted_data") || !observation.has("context_output")
                            || JSON.writeValueAsBytes(observation.path("context_output")).length > 2048) throw stop("TOOL_OBSERVATION_REJECTED");
                    ObjectNode bounded = JSON.createObjectNode();
                    for (String field : List.of("version", "tool_name", "status", "error_type", "effect", "instruction_trust", "context_output", "context_truncated")) if (observation.has(field)) bounded.set(field, observation.get(field));
                    bounded.put("output_truncated", observation.path("truncated").asBoolean());
                    if(options.extended()){ObjectNode entry=JSON.createObjectNode();entry.set("operation",operation.deepCopy());entry.set("observation",bounded.deepCopy());((ArrayNode)state.path("observations")).add(entry);}
                    ObjectNode message = JSON.createObjectNode(); message.put("role", "tool"); message.put("tool_call_id", operation.path("model_call_id").asText()); message.put("content", JSON.writeValueAsString(bounded)); ((ArrayNode) state.path("messages")).add(message);
                } catch (CapabilityClient.Failure error) { throw error; }
                catch (Exception ignored) { throw stop("TOOL_OBSERVATION_REJECTED"); }
                int previousToolCount = state.path("tool_count").asInt();
                pending.remove(0); state.put("tool_count", previousToolCount + 1); state.put("phase", "tool");
                String counted = state.path("repeat_counted_call_id").asText();
                if (recovering && legacyPolicyState && previousToolCount > 0) {
                    if (pending.isEmpty()) { state.put("round", round + 1); state.put("phase", "model"); }
                    state.putArray("pending").addAll(pending);
                    save(port, options, revision, state, clock, true);
                    throw stop("HARNESS_STATE_REJECTED");
                }
                if (counted.equals(operation.path("call_id").asText())) state.put("repeat_counted_call_id", "");
                else if (recovering && legacyPolicyState) {
                    bindPolicy(state, policy, clock.deadlineMs, legacyRepeats);
                    legacyPolicyState = false;
                    String digest = repeatedToolDigest(operation.path("name").asText(), operation.path("payload"));
                    ObjectNode repeats = (ObjectNode) state.path("tool_repeats");
                    repeats.put(digest, repeats.path(digest).asInt(0) + 1);
                } else if (recovering) throw stop("HARNESS_STATE_REJECTED");
                if (pending.isEmpty()) { state.put("round", round + 1); state.put("phase", "model"); }
                if(options.progressEvaluator()!=null){Map<String,Object> outcome=options.progressEvaluator().evaluate(object(observation.deepCopy()),extensionView(state));if(outcome!=null){if(!Set.of("completed","incomplete").contains(String.valueOf(outcome.get("completion_status"))))throw stop("HARNESS_PROGRESS_REJECTED");state.put("phase","done");state.putArray("pending");state.set("output",JSON.valueToTree(outcome));}}
                revision = save(port, options, revision, state, clock, true);
                if (restored && hasCompletePolicyState(state) && !matchesPolicy(state, policy)) throw stop("HARNESS_POLICY_CHANGED");
                if (clock.expired(port)) {
                    finishForLimit(port, options, state, revision, state.path("output"), "elapsed_limit", policy, clock);
                    revision++; continue;
                }
            } else throw stop("HARNESS_STATE_REJECTED");
        }
    }

    private static Map<String,Object> extensionView(ObjectNode state){return Map.of("round",state.path("round").asInt(),"tool_count",state.path("tool_count").asInt(),"observations",JSON.convertValue(state.path("observations").deepCopy(),List.class));}
    private static Set<String> fieldNames(JsonNode node) {
        Set<String> names = new HashSet<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
