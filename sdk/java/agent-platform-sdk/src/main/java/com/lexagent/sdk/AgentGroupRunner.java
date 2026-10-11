package com.lexagent.sdk;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Fixed-plan checkpointed delegation. Never polls or replaces an uncertain child. */
public final class AgentGroupRunner {
    public static final String STATE_SCHEMA = "schema://agentplug/agent-group/v1";
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final Pattern KEY = Pattern.compile("[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}");
    private static final Pattern HASH = Pattern.compile("[0-9a-f]{64}");
    private AgentGroupRunner() {}

    public record Options(String key, String operationKey, String taskType,
            String inputSchema, String outputSchema) {
        public Options(String key, String operationKey, String taskType) {
            this(key, operationKey, taskType, "", "");
        }
    }

    private static CapabilityClient.Failure stop(String code) {
        return new CapabilityClient.Failure(code, 409, false);
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(JsonNode value) {
        return JSON.convertValue(value, Map.class);
    }
    private static String digest(Object value) throws CapabilityClient.Failure {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(JSON.writeValueAsBytes(value))); }
        catch (Exception ignored) { throw stop("REQUEST_INVALID"); }
    }
    private static boolean hash(JsonNode value) { return value.isTextual() && HASH.matcher(value.textValue()).matches(); }
    private static boolean schemaIdentifier(String value) {
        return value != null && value.startsWith("schema://") && value.length() > "schema://".length()
                && value.getBytes(StandardCharsets.UTF_8).length <= 256
                && value.chars().noneMatch(ch -> "*\u0000\r\n\t ".indexOf(ch) >= 0);
    }

    static boolean validKey(String value) { return value != null && KEY.matcher(value).matches(); }

    /** Same sorted, compact platform JSON representation used by Go/Python. */
    public static String planInputHash(String operationKey, String taskType, List<Map<String, Object>> inputs)
            throws CapabilityClient.Failure {
        if (!HarnessRunner.skillIdentifier(operationKey) || !HarnessRunner.skillIdentifier(taskType)
                || inputs == null || inputs.isEmpty() || inputs.size() > 16) throw stop("REQUEST_INVALID");
        try {
            JsonNode frozen = JSON.valueToTree(inputs);
            if (!frozen.isArray()) throw stop("REQUEST_INVALID");
            for (JsonNode item : frozen) {
                if (!item.isObject() || item.has("policy_snapshot") || JSON.writeValueAsBytes(item).length > 65536)
                    throw stop("REQUEST_INVALID");
            }
            byte[] canonical = platformJson(List.of(operationKey, taskType, frozen)).getBytes(StandardCharsets.UTF_8);
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical));
        } catch (CapabilityClient.Failure failure) {
            throw failure;
        } catch (Exception ignored) {
            throw stop("REQUEST_INVALID");
        }
    }

    private static String platformJson(Object value) throws Exception {
        return JSON.writeValueAsString(value).replace("&", "\\u0026").replace("<", "\\u003c")
                .replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029");
    }

    /** One pass admits up to sixteen children, then returns one fresh group read.
     * Run outputs and tokens are never checkpointed. Every subsequent call reads
     * current authority; no saved completed output bypasses revocation.
     */
    public static Map<String, Object> run(CapabilityClient client, List<Map<String, Object>> inputs, Options options)
            throws CapabilityClient.Failure, AgentGroupPause {
        if (client == null || options == null || options.key() == null || !KEY.matcher(options.key()).matches()
                || !HarnessRunner.skillIdentifier(options.operationKey()) || !HarnessRunner.skillIdentifier(options.taskType())
                || options.inputSchema() == null || options.outputSchema() == null
                || options.inputSchema().isEmpty() != options.outputSchema().isEmpty()
                || !options.inputSchema().isEmpty() && (!schemaIdentifier(options.inputSchema()) || !schemaIdentifier(options.outputSchema()))
                || inputs == null || inputs.size() < 1 || inputs.size() > 16) throw stop("REQUEST_INVALID");
        ArrayNode frozen;
        try {
            frozen = (ArrayNode) JSON.readTree(JSON.writeValueAsBytes(inputs));
            for (JsonNode input : frozen) {
                if (!input.isObject() || input.has("policy_snapshot") || JSON.writeValueAsBytes(input).length > 65536) throw stop("REQUEST_INVALID");
            }
        } catch (CapabilityClient.Failure failure) { throw failure; }
        catch (Exception ignored) { throw stop("REQUEST_INVALID"); }
        String parentId = client.taskId();
        if (parentId == null || parentId.isEmpty()) throw stop("AGENT_GROUP_STATE_REJECTED");
        String inputHash = planInputHash(options.operationKey(), options.taskType(), inputs);
        String inputFingerprint = client.businessInputFingerprint();
        AgentGroupResumeBinding resumeBinding = client.authorizeAgentGroupInvocation(options.key(),
                options.operationKey(), inputHash);
        ObjectNode state = JSON.createObjectNode();
        state.put("version", "agent-group/v1"); state.put("parent_run_id", parentId); state.put("input_hash", inputHash);
        state.put("group_key", options.key()); state.put("operation_key", options.operationKey());
        state.put("input_fingerprint", inputFingerprint);
        state.put("phase", "route"); state.put("ordinal", 0); state.putArray("targets"); state.putArray("bindings"); state.putArray("child_keys");
        JsonNode loaded = JSON.valueToTree(client.loadCheckpoint("coordination", options.key(), STATE_SCHEMA, 0));
        long revision = 0;
        JsonNode checkpoint = loaded.get("checkpoint");
        if (checkpoint != null && !checkpoint.isNull()) {
            JsonNode rev = checkpoint.path("revision"), previous = checkpoint.path("value");
            if (!rev.isIntegralNumber() || !rev.canConvertToLong() || rev.longValue() < 1 || rev.longValue() > 63
                    || !previous.isObject() || !previous.path("version").asText().equals("agent-group/v1")
                    || !previous.path("parent_run_id").asText().equals(parentId) || !previous.path("input_hash").asText().equals(inputHash)
                    || !previous.path("group_key").asText().equals(options.key())
                    || !previous.path("operation_key").asText().equals(options.operationKey())
                    || !previous.path("input_fingerprint").asText().equals(inputFingerprint)) throw stop("AGENT_GROUP_STATE_REJECTED");
            if (resumeBinding != null && !validResumeCheckpoint(loaded, resumeBinding))
                throw stop("AGENT_GROUP_STATE_REJECTED");
            revision = rev.longValue(); state = ((ObjectNode) previous).deepCopy();
        } else if (resumeBinding != null) throw stop("AGENT_GROUP_STATE_REJECTED");
        String phase = state.path("phase").asText();
        JsonNode ordinalNode = state.path("ordinal"), targets = state.path("targets"), bindings = state.path("bindings"), childKeys = state.path("child_keys");
        if (!List.of("route", "prepare", "admitting", "gather").contains(phase) || !ordinalNode.isIntegralNumber() || !ordinalNode.canConvertToInt()
                || !targets.isArray() || !bindings.isArray() || !childKeys.isArray() || childKeys.size() != bindings.size()) throw stop("AGENT_GROUP_STATE_REJECTED");
        if (resumeBinding != null) {
            List<String> expectedKeys = resumeBinding.handoff().childKeys();
            if (!"gather".equals(phase) || childKeys.size() != expectedKeys.size()) throw stop("AGENT_GROUP_STATE_REJECTED");
            for (int index = 0; index < expectedKeys.size(); index++)
                if (!childKeys.get(index).isTextual() || !expectedKeys.get(index).equals(childKeys.get(index).asText()))
                    throw stop("AGENT_GROUP_STATE_REJECTED");
        }
        int ordinal = ordinalNode.intValue(), count = frozen.size();
        if (ordinal < 0 || ordinal > count || (phase.equals("route") && (ordinal != 0 || !targets.isEmpty() || !bindings.isEmpty()))
                || (!phase.equals("route") && targets.size() != count) || bindings.size() != ordinal + (phase.equals("admitting") ? 1 : 0)
                || bindings.size() > count || (phase.equals("gather") && ordinal != count)
                || (List.of("prepare", "admitting").contains(phase) && ordinal >= count)) throw stop("AGENT_GROUP_STATE_REJECTED");
        if (!options.inputSchema().isEmpty()) {
            for (JsonNode target : targets) if (!options.inputSchema().equals(target.path("input_schema").asText())
                    || !options.outputSchema().equals(target.path("output_schema").asText())) throw stop("AGENT_ROUTE_REJECTED");
        }
        for (int index = 0; index < bindings.size(); index++) {
            JsonNode binding = bindings.get(index), target = targets.get(index);
            if (!binding.isObject() || !target.isObject() || !hash(binding.path("child_key")) || !hash(binding.path("input_fingerprint"))
                    || !childKeys.get(index).isTextual() || !childKeys.get(index).asText().equals(binding.path("child_key").asText())
                    || !binding.path("output_schema").equals(target.path("output_schema"))) throw stop("AGENT_GROUP_STATE_REJECTED");
        }
        if (resumeBinding != null) client.markAgentGroupResumeCheckpointVerified(resumeBinding);
        client.authorizeAgentGroupCheckpointLoaded(options.key(), options.operationKey(), inputHash);
        if (revision == 0) revision = save(client, options.key(), state, revision);
        for (int step = 0; step < 36; step++) {
            phase = state.path("phase").asText(); ordinal = state.path("ordinal").intValue();
            switch (phase) {
                case "route" -> {
                    JsonNode result = JSON.valueToTree(client.routeAgents(options.operationKey(), options.taskType(), count));
                    ArrayNode selected = JSON.createArrayNode();
                    for (JsonNode target : result.path("route").path("targets")) {
                        if (!options.inputSchema().isEmpty()
                                && (!options.inputSchema().equals(target.path("input_schema").asText())
                                        || !options.outputSchema().equals(target.path("output_schema").asText())))
                            throw stop("AGENT_ROUTE_REJECTED");
                        ObjectNode item = JSON.createObjectNode(); item.set("input_schema", target.get("input_schema")); item.set("output_schema", target.get("output_schema")); selected.add(item);
                    }
                    state.set("targets", selected); state.put("phase", "prepare");
                    revision = save(client, options.key(), state, revision);
                }
                case "prepare" -> {
                    JsonNode result = JSON.valueToTree(client.prepareAgentChild(options.operationKey(), ordinal, state.path("targets").get(ordinal).path("input_schema").asText(), object(frozen.get(ordinal))));
                    JsonNode preparation = result.path("preparation");
                    ObjectNode binding = JSON.createObjectNode(); binding.set("child_key", preparation.get("child_key")); binding.set("input_fingerprint", preparation.get("input_fingerprint")); binding.set("output_schema", state.path("targets").get(ordinal).get("output_schema"));
                    ((ArrayNode) state.get("bindings")).add(binding);
                    ((ArrayNode) state.get("child_keys")).add(binding.path("child_key"));
                    state.put("phase", "admitting");
                    revision = save(client, options.key(), state, revision);
                    client.admitAgentChild(options.operationKey(), ordinal, binding.path("child_key").asText(), binding.path("input_fingerprint").asText());
                    state.put("ordinal", ordinal + 1); state.put("phase", ordinal + 1 == count ? "gather" : "prepare");
                    revision = save(client, options.key(), state, revision);
                }
                case "admitting" -> {
                    JsonNode binding = state.path("bindings").get(ordinal);
                    JsonNode snapshot = JSON.valueToTree(client.readAgentAdmissionState(options.operationKey(), ordinal, binding.path("child_key").asText(), binding.path("input_fingerprint").asText(), binding.path("output_schema").asText())).path("admission_state");
                    if (snapshot.path("status").asText().equals("preparing")) client.admitAgentChild(options.operationKey(), ordinal, binding.path("child_key").asText(), binding.path("input_fingerprint").asText());
                    state.put("ordinal", ordinal + 1); state.put("phase", ordinal + 1 == count ? "gather" : "prepare");
                    revision = save(client, options.key(), state, revision);
                }
                case "gather" -> {
                    List<CapabilityClient.AgentChildBinding> saved = new ArrayList<>();
                    for (JsonNode binding : state.path("bindings")) saved.add(new CapabilityClient.AgentChildBinding(binding.path("child_key").asText(), binding.path("output_schema").asText()));
                    Map<String, Object> gathered = client.gatherAgentChildren(options.operationKey(), saved);
                    JsonNode group = JSON.valueToTree(gathered.get("group"));
                    if (!group.path("terminal").asBoolean())
                        throw waiting(client, options, state, parentId, inputFingerprint, saved.size());
                    client.finishAgentGroupInvocation(options.key(), options.operationKey(), inputHash);
                    return gathered;
                }
                default -> throw stop("AGENT_GROUP_STATE_REJECTED");
            }
        }
        throw stop("AGENT_GROUP_STATE_LIMIT");
    }

    private static AgentGroupPause waiting(CapabilityClient client, Options options, ObjectNode state,
            String parentId, String inputFingerprint, int count) throws CapabilityClient.Failure {
        Map<String, Object> loaded = client.loadCheckpoint("coordination", options.key(), STATE_SCHEMA, 0);
        JsonNode response = JSON.valueToTree(loaded);
        JsonNode checkpoint = response.path("checkpoint");
        JsonNode stateKey = response.path("state_key");
        Set<String> checkpointFields = Set.of("revision", "schema_id", "value", "content_hash", "expires_at", "execution_revision");
        if (!response.isObject() || !fieldSet(response).equals(Set.of("checkpoint", "state_key")) || !stateKey.isTextual() || !hash(stateKey)
                || !checkpoint.isObject() || !fieldSet(checkpoint).equals(checkpointFields)
                || !checkpoint.path("revision").isIntegralNumber() || !checkpoint.path("revision").canConvertToLong()
                || checkpoint.path("revision").longValue() < 1 || checkpoint.path("revision").longValue() > 64
                || !checkpoint.path("schema_id").asText().equals(STATE_SCHEMA)
                || !hash(checkpoint.path("content_hash")) || !checkpoint.path("execution_revision").isIntegralNumber()
                || !checkpoint.path("execution_revision").canConvertToLong() || checkpoint.path("execution_revision").longValue() < 1
                || !checkpoint.path("expires_at").isTextual() || !sameJson(checkpoint.path("value"), state)
                || !state.path("parent_run_id").asText().equals(parentId)
                || !state.path("group_key").asText().equals(options.key())
                || !state.path("operation_key").asText().equals(options.operationKey())
                || !state.path("input_fingerprint").asText().equals(inputFingerprint)
                || !state.path("phase").asText().equals("gather")
                || state.path("ordinal").asInt(-1) != count
                || state.path("bindings").size() != count || state.path("child_keys").size() != count)
            throw stop("AGENT_GROUP_STATE_REJECTED");
        String expiresAt = checkpoint.path("expires_at").asText();
        try {
            if (!Instant.parse(expiresAt).isAfter(Instant.ofEpochSecond(client.nowEpochSeconds()))) throw stop("AGENT_GROUP_STATE_REJECTED");
        } catch (CapabilityClient.Failure failure) {
            throw failure;
        } catch (RuntimeException invalid) {
            throw stop("AGENT_GROUP_STATE_REJECTED");
        }
        List<String> childKeys = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            JsonNode binding = state.path("bindings").get(index), key = state.path("child_keys").get(index);
            if (binding == null || !hash(binding.path("child_key")) || !key.isTextual()
                    || !key.asText().equals(binding.path("child_key").asText())) throw stop("AGENT_GROUP_STATE_REJECTED");
            childKeys.add(key.asText());
        }
        Map<String, Object> reference = new LinkedHashMap<>();
        reference.put("state_key", stateKey.asText());
        reference.put("revision", checkpoint.path("revision").longValue());
        reference.put("schema_id", STATE_SCHEMA);
        reference.put("content_hash", checkpoint.path("content_hash").asText());
        reference.put("execution_revision", checkpoint.path("execution_revision").longValue());
        reference.put("expires_at", expiresAt);
        try {
            return new AgentGroupPause(options.key(), options.operationKey(), inputFingerprint, reference, childKeys);
        } catch (IllegalArgumentException invalid) {
            throw stop("AGENT_GROUP_STATE_REJECTED");
        }
    }

    private static Set<String> fieldSet(JsonNode object) {
        java.util.HashSet<String> fields = new java.util.HashSet<>();
        object.fieldNames().forEachRemaining(fields::add);
        return fields;
    }

    private static boolean sameJson(JsonNode left, JsonNode right) {
        if (left == null || right == null) return false;
        try {
            // Wire integers restore as BigIntegerNode while the live ordinal
            // uses IntNode. Compare through the same decoder, preserving exact
            // values, object fields and array order; no floating-point coercion.
            return JSON.readTree(JSON.writeValueAsBytes(left))
                    .equals(JSON.readTree(JSON.writeValueAsBytes(right)));
        } catch (java.io.IOException invalid) {
            return false;
        }
    }

    private static boolean validResumeCheckpoint(JsonNode response, AgentGroupResumeBinding binding) {
        JsonNode checkpoint = response.path("checkpoint");
        JsonNode reference = JSON.valueToTree(binding.handoff().checkpoint());
        Set<String> fields = Set.of("revision", "schema_id", "value", "content_hash", "expires_at", "execution_revision");
        if (!response.isObject() || !fieldSet(response).equals(Set.of("checkpoint", "state_key"))
                || !response.path("state_key").isTextual()
                || !response.path("state_key").asText().equals(reference.path("state_key").asText())
                || !checkpoint.isObject() || !fieldSet(checkpoint).equals(fields)
                || checkpoint.path("revision").asLong(-1) != reference.path("revision").asLong(-2)
                || !checkpoint.path("schema_id").asText().equals(reference.path("schema_id").asText())
                || !checkpoint.path("content_hash").asText().equals(reference.path("content_hash").asText())
                || checkpoint.path("execution_revision").asLong(-1) != reference.path("execution_revision").asLong(-2)
                || !checkpoint.path("expires_at").asText().equals(reference.path("expires_at").asText())) return false;
        JsonNode value = checkpoint.path("value");
        Set<String> stateFields = Set.of("version", "parent_run_id", "input_hash", "group_key", "operation_key",
                "input_fingerprint", "phase", "ordinal", "targets", "bindings", "child_keys");
        return value.isObject() && fieldSet(value).equals(stateFields)
                && "agent-group/v1".equals(value.path("version").asText())
                && binding.handoff().runId().equals(value.path("parent_run_id").asText())
                && binding.handoff().groupKey().equals(value.path("group_key").asText())
                && binding.handoff().operationKey().equals(value.path("operation_key").asText())
                && binding.handoff().inputFingerprint().equals(value.path("input_fingerprint").asText())
                && binding.inputHash().equals(value.path("input_hash").asText())
                && "gather".equals(value.path("phase").asText());
    }

    private static long save(CapabilityClient client, String key, ObjectNode state, long revision) throws CapabilityClient.Failure {
        if (revision >= 63) throw stop("AGENT_GROUP_STATE_LIMIT");
        JsonNode receipt = JSON.valueToTree(client.saveCheckpoint("coordination", key, STATE_SCHEMA, object(state), revision, "group-" + (revision + 1))).path("checkpoint").path("revision");
        if (!receipt.isIntegralNumber() || !receipt.canConvertToLong() || receipt.longValue() != revision + 1) throw stop("AGENT_GROUP_STATE_REJECTED");
        return revision + 1;
    }
}
