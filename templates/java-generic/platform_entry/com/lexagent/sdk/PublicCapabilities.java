package com.lexagent.sdk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Native helpers over the signed capability client. No provider credentials,
 * database connections or cached authorization decisions are introduced. */
public final class PublicCapabilities {
    static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);
    private final CapabilityPoster client;
    private final String binding;
    public PublicCapabilities(CapabilityPoster client, String binding) { this.client = client; this.binding = binding; }

    public record ChatOptions(double temperature, int maxTokens, String stepName,
            boolean requireJson, Map<String, Object> responseSchema, String responseSchemaMode) {
        public static ChatOptions defaults() { return new ChatOptions(0.3, 2048, "model.generate", false, null, ""); }
    }
    public record KnowledgeOptions(int topK, String asOf, String cacheMode, List<String> sourceIds,
            boolean recoveryOnly, List<Map<String, Object>> skillRequests, Map<String, Object> skillBindings) {
        public static KnowledgeOptions defaults() { return new KnowledgeOptions(3, "", "use", null, false, null, null); }
        public KnowledgeOptions recovery() { return new KnowledgeOptions(topK, asOf, cacheMode, sourceIds, true, skillRequests, skillBindings); }
    }
    static CapabilityClient.Failure stop(String code) { return new CapabilityClient.Failure(code, 409, false); }
    static byte[] canonical(Object value) throws CapabilityClient.Failure {
        try { return JSON.writeValueAsBytes(value); }
        catch (Exception error) { throw stop("REQUEST_INVALID"); }
    }
    static String sha(byte[] value) throws CapabilityClient.Failure {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (Exception error) { throw stop("REQUEST_INVALID"); }
    }
    static String digest(Object value) throws CapabilityClient.Failure { return sha(canonical(value)); }
    static Map<String, Object> copy(Map<String, Object> value) throws CapabilityClient.Failure {
        try { return JSON.readValue(canonical(value), new TypeReference<Map<String, Object>>() {}); }
        catch (Exception error) { throw stop("REQUEST_INVALID"); }
    }
    static long integer(Object value) throws CapabilityClient.Failure {
        try {
            if (value instanceof Boolean || !(value instanceof Number)) throw stop("STATE_CAPACITY_INVALID");
            return new java.math.BigDecimal(value.toString()).longValueExact();
        } catch (ArithmeticException | NumberFormatException error) { throw stop("STATE_CAPACITY_INVALID"); }
    }
    String operationKey(String prefix, Map<String, Object> identity) throws CapabilityClient.Failure {
        if (binding == null || binding.isEmpty()) throw stop("CONTEXT_INVALID");
        return prefix + sha((binding + ":" + new String(canonical(identity), StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
    }
    static String schemaMode(Map<String, Object> schema, String mode, boolean requireJson) throws CapabilityClient.Failure {
        mode = mode == null ? "" : mode;
        if (schema == null) { if (!mode.isEmpty()) throw stop("REQUEST_INVALID"); return ""; }
        if (!requireJson || !"object".equals(schema.get("type")) || canonical(schema).length > 16384) throw stop("REQUEST_INVALID");
        if (mode.isEmpty()) mode = "required";
        if (!Set.of("required", "prefer_supported").contains(mode)) throw stop("REQUEST_INVALID");
        return mode;
    }

    public Map<String, Object> chat(List<Map<String, Object>> messages, ChatOptions options) throws CapabilityClient.Failure {
        if (messages == null || messages.isEmpty() || options == null || !Double.isFinite(options.temperature()) || options.maxTokens() < 1) throw stop("REQUEST_INVALID");
        String mode = schemaMode(options.responseSchema(), options.responseSchemaMode(), options.requireJson());
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("messages", messages); input.put("temperature", options.temperature()); input.put("max_tokens", options.maxTokens());
        input.put("usage_step", options.stepName() == null || options.stepName().isEmpty() ? "model.generate" : options.stepName());
        if (options.requireJson()) input.put("require_json", true);
        if (options.responseSchema() != null) { input.put("response_schema", options.responseSchema()); input.put("response_schema_mode", mode); }
        input.put("idempotency_key", operationKey("model-", input));
        Map<String, Object> result = client.post("/internal/model/generate", input);
        if (!(result.get("text") instanceof String)) throw stop("MODEL_RESPONSE_INVALID");
        return result;
    }
    public Map<String, Object> embed(List<String> texts, String stepName) throws CapabilityClient.Failure {
        if (texts == null || texts.isEmpty()) throw stop("REQUEST_INVALID");
        return client.post("/internal/model/embed", Map.of("texts", texts, "usage_step", stepName == null || stepName.isEmpty() ? "knowledge.embedding" : stepName));
    }
    public Map<String, Object> resolvePrompt() throws CapabilityClient.Failure { return client.post("/internal/prompt/resolve", Map.of()); }
    public Map<String, Object> memoryLoad(String namespace, String key) throws CapabilityClient.Failure {
        return client.post("/internal/memory/access", Map.of("operation", "load", "namespace", namespace, "key", key));
    }
    public Map<String, Object> memorySave(String namespace, String key, Map<String, Object> value) throws CapabilityClient.Failure {
        if (value == null) throw stop("REQUEST_INVALID");
        return client.post("/internal/memory/access", Map.of("operation", "save", "namespace", namespace, "key", key, "value", value));
    }
    static Map<String, Object> knowledgeIdentity(String query, String scope, KnowledgeOptions options) throws CapabilityClient.Failure {
        if (query == null || query.isBlank() || query.getBytes(StandardCharsets.UTF_8).length > 8192 || scope == null || scope.isEmpty() || scope.length() > 128
                || options == null || options.topK() < 1 || options.topK() > 20 || options.asOf() == null || options.cacheMode() == null
                || !Set.of("", "use", "cold", "bypass").contains(options.cacheMode())) throw stop("REQUEST_INVALID");
        if (!options.asOf().isEmpty()) { try { LocalDate.parse(options.asOf()); } catch (Exception error) { throw stop("REQUEST_INVALID"); } }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("query", query); result.put("knowledge_scope", scope); result.put("top_k", options.topK()); result.put("as_of", options.asOf());
        if (!options.cacheMode().isEmpty()) result.put("cache_mode", options.cacheMode());
        if (options.sourceIds() != null) {
            Set<String> seen = new LinkedHashSet<>();
            if (options.sourceIds().isEmpty() || options.sourceIds().size() > 16) throw stop("REQUEST_INVALID");
            for (String id : options.sourceIds()) if (id == null || id.isBlank() || !id.equals(id.strip()) || id.length() > 128 || !seen.add(id)) throw stop("REQUEST_INVALID");
            result.put("source_ids", List.copyOf(options.sourceIds()));
        }
        return result;
    }
    public Map<String, Object> searchKnowledge(String query, String scope, KnowledgeOptions options) throws CapabilityClient.Failure {
        Map<String, Object> input = knowledgeIdentity(query, scope, options);
        input.put("idempotency_key", operationKey("knowledge-", input));
        return client.post("/internal/knowledge/search" + (options.recoveryOnly() ? "/recovery" : ""), input);
    }
    public Map<String, Object> answerKnowledge(String query, String scope, KnowledgeOptions options) throws CapabilityClient.Failure {
        Map<String, Object> input = knowledgeIdentity(query, scope, options);
        if (options.asOf().isEmpty()) input.remove("as_of");
        if (options.cacheMode().isEmpty()) input.put("cache_mode", "use");
        if (options.skillRequests() != null || options.skillBindings() != null) {
            if (options.skillRequests() == null || options.skillBindings() == null || options.skillRequests().isEmpty()
                    || options.skillRequests().size() > 4 || options.skillBindings().size() != options.skillRequests().size()) throw stop("HARNESS_SKILL_REJECTED");
            input.put("skill_requests", options.skillRequests()); input.put("skill_bindings", options.skillBindings());
        }
        input.put("idempotency_key", operationKey("knowledge-answer-", input));
        return client.post("/internal/knowledge/answer" + (options.recoveryOnly() ? "/recovery" : ""), input);
    }
    public Map<String, Object> replayKnowledge(String requestId) throws CapabilityClient.Failure {
        return client.post("/internal/knowledge/replay", Map.of("request_id", requestId));
    }
    public void authorizeReferences(List<Map<String, Object>> references, String scope) throws CapabilityClient.Failure {
        if (references == null) throw stop("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED");
        Map<String, Map<String, Object>> unique = new LinkedHashMap<>();
        for (Map<String, Object> reference : references) {
            Map<String, Object> identity = new LinkedHashMap<>();
            for (String field : List.of("source", "provider_knowledge_base_id", "provider_document_id", "document_version")) {
                if (reference == null || !(reference.get(field) instanceof String value) || value.isEmpty()) throw stop("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED");
                identity.put(field, reference.get(field));
            }
            unique.putIfAbsent(digest(identity), identity);
        }
        var identities = new ArrayList<>(unique.values());
        for (int offset = 0; offset < identities.size(); offset += 128) {
            var page = identities.subList(offset, Math.min(offset + 128, identities.size()));
            Map<String, Object> result = client.post("/internal/knowledge/references/authorize", Map.of(
                    "version", "knowledge-reference-authorization/v1", "knowledge_scope", scope, "references", page));
            if (!"knowledge-reference-authorization/v1".equals(result.get("version")) || !Boolean.TRUE.equals(result.get("authorized"))
                    || integer(result.get("reference_count")) != page.size() || integer(result.get("model_requests_sent")) != 0) throw stop("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED");
        }
    }
    public void authorizeCachedResult(Map<String, Object> result, String scope) throws CapabilityClient.Failure {
        List<Map<String, Object>> references = new ArrayList<>(); collectReferences(copy(result), references);
        authorizeReferences(references, scope);
    }
    @SuppressWarnings("unchecked")
    private static void collectReferences(Object value, List<Map<String, Object>> output) throws CapabilityClient.Failure {
        if (value instanceof Map<?, ?> raw) {
            Map<String, Object> map = (Map<String, Object>) raw;
            if (map.containsKey("doc_id") && map.containsKey("content")) {
                output.add(map);
                if (map.containsKey("parent_context")) {
                    if (!(map.get("parent_context") instanceof Map<?, ?> parent) || !"authorized-parent-context/v1".equals(parent.get("schema_version"))
                            || !(parent.get("source_documents") instanceof List<?> siblings) || siblings.isEmpty() || siblings.size() > 1000) throw stop("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED");
                    boolean found = false;
                    for (Object item : siblings) {
                        if (!(item instanceof Map<?, ?>)) throw stop("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED");
                        Map<String, Object> reference = (Map<String, Object>) item;
                        boolean same = true;
                        for (String field : List.of("source", "provider_knowledge_base_id", "provider_document_id", "document_version")) same &= java.util.Objects.equals(reference.get(field), map.get(field));
                        found |= same; output.add(reference);
                    }
                    if (!found) throw stop("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED");
                }
                return;
            }
            if(map.containsKey("references")){if(!(map.get("references") instanceof List<?> refs)||refs.size()>4096)throw stop("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED");for(Object item:refs){if(!(item instanceof Map<?,?>))throw stop("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED");output.add((Map<String,Object>)item);}}
            for (var entry : map.entrySet()) if (!Set.of("context", "prompt_program", "messages").contains(entry.getKey())) collectReferences(entry.getValue(), output);
        } else if (value instanceof List<?> list) for (Object item : list) collectReferences(item, output);
    }
    public Map<String, Object> loadExecutionPolicy() throws CapabilityClient.Failure {
        Map<String, Object> result = client.post("/internal/runtime/harness-policy", Map.of("include_batch", true));
        ExecutionPolicy.validate(result);
        return result;
    }
    public static Map<String, Object> modelResultMetadata(Map<String, Object> result) {
        Map<String, Object> value = new LinkedHashMap<>();
        for (String key : List.of("routing", "route_execution", "context_cache", "response_schema", "model_version_id", "provider_id", "model_id", "step_id", "billing"))
            if (result.containsKey(key)) value.put(key, result.get(key));
        return value;
    }
}
