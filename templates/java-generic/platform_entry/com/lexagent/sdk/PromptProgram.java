package com.lexagent.sdk;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** Published stages remain data; the entire approved template remains system. */
public final class PromptProgram {
    private final Map<String, Object> value;
    private PromptProgram(Map<String, Object> value) { this.value = value; }
    public static PromptProgram parse(String template) throws CapabilityClient.Failure {
        if (template == null || template.isBlank()) throw PublicCapabilities.stop("PROMPT_PROGRAM_REJECTED");
        Map<String, Object> value;
        try {
            var node = PublicCapabilities.JSON.readTree(template);
            if (!node.isObject() || !"agentplug-prompt-program/v1".equals(node.path("version").asText())) return legacy();
            value = PublicCapabilities.JSON.convertValue(node, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
        } catch (Exception error) { return legacy(); }
        if (!value.keySet().equals(Set.of("version", "instructions", "default_stage", "execution_modes", "stages"))
                || !(value.get("instructions") instanceof String instructions) || instructions.isBlank()
                || !(value.get("execution_modes") instanceof List<?> modes) || modes.size() > 8 || new java.util.HashSet<>(modes).size() != modes.size()
                || modes.stream().anyMatch(mode -> !(mode instanceof String text) || !text.matches("[A-Za-z0-9_.:/-]{1,128}"))
                || !(value.get("stages") instanceof Map<?, ?> stages) || stages.isEmpty() || stages.size() > 8
                || !stages.containsKey(value.get("default_stage"))) throw PublicCapabilities.stop("PROMPT_PROGRAM_REJECTED");
        for (var entry : stages.entrySet()) if (!(entry.getKey() instanceof String name) || !name.matches("[A-Za-z0-9_.-]{1,64}")
                || !(entry.getValue() instanceof String body) || body.isBlank()) throw PublicCapabilities.stop("PROMPT_PROGRAM_REJECTED");
        return new PromptProgram(PublicCapabilities.copy(value));
    }
    private static PromptProgram legacy() { return new PromptProgram(Map.of("version", "legacy-prompt", "execution_modes", List.of(), "stages", Map.of())); }
    public Map<String, Object> value() throws CapabilityClient.Failure { return PublicCapabilities.copy(value); }
    public List<Map<String, Object>> stageMessages(String stage, Map<String, Object> payload) throws CapabilityClient.Failure {
        if (!"agentplug-prompt-program/v1".equals(value.get("version")) || stage == null || !(value.get("stages") instanceof Map<?, ?> stages)
                || !stages.containsKey(stage) || payload == null || payload.containsKey("stage")) throw PublicCapabilities.stop("PROMPT_STAGE_REJECTED");
        return List.of(Map.of("role", "user", "content", new String(PublicCapabilities.canonical(Map.of("stage", stage, "input", payload)), java.nio.charset.StandardCharsets.UTF_8)));
    }
}
