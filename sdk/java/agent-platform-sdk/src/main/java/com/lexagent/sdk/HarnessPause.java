package com.lexagent.sdk;

import java.util.Map;

/** Human approval pause. Arguments/tokens stay out of lifecycle events. */
public final class HarnessPause extends Exception {
    private final String key, toolName, callId;
    private HarnessPause(String key, String toolName, String callId) {
        super("harness requires governed human approval");
        this.key = key; this.toolName = toolName; this.callId = callId;
    }
    public static HarnessPause from(Map<String, Object> result, String key) throws CapabilityClient.Failure {
        if (result == null || !"approval_required".equals(result.get("status")) || key == null || !key.matches("[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
                || !(result.get("pending") instanceof Map<?, ?> pending) || !(pending.get("name") instanceof String name)
                || !(pending.get("call_id") instanceof String callId) || !HarnessRunner.skillIdentifier(name) || !HarnessRunner.skillIdentifier(callId))
            throw new CapabilityClient.Failure("HARNESS_INCOMPLETE", 409, false);
        return new HarnessPause(key, name, callId);
    }
    Map<String, Object> metadata() {
        return Map.of("reason", "approval_required", "harness_key", key, "tool_name", toolName, "call_id", callId);
    }
}
