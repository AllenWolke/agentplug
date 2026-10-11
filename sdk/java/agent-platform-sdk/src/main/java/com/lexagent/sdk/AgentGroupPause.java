package com.lexagent.sdk;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** SDK-owned cooperative wait for already-admitted AgentGroup children. */
public final class AgentGroupPause extends Exception {
    private static final Pattern DIGEST = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern KEY = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}");
    private static final Set<String> CHECKPOINT_FIELDS = Set.of(
            "state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at");

    private final String groupKey;
    private final String operationKey;
    private final String inputFingerprint;
    private final Map<String, Object> checkpoint;
    private final List<String> childKeys;

    AgentGroupPause(String groupKey, String operationKey, String inputFingerprint,
            Map<String, Object> checkpoint, List<String> childKeys) {
        super("agent group is waiting for admitted child runs");
        if (groupKey == null || !KEY.matcher(groupKey).matches()
                || !HarnessRunner.skillIdentifier(operationKey)
                || inputFingerprint == null || !DIGEST.matcher(inputFingerprint).matches()
                || checkpoint == null || !checkpoint.keySet().equals(CHECKPOINT_FIELDS)
                || !(checkpoint.get("state_key") instanceof String stateKey) || !DIGEST.matcher(stateKey).matches()
                || !exactLong(checkpoint.get("revision"), 1, 64)
                || !AgentGroupRunner.STATE_SCHEMA.equals(checkpoint.get("schema_id"))
                || !(checkpoint.get("content_hash") instanceof String contentHash) || !DIGEST.matcher(contentHash).matches()
                || !exactLong(checkpoint.get("execution_revision"), 1, Lifecycle.MAX_GENERATION_REVISION)
                || !(checkpoint.get("expires_at") instanceof String expiresAt)
                || !validTimestamp(expiresAt)
                || childKeys == null || childKeys.isEmpty() || childKeys.size() > 16
                || childKeys.stream().anyMatch(key -> key == null || !DIGEST.matcher(key).matches())
                || childKeys.stream().distinct().count() != childKeys.size()) {
            throw new IllegalArgumentException("invalid AgentGroup pause reference");
        }
        this.groupKey = groupKey;
        this.operationKey = operationKey;
        this.inputFingerprint = inputFingerprint;
        this.checkpoint = Map.copyOf(checkpoint);
        this.childKeys = List.copyOf(childKeys);
    }

    public String groupKey() { return groupKey; }
    public String operationKey() { return operationKey; }
    public String inputFingerprint() { return inputFingerprint; }
    public Map<String, Object> checkpoint() { return checkpoint; }
    public List<String> childKeys() { return childKeys; }

    Map<String, Object> metadata() {
        return Map.of("reason", "agent_group_waiting", "group_key", groupKey,
                "operation_key", operationKey, "child_count", childKeys.size());
    }

    boolean matches(ExecutionContract.AgentGroupHandoff handoff) {
        return handoff != null && groupKey.equals(handoff.groupKey())
                && operationKey.equals(handoff.operationKey())
                && inputFingerprint.equals(handoff.inputFingerprint())
                && checkpoint.equals(handoff.checkpoint())
                && childKeys.equals(handoff.childKeys());
    }

    private static boolean exactLong(Object value, long minimum, long maximum) {
        if (!(value instanceof Number number)) return false;
        try {
            long result = new BigDecimal(number.toString()).longValueExact();
            return result >= minimum && result <= maximum;
        } catch (ArithmeticException | NumberFormatException ignored) {
            return false;
        }
    }

    private static boolean validTimestamp(String value) {
        try { Instant.parse(value); return true; }
        catch (RuntimeException invalid) { return false; }
    }
}

record AgentGroupResumeBinding(ExecutionContract.AgentGroupHandoff handoff, String inputHash) {}
