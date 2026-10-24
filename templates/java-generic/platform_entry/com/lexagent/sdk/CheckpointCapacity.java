package com.lexagent.sdk;

import java.util.LinkedHashMap;
import java.util.Map;

/** Only capacity metadata is remembered; every operation still checks IAM. */
public final class CheckpointCapacity {
    public static final long MAXIMUM_REVISIONS = 4096;
    private final Map<String, Long> limits = new LinkedHashMap<>();
    public static long replyLimit(Map<String, Object> result) throws CapabilityClient.Failure {
        if (result == null) throw PublicCapabilities.stop("STATE_CAPACITY_INVALID");
        if (!result.containsKey("checkpoint_history")) return 64;
        if (!(result.get("checkpoint_history") instanceof Map<?, ?> history) || history.size() != 2
                || !"checkpoint-history/v1".equals(history.get("version"))) throw PublicCapabilities.stop("STATE_CAPACITY_INVALID");
        long limit = PublicCapabilities.integer(history.get("max_revisions"));
        if (limit < 1 || limit > MAXIMUM_REVISIONS) throw PublicCapabilities.stop("STATE_CAPACITY_INVALID");
        return limit;
    }
    synchronized long limit(String scope) { return limits.getOrDefault(scope, 64L); }
    synchronized Map<String, Object> remember(String scope, Map<String, Object> result) throws CapabilityClient.Failure {
        long limit = replyLimit(result);
        if (!result.containsKey("checkpoint_history")) limits.remove(scope);
        else {
            limits.remove(scope); limits.put(scope, limit);
            while (limits.size() > 32) limits.remove(limits.keySet().iterator().next());
        }
        return result;
    }
}
