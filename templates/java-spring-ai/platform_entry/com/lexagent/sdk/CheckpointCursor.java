package com.lexagent.sdk;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Set;

/** CAS progress is never proof that a model/tool effect completed. A pending
 * item must be reconciled by its original receipt-aware operation. */
public final class CheckpointCursor {
    public static final String NAMESPACE = "checkpoint-cursor";
    public static final String SCHEMA = "schema://agentplug/checkpoint-cursor/v1";
    private final CapabilityPort port;
    private final String key;
    private Map<String, Object> state;
    private long revision;
    private CheckpointCursor(CapabilityPort port, String key) { this.port = port; this.key = key; }
    @SuppressWarnings("unchecked")
    public static CheckpointCursor open(CapabilityPort port, String key, String inputHash, int total) throws CapabilityClient.Failure {
        if (port == null || key == null || !key.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}") || inputHash == null
                || !inputHash.matches("[a-f0-9]{64}") || total < 0 || total > 1000) throw PublicCapabilities.stop("CURSOR_CONFIG_INVALID");
        Map<String, Object> loaded = port.loadCheckpoint(NAMESPACE, key, SCHEMA, 0);
        long limit = CheckpointCapacity.replyLimit(loaded);
        if (2L * total + 1 > limit) throw PublicCapabilities.stop("CURSOR_CAPACITY_INSUFFICIENT");
        String empty = PublicCapabilities.sha(new byte[0]);
        CheckpointCursor cursor = new CheckpointCursor(port, key);
        if (loaded.get("checkpoint") == null) {
            Map<String, Object> state = new LinkedHashMap<>();
            state.put("version", "checkpoint-cursor/v1"); state.put("input_hash", inputHash); state.put("total", total);
            state.put("index", 0); state.put("phase", total == 0 ? "completed" : "ready"); state.put("result_digest", empty);
            if (port instanceof CapabilityClient client) client.authorizeRuntimeRecoveryStart(NAMESPACE, key, SCHEMA, inputHash);
            cursor.save(state); return cursor;
        }
        if (!(loaded.get("checkpoint") instanceof Map<?, ?> cp) || !(cp.get("value") instanceof Map<?, ?> raw)) throw PublicCapabilities.stop("CURSOR_STATE_REJECTED");
        Map<String, Object> state = (Map<String, Object>) raw;
        long revision = PublicCapabilities.integer(cp.get("revision"));
        long index = PublicCapabilities.integer(state.get("index"));
        String phase = state.get("phase") instanceof String text ? text : "";
        long expected = 2 * index + (phase.equals("pending") ? 2 : 1);
        if (revision < 1 || revision > limit || revision != expected || !state.keySet().equals(Set.of("version", "input_hash", "total", "index", "phase", "result_digest"))
                || !"checkpoint-cursor/v1".equals(state.get("version")) || !inputHash.equals(state.get("input_hash"))
                || PublicCapabilities.integer(state.get("total")) != total || index < 0 || index > total
                || !Set.of("ready", "pending", "completed").contains(phase) || phase.equals("completed") != (index == total)
                || !(state.get("result_digest") instanceof String digest) || !digest.matches("[a-f0-9]{64}")
                || index == 0 && !empty.equals(digest)) throw PublicCapabilities.stop("CURSOR_STATE_REJECTED");
        cursor.state = PublicCapabilities.copy(state); cursor.revision = revision; return cursor;
    }
    public int index() throws CapabilityClient.Failure { return (int) PublicCapabilities.integer(state.get("index")); }
    public boolean completed() { return "completed".equals(state.get("phase")); }
    /** true requires read-only reconciliation of the original operation. */
    public boolean begin() throws CapabilityClient.Failure {
        if (completed()) throw PublicCapabilities.stop("CURSOR_ALREADY_COMPLETED");
        if ("pending".equals(state.get("phase"))) { port.validateCurrentExecution(); return true; }
        Map<String, Object> next = PublicCapabilities.copy(state); next.put("phase", "pending"); save(next); return false;
    }
    public void confirm(String resultHash) throws CapabilityClient.Failure {
        if (!"pending".equals(state.get("phase")) || resultHash == null || !resultHash.matches("[a-f0-9]{64}")) throw PublicCapabilities.stop("CURSOR_CONFIRMATION_REJECTED");
        int index = index();
        String digest = PublicCapabilities.sha((state.get("result_digest") + ":" + index + ":" + resultHash).getBytes(StandardCharsets.UTF_8));
        Map<String, Object> next = PublicCapabilities.copy(state); next.put("index", index + 1); next.put("result_digest", digest);
        next.put("phase", index + 1 == PublicCapabilities.integer(state.get("total")) ? "completed" : "ready"); save(next);
    }
    @SuppressWarnings("unchecked")
    private void save(Map<String, Object> next) throws CapabilityClient.Failure {
        Map<String, Object> result = port.saveCheckpoint(NAMESPACE, key, SCHEMA, PublicCapabilities.copy(next), revision, "cursor-" + (revision + 1));
        if (!(result.get("checkpoint") instanceof Map<?, ?> cp) || PublicCapabilities.integer(cp.get("revision")) != revision + 1
                || !Objects.equals(PublicCapabilities.digest(cp.get("value")), PublicCapabilities.digest(next))) throw PublicCapabilities.stop("CURSOR_STATE_REJECTED");
        state = PublicCapabilities.copy(next); revision++;
    }
}
