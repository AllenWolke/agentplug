package com.lexagent.sdk;

import com.lexagent.sdk.ExecutionContract.AppError;
import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.ExecutionContract.ExecutionEvent;
import com.lexagent.sdk.Lifecycle.GenerationRunStore;
import com.lexagent.sdk.Lifecycle.HandoffRunStore;
import com.lexagent.sdk.Lifecycle.IdempotencyConflictException;
import com.lexagent.sdk.Lifecycle.InvalidTransitionException;
import com.lexagent.sdk.Lifecycle.RunRecord;
import com.lexagent.sdk.Lifecycle.RecoveryGenerationRunStore;
import com.lexagent.sdk.Lifecycle.RunSignals;
import com.lexagent.sdk.Lifecycle.RunUnknownException;
import com.lexagent.sdk.Lifecycle.StartResult;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Development-only in-memory RunStore. NOT FOR L2/L3 — state dies with the
 * process and there is no cross-replica recovery; production deployments must
 * inject a durable scoped store.
 * 仅限开发环境的内存 RunStore：不可用于 L2/L3 —— 状态随进程消失且无跨副本恢复；
 * 生产必须注入持久化存储。
 */
public final class MemoryRunStore implements HandoffRunStore, RecoveryGenerationRunStore {
    /** The bundled memory store must be labelled in the manifest so operators
     * can reject it before L2/L3 deployment. / 内置存储必须在 manifest 标注，
     * 运维可在 L2/L3 前拒绝。
     */
    public static final String LABEL = Lifecycle.MEMORY_RUN_STORE_LABEL;

    private static final class MemoryRun {
        final ExecutionContract.ScopeKey scope;
        final String runId;
        final String idempotencyKey;
        RunSignals signals = new RunSignals();
        String status = Lifecycle.RUNNING;
        Map<String, Object> output = Map.of();
        AppError error;
        final List<ExecutionEvent> events = new ArrayList<>();
        long lastEventSeq;
        long generationRevision;
        long generationBase;

        MemoryRun(ExecutionContract.ScopeKey scope, String idempotencyKey) {
            this.scope = scope;
            this.runId = scope.runId();
            this.idempotencyKey = idempotencyKey;
        }
    }

    private final Object monitor = new Object();
    private final Map<String, MemoryRun> runs = new HashMap<>();

    @Override
    public boolean adoptWaiting(ExecutionContract.ScopeKey scope, String idempotencyKey,
            long lastEventSeq, Map<String, Object> metadata) {
        if (scope == null || scope.runId() == null || scope.runId().isBlank() || idempotencyKey == null
                || idempotencyKey.isBlank() || lastEventSeq < 1 || lastEventSeq >= (1L << 53)
                || !validWaitingMetadata(metadata)) return false;
        synchronized (monitor) {
            String runId = scope.runId();
            if (runs.containsKey(runId)) return false;
            MemoryRun run = new MemoryRun(scope, idempotencyKey);
            run.status = Lifecycle.WAITING;
            run.lastEventSeq = lastEventSeq;
            runs.put(runId, run);
            return true;
        }
    }

    private static boolean validWaitingMetadata(Map<String, Object> metadata) {
        if (metadata == null || metadata.size() != 4) return false;
        if (metadata.keySet().equals(Set.of("reason", "harness_key", "tool_name", "call_id")))
            return "approval_required".equals(metadata.get("reason"))
                    && metadata.get("harness_key") instanceof String key && key.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
                    && metadata.get("tool_name") instanceof String tool && tool.matches("[A-Za-z0-9_.:-]{1,128}")
                    && metadata.get("call_id") instanceof String call && call.matches("[A-Za-z0-9_.:-]{1,128}");
        if (!metadata.keySet().equals(Set.of("reason", "group_key", "operation_key", "child_count"))
                || !"agent_group_waiting".equals(metadata.get("reason"))
                || !(metadata.get("group_key") instanceof String groupKey)
                || !groupKey.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
                || !(metadata.get("operation_key") instanceof String operationKey)
                || !HarnessRunner.skillIdentifier(operationKey)
                || !(metadata.get("child_count") instanceof Number childCount)) return false;
        try {
            long count = new java.math.BigDecimal(childCount.toString()).longValueExact();
            return count >= 1 && count <= 16;
        } catch (ArithmeticException | NumberFormatException ignored) { return false; }
    }

    @Override
    public StartResult startRun(ExecuteRequest request) {
        synchronized (monitor) {
            String runId = request.scope().runId();
            if (runId == null || runId.isBlank()) {
                throw new InvalidTransitionException("run id is required");
            }
            MemoryRun existing = runs.get(runId);
            if (existing != null) {
                if (!existing.idempotencyKey.equals(request.idempotencyKey())) {
                    throw new IdempotencyConflictException("run id reused with a different idempotency key");
                }
                return new StartResult(snapshot(runId, existing), false);
            }
            MemoryRun run = new MemoryRun(request.scope(), request.idempotencyKey());
            appendLocked(run, Lifecycle.EVENT_ACCEPTED, Map.of("idempotency_key", request.idempotencyKey()));
            runs.put(runId, run);
            return new StartResult(snapshot(runId, run), true);
        }
    }

    @Override
    public StartResult startGeneration(ExecutionContract.ScopeKey scope, String idempotencyKey, long executionRevision) {
        if (scope == null || scope.runId() == null || scope.runId().isBlank() || idempotencyKey == null || idempotencyKey.isBlank())
            throw new InvalidTransitionException("generation identity is required");
        long base = eventBase(executionRevision);
        synchronized (monitor) {
            String runId = scope.runId();
            MemoryRun existing = runs.get(runId);
            if (existing != null) {
                requireIdentity(existing, scope, idempotencyKey);
                if (existing.generationRevision != executionRevision)
                    throw new InvalidTransitionException("run belongs to another execution generation");
                return new StartResult(snapshot(runId, existing), false);
            }
            MemoryRun run = new MemoryRun(scope, idempotencyKey);
            run.generationRevision = executionRevision;
            run.generationBase = base;
            run.lastEventSeq = base;
            ensureCanAppendLocked(run);
            appendLocked(run, Lifecycle.EVENT_ACCEPTED, Map.of("idempotency_key", idempotencyKey));
            runs.put(runId, run);
            return new StartResult(snapshot(runId, run), true);
        }
    }

    @Override
    public void resumeGeneration(ExecutionContract.ScopeKey scope, String idempotencyKey, long executionRevision) {
        if (scope == null || scope.runId() == null || scope.runId().isBlank() || idempotencyKey == null || idempotencyKey.isBlank())
            throw new InvalidTransitionException("generation identity is required");
        long base = eventBase(executionRevision);
        synchronized (monitor) {
            MemoryRun run = require(scope.runId());
            requireIdentity(run, scope, idempotencyKey);
            if (!Lifecycle.WAITING.equals(run.status))
                throw new InvalidTransitionException("only a waiting generation can resume");
            if (run.generationRevision > 0 && executionRevision <= run.generationRevision)
                throw new InvalidTransitionException("execution revision did not advance");
            if (base < run.lastEventSeq)
                throw new InvalidTransitionException("new event generation overlaps the prior sequence");
            ensureCanAppendLocked(run, executionRevision, base);
            run.generationRevision = executionRevision;
            run.generationBase = base;
            run.lastEventSeq = Math.max(run.lastEventSeq, base);
            run.status = Lifecycle.RUNNING;
            appendLocked(run, Lifecycle.EVENT_STARTED, Map.of("operation", "resume"));
            // The signal stays set: a handler that parks after the resume must
            // observe it and re-read the state instead of waiting forever.
            run.signals.signalResume();
        }
    }

    @Override
    public RunRecord recoverGeneration(ExecutionContract.ScopeKey scope, String idempotencyKey,
            long stoppedRevision, long executionRevision) {
        if (scope == null || scope.runId() == null || scope.runId().isBlank()
                || idempotencyKey == null || idempotencyKey.isBlank() || stoppedRevision < 1
                || executionRevision <= stoppedRevision)
            throw new InvalidTransitionException("recovery generation identity is invalid");
        eventBase(stoppedRevision);
        long base = eventBase(executionRevision);
        synchronized (monitor) {
            String runId = scope.runId();
            MemoryRun existing = runs.get(runId);
            if (existing == null) {
                MemoryRun created = new MemoryRun(scope, idempotencyKey);
                created.generationRevision = executionRevision;
                created.generationBase = base;
                created.lastEventSeq = base;
                ensureCanAppendLocked(created);
                created.status = Lifecycle.RUNNING;
                appendLocked(created, Lifecycle.EVENT_STARTED,
                        Map.of("operation", "resume", "reason", "runtime_recovery"));
                runs.put(runId, created);
                return snapshot(runId, created);
            }

            requireIdentity(existing, scope, idempotencyKey);
            if (!Lifecycle.TERMINAL_STATUSES.contains(existing.status))
                throw new InvalidTransitionException("only a terminal generation can be recovered");
            if (existing.generationRevision != stoppedRevision)
                throw new InvalidTransitionException("stopped generation cannot be verified");
            if (base < existing.lastEventSeq)
                throw new InvalidTransitionException("recovery event generation overlaps prior events");
            ensureCanAppendLocked(existing, executionRevision, base);

            // Keep only real historical events. The new generation starts in
            // its own reserved interval and receives one actual started event.
            existing.generationRevision = executionRevision;
            existing.generationBase = base;
            existing.lastEventSeq = Math.max(existing.lastEventSeq, base);
            existing.status = Lifecycle.RUNNING;
            existing.output = Map.of();
            existing.error = null;
            existing.signals = new RunSignals();
            appendLocked(existing, Lifecycle.EVENT_STARTED,
                    Map.of("operation", "resume", "reason", "runtime_recovery"));
            return snapshot(runId, existing);
        }
    }

    @Override
    public RunRecord getRun(String runId) {
        synchronized (monitor) {
            MemoryRun run = runs.get(runId);
            return run == null ? null : snapshot(runId, run);
        }
    }

    @Override
    public ExecutionEvent appendEvent(String runId, String eventType, Map<String, Object> payload) {
        synchronized (monitor) {
            return appendLocked(require(runId), eventType, payload);
        }
    }

    @Override
    public List<ExecutionEvent> eventsAfter(String runId, long afterSeq) {
        synchronized (monitor) {
            MemoryRun run = require(runId);
            List<ExecutionEvent> result = new ArrayList<>();
            for (ExecutionEvent event : run.events) {
                if (event.seq() > afterSeq) {
                    result.add(event);
                }
            }
            return result;
        }
    }

    @Override
    public void markWaiting(String runId, Map<String, Object> payload) {
        synchronized (monitor) {
            MemoryRun run = require(runId);
            if (!Lifecycle.RUNNING.equals(run.status)) {
                throw new InvalidTransitionException("only a running run can wait");
            }
            Map<String, Object> safePayload = safeEventPayload(payload);
            ensureCanAppendLocked(run);
            run.status = Lifecycle.WAITING;
            appendLocked(run, Lifecycle.EVENT_WAITING, safePayload);
        }
    }

    @Override
    public void resume(String runId, Map<String, Object> payload) {
        synchronized (monitor) {
            MemoryRun run = require(runId);
            if (!Lifecycle.WAITING.equals(run.status)) {
                return;
            }
            Map<String, Object> safePayload = safeEventPayload(payload);
            ensureCanAppendLocked(run);
            run.status = Lifecycle.RUNNING;
            appendLocked(run, Lifecycle.EVENT_STARTED, safePayload);
            // The signal stays set: a handler that parks after the resume must
            // observe it and re-read the state instead of waiting forever.
            // 信号保持置位：恢复之后才挂起的处理器必须能观察到它并重读状态。
            run.signals.signalResume();
        }
    }

    @Override
    public RunRecord cancel(String runId, String reason) {
        synchronized (monitor) {
            MemoryRun run = require(runId);
            if (Lifecycle.TERMINAL_STATUSES.contains(run.status)) {
                return snapshot(runId, run);
            }
            Map<String, Object> payload = safeEventPayload(reason == null || reason.isBlank()
                    ? Map.of() : Map.of("reason", reason));
            ensureCanAppendLocked(run);
            run.status = Lifecycle.CANCELLED;
            appendLocked(run, Lifecycle.EVENT_CANCELLED, payload);
            run.signals.requestCancel();
            return snapshot(runId, run);
        }
    }

    @Override
    public void complete(String runId, Map<String, Object> output) {
        synchronized (monitor) {
            MemoryRun run = require(runId);
            if (Lifecycle.TERMINAL_STATUSES.contains(run.status)) {
                throw new InvalidTransitionException("run is already terminal");
            }
            Map<String, Object> safeOutput = output == null ? Map.of() : new LinkedHashMap<>(output);
            ensureCanAppendLocked(run);
            run.status = Lifecycle.SUCCEEDED;
            run.output = safeOutput;
            appendLocked(run, Lifecycle.EVENT_COMPLETED, Map.of());
        }
    }

    @Override
    public void fail(String runId, AppError error) {
        synchronized (monitor) {
            MemoryRun run = require(runId);
            if (Lifecycle.TERMINAL_STATUSES.contains(run.status)) {
                throw new InvalidTransitionException("run is already terminal");
            }
            if (error == null || error.code() == null) throw new InvalidTransitionException("run failure is missing an error");
            Map<String, Object> payload = safeEventPayload(Map.of("code", error.code()));
            ensureCanAppendLocked(run);
            run.status = Lifecycle.FAILED;
            run.error = error;
            appendLocked(run, Lifecycle.EVENT_FAILED, payload);
        }
    }

    @Override
    public RunSignals signals(String runId) {
        synchronized (monitor) {
            return require(runId).signals;
        }
    }

    private MemoryRun require(String runId) {
        MemoryRun run = runs.get(runId);
        if (run == null) {
            throw new RunUnknownException("run is unknown: " + runId);
        }
        return run;
    }

    private ExecutionEvent appendLocked(MemoryRun run, String eventType, Map<String, Object> payload) {
        long nextSeq = nextEventSequence(run, run.generationRevision, run.generationBase);
        ExecutionEvent event = new ExecutionEvent(run.runId, nextSeq,
                eventType, Instant.now(), safeEventPayload(payload));
        run.events.add(event);
        run.lastEventSeq = nextSeq;
        return event;
    }

    private static Map<String, Object> safeEventPayload(Map<String, Object> payload) {
        return payload == null ? Map.of() : Map.copyOf(payload);
    }

    private static long eventBase(long executionRevision) {
        try { return Lifecycle.eventSequenceBase(executionRevision); }
        catch (IllegalArgumentException ignored) { throw new InvalidTransitionException("execution revision is outside the event sequence range"); }
    }

    private static long nextEventSequence(MemoryRun run, long executionRevision, long generationBase) {
        long floor = Math.max(run.lastEventSeq, generationBase);
        if (floor >= Lifecycle.MAX_EVENT_SEQUENCE_EXCLUSIVE - 1)
            throw new InvalidTransitionException("event sequence limit reached");
        long next = floor + 1;
        long max = executionRevision > 0 ? Lifecycle.maxEventSequence(executionRevision) : Lifecycle.MAX_EVENT_SEQUENCE_EXCLUSIVE - 1;
        if (next > max) throw new InvalidTransitionException("execution generation event range is exhausted");
        return next;
    }

    private static void ensureCanAppendLocked(MemoryRun run) {
        nextEventSequence(run, run.generationRevision, run.generationBase);
    }

    private static void ensureCanAppendLocked(MemoryRun run, long executionRevision, long generationBase) {
        nextEventSequence(run, executionRevision, generationBase);
    }

    private static void requireIdentity(MemoryRun run, ExecutionContract.ScopeKey scope, String idempotencyKey) {
        if (!ExecutionTracker.stable(run.scope).equals(ExecutionTracker.stable(scope))
                || !run.idempotencyKey.equals(idempotencyKey))
            throw new IdempotencyConflictException("run identity differs from execution generation");
    }

    private RunRecord snapshot(String runId, MemoryRun run) {
        return new RunRecord(runId, run.scope, run.idempotencyKey, run.status,
                run.output, run.error, List.copyOf(run.events));
    }
}
