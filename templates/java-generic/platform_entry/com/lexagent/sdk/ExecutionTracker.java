package com.lexagent.sdk;

import com.lexagent.sdk.ExecutionContract.CapabilityClaims;
import com.lexagent.sdk.ExecutionContract.AgentGroupHandoff;
import com.lexagent.sdk.ExecutionContract.HandlerHandoff;
import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.ExecutionContract.ScopeKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/** Process-local handler exit evidence. Persistent state alone cannot prove stop. */
final class ExecutionTracker {
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    private static final Pattern HANDOFF_DIGEST = Pattern.compile("[a-f0-9]{64}");
    private static final Pattern HANDOFF_KEY = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}");
    private static final Pattern HANDOFF_IDENTIFIER = Pattern.compile("[A-Za-z0-9_.:-]{1,128}");
    static final class Active {
        final ScopeKey scope;
        final String bodyHash;
        final Long revision;
        final String leaseHash;
        final CountDownLatch exited = new CountDownLatch(1);
        private Thread thread;
        final String businessHash;
        String originOperation;
        String pauseKey, pauseToolName, pauseCallId;
        AgentGroupPause groupPause;
        AgentGroupResumeBinding groupResumeBinding;
        RecoveryPlan.RuntimeRecoveryBinding runtimeRecoveryBinding;
        boolean parked, resumed, groupPaused, groupResumed;

        Active(ExecuteRequest request, CapabilityClaims claims) {
            scope = request.scope(); bodyHash = claims.bodyHash();
            revision = claims.executionRevision(); leaseHash = claims.leaseTokenHash();
            businessHash = businessHash(request); originOperation = request.operation();
        }

        boolean generation(ScopeKey candidate, CapabilityClaims claims) {
            return scope.equals(candidate) && Objects.equals(revision, claims.executionRevision())
                    && Objects.equals(leaseHash, claims.leaseTokenHash());
        }

        synchronized void enter() { thread = Thread.currentThread(); }
        synchronized void leave() { thread = null; exited.countDown(); Thread.interrupted(); }
        synchronized void interrupt() { if (thread != null) thread.interrupt(); }
    }

    record Admission(Active active, boolean created) {}
    record RecoveryCandidate(Active active, boolean replay) {}
    record AgentGroupCandidate(Active active, boolean replay) {}
    private final Map<String, Active> runs = new HashMap<>();

    static String businessHash(ExecuteRequest request) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(JSON.writeValueAsBytes(List.of(request.inputSchema(), request.idempotencyKey(), request.input())))); }
        catch (Exception ignored) { throw new Lifecycle.InvalidTransitionException("business input cannot be verified"); }
    }
    private static boolean handoffDigest(String value) {
        return value != null && HANDOFF_DIGEST.matcher(value).matches();
    }
    static ScopeKey stable(ScopeKey s) {
        return new ScopeKey(s.tenantId(), s.departmentId(), s.applicationId(), s.agentInstanceId(), s.installationId(), s.agentId(), s.agentVersionId(), s.principalType(), s.principalId(), s.sessionId(), s.runId(), 0, "", s.parentRunId(), s.delegationDepth());
    }

    private static long verifiedGenerationRevision(CapabilityClaims claims) {
        Long revision = claims.executionRevision();
        if (revision == null || revision == 0) return 0;
        if (revision < 0) throw new Lifecycle.InvalidTransitionException("execution revision is invalid");
        Lifecycle.eventSequenceBase(revision);
        return revision;
    }

    private static long lastEventSequence(Lifecycle.RunRecord record) {
        if (record.events() == null || record.events().isEmpty()) return 0;
        var last = record.events().get(record.events().size() - 1);
        if (last == null || last.seq() < 1 || last.seq() >= Lifecycle.MAX_EVENT_SEQUENCE_EXCLUSIVE)
            throw new Lifecycle.InvalidTransitionException("run event sequence cannot be verified");
        return last.seq();
    }

    synchronized void park(String runId, Active active, Lifecycle.RunStore store, HarnessPause pause) {
        if (runs.get(runId) != active) throw new Lifecycle.InvalidTransitionException("run generation differs");
        Map<String, Object> metadata = pause.metadata();
        store.markWaiting(runId, metadata);
        active.pauseKey = (String) metadata.get("harness_key");
        active.pauseToolName = (String) metadata.get("tool_name");
        active.pauseCallId = (String) metadata.get("call_id");
        active.parked = true;
    }

    /** Return a non-secret receipt only for this exact, exited SDK pause. */
    synchronized HandlerHandoff handoff(String runId, Active active, Lifecycle.RunStore store) {
        if (runId == null || active == null || runs.get(runId) != active || !active.parked
                || active.exited.getCount() != 0 || !runId.equals(active.scope.runId())) return null;
        Lifecycle.RunRecord record = store.getRun(runId);
        if (record == null || record.scope() == null || !Lifecycle.WAITING.equals(record.status())
                || !stable(active.scope).equals(stable(record.scope())) || record.events().isEmpty()) return null;
        var event = record.events().get(record.events().size() - 1);
        if (event == null || event.payload() == null) return null;
        Map<String, Object> payload = event.payload();
        if (!runId.equals(event.runId()) || !Lifecycle.EVENT_WAITING.equals(event.eventType())
                || !"approval_required".equals(payload.get("reason"))
                || !Objects.equals(active.pauseKey, payload.get("harness_key"))
                || !Objects.equals(active.pauseToolName, payload.get("tool_name"))
                || !Objects.equals(active.pauseCallId, payload.get("call_id"))) return null;

        if (active.revision == null || active.revision <= 0 || active.revision >= (1L << 53)
                || event.seq() <= 0 || event.seq() >= (1L << 53)
                || !HANDOFF_IDENTIFIER.matcher(runId).matches()
                || !handoffDigest(active.bodyHash)
                || !handoffDigest(active.leaseHash)
                || !handoffDigest(active.businessHash)
                || !("invoke".equals(active.originOperation) || "run".equals(active.originOperation))
                || active.pauseKey == null || !HANDOFF_KEY.matcher(active.pauseKey).matches()
                || active.pauseToolName == null || !HANDOFF_IDENTIFIER.matcher(active.pauseToolName).matches()
                || active.pauseCallId == null || !HANDOFF_IDENTIFIER.matcher(active.pauseCallId).matches()) return null;

        return new HandlerHandoff("sdk-handler-exit/v1", runId, active.revision,
                active.bodyHash, active.leaseHash, active.businessHash, active.originOperation,
                active.pauseKey, active.pauseToolName, active.pauseCallId, event.seq());
    }

    synchronized void parkAgentGroup(String runId, Active active, Lifecycle.RunStore store,
            AgentGroupPause pause) {
        if (runs.get(runId) != active || active.groupPaused || active.parked
                || active.revision == null || !runId.equals(active.scope.runId())
                || active.revision < 1 || active.revision > Lifecycle.MAX_GENERATION_REVISION - 3
                || !(store instanceof Lifecycle.GenerationRunStore)
                || pause == null || !active.businessHash.equals(pause.inputFingerprint())
                || !Objects.equals(active.revision, exactLong(pause.checkpoint().get("execution_revision"))))
            throw new Lifecycle.InvalidTransitionException("AgentGroup wait binding differs");
        Lifecycle.eventSequenceBase(active.revision);
        store.markWaiting(runId, pause.metadata());
        active.groupPause = pause;
        active.groupPaused = true;
    }

    /** A group handoff is exposed only after the actual group handler exited. */
    synchronized AgentGroupHandoff agentGroupHandoff(String runId, Active active, Lifecycle.RunStore store) {
        if (runId == null || active == null || runs.get(runId) != active || !active.groupPaused
                || active.groupPause == null || active.exited.getCount() != 0 || !runId.equals(active.scope.runId())
                || active.revision == null || active.revision < 1
                || active.revision > Lifecycle.MAX_GENERATION_REVISION - 3
                || !(store instanceof Lifecycle.GenerationRunStore)) return null;
        Lifecycle.RunRecord record = store.getRun(runId);
        if (record == null || record.scope() == null || !Lifecycle.WAITING.equals(record.status())
                || !stable(active.scope).equals(stable(record.scope())) || record.events() == null || record.events().isEmpty()) return null;
        var event = record.events().get(record.events().size() - 1);
        if (event == null || event.payload() == null || !runId.equals(event.runId())
                || !Lifecycle.EVENT_WAITING.equals(event.eventType())
                || !active.groupPause.metadata().equals(event.payload())) return null;
        long base;
        long max;
        try {
            base = Lifecycle.eventSequenceBase(active.revision);
            max = Lifecycle.maxEventSequence(active.revision);
        } catch (RuntimeException invalid) { return null; }
        if (event.seq() <= base || event.seq() > max || event.seq() >= Lifecycle.MAX_EVENT_SEQUENCE_EXCLUSIVE
                || !HANDOFF_IDENTIFIER.matcher(runId).matches() || !handoffDigest(active.bodyHash)
                || !handoffDigest(active.leaseHash) || !handoffDigest(active.businessHash)
                || !("invoke".equals(active.originOperation) || "run".equals(active.originOperation))) return null;
        return new AgentGroupHandoff("sdk-agent-group-exit/v1", runId, active.revision, active.bodyHash,
                active.leaseHash, active.businessHash, active.originOperation, active.groupPause.groupKey(),
                active.groupPause.operationKey(), event.seq(), active.groupPause.checkpoint(), active.groupPause.childKeys());
    }

    /** Capture local stopped-handler identity before checkpoint/network reads. */
    synchronized AgentGroupCandidate inspectAgentGroupResume(ExecuteRequest request, CapabilityClaims claims,
            Lifecycle.RunStore store, AgentGroupHandoff handoff) {
        long revision = verifiedGenerationRevision(claims);
        Active active = runs.get(request.scope().runId());
        if (active == null) return new AgentGroupCandidate(null, false);
        if (!stable(active.scope).equals(stable(request.scope()))
                || !active.businessHash.equals(businessHash(request)))
            throw new Lifecycle.IdempotencyConflictException("AgentGroup run identity differs");
        if (stable(active.scope).equals(stable(request.scope()))
                && Objects.equals(active.revision, claims.executionRevision())
                && Objects.equals(active.leaseHash, claims.leaseTokenHash()) && active.groupResumed
                && active.bodyHash.equals(claims.bodyHash())) return new AgentGroupCandidate(active, true);
        if (!active.groupPaused || active.groupPause == null || active.exited.getCount() != 0
                || !Objects.equals(active.revision, handoff.executionRevision())
                || !Objects.equals(active.bodyHash, handoff.bodyHash())
                || !Objects.equals(active.leaseHash, handoff.leaseTokenHash())
                || !Objects.equals(active.originOperation, handoff.originOperation()))
            throw new Lifecycle.InvalidTransitionException("exited AgentGroup generation cannot be verified");
        AgentGroupHandoff local = agentGroupHandoff(request.scope().runId(), active, store);
        if (local == null || !local.equals(handoff) || revision <= active.revision)
            throw new Lifecycle.InvalidTransitionException("AgentGroup waiting receipt differs");
        return new AgentGroupCandidate(active, false);
    }

    /** Import or resume only the exact waiting projection after all State reads and authorization checks. */
    synchronized Admission resumeAgentGroup(ExecuteRequest request, CapabilityClaims claims,
            Lifecycle.RunStore store, AgentGroupHandoff handoff, String checkpointInputHash,
            AgentGroupCandidate expected) {
        long revision = verifiedGenerationRevision(claims);
        AgentGroupCandidate current = inspectAgentGroupResume(request, claims, store, handoff);
        if (current.replay()) {
            if (expected == null || !expected.replay() || expected.active() != current.active())
                throw new Lifecycle.InvalidTransitionException("AgentGroup replay generation changed during verification");
            return new Admission(current.active(), false);
        }
        if (expected == null || expected.replay() || expected.active() != current.active())
            throw new Lifecycle.InvalidTransitionException("AgentGroup run changed during verification");
        if (runs.size() >= 4096 || !(store instanceof Lifecycle.HandoffRunStore handoffStore)
                || !(store instanceof Lifecycle.GenerationRunStore generationStore))
            throw new Lifecycle.InvalidTransitionException("RunStore cannot adopt and resume AgentGroup waiting");
        String runId = request.scope().runId();
        long eventBase = Lifecycle.eventSequenceBase(revision);
        if (eventBase < handoff.lastEventSeq())
            throw new Lifecycle.InvalidTransitionException("AgentGroup event generation overlaps the waiting event");

        Lifecycle.RunRecord before = store.getRun(runId);
        if (current.active() == null) {
            if (!handoffStore.adoptWaiting(request.scope(), request.idempotencyKey(), handoff.lastEventSeq(), groupMetadata(handoff)))
                throw new Lifecycle.InvalidTransitionException("RunStore rejected AgentGroup waiting projection");
            before = store.getRun(runId);
            verifyGroupProjection(before, request, handoff, false);
        } else {
            verifyGroupProjection(before, request, handoff, true);
        }
        List<ExecutionContract.ExecutionEvent> beforeEvents = before.events();
        generationStore.resumeGeneration(request.scope(), request.idempotencyKey(), revision);
        Lifecycle.RunRecord resumed = store.getRun(runId);
        if (resumed == null || !Lifecycle.RUNNING.equals(resumed.status()) || resumed.error() != null
                || (resumed.output() != null && !resumed.output().isEmpty()) || resumed.events() == null
                || resumed.events().size() != beforeEvents.size() + 1
                || !resumed.events().subList(0, beforeEvents.size()).equals(beforeEvents))
            throw new Lifecycle.InvalidTransitionException("AgentGroup resume projection differs");
        var started = resumed.events().get(resumed.events().size() - 1);
        long eventFloor = Math.max(handoff.lastEventSeq(), eventBase);
        if (started == null || !runId.equals(started.runId()) || started.seq() != eventFloor + 1
                || started.seq() >= Lifecycle.MAX_EVENT_SEQUENCE_EXCLUSIVE
                || !Lifecycle.EVENT_STARTED.equals(started.eventType()) || started.payload() == null
                || !"resume".equals(started.payload().get("operation")))
            throw new Lifecycle.InvalidTransitionException("AgentGroup resume event sequence differs");
        List<ExecutionContract.ExecutionEvent> afterWaiting = store.eventsAfter(runId, handoff.lastEventSeq());
        if (afterWaiting == null || afterWaiting.size() != 1 || !started.equals(afterWaiting.get(0)))
            throw new Lifecycle.InvalidTransitionException("AgentGroup resume appended unexpected events");

        Active active = new Active(request, claims);
        active.originOperation = handoff.originOperation();
        active.resumed = true;
        active.groupResumed = true;
        active.groupResumeBinding = new AgentGroupResumeBinding(handoff, checkpointInputHash);
        runs.put(runId, active);
        return new Admission(active, true);
    }

    private static Map<String, Object> groupMetadata(AgentGroupHandoff handoff) {
        return Map.of("reason", "agent_group_waiting", "group_key", handoff.groupKey(),
                "operation_key", handoff.operationKey(), "child_count", handoff.childKeys().size());
    }

    private static void verifyGroupProjection(Lifecycle.RunRecord record, ExecuteRequest request,
            AgentGroupHandoff handoff, boolean requireActualWaitingEvent) {
        if (record == null || !request.scope().runId().equals(record.runId()) || record.scope() == null
                || !stable(request.scope()).equals(stable(record.scope()))
                || !request.idempotencyKey().equals(record.idempotencyKey())
                || !Lifecycle.WAITING.equals(record.status()) || record.error() != null
                || (record.output() != null && !record.output().isEmpty()) || record.events() == null)
            throw new Lifecycle.InvalidTransitionException("AgentGroup waiting projection differs");
        if (record.events().isEmpty()) {
            if (requireActualWaitingEvent) throw new Lifecycle.InvalidTransitionException("local AgentGroup waiting event is missing");
            return;
        }
        var last = record.events().get(record.events().size() - 1);
        if (last == null || last.seq() != handoff.lastEventSeq() || !request.scope().runId().equals(last.runId())
                || !Lifecycle.EVENT_WAITING.equals(last.eventType()) || !groupMetadata(handoff).equals(last.payload()))
            throw new Lifecycle.InvalidTransitionException("AgentGroup waiting event differs from its handoff");
    }

    private static Long exactLong(Object value) {
        if (!(value instanceof Number number)) return null;
        try { return new java.math.BigDecimal(number.toString()).longValueExact(); }
        catch (ArithmeticException | NumberFormatException ignored) { return null; }
    }

    synchronized boolean managedPause(String runId) {
        Active active = runs.get(runId);
        return active != null && (active.parked || active.resumed);
    }

    synchronized Admission resume(ExecuteRequest request, CapabilityClaims claims, Lifecycle.RunStore store) {
        long generationRevision = verifiedGenerationRevision(claims);
        Active old = runs.get(request.scope().runId());
        if (old == null || !stable(old.scope).equals(stable(request.scope())) || !old.businessHash.equals(businessHash(request)) || request.resumeInput() == null)
            throw new Lifecycle.IdempotencyConflictException("resume business binding differs");
        if (!old.parked) {
            if (old.generation(request.scope(), claims) && old.bodyHash.equals(claims.bodyHash())) return new Admission(old, false);
            throw new Lifecycle.InvalidTransitionException("resume generation differs");
        }
        Lifecycle.RunRecord record = store.getRun(request.scope().runId());
        if (old.exited.getCount() != 0 || record == null || !Lifecycle.WAITING.equals(record.status()) || claims.executionRevision() == null || old.revision == null
                || claims.executionRevision() <= old.revision || Objects.equals(claims.leaseTokenHash(), old.leaseHash))
            throw new Lifecycle.InvalidTransitionException("exited waiting generation required");
        long previousEventSequence = lastEventSequence(record);
        long eventFloor = previousEventSequence;
        if (generationRevision > 0 && Lifecycle.eventSequenceBase(generationRevision) < previousEventSequence)
            throw new Lifecycle.InvalidTransitionException("new event generation overlaps the prior sequence");
        if (generationRevision > 0 && store instanceof Lifecycle.GenerationRunStore generationStore) {
            eventFloor = Lifecycle.eventSequenceBase(generationRevision);
            generationStore.resumeGeneration(request.scope(), request.idempotencyKey(), generationRevision);
        } else store.resume(request.scope().runId(), Map.of("operation", "resume"));
        record = store.getRun(request.scope().runId());
        if (record == null || !Lifecycle.RUNNING.equals(record.status())) throw new Lifecycle.InvalidTransitionException("resume transition failed");
        if (generationRevision > 0 && store instanceof Lifecycle.GenerationRunStore) {
            List<ExecutionContract.ExecutionEvent> resumedEvents = store.eventsAfter(request.scope().runId(), previousEventSequence);
            if (resumedEvents == null || resumedEvents.size() != 1 || resumedEvents.get(0).seq() != eventFloor + 1
                    || !Lifecycle.EVENT_STARTED.equals(resumedEvents.get(0).eventType()))
                throw new Lifecycle.InvalidTransitionException("resume event sequence did not continue");
        }
        Active active = new Active(request, claims); active.originOperation = old.originOperation; active.resumed = true;
        runs.put(request.scope().runId(), active);
        return new Admission(active, true);
    }

    synchronized Admission admit(ExecuteRequest request, CapabilityClaims claims, Lifecycle.RunStore store) {
        long generationRevision = verifiedGenerationRevision(claims);
        Active existing = runs.get(request.scope().runId());
        if (existing != null) {
            if (!existing.generation(request.scope(), claims) || !existing.bodyHash.equals(claims.bodyHash()))
                throw new Lifecycle.IdempotencyConflictException("execution generation differs");
            return new Admission(existing, false);
        }
        // Bounded proof retention fails closed; evicting a run could allow duplicate execution.
        if (runs.size() >= 4096)
            throw new Lifecycle.InvalidTransitionException("execution generation cannot be verified");
        Lifecycle.StartResult started;
        if (generationRevision > 0 && store instanceof Lifecycle.GenerationRunStore generationStore) {
            started = generationStore.startGeneration(request.scope(), request.idempotencyKey(), generationRevision);
            if (started == null || !started.created())
                throw new Lifecycle.InvalidTransitionException("execution generation cannot be verified");
            Lifecycle.RunRecord projection = started.record();
            long firstExpected = Lifecycle.eventSequenceBase(generationRevision) + 1;
            ExecutionContract.ExecutionEvent accepted = projection == null || projection.events() == null || projection.events().size() != 1
                    ? null : projection.events().get(0);
            if (projection == null || !request.scope().runId().equals(projection.runId()) || projection.scope() == null
                    || !stable(request.scope()).equals(stable(projection.scope()))
                    || !request.idempotencyKey().equals(projection.idempotencyKey()) || !Lifecycle.RUNNING.equals(projection.status())
                    || projection.error() != null || (projection.output() != null && !projection.output().isEmpty())
                    || accepted == null || !request.scope().runId().equals(accepted.runId()) || accepted.seq() != firstExpected
                    || !Lifecycle.EVENT_ACCEPTED.equals(accepted.eventType()) || accepted.payload() == null
                    || !request.idempotencyKey().equals(accepted.payload().get("idempotency_key")))
                throw new Lifecycle.InvalidTransitionException("execution generation projection differs");
        } else {
            started = store.startRun(request);
            if (started == null || !started.created())
                throw new Lifecycle.InvalidTransitionException("execution generation cannot be verified");
        }
        Active active = new Active(request, claims);
        runs.put(request.scope().runId(), active);
        return new Admission(active, true);
    }

    synchronized Active control(ScopeKey scope, CapabilityClaims claims) {
        Active active = runs.get(scope.runId());
        if (active != null && (active.parked || active.groupPaused) && active.exited.getCount() == 0 && stable(active.scope).equals(stable(scope))
                && claims.executionRevision() != null && active.revision != null && claims.executionRevision() >= active.revision) return active;
        return active != null && active.generation(scope, claims) ? active : null;
    }

    synchronized boolean owns(ScopeKey scope) {
        Active active = runs.get(scope.runId());
        return active != null && stable(active.scope).equals(stable(scope));
    }

    synchronized boolean hasRun(String runId) {
        return runId != null && runs.containsKey(runId);
    }

    /** Check process-local identity and exit evidence without changing either
     * the Active registry or RunStore. This short monitor section precedes all
     * checkpoint and authorization network calls.
     */
    synchronized RecoveryCandidate inspectRecovery(ExecuteRequest request, CapabilityClaims claims,
            long stoppedRevision, String stoppedBodyHash, String stoppedLeaseHash,
            String expectedOriginOperation, AgentGroupHandoff expectedGroupHandoff) {
        long revision = verifiedGenerationRevision(claims);
        if (revision <= stoppedRevision || request == null || request.scope() == null
                || !Set.of("invoke", "run").contains(expectedOriginOperation)
                || (expectedGroupHandoff == null && !"invoke".equals(expectedOriginOperation)))
            throw new Lifecycle.InvalidTransitionException("recovery generation binding differs");
        Active active = runs.get(request.scope().runId());
        if (active == null) return new RecoveryCandidate(null, false);
        if (!stable(active.scope).equals(stable(request.scope()))
                || !active.businessHash.equals(businessHash(request)))
            throw new Lifecycle.IdempotencyConflictException("recovery run identity differs");
        if (Objects.equals(active.revision, claims.executionRevision())) {
            if (!Objects.equals(active.leaseHash, claims.leaseTokenHash())
                    || !Objects.equals(active.bodyHash, claims.bodyHash())
                    || !expectedOriginOperation.equals(active.originOperation)
                    || !Objects.equals(active.groupResumeBinding == null ? null : active.groupResumeBinding.handoff(),
                            expectedGroupHandoff))
                throw new Lifecycle.InvalidTransitionException("recovery generation cannot be replayed");
            return new RecoveryCandidate(active, true);
        }
        if (!Objects.equals(active.revision, stoppedRevision)
                || !Objects.equals(active.bodyHash, stoppedBodyHash)
                || !Objects.equals(active.leaseHash, stoppedLeaseHash)
                || !expectedOriginOperation.equals(active.originOperation)
                || !Objects.equals(active.groupResumeBinding == null ? null : active.groupResumeBinding.handoff(),
                        expectedGroupHandoff)
                || active.parked
                || active.exited.getCount() != 0)
            throw new Lifecycle.InvalidTransitionException("stopped handler exit cannot be verified");
        return new RecoveryCandidate(active, false);
    }

    /** Re-check a private same-generation replay after current authorization succeeds. */
    synchronized Active confirmRecoveryReplay(ExecuteRequest request, CapabilityClaims claims,
            long stoppedRevision, String stoppedBodyHash, String stoppedLeaseHash,
            String expectedOriginOperation, AgentGroupHandoff expectedGroupHandoff,
            RecoveryCandidate expected) {
        RecoveryCandidate current = inspectRecovery(request, claims, stoppedRevision,
                stoppedBodyHash, stoppedLeaseHash, expectedOriginOperation, expectedGroupHandoff);
        if (expected == null || !expected.replay() || !current.replay()
                || expected.active() != current.active())
            throw new Lifecycle.InvalidTransitionException("recovery replay identity changed during authorization");
        return current.active();
    }

    /** Atomically replace/import the RunStore projection and register the new
     * Active only after the caller completed all network checks outside this
     * monitor. The old handler must still be the exact exited generation.
     */
    synchronized Admission recoverGeneration(ExecuteRequest request, CapabilityClaims claims,
            Lifecycle.RunStore store, long stoppedRevision, String stoppedBodyHash,
            String stoppedLeaseHash, RecoveryCandidate expected,
            AgentGroupResumeBinding groupResumeBinding, RecoveryPlan.RuntimeRecoveryBinding runtimeRecoveryBinding,
            String originOperation) {
        long revision = verifiedGenerationRevision(claims);
        RecoveryCandidate current = inspectRecovery(request, claims, stoppedRevision,
                stoppedBodyHash, stoppedLeaseHash, originOperation,
                groupResumeBinding == null ? null : groupResumeBinding.handoff());
        if (current.replay()) {
            if (expected != null && expected.replay() && expected.active() != current.active())
                throw new Lifecycle.InvalidTransitionException("recovery generation changed during verification");
            if (!Objects.equals(current.active().groupResumeBinding == null ? null : current.active().groupResumeBinding.inputHash(),
                    groupResumeBinding == null ? null : groupResumeBinding.inputHash()))
                throw new Lifecycle.InvalidTransitionException("recovery AgentGroup input changed during verification");
            return new Admission(current.active(), false);
        }
        Active runActive = current.active();
        if (expected == null || expected.replay() || expected.active() != runActive)
            throw new Lifecycle.InvalidTransitionException("recovery run changed during verification");
        if (runActive != null && !Objects.equals(runActive.groupResumeBinding == null ? null : runActive.groupResumeBinding.inputHash(),
                groupResumeBinding == null ? null : groupResumeBinding.inputHash()))
            throw new Lifecycle.InvalidTransitionException("stopped AgentGroup input differs from its local binding");
        if (runs.size() >= 4096 || !(store instanceof Lifecycle.RecoveryGenerationRunStore recoveryStore))
            throw new Lifecycle.InvalidTransitionException("run store cannot recover an execution generation");

        String runId = request.scope().runId();
        Lifecycle.RunRecord before = store.getRun(runId);
        long oldLastSeq = 0;
        if ((before == null) != (runActive == null))
            throw new Lifecycle.InvalidTransitionException("recovery projection and local exit proof differ");
        if (before != null) {
            if (!runId.equals(before.runId()) || before.scope() == null
                    || !stable(request.scope()).equals(stable(before.scope()))
                    || !request.idempotencyKey().equals(before.idempotencyKey())
                    || !Lifecycle.TERMINAL_STATUSES.contains(before.status()))
                throw new Lifecycle.InvalidTransitionException("recovery projection conflicts with an existing run");
            oldLastSeq = lastEventSequence(before);
        }
        long newBase = Lifecycle.eventSequenceBase(revision);
        if (newBase < oldLastSeq)
            throw new Lifecycle.InvalidTransitionException("recovery event generation overlaps prior events");

        Lifecycle.RunRecord recovered = recoveryStore.recoverGeneration(request.scope(),
                request.idempotencyKey(), stoppedRevision, revision);
        if (recovered == null || !runId.equals(recovered.runId()) || recovered.scope() == null
                || !stable(request.scope()).equals(stable(recovered.scope()))
                || !request.idempotencyKey().equals(recovered.idempotencyKey())
                || !Lifecycle.RUNNING.equals(recovered.status()) || recovered.error() != null
                || (recovered.output() != null && !recovered.output().isEmpty()))
            throw new Lifecycle.InvalidTransitionException("recovery projection differs");
        List<ExecutionContract.ExecutionEvent> beforeEvents = before == null ? List.of() : before.events();
        List<ExecutionContract.ExecutionEvent> events = recovered.events();
        if (events == null || events.size() != beforeEvents.size() + 1
                || !events.subList(0, beforeEvents.size()).equals(beforeEvents))
            throw new Lifecycle.InvalidTransitionException("recovery projection did not preserve actual events");
        ExecutionContract.ExecutionEvent started = events.get(events.size() - 1);
        if (started == null || !runId.equals(started.runId())
                || started.seq() != newBase + 1 || started.seq() >= Lifecycle.MAX_EVENT_SEQUENCE_EXCLUSIVE
                || !Lifecycle.EVENT_STARTED.equals(started.eventType()) || started.payload() == null
                || !"resume".equals(started.payload().get("operation"))
                || !"runtime_recovery".equals(started.payload().get("reason")))
            throw new Lifecycle.InvalidTransitionException("recovery started event differs");

        Active active = new Active(request, claims);
        active.originOperation = originOperation;
        active.groupResumeBinding = groupResumeBinding;
        active.runtimeRecoveryBinding = runtimeRecoveryBinding;
        active.resumed = true;
        runs.put(runId, active);
        return new Admission(active, true);
    }

    /** Import and resume an authenticated handoff only after all network
     * authorization/checkpoint checks have completed outside this monitor. */
    synchronized Admission adoptWaiting(ExecuteRequest request, CapabilityClaims claims,
            Lifecycle.RunStore store, HandlerHandoff handoff, Map<String, Object> metadata) {
        long generationRevision = verifiedGenerationRevision(claims);
        String runId = request.scope().runId();
        if (runs.containsKey(runId)) throw new Lifecycle.InvalidTransitionException("run generation already exists locally");
        if (runs.size() >= 4096 || !(store instanceof Lifecycle.HandoffRunStore handoffStore))
            throw new Lifecycle.InvalidTransitionException("run store cannot adopt a verified handoff");
        if (handoff == null || !runId.equals(handoff.runId()) || !handoff.inputFingerprint().equals(businessHash(request))
                || claims.executionRevision() == null || handoff.executionRevision() <= 0
                || handoff.executionRevision() >= (1L << 53) || claims.executionRevision() <= handoff.executionRevision()
                || Objects.equals(claims.leaseTokenHash(), handoff.leaseTokenHash()))
            throw new Lifecycle.InvalidTransitionException("handoff binding differs");
        long eventBase = Lifecycle.eventSequenceBase(generationRevision);
        if (eventBase < handoff.lastEventSeq())
            throw new Lifecycle.InvalidTransitionException("new event generation overlaps the handoff sequence");
        if (!handoffStore.adoptWaiting(request.scope(), request.idempotencyKey(), handoff.lastEventSeq(), metadata))
            throw new Lifecycle.InvalidTransitionException("run store rejected handoff projection");

        Lifecycle.RunRecord adopted = store.getRun(runId);
        if (adopted == null || !runId.equals(adopted.runId()) || adopted.scope() == null
                || !stable(request.scope()).equals(stable(adopted.scope()))
                || !request.idempotencyKey().equals(adopted.idempotencyKey())
                || !Lifecycle.WAITING.equals(adopted.status()) || adopted.error() != null || !adopted.output().isEmpty())
            throw new Lifecycle.InvalidTransitionException("run store returned an incompatible handoff projection");
        if (!adopted.events().isEmpty()) {
            var last = adopted.events().get(adopted.events().size() - 1);
            if (last.seq() != handoff.lastEventSeq() || !runId.equals(last.runId())
                    || !Lifecycle.EVENT_WAITING.equals(last.eventType()) || last.payload() == null
                    || !"approval_required".equals(last.payload().get("reason"))
                    || !Objects.equals(handoff.harnessKey(), last.payload().get("harness_key"))
                    || !Objects.equals(handoff.toolName(), last.payload().get("tool_name"))
                    || !Objects.equals(handoff.callId(), last.payload().get("call_id")))
                throw new Lifecycle.InvalidTransitionException("run store waiting event differs from handoff");
        }

        if (generationRevision > 0 && store instanceof Lifecycle.GenerationRunStore generationStore)
            generationStore.resumeGeneration(request.scope(), request.idempotencyKey(), generationRevision);
        else store.resume(runId, Map.of("operation", "resume"));
        Lifecycle.RunRecord record = store.getRun(runId);
        if (record == null || !Lifecycle.RUNNING.equals(record.status()))
            throw new Lifecycle.InvalidTransitionException("handoff resume transition failed");
        long eventFloor = Math.max(handoff.lastEventSeq(), eventBase);
        List<ExecutionContract.ExecutionEvent> resumedEvents = store.eventsAfter(runId, handoff.lastEventSeq());
        if (resumedEvents == null || resumedEvents.size() != 1
                || resumedEvents.get(0).seq() != eventFloor + 1
                || !Lifecycle.EVENT_STARTED.equals(resumedEvents.get(0).eventType()))
            throw new Lifecycle.InvalidTransitionException("handoff event sequence did not continue");

        Active active = new Active(request, claims);
        active.originOperation = handoff.originOperation();
        active.resumed = true;
        runs.put(runId, active);
        return new Admission(active, true);
    }

    synchronized boolean exited(ScopeKey scope) {
        Active active = runs.get(scope.runId());
        return active != null && stable(active.scope).equals(stable(scope)) && active.exited.getCount() == 0;
    }
}
