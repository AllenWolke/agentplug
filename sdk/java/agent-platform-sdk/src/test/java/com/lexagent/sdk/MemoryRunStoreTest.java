package com.lexagent.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.lexagent.sdk.ExecutionContract.AppError;
import com.lexagent.sdk.ExecutionContract.ExecuteRequest;
import com.lexagent.sdk.ExecutionContract.ScopeKey;
import com.lexagent.sdk.Lifecycle.IdempotencyConflictException;
import com.lexagent.sdk.Lifecycle.InvalidTransitionException;
import com.lexagent.sdk.Lifecycle.RunRecord;
import com.lexagent.sdk.Lifecycle.RunSignals;
import com.lexagent.sdk.Lifecycle.RunUnknownException;
import com.lexagent.sdk.Lifecycle.StartResult;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** MemoryRunStore state-machine tests: idempotency, transitions, cancellation
 * and per-run event sequence numbering. / MemoryRunStore 状态机测试：幂等、迁移、
 * 取消与逐运行事件次序号。
 */
final class MemoryRunStoreTest {
    private final MemoryRunStore store = new MemoryRunStore();

    private ExecuteRequest request(String runId, String idempotency) {
        return new ExecuteRequest(ExecutionContract.PROTOCOL_VERSION, "token", scope(runId),
                "run", idempotency, "schema://example/input/v1",
                Map.of("policy_snapshot", Map.of("content_hash", "a".repeat(64))));
    }

    private ScopeKey scope(String runId) {
        return new ScopeKey("tenant-a", "business-department", "business-app", "instance-a", "installation-a", "conformance-agent",
                "v2", "user", "user-a", "session-a", runId, 1, "0".repeat(32), "", 0);
    }

    @Test
    void startRunIsIdempotentPerKeyAndConflictsAcrossKeys() {
        StartResult first = store.startRun(request("run-1", "idem-key-0001"));
        assertTrue(first.created());
        StartResult replay = store.startRun(request("run-1", "idem-key-0001"));
        assertEquals(false, replay.created());
        assertEquals(first.record().status(), replay.record().status());
        assertThrows(IdempotencyConflictException.class, () -> store.startRun(request("run-1", "another-key")));
    }

    @Test
    void eventsCarryPerRunSequenceNumbers() {
        store.startRun(request("run-1", "idem-key-0001"));
        // accepted already took seq 1 at start; the next event is seq 2.
        // accepted 在启动时占用 seq 1；下一事件为 seq 2。
        assertEquals(2L, store.appendEvent("run-1", Lifecycle.EVENT_PROGRESS, Map.of()).seq());
        assertEquals(3L, store.appendEvent("run-1", Lifecycle.EVENT_ARTIFACT, Map.of()).seq());
        store.startRun(request("run-2", "idem-key-0002"));
        assertEquals(2L, store.appendEvent("run-2", Lifecycle.EVENT_PROGRESS, Map.of()).seq());
        assertEquals(1, store.eventsAfter("run-1", 2L).size());
        assertEquals(2, store.eventsAfter("run-1", 1L).size());
        assertThrows(RunUnknownException.class, () -> store.appendEvent("run-unknown", Lifecycle.EVENT_PROGRESS, Map.of()));
    }

    @Test
    void waitingResumeCycleSignalsTheParkedHandler() throws Exception {
        store.startRun(request("run-1", "idem-key-0001"));
        RunSignals signals = store.signals("run-1");
        store.markWaiting("run-1", Map.of("question", "approve?"));
        assertEquals(Lifecycle.WAITING, store.getRun("run-1").status());
        assertThrows(InvalidTransitionException.class, () -> store.markWaiting("run-1", Map.of()));

        Thread watcher = new Thread(() -> {
            try {
                signals.awaitResumeOrCancel(5_000L);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }, "parked-handler");
        watcher.start();
        store.resume("run-1", Map.of("approval", "approved"));
        watcher.join(2_000L);
        // The parked handler observed the resume signal. / 挂起处理器观察到恢复信号。
        assertTrue(watcher.isAlive() == false || signals.isResumeSignalled());
        assertEquals(Lifecycle.RUNNING, store.getRun("run-1").status());
        // Replayed resumes stay idempotent no-ops. / 重放 resume 保持幂等无操作。
        store.resume("run-1", Map.of());
        assertEquals(Lifecycle.RUNNING, store.getRun("run-1").status());
    }

    @Test
    void cancelIsObservableAndIdempotentOnTerminalRuns() {
        store.startRun(request("run-1", "idem-key-0001"));
        RunSignals signals = store.signals("run-1");
        RunRecord cancelled = store.cancel("run-1", "gone");
        assertEquals(Lifecycle.CANCELLED, cancelled.status());
        assertTrue(signals.isCancelled());
        // A second cancel replays the terminal snapshot. / 二次取消重放终态快照。
        assertEquals(Lifecycle.CANCELLED, store.cancel("run-1", "again").status());
        // Resume on a terminal run is a no-op. / 终态运行上 resume 为无操作。
        store.resume("run-1", Map.of());
        assertEquals(Lifecycle.CANCELLED, store.getRun("run-1").status());
        assertTrue(store.eventsAfter("run-1", 0L).stream().anyMatch(e -> Lifecycle.EVENT_CANCELLED.equals(e.eventType())));
    }

    @Test
    void completeAndFailRejectTerminalTransitions() {
        store.startRun(request("run-1", "idem-key-0001"));
        store.complete("run-1", Map.of("done", true));
        assertEquals(Lifecycle.SUCCEEDED, store.getRun("run-1").status());
        assertThrows(InvalidTransitionException.class, () -> store.complete("run-1", Map.of()));

        store.startRun(request("run-2", "idem-key-0002"));
        store.fail("run-2", new AppError("INTERNAL", "boom", false, Map.of()));
        assertEquals(Lifecycle.FAILED, store.getRun("run-2").status());
        // Cancel on a terminal run replays the terminal snapshot instead of
        // throwing, mirroring the Go and Python stores. / 终态运行上重放取消返回
        // 终态快照而非抛错，与 Go/Python 实现一致。
        assertEquals(Lifecycle.FAILED, store.cancel("run-2", "").status());
    }
}
