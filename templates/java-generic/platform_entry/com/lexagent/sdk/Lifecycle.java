package com.lexagent.sdk;

import java.util.List;
import java.util.Map;

/** Run lifecycle SPI: the SDK owns the run state machine so generated Agents
 * never build a parallel one; business code only implements the handler seams.
 * 运行生命周期 SPI：状态机由 SDK 持有，生成 Agent 不得自建；业务代码只实现
 * 处理器接缝。
 */
public final class Lifecycle {
    private Lifecycle() {}

    public static final String RUNNING = "running";
    public static final String WAITING = "waiting";
    public static final String SUCCEEDED = "succeeded";
    public static final String FAILED = "failed";
    public static final String CANCELLED = "cancelled";

    /** A bounded event-sequence interval is reserved for each signed execution generation. */
    public static final long EVENT_SEQUENCE_WIDTH = 1L << 20;
    public static final long MAX_GENERATION_REVISION = 1L << 33;
    public static final long MAX_EVENT_SEQUENCE_EXCLUSIVE = 1L << 53;

    public static long eventSequenceBase(long executionRevision) {
        if (executionRevision < 1 || executionRevision > MAX_GENERATION_REVISION)
            throw new IllegalArgumentException("execution revision is outside the event sequence range");
        return (executionRevision - 1) * EVENT_SEQUENCE_WIDTH;
    }

    public static long maxEventSequence(long executionRevision) {
        return eventSequenceBase(executionRevision) + EVENT_SEQUENCE_WIDTH - 1;
    }

    public static final List<String> TERMINAL_STATUSES = List.of(SUCCEEDED, FAILED, CANCELLED);

    // SSE event types carried by the events endpoint. / events 端点输出的 SSE 事件类型。
    public static final String EVENT_ACCEPTED = "accepted";
    public static final String EVENT_STARTED = "started";
    public static final String EVENT_PROGRESS = "progress";
    public static final String EVENT_WAITING = "waiting";
    public static final String EVENT_ARTIFACT = "artifact";
    public static final String EVENT_COMPLETED = "completed";
    public static final String EVENT_FAILED = "failed";
    public static final String EVENT_CANCELLED = "cancelled";

    /** The bundled memory store must be labelled this way in every manifest that
     * uses it, so operators can reject it before L2/L3 deployment.
     * 内置内存存储在 manifest 中必须如此标注，运维可在 L2/L3 前拒绝该配置。
     */
    public static final String MEMORY_RUN_STORE_LABEL = "memory-dev-only(L2/L3 forbidden)";

    /** The referenced run does not exist. / 目标运行不存在。 */
    public static class RunUnknownException extends RuntimeException {
        public RunUnknownException(String message) {
            super(message);
        }
    }

    /** The run id was reused with a different idempotency key. / run_id 被不同的幂等键复用。 */
    public static class IdempotencyConflictException extends RuntimeException {
        public IdempotencyConflictException(String message) {
            super(message);
        }
    }

    /** The run state transition is invalid. / 运行状态迁移不合法。 */
    public static class InvalidTransitionException extends RuntimeException {
        public InvalidTransitionException(String message) {
            super(message);
        }
    }

    /** Immutable view of one run returned by a RunStore. / RunStore 返回的单次运行的只读视图。 */
    public record RunRecord(String runId, ExecutionContract.ScopeKey scope, String idempotencyKey,
            String status, Map<String, Object> output, ExecutionContract.AppError error,
            List<ExecutionContract.ExecutionEvent> events) {
        public RunRecord {
            output = output == null ? Map.of() : Map.copyOf(output);
            events = events == null ? List.of() : List.copyOf(events);
        }
    }

    /** startRun result: the record plus whether this call created the run.
     * startRun 结果：记录加本次调用是否新建了运行。
     */
    public record StartResult(RunRecord record, boolean created) {}

    /** Lets a run handler append progress events through the store.
     * 让运行处理器通过 Store 追加进度事件。
     */
    @FunctionalInterface
    public interface EventSink {
        void append(String eventType, Map<String, Object> payload);
    }

    /** Cooperative per-run signals: cancellation is requested once, and a
     * parked handler is woken when the platform resume leg arrives. The
     * business handler must observe cancellation.
     * 逐运行协作信号：取消请求置位一次；挂起的处理器在平台 resume 腿到达时被
     * 唤醒。业务处理器必须观察取消。
     */
    public static final class RunSignals {
        private boolean cancelled;
        private boolean resumed;

        public synchronized boolean isCancelled() {
            return cancelled;
        }

        public synchronized boolean isResumeSignalled() {
            return resumed;
        }

        /** Block until cancelled, resumed or the timeout; parked business
         * handlers poll this. / 阻塞直到取消、恢复或超时；挂起的业务处理器轮询。
         */
        public synchronized void awaitResumeOrCancel(long timeoutMillis) throws InterruptedException {
            long deadline = System.currentTimeMillis() + timeoutMillis;
            while (!cancelled && !resumed) {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0L) {
                    return;
                }
                wait(remaining);
            }
        }

        synchronized void requestCancel() {
            cancelled = true;
            notifyAll();
        }

        synchronized void signalResume() {
            resumed = true;
            notifyAll();
        }
    }

    /** Platform run state SPI. L2/L3 deployments must provide a scoped, durable
     * implementation (tenant isolation, restart recovery); the bundled
     * MemoryRunStore is explicitly forbidden there.
     * 平台运行状态 SPI：L2/L3 必须提供带 Scope 隔离与重启恢复的持久化实现；
     * 内置 MemoryRunStore 显式禁止用于 L2/L3。
     */
    public interface RunStore {
        /** Create a run or return the existing record for the same run id and
         * idempotency key; a different key on the same id is a conflict.
         * 创建运行；同 run_id 且同幂等键时返回既有记录，幂等键不同则视为冲突。
         */
        StartResult startRun(ExecutionContract.ExecuteRequest request);

        RunRecord getRun(String runId);

        /** Append one event with the next per-run sequence number; appending to
         * an unknown run fails. / 追加事件并分配下一次序号；未知运行必须失败。
         */
        ExecutionContract.ExecutionEvent appendEvent(String runId, String eventType, Map<String, Object> payload);

        List<ExecutionContract.ExecutionEvent> eventsAfter(String runId, long afterSeq);

        /** Park an interruptible run awaiting resume. / 挂起可中断的运行等待恢复。 */
        void markWaiting(String runId, Map<String, Object> payload);

        /** Move a waiting run back to running; other states are no-ops so
         * replayed resumes stay idempotent.
         * 将 waiting 恢复为 running；其余状态幂等无操作。
         */
        void resume(String runId, Map<String, Object> payload);

        RunRecord cancel(String runId, String reason);

        void complete(String runId, Map<String, Object> output);

        void fail(String runId, ExecutionContract.AppError error);

        /** Cooperative signals for one run; the business handler must observe
         * cancellation. / 单次运行的协作信号；业务处理器必须观察取消。
         */
        RunSignals signals(String runId);
    }

    /** Optional event-sequence allocation for SDK-verified non-zero generations.
     * Implementations must atomically reserve the revision interval and reject
     * stale, conflicting or over-capacity transitions. Parameters deliberately
     * contain no execution or lease token. Legacy stores may omit this SPI.
     */
    public interface GenerationRunStore extends RunStore {
        StartResult startGeneration(ExecutionContract.ScopeKey scope, String idempotencyKey, long executionRevision);

        void resumeGeneration(ExecutionContract.ScopeKey scope, String idempotencyKey, long executionRevision);
    }

    /** Explicit opt-in for importing a platform-attested stopped generation.
     * Implementations atomically create the current RUNNING projection or replace
     * only a terminal projection for the exact stopped generation. The input is
     * deliberately limited to stable identity and revision numbers; it carries
     * no recovery reference, checkpoint body, or execution token.
     */
    public interface RecoveryGenerationRunStore extends GenerationRunStore {
        RunRecord recoverGeneration(ExecutionContract.ScopeKey scope, String idempotencyKey,
                long stoppedRevision, long executionRevision);
    }

    /** Explicit opt-in for importing an authenticated, signed handler handoff.
     * Implementations must atomically reject conflicting runs and create or
     * verify only a waiting projection; they must not replay old events or
     * persist resume tokens. / 受控接纳已验签处理器交接的显式接口。实现必须原子拒绝
     * 冲突Run，只创建或核对waiting投影；不得伪造历史事件或持久化恢复令牌。
     */
    public interface HandoffRunStore extends RunStore {
        /**
         * Adopt an already-authorized waiting generation with its original
         * idempotency binding and event sequence base. Returns false when the
         * store already contains an incompatible run. The metadata contains
         * safe pause identifiers only; no token, output or tool arguments.
         */
        boolean adoptWaiting(ExecutionContract.ScopeKey scope, String idempotencyKey, long lastEventSeq,
                Map<String, Object> metadata);
    }
}
