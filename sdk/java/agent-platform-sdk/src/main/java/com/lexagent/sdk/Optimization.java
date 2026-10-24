package com.lexagent.sdk;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.function.Consumer;

public final class Optimization {
    private Optimization() {}
    public static final class DeadlineBudget {
        private final long expires;
        private final int maximumCalls;
        private int calls;
        public DeadlineBudget(Duration duration, int maximumCalls) throws CapabilityClient.Failure {
            if (duration == null || duration.isNegative() || duration.isZero() || maximumCalls < 1 || maximumCalls > 1024) throw PublicCapabilities.stop("LOCAL_BUDGET_INVALID");
            try { expires = Math.addExact(System.nanoTime(), duration.toNanos()); } catch (ArithmeticException error) { throw PublicCapabilities.stop("LOCAL_BUDGET_INVALID"); }
            this.maximumCalls = maximumCalls;
        }
        public Duration remaining() throws CapabilityClient.Failure {
            long remaining = expires - System.nanoTime(); if (remaining <= 0) throw PublicCapabilities.stop("LOCAL_DEADLINE_EXCEEDED"); return Duration.ofNanos(remaining);
        }
        public synchronized void admitCall() throws CapabilityClient.Failure {
            remaining(); if (calls >= maximumCalls) throw PublicCapabilities.stop("LOCAL_CALL_BUDGET_EXHAUSTED"); calls++;
        }
    }
    public static boolean authorityFailure(Exception error) {
        if (error instanceof InterruptedException) return true;
        if (!(error instanceof CapabilityClient.Failure failure)) return false;
        if (failure.status() == 401 || failure.status() == 403) return true;
        String code = failure.code().toUpperCase(java.util.Locale.ROOT);
        if (Set.of("MODEL_BUDGET_UNAVAILABLE", "MODEL_BUDGET_ADMISSION_DEFERRED", "RUNTIME_BUDGET_UNAVAILABLE").contains(code)) return false;
        for (String part : List.of("DENIED", "UNAUTHORIZED", "FORBIDDEN", "SIGNATURE", "CONTEXT_INVALID", "CONTEXT_EXPIRED", "POLICY_", "AUTHORIZATION_", "WORKLOAD_", "CREDENTIAL_", "TOKEN_", "BUDGET_", "RUN_CANCEL", "EXECUTION_STOP", "RUN_LEASE", "RUN_RESUME_UNCONFIRMED", "MODEL_SELECTION_MISMATCH", "ASSET_VERSION_MISMATCH", "INSTALLATION_REVOKED", "TOOL_CONFIRMATION_")) if (code.contains(part)) return true;
        return false;
    }
    public interface RetryAfter { Duration retryAfter(); }
    @FunctionalInterface public interface Attempt<T> { T call(Duration remaining) throws Exception; }
    /** Only positive read/not-submitted evidence can authorize retry. */
    public static <T> T retryBounded(DeadlineBudget budget, int attempts, Predicate<Exception> safeToRetry, Attempt<T> call) throws Exception {
        if (budget == null || attempts < 1 || attempts > 8 || safeToRetry == null || call == null) throw PublicCapabilities.stop("LOCAL_RETRY_INVALID");
        for (int index = 0; index < attempts; index++) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
            budget.admitCall();
            try { return call.call(budget.remaining()); }
            catch (Exception error) {
                if (authorityFailure(error) || index + 1 == attempts || !safeToRetry.test(error)) throw error;
                long delay = (long) (Math.min(50L << index, 1000L) * ThreadLocalRandom.current().nextDouble(0.5, 1.5));
                if(error instanceof RetryAfter hint && hint.retryAfter()!=null && !hint.retryAfter().isNegative())delay=Math.max(delay,Math.min(30000L,hint.retryAfter().toMillis()));
                if (delay >= budget.remaining().toMillis()) throw error; Thread.sleep(delay);
            }
        }
        throw PublicCapabilities.stop("LOCAL_RETRY_INVALID");
    }
    @FunctionalInterface public interface ItemCall<T, R> { R call(T item) throws Exception; }
    public record Result<T>(T value, Exception error) {}
    /** Workers are owned and joined. Cancellation never detaches a still
     * running provider call and calls itself stopped. */
    public static <T, R> List<Result<R>> boundedMap(List<T> items, int workers, int queueSize, ItemCall<T, R> call) throws Exception {
        if (items == null || items.size() > 10000 || workers < 1 || workers > 64 || queueSize < 1 || queueSize > 10000 || call == null) throw PublicCapabilities.stop("BATCH_CONFIG_INVALID");
        List<Result<R>> results = new ArrayList<>(Collections.nCopies(items.size(), null));
        var jobs = new ArrayBlockingQueue<Integer>(queueSize); var done = new CountDownLatch(workers);
        var producing = new AtomicBoolean(true); var stopped = new AtomicBoolean(false); var decisive = new AtomicReference<Exception>();
        var workerThreads=new ArrayList<Thread>();
        for (int worker = 0; worker < workers; worker++) workerThreads.add(new Thread(() -> {
            try {
                while (producing.get() || !jobs.isEmpty()) {
                    Integer index = jobs.poll(50, TimeUnit.MILLISECONDS); if (index == null) continue;
                    if (stopped.get()) { results.set(index, new Result<>(null, new InterruptedException())); continue; }
                    try { results.set(index, new Result<>(call.call(items.get(index)), null)); }
                    catch (Exception error) { results.set(index, new Result<>(null, error)); if (authorityFailure(error)) { decisive.compareAndSet(null, error); stopped.set(true); for(Thread sibling:workerThreads)if(sibling!=Thread.currentThread())sibling.interrupt(); } }
                }
            } catch (InterruptedException error) { stopped.set(true); }
            finally { done.countDown(); }
        }));
        workerThreads.forEach(Thread::start);
        boolean interrupted = false;
        try {
            for (int index = 0; index < items.size(); index++) {
                while (!jobs.offer(index, 50, TimeUnit.MILLISECONDS)) if (stopped.get()) break;
                if (stopped.get()) break;
            }
        } catch (InterruptedException error) { interrupted = true; stopped.set(true); workerThreads.forEach(Thread::interrupt); }
        finally {
            producing.set(false);if(stopped.get())workerThreads.forEach(Thread::interrupt);
            boolean joined = false;
            while (!joined) try { done.await(); joined = true; } catch (InterruptedException error) { interrupted = true; stopped.set(true); workerThreads.forEach(Thread::interrupt); }
        }
        if (interrupted) { Thread.currentThread().interrupt(); throw new InterruptedException(); }
        if (decisive.get() != null) throw decisive.get();
        for (int index = 0; index < results.size(); index++) if (results.get(index) == null) results.set(index, new Result<>(null, new InterruptedException()));
        return results;
    }
    @FunctionalInterface public interface StageCall<T> { T call() throws Exception; }
    private static final Set<String> COUNTERS = Set.of("calls", "input_tokens", "output_tokens", "retry_count", "cache_hits", "cache_misses", "queue_depth", "admission_ms", "queue_wait_ms", "documents", "chunks");
    public static <T> T measuredStage(String stage, Map<String, Long> counters, Consumer<Map<String, Object>> sink, StageCall<T> call) throws Exception {
        if (stage == null || !stage.matches("[A-Za-z0-9_.-]{1,64}") || counters == null || counters.entrySet().stream().anyMatch(entry -> !COUNTERS.contains(entry.getKey()) || entry.getValue() == null || entry.getValue() < 0)) throw PublicCapabilities.stop("STAGE_MEASUREMENT_INVALID");
        long started = System.nanoTime(); String status = "succeeded", errorType = "";
        try { return call.call(); }
        catch (Exception error) { status = error instanceof InterruptedException ? "cancelled" : "failed"; errorType = error.getClass().getSimpleName(); throw error; }
        finally {
            if (sink != null) try {
                Map<String, Object> sample = new java.util.LinkedHashMap<>(counters);
                sample.put("version", "agent-stage-measurement/v1"); sample.put("stage", stage); sample.put("wall_ms", Math.max(0, System.nanoTime() - started) / 1_000_000.0);
                sample.put("status", status); sample.put("error_type", errorType); sample.put("cpu_attribution", "unavailable"); sink.accept(sample);
            } catch (Exception ignored) { /* Optional telemetry cannot change the operation outcome. */ }
        }
    }
}
