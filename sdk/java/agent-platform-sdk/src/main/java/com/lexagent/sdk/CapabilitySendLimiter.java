package com.lexagent.sdk;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Physical-send capacity only; never an authentication or permission cache. */
public final class CapabilitySendLimiter implements CapabilityClient.SendLimiter {
    private static final Set<String> PATHS=Set.of("/internal/context/renew","/internal/model/generate","/internal/model/embed","/internal/model/receipt","/internal/knowledge/search","/internal/knowledge/search/recovery","/internal/knowledge/answer","/internal/knowledge/answer/recovery","/internal/knowledge/references/authorize","/internal/state/checkpoint","/internal/runtime/harness-policy","/internal/prompt/resolve","/internal/tool/invoke","/internal/tool/receipt","/internal/memory/access");
    private final Semaphore permits;
    public CapabilitySendLimiter(int maximum){if(maximum<1||maximum>1024)throw new IllegalArgumentException("invalid send capacity");permits=new Semaphore(maximum,true);}
    public AutoCloseable acquire(Duration remaining)throws Exception{
        if(remaining==null||remaining.isNegative()||remaining.isZero()||!permits.tryAcquire(remaining.toNanos(),TimeUnit.NANOSECONDS))throw new CapabilityClient.Failure("CAPABILITY_LIMIT_EXCEEDED",429,true);
        AtomicBoolean closed=new AtomicBoolean();return ()->{if(closed.compareAndSet(false,true))permits.release();};
    }
    public static String safePath(String path){return PATHS.contains(path)?path:"other";}
}
