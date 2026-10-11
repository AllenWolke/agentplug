package com.lexagent.sdk;

import static org.junit.jupiter.api.Assertions.*;
import com.lexagent.sdk.ExecutionContract.*;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ExecutionTrackerTest {
    private static ScopeKey scope(String owner) {
        return new ScopeKey("t", "d", "a", "i", "installation", "agent", "v", "user", owner, "s", "r", 1, "trace", "", 0);
    }
    private static CapabilityClaims claims(long revision, String lease) {
        return new CapabilityClaims("issuer", "aud", "user", "owner", "t", "a", "i", "installation", 1,
                List.of("invoke"), "policy", "body", 1, 2, "d", "agent", "v", "r", "s", "trace", revision, lease);
    }
    private static ExecuteRequest request() {
        return new ExecuteRequest(ExecutionContract.PROTOCOL_VERSION, "token", scope("owner"), "invoke", "idempotency", "schema", Map.of());
    }
    @Test void fullScopeAndGenerationControlCannotBeForged() {
        var tracker = new ExecutionTracker(); var store = new MemoryRunStore();
        var active = tracker.admit(request(), claims(3, "lease"), store).active();
        assertSame(active, tracker.control(scope("owner"), claims(3, "lease")));
        assertNull(tracker.control(scope("other"), claims(3, "lease")));
        assertNull(tracker.control(scope("owner"), claims(4, "lease")));
        assertNull(tracker.control(scope("owner"), claims(3, "other")));
        assertThrows(Lifecycle.IdempotencyConflictException.class,
                () -> tracker.admit(request(), claims(4, "lease"), store));
        assertFalse(tracker.admit(request(), claims(3, "lease"), store).created());
    }
    @Test void cancellationIntentAndRestoredStateAreNotHandlerExitProof() {
        var tracker = new ExecutionTracker(); var store = new MemoryRunStore();
        var active = tracker.admit(request(), claims(3, "lease"), store).active();
        store.cancel("r", "requested");
        assertFalse(tracker.exited(scope("owner")));
        active.exited.countDown();
        assertTrue(tracker.exited(scope("owner")));
        var restarted = new ExecutionTracker();
        assertNull(restarted.control(scope("owner"), claims(3, "lease")));
        assertFalse(restarted.exited(scope("owner")));
        assertThrows(Lifecycle.InvalidTransitionException.class,
                () -> restarted.admit(request(), claims(3, "lease"), store));
    }
}
