package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCapabilityPhaseObservationIsBoundedAndContainsNoPayload(t *testing.T) {
	var events [][]byte
	ctx, finish := capabilityPhaseContext(context.Background(), "/untrusted/private-token", true, func(p []byte) { events = append(events, append([]byte(nil), p...)) })
	capabilityPhaseRoot(ctx, "SENSITIVE_ROOT")
	capabilityPhaseState(ctx, "SECRET_NAMESPACE", "SECRET_OPERATION")
	stop := capabilityPhase(ctx, "state.encode")
	stop()
	stop()
	capabilityPhase(ctx, "SECRET_PHASE")()
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); capabilityPhase(ctx, "state.guarded_check")() }()
	}
	workers.Wait()
	finish()
	if len(events) != 1 {
		t.Fatal("one bounded event required")
	}
	for _, secret := range []string{"SENSITIVE_ROOT", "SECRET_NAMESPACE", "SECRET_OPERATION", "SECRET_PHASE", "private-token"} {
		if bytes.Contains(events[0], []byte(secret)) {
			t.Fatal("diagnostic metadata leaked input")
		}
	}
	var got capabilityPhaseTrace
	if json.Unmarshal(events[0], &got) != nil || len(got.RunRef) != 16 || got.Path != "other" || got.Namespace != "other" || got.Operation != "other" || len(got.Phases) != 2 || got.Phases["state.encode"].Count != 1 || got.Phases["state.guarded_check"].Count != 8 {
		t.Fatal("unexpected phase identity, repeat stop or concurrent counting")
	}
}

func TestCapabilityPhaseObservationDisabledOrSinkFailureCannotChangeHandler(t *testing.T) {
	t.Setenv("PLATFORM_CAPABILITY_PHASE_TIMING", "0")
	original := httptest.NewRequest(http.MethodPost, "/internal/state/checkpoint", strings.NewReader("private body"))
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r != original {
			t.Fatal("disabled observer replaced request")
		}
		w.WriteHeader(409)
	})
	response := httptest.NewRecorder()
	capabilityPhaseHandler(next).ServeHTTP(response, original)
	if !called || response.Code != 409 {
		t.Fatal("observer changed handler result")
	}
	ctx, finish := capabilityPhaseContext(context.Background(), "/internal/state/checkpoint", true, func([]byte) { panic("sink unavailable") })
	capabilityPhaseRoot(ctx, "one-original-root")
	capabilityPhase(ctx, "state.commit")()
	finish()
}

func TestCapabilityPhaseObservationRetainsCancellationAndStateTags(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	cancel()
	var encoded []byte
	ctx, finish := capabilityPhaseContext(base, "/internal/state/checkpoint", true, func(p []byte) { encoded = append([]byte(nil), p...) })
	capabilityPhaseRoot(ctx, "run")
	capabilityPhaseState(ctx, "harness", "save")
	capabilityPhase(ctx, "authority.live_recheck")()
	finish()
	var got capabilityPhaseTrace
	if ctx.Err() != context.Canceled || json.Unmarshal(encoded, &got) != nil || got.Namespace != "harness" || got.Operation != "save" || got.Phases["authority.live_recheck"].Count != 1 {
		t.Fatal("observer changed cancellation or discarded stage")
	}
}
