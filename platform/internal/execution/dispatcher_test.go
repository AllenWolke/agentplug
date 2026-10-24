package execution

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

const dispatcherFixtureContextToken = "ctx-token-0123456789abcdef0123456789"

func legacyExecuteRequest(t *testing.T, runID, operation string, input map[string]any) []byte {
	t.Helper()
	if input == nil {
		input = map[string]any{}
	}
	request := contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		ContextToken:    dispatcherFixtureContextToken,
		Scope: contract.ScopeKey{
			TenantID: "tenant", DepartmentID: "dept", ApplicationID: "app",
			AgentInstanceID: "instance", AgentID: "agent", AgentVersionID: "v1",
			PrincipalType: "user", PrincipalID: "user", InstallationID: "install",
			SessionID: "session", RunID: runID, AuthorizationEpoch: 1,
			TraceID: "0123456789abcdef0123456789abcdef",
		},
		Operation: operation, IdempotencyKey: "idem-" + runID,
		InputSchema: "schema://test/agent-input/v1", Input: input,
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertLegacyStopPending(t *testing.T, repository *platformruntime.Store, runID, code string) {
	t.Helper()
	final, err := repository.Get(runID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != platformruntime.StatusCancelling {
		t.Fatalf("uncertain remote execution must remain stop-pending, status=%s", final.Status)
	}
	events, err := repository.Events(runID, 0)
	if err != nil {
		t.Fatal(err)
	}
	sawAttempt, sawStopIntent := false, false
	for _, event := range events {
		switch event.Type {
		case "attempt_failed":
			sawAttempt = event.Payload["code"] == code && event.Payload["retryable"] == false
		case "cancel_requested":
			sawStopIntent = event.Payload["code"] == code
		case "task_failed", "task_completed", "cancelled":
			t.Fatalf("uncertain outcome was finalized without stop proof: events=%+v", events)
		}
	}
	if !sawAttempt || !sawStopIntent {
		t.Fatalf("missing non-retry attempt evidence or durable stop intent: events=%+v", events)
	}
}

func TestDispatcherInvokesAgentAndOwnsTerminalTransition(t *testing.T) {
	called := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/agent-execution/v2/invoke" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+dispatcherFixtureContextToken {
			t.Fatalf("missing context token")
		}
		called <- struct{}{}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"succeeded"}`))
	}))
	defer agent.Close()

	repository := platformruntime.NewStore()
	raw := legacyExecuteRequest(t, "dispatch-run", "invoke", nil)
	scope := testScope("dispatch-run")
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "dispatch-run", Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "idem-dispatch-run", Fingerprint: "fp-dispatch", RequestJSON: raw, AgentEndpoint: agent.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := NewDispatcher(repository, "secret", 1)
	if err := dispatcher.dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	default:
		t.Fatal("agent was not invoked")
	}
	final, err := repository.Get("dispatch-run")
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != platformruntime.StatusSucceeded {
		t.Fatalf("status=%s", final.Status)
	}
	events, err := repository.Events("dispatch-run", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[3].Type != "task_completed" {
		t.Fatalf("events=%+v", events)
	}
}

func TestDispatcherPreservesWaitingInterruptStatus(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"waiting"}`))
	}))
	defer agent.Close()

	repository := platformruntime.NewStore()
	raw := legacyExecuteRequest(t, "waiting-dispatch", "invoke", nil)
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "waiting-dispatch", Scope: testScope("waiting-dispatch").domain(), AgentVersionID: "v1",
		IdempotencyKey: "idem-waiting-dispatch", Fingerprint: "fp-waiting", RequestJSON: raw, AgentEndpoint: agent.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDispatcher(repository, "secret", 1).dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	final, err := repository.Get(created.Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != platformruntime.StatusWaiting {
		t.Fatalf("status=%s, expected waiting", final.Status)
	}
	events, err := repository.Events(created.Run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[3].Type != "waiting" {
		t.Fatalf("events=%+v", events)
	}
}

func TestDispatcherResumesThroughDedicatedAgentEndpoint(t *testing.T) {
	called := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/agent-execution/v2/runs/resume-dispatch/resume" {
			t.Fatalf("unexpected resume path %s", r.URL.Path)
		}
		if r.Header.Get("X-Platform-Resume-Dispatch") != "" || r.Header.Get("X-Platform-Resume-Input") != "" {
			t.Fatalf("unsigned resume headers emitted: %v", r.Header)
		}
		var envelope map[string]any
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Fatal(err)
		}
		if envelope["operation"] != "resume" {
			t.Fatalf("signed request body must remain unchanged: %#v", envelope)
		}
		called <- struct{}{}
		_, _ = w.Write([]byte(`{"status":"succeeded"}`))
	}))
	defer agent.Close()

	repository := platformruntime.NewStore()
	raw := legacyExecuteRequest(t, "resume-dispatch", "run", map[string]any{"question": "q"})
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "resume-dispatch", Scope: testScope("resume-dispatch").domain(), AgentVersionID: "v1",
		IdempotencyKey: "idem-resume-dispatch", Fingerprint: "fp-resume-dispatch", RequestJSON: raw, AgentEndpoint: agent.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	running, err := repository.Transition(created.Run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, created.Run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := repository.Transition(running.ID, platformruntime.StatusRunning, platformruntime.StatusWaiting, running.Revision)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := repository.PrepareResume(waiting.ID, []byte(`{"approved":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDispatcher(repository, "secret", 1).dispatch(context.Background(), resumed); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	default:
		t.Fatal("resume endpoint was not invoked")
	}
	final, err := repository.Get(resumed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != platformruntime.StatusSucceeded {
		t.Fatalf("status=%s", final.Status)
	}
}

func TestDispatcherFailsClosedForInvalidEnvelope(t *testing.T) {
	repository := platformruntime.NewStore()
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "invalid-dispatch", Scope: testScope("invalid-dispatch").domain(), AgentVersionID: "v1", IdempotencyKey: "idem-invalid", Fingerprint: "fp-invalid", RequestJSON: []byte(`{"context_token":""}`), AgentEndpoint: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDispatcher(repository, "secret", 1).dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	final, err := repository.Get("invalid-dispatch")
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != platformruntime.StatusFailed {
		t.Fatalf("status=%s", final.Status)
	}
}

func TestDispatcherReconcilesAcceptedRunAfterQueueLoss(t *testing.T) {
	called := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called <- struct{}{}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"succeeded"}`))
	}))
	defer agent.Close()

	repository := platformruntime.NewStore()
	raw := legacyExecuteRequest(t, "reconcile-run", "invoke", nil)
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "reconcile-run", Scope: testScope("reconcile-run").domain(), AgentVersionID: "v1",
		IdempotencyKey: "idem-reconcile-run", Fingerprint: "fp-reconcile", RequestJSON: raw, AgentEndpoint: agent.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Do not call Enqueue: this simulates a process crash immediately after
	// the SQL transaction committed the accepted Run.
	dispatcher := NewDispatcher(repository, "secret", 1)
	ctx, cancel := context.WithCancel(context.Background())
	dispatcher.Start(ctx)
	defer cancel()
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatcher did not recover accepted run")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		final, getErr := repository.Get(created.Run.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if final.Status == platformruntime.StatusSucceeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status=%s", final.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDispatcherCannotReclaimExpiredRunningWithoutSignedStop(t *testing.T) {
	called := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called <- struct{}{}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"succeeded"}`))
	}))
	defer agent.Close()

	repository := platformruntime.NewStore()
	raw := legacyExecuteRequest(t, "expired-running", "invoke", nil)
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "expired-running", Scope: testScope("expired-running").domain(), AgentVersionID: "v1",
		IdempotencyKey: "idem-expired-running", Fingerprint: "fp-expired", RequestJSON: raw, AgentEndpoint: agent.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	running, err := repository.Transition(created.Run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, created.Run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repository.AcquireLease(running.ID, "stale-owner", time.Now().Add(-2*time.Minute), time.Minute); err != nil {
		t.Fatal(err)
	}

	dispatcher := NewDispatcher(repository, "secret", 1)
	ctx, cancel := context.WithCancel(context.Background())
	dispatcher.Start(ctx)
	defer cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		final, getErr := repository.Get(created.Run.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if final.Status == platformruntime.StatusRecovering {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status=%s", final.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-called:
		t.Fatal("unsigned old-owner recovery invoked business code")
	default:
	}
}

func TestDispatcherUsesMaterializedRuntimePolicy(t *testing.T) {
	policy := policyFromRequest([]byte(`{"input":{"policy_snapshot":{"runtime":{"max_attempts":4,"task_timeout_seconds":17,"lease_seconds":23}}}}`))
	if policy.MaxAttempts != 4 || policy.Timeout != 17*time.Second || policy.Lease != 23*time.Second {
		t.Fatalf("runtime policy was not materialized: %+v", policy)
	}
	defaults := policyFromRequest([]byte(`{"input":{}}`))
	if defaults.MaxAttempts != 1 || defaults.Timeout != 25*time.Minute || defaults.Lease != dispatcherLeaseTTL {
		t.Fatalf("invalid policy must fail closed to bounded defaults: %+v", defaults)
	}
}

func TestDispatcherStopsUncertain503WithoutRetry(t *testing.T) {
	called := 0
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer agent.Close()

	repository := platformruntime.NewStore()
	raw := legacyExecuteRequest(t, "retry-dispatch", "invoke", map[string]any{"policy_snapshot": map[string]any{"runtime": map[string]any{"max_attempts": 3, "task_timeout_seconds": 5, "lease_seconds": 30}}})
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "retry-dispatch", Scope: testScope("retry-dispatch").domain(), AgentVersionID: "v1",
		IdempotencyKey: "idem-retry-dispatch", Fingerprint: "fp-retry", RequestJSON: raw, AgentEndpoint: agent.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDispatcher(repository, "secret", 1).dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("ambiguous 503 must not replay the Agent request, calls=%d", called)
	}
	assertLegacyStopPending(t, repository, created.Run.ID, "AGENT_HTTP_RETRYABLE")
}

func TestDispatcherStopsUncertain4xxWithoutRetry(t *testing.T) {
	called := 0
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"invalid request fixture-sensitive-upstream-body"}`))
	}))
	defer agent.Close()

	repository := platformruntime.NewStore()
	raw := legacyExecuteRequest(t, "non-retry-dispatch", "invoke", map[string]any{"policy_snapshot": map[string]any{"runtime": map[string]any{"max_attempts": 3, "task_timeout_seconds": 5, "lease_seconds": 30}}})
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "non-retry-dispatch", Scope: testScope("non-retry-dispatch").domain(), AgentVersionID: "v1",
		IdempotencyKey: "idem-non-retry-dispatch", Fingerprint: "fp-non-retry", RequestJSON: raw, AgentEndpoint: agent.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDispatcher(repository, "secret", 1).dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("ambiguous 4xx must not replay the Agent request, calls=%d", called)
	}
	assertLegacyStopPending(t, repository, created.Run.ID, "AGENT_HTTP_NON_RETRYABLE")
	events, err := repository.Events(created.Run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(events)
	if strings.Contains(string(encoded), "fixture-sensitive-upstream-body") {
		t.Fatal("untrusted upstream error body leaked into durable events")
	}
}

func TestDispatcherClassifiesTimeout(t *testing.T) {
	repository := platformruntime.NewStore()
	raw := legacyExecuteRequest(t, "timeout-dispatch", "invoke", map[string]any{"policy_snapshot": map[string]any{"runtime": map[string]any{"max_attempts": 3, "task_timeout_seconds": 1, "lease_seconds": 30}}})
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "timeout-dispatch", Scope: testScope("timeout-dispatch").domain(), AgentVersionID: "v1",
		IdempotencyKey: "idem-timeout-dispatch", Fingerprint: "fp-timeout", RequestJSON: raw, AgentEndpoint: "http://agent.invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := NewDispatcher(repository, "secret", 1)
	called := 0
	dispatcher.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called++
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	if err := dispatcher.dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("ambiguous timeout must not replay the Agent request, calls=%d", called)
	}
	assertLegacyStopPending(t, repository, created.Run.ID, "AGENT_EXECUTION_TIMEOUT")
}

func TestDispatcherFailsClosedAndAuditsMalformedSuccessResponse(t *testing.T) {
	called := 0
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":`))
	}))
	defer agent.Close()

	repository := platformruntime.NewStore()
	raw := legacyExecuteRequest(t, "malformed-success", "invoke", map[string]any{"policy_snapshot": map[string]any{"runtime": map[string]any{"max_attempts": 3, "task_timeout_seconds": 5, "lease_seconds": 30}}})
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "malformed-success", Scope: testScope("malformed-success").domain(), AgentVersionID: "v1",
		IdempotencyKey: "idem-malformed-success", Fingerprint: "fp-malformed-success", RequestJSON: raw, AgentEndpoint: agent.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDispatcher(repository, "secret", 1).dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("malformed success response must not be retried, calls=%d", called)
	}
	assertLegacyStopPending(t, repository, created.Run.ID, "AGENT_CONTRACT_INVALID")
}

func TestDispatcherFailsClosedAndAuditsUnsupportedSuccessStatus(t *testing.T) {
	called := 0
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		_, _ = w.Write([]byte(`{"status":"paused_by_unknown_state_fixture-sensitive-status"}`))
	}))
	defer agent.Close()

	repository := platformruntime.NewStore()
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "unsupported-success", Scope: testScope("unsupported-success").domain(), AgentVersionID: "v1",
		IdempotencyKey: "idem-unsupported-success", Fingerprint: "fp-unsupported-success", RequestJSON: legacyExecuteRequest(t, "unsupported-success", "invoke", nil), AgentEndpoint: agent.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDispatcher(repository, "secret", 1).dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("unsupported response must not replay the Agent request, calls=%d", called)
	}
	assertLegacyStopPending(t, repository, created.Run.ID, "AGENT_CONTRACT_INVALID")
	events, err := repository.Events(created.Run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("unsupported status must be durably recorded")
	}
	encoded, _ := json.Marshal(events)
	if strings.Contains(string(encoded), "fixture-sensitive-status") {
		t.Fatal("untrusted Agent status leaked into durable events")
	}
}

func TestDispatcherSingleFlightRejectsDuplicateRunRegistration(t *testing.T) {
	dispatcher := NewDispatcher(platformruntime.NewStore(), "secret", 1)
	firstCancelled := false
	first := func() { firstCancelled = true }
	if !dispatcher.tryRegisterInflight("same-run", first) {
		t.Fatal("first registration should own the run")
	}
	second := func() {}
	if dispatcher.tryRegisterInflight("same-run", second) {
		t.Fatal("duplicate registration must be rejected")
	}
	dispatcher.unregisterInflight("same-run")
	if firstCancelled {
		t.Fatal("test cancel hook must not be invoked by registration")
	}
	if !dispatcher.tryRegisterInflight("same-run", second) {
		t.Fatal("run should be registerable after owner release")
	}
	dispatcher.unregisterInflight("same-run")
}

func TestTargetFromRunRequiresPublishedManifestHash(t *testing.T) {
	run := platformruntime.Run{
		Scope:         testScope("run-manifest").domain(),
		AgentEndpoint: "http://agent:8000",
	}
	if _, err := targetFromRun(run, contract.ExecuteRequest{}); err == nil {
		t.Fatal("dispatch target must not be synthesized without the published policy snapshot")
	} else if err != agentgateway.ErrInvalidTarget {
		t.Fatalf("missing manifest error=%v, want %v", err, agentgateway.ErrInvalidTarget)
	}

	request := contract.ExecuteRequest{Input: map[string]any{
		"policy_snapshot": map[string]any{"content_hash": "published-manifest-hash"},
	}}
	target, err := targetFromRun(run, request)
	if err != nil {
		t.Fatalf("targetFromRun() error=%v", err)
	}
	if target.ManifestHash != "published-manifest-hash" {
		t.Fatalf("manifest hash=%q", target.ManifestHash)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
