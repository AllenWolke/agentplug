package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type leaseAwareTestSigner struct {
	calls   int
	request contract.ExecuteRequest
}

func (s *leaseAwareTestSigner) Sign(ctx context.Context, _ sharedkernel.Scope, request contract.ExecuteRequest) (string, error) {
	if _, ok := sharedkernel.ExecutionLeaseFromContext(ctx); !ok {
		return "", errors.New("lease proof missing")
	}
	s.calls++
	s.request = request
	return "renewed-test-token", nil
}

func TestCapabilityRenewalRechecksLeaseCommandAndAuthorization(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("renewal-run")
	body := gatewayRequest(t, scope, "invoke")
	var request contract.ExecuteRequest
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	request.Input["numeric_evidence"] = map[string]any{"coverage": json.Number("1.0"), "source_id": json.Number("9007199254740993")}
	var encodeErr error
	body, encodeErr = json.Marshal(request)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "renewal-key", Fingerprint: "fp", RequestJSON: body})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(created.Run.ID, "current-worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil {
		t.Fatal(err)
	}
	policy := request.Input["policy_snapshot"].(map[string]any)["content_hash"].(string)
	command := platformruntime.DispatchCommand{RunID: running.ID, Revision: running.Revision, Operation: "invoke", BodyHash: hash, PolicyHash: policy}
	if err := store.RecordDispatchCommand(command, running.LeaseToken); err != nil {
		t.Fatal(err)
	}
	signer := &leaseAwareTestSigner{}
	m := NewModuleWithSharedRepository("", store)
	m.dispatcher = NewDispatcher(store, "", 1)
	allowed := true
	authorizationChecks := 0
	m.dispatcher.SetSecurity(signer, func(context.Context, sharedkernel.Scope) error {
		authorizationChecks++
		if !allowed {
			return errors.New("revoked")
		}
		return nil
	})
	ctx := sharedkernel.BindExecutionLease(context.Background(), running.Revision, running.LeaseToken)
	if token, err := m.RenewCapabilityToken(ctx, running.Scope, "invoke", hash, policy); err != nil || token != "renewed-test-token" || authorizationChecks != 1 {
		t.Fatal("current execution renewal failed", err)
	}
	numbers := signer.request.Input["numeric_evidence"].(map[string]any)
	if numbers["coverage"] != json.Number("1.0") || numbers["source_id"] != json.Number("9007199254740993") {
		t.Fatal("capability renewal changed original evidence")
	}
	allowed = false
	if _, err := m.RenewCapabilityToken(ctx, running.Scope, "invoke", hash, policy); err == nil {
		t.Fatal("revoked execution renewed")
	}
	allowed = true
	if _, err := m.RenewCapabilityToken(sharedkernel.BindExecutionLease(context.Background(), running.Revision, "foreign-worker"), running.Scope, "invoke", hash, policy); err == nil {
		t.Fatal("foreign lease renewed")
	}
	changed := running.Scope
	changed.SessionID = "another-session"
	if _, err := m.RenewCapabilityToken(ctx, changed, "invoke", hash, policy); err == nil {
		t.Fatal("foreign session renewed")
	}
	if _, err := m.RenewCapabilityToken(ctx, running.Scope, "resume", hash, policy); err == nil {
		t.Fatal("different command renewed")
	}
	if _, err := store.Cancel(running.ID, running.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RenewCapabilityToken(ctx, running.Scope, "invoke", hash, policy); err == nil {
		t.Fatal("cancelled execution renewed")
	}
	if signer.calls != 1 {
		t.Fatalf("denials had signing side effects: %d", signer.calls)
	}
}

func TestCapabilityRenewalRebuildsApprovedResumeEnvelope(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("approved-resume-renewal")
	requestBody := gatewayRequest(t, scope, "run")
	var request contract.ExecuteRequest
	if err := json.Unmarshal(requestBody, &request); err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(platformruntime.CreateRequest{
		ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "approved-resume-key",
		Fingerprint: "approved-resume-fingerprint", RequestJSON: requestBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(created.Run.ID, "initial-worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := store.TransitionLeased(running.ID, platformruntime.StatusRunning, platformruntime.StatusWaiting, running.Revision, running.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	durableResume := json.RawMessage(`{"version":"harness-tool-resume/v1","reference":"committed-approval"}`)
	resumed, err := store.PrepareResume(waiting.ID, durableResume)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err = store.AcquireLease(resumed.ID, "resume-worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// This is the exact transient envelope returned by the production resolver:
	// the confirmation token is present only in the signed command, not Run JSON.
	resolvedResume := map[string]any{
		"confirmation_token": "transient-approved-token",
		"handoff":            map[string]any{"version": "sdk-handler-exit/v1"},
		"checkpoint":         map[string]any{"namespace": "harness", "key": "pending-key"},
	}
	request.ContextToken = ""
	request.Operation = "resume"
	request.ResumeInput = resolvedResume
	bodyHash, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil {
		t.Fatal(err)
	}
	policy := request.Input["policy_snapshot"].(map[string]any)["content_hash"].(string)
	command := platformruntime.DispatchCommand{RunID: resumed.ID, Revision: resumed.Revision, Operation: "resume", BodyHash: bodyHash, PolicyHash: policy}
	if err := store.RecordDispatchCommand(command, resumed.LeaseToken); err != nil {
		t.Fatal(err)
	}

	signer := &leaseAwareTestSigner{}
	module := NewModuleWithSharedRepository("", store)
	module.dispatcher = NewDispatcher(store, "", 1)
	module.dispatcher.SetSecurity(signer, func(context.Context, sharedkernel.Scope) error { return nil })
	dispatchResolverCalls := 0
	module.SetApprovedResumeResolver(func(context.Context, sharedkernel.Scope, json.RawMessage) (map[string]any, error) {
		dispatchResolverCalls++
		return nil, errors.New("dispatch requires the current approval head")
	})
	ctx := sharedkernel.BindExecutionLease(context.Background(), resumed.Revision, resumed.LeaseToken)
	if _, err := module.RenewCapabilityToken(ctx, resumed.Scope, "resume", bodyHash, policy); err == nil || signer.calls != 0 || dispatchResolverCalls != 0 {
		t.Fatal("renewal reused the stricter dispatch resolver or proceeded without its own resolver")
	}
	resolverCalls := 0
	module.SetApprovedResumeRenewalResolver(func(_ context.Context, gotScope sharedkernel.Scope, raw json.RawMessage) (map[string]any, error) {
		resolverCalls++
		if gotScope != resumed.Scope || !bytes.Equal(raw, durableResume) {
			return nil, errors.New("unexpected approval reference")
		}
		return resolvedResume, nil
	})
	if token, err := module.RenewCapabilityToken(ctx, resumed.Scope, "resume", bodyHash, policy); err != nil || token != "renewed-test-token" {
		t.Fatalf("approved resume renewal failed: token=%q err=%v", token, err)
	}
	actualHash, err := contract.CanonicalExecuteBodyHash(signer.request)
	if err != nil || actualHash != bodyHash || resolverCalls != 1 || dispatchResolverCalls != 0 || signer.request.ResumeInput["confirmation_token"] != "transient-approved-token" {
		t.Fatalf("renewal did not bind the resolved resume command: hash=%q err=%v renewal_calls=%d dispatch_calls=%d", actualHash, err, resolverCalls, dispatchResolverCalls)
	}
	latest, err := store.Get(resumed.ID)
	if err != nil || bytes.Contains(latest.ResumeInputJSON, []byte("transient-approved-token")) {
		t.Fatal("transient confirmation token was persisted in the Run")
	}

	before := signer.calls
	module.SetApprovedResumeRenewalResolver(func(context.Context, sharedkernel.Scope, json.RawMessage) (map[string]any, error) {
		return nil, errors.New("approval is no longer current")
	})
	if _, err := module.RenewCapabilityToken(ctx, resumed.Scope, "resume", bodyHash, policy); err == nil || signer.calls != before {
		t.Fatal("renewal bypassed a failed current-approval recheck")
	}
}
