package execution

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type resumeRenewalReferenceRepository struct {
	*platformruntime.Store
	recovery          *RecoveryStopReference
	group             *AgentGroupWaitReference
	resumeInputAbsent bool
}

func (r *resumeRenewalReferenceRepository) Get(id string) (platformruntime.Run, error) {
	run, err := r.Store.Get(id)
	if err == nil && r.resumeInputAbsent && id == run.ID {
		run.ResumeInputJSON = nil
	}
	return run, err
}

func (r *resumeRenewalReferenceRepository) CurrentRecoveryStopReference(context.Context, platformruntime.Run) (*RecoveryStopReference, error) {
	if r.recovery == nil {
		return nil, nil
	}
	copy := *r.recovery
	return &copy, nil
}

func (r *resumeRenewalReferenceRepository) CurrentAgentGroupResumeReference(context.Context, platformruntime.Run) (*AgentGroupWaitReference, error) {
	if r.group == nil {
		return nil, nil
	}
	copy := *r.group
	return &copy, nil
}

type resumeRenewalCase struct {
	module     *Module
	dispatcher *Dispatcher
	store      *platformruntime.Store
	repository *resumeRenewalReferenceRepository
	running    platformruntime.Run
	approved   bool
	group      bool
	policyHash string
}

func newResumeRenewalCase(t *testing.T, kind string) resumeRenewalCase {
	t.Helper()
	store := platformruntime.NewStore()
	scope := testScope("renew-envelope-" + kind)
	requestBody := gatewayRequest(t, scope, "run")
	var original contract.ExecuteRequest
	if err := json.Unmarshal(requestBody, &original); err != nil {
		t.Fatal(err)
	}
	policyHash := original.Input["policy_snapshot"].(map[string]any)["content_hash"].(string)
	marker := []byte(`{}`)
	stateBySchema := map[string]map[string]any{
		"schema://example/state/v1": {"version": "example/v1"},
	}
	var group *AgentGroupWaitReference
	approved := false
	switch kind {
	case "runtime-recovery-approved":
		approved = true
		checkpointHash := strings.Repeat("b", 64)
		checkpoint := contract.RecoveryCheckpointReference{StateKey: strings.Repeat("a", 64), Revision: 2,
			SchemaID: "schema://agentplug/harness-loop/v1", ContentHash: checkpointHash,
			ExecutionRevision: 1, ExpiresAt: time.Now().UTC().Add(time.Hour)}
		claims := ApprovedToolResumeClaims{Version: "tool-confirmation/v1", ApprovalID: "approval-id", ActorID: scope.PrincipalID,
			ScopeHash: strings.Repeat("c", 64), AuthorizationEpoch: scope.AuthorizationEpoch, PolicyHash: policyHash,
			ToolName: "clock.now", CallID: "call-1", Fingerprint: strings.Repeat("d", 64),
			IssuedAt: time.Now().UTC().Unix(), ExpiresAt: time.Now().UTC().Add(time.Minute).Unix(), PendingKey: "harness", CheckpointRevision: 2}
		resume := ApprovedToolResume{Version: "harness-tool-resume/v1", WaitingRevision: 2, Claims: claims,
			Handoff: contract.HandlerHandoff{Version: "sdk-handler-exit/v1", RunID: scope.RunID, ExecutionRevision: 1,
				HarnessKey: "harness", ToolName: "clock.now", CallID: "call-1"}, CheckpointHash: checkpointHash}
		var err error
		marker, err = json.Marshal(resume)
		if err != nil {
			t.Fatal(err)
		}
		stateBySchema[checkpoint.SchemaID] = map[string]any{"version": "harness-loop/v1", "phase": "approval_required", "pending": []any{map[string]any{
			"name": "clock.now", "call_id": "call-1", "payload": map[string]any{"timezone": "UTC"}, "model_call_id": "model-call-1", "run_id": scope.RunID,
		}}}
	case "runtime-recovery-group", "group-resume":
		digest := strings.Repeat("a", 64)
		checkpoint := contract.RecoveryCheckpointReference{StateKey: digest, Revision: 1,
			SchemaID: "schema://agentplug/agent-group/v1", ContentHash: strings.Repeat("b", 64),
			ExecutionRevision: 3, ExpiresAt: time.Now().UTC().Add(time.Hour)}
		handoff := contract.AgentGroupHandoff{Version: "sdk-agent-group-exit/v1", RunID: scope.RunID, ExecutionRevision: 3,
			BodyHash: strings.Repeat("c", 64), LeaseTokenHash: strings.Repeat("d", 64), InputFingerprint: strings.Repeat("e", 64),
			OriginOperation: "invoke", GroupKey: "group-key", OperationKey: "operation-key", LastEventSeq: (2 << 20) + 1,
			Checkpoint: checkpoint, ChildKeys: []string{digest}}
		group = &AgentGroupWaitReference{Version: "agent-group-resume/v1", OriginOperation: "invoke", WaitingRevision: 4,
			Handoff: handoff, Checkpoints: []contract.RecoveryCheckpointReference{checkpoint}}
		var err error
		marker, err = json.Marshal(group)
		if err != nil {
			t.Fatal(err)
		}
		stateBySchema[checkpoint.SchemaID] = map[string]any{"version": "agent-group/v1", "phase": "gather", "parent_run_id": scope.RunID,
			"group_key": handoff.GroupKey, "operation_key": handoff.OperationKey, "input_fingerprint": handoff.InputFingerprint,
			"bindings": []any{map[string]any{"child_key": digest}},
		}
	case "runtime-recovery":
	default:
		t.Fatalf("unknown renewal fixture kind %q", kind)
	}
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1",
		IdempotencyKey: "renew-envelope-key", Fingerprint: "renew-envelope-fingerprint", RequestJSON: requestBody})
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
	resumed, err := store.PrepareResume(waiting.ID, marker)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = store.AcquireLease(resumed.ID, "intermediate-worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	waiting, err = store.TransitionLeased(claimed.ID, platformruntime.StatusRunning, platformruntime.StatusWaiting, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err = store.PrepareResume(waiting.ID, marker)
	if err != nil {
		t.Fatal(err)
	}
	running, err = store.AcquireLease(resumed.ID, "current-worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err = store.Get(running.ID)
	if err != nil {
		t.Fatal(err)
	}
	if running.Revision != 9 {
		t.Fatalf("unexpected fixture generation revision: %d", running.Revision)
	}
	resumeInputHash := stopHash(running.ResumeInputJSON)
	requestHash := stopHash(running.RequestJSON)
	checkpointRefs := []contract.RecoveryCheckpointReference{{StateKey: strings.Repeat("f", 64), Revision: 1,
		SchemaID: "schema://example/state/v1", ContentHash: strings.Repeat("1", 64), ExecutionRevision: 1,
		ExpiresAt: time.Now().UTC().Add(time.Hour)}}
	if kind == "runtime-recovery-approved" {
		var resume ApprovedToolResume
		if json.Unmarshal(marker, &resume) != nil {
			t.Fatal("invalid approved fixture")
		}
		checkpointRefs = []contract.RecoveryCheckpointReference{{StateKey: strings.Repeat("a", 64), Revision: resume.Claims.CheckpointRevision,
			SchemaID: "schema://agentplug/harness-loop/v1", ContentHash: resume.CheckpointHash, ExecutionRevision: resume.Handoff.ExecutionRevision,
			ExpiresAt: time.Now().UTC().Add(time.Hour)}}
	}
	if kind == "runtime-recovery-group" {
		checkpointRefs = append([]contract.RecoveryCheckpointReference(nil), group.Checkpoints...)
	}
	recovery := &RecoveryStopReference{Version: "runtime-recovery-stop/v1", RunID: scope.RunID,
		StoppedRevision: 6, ReadyRevision: 8, Operation: "resume", BodyHash: strings.Repeat("2", 64), PolicyHash: policyHash,
		LeaseHash: strings.Repeat("3", 64), RequestHash: requestHash, ResumeInputHash: resumeInputHash,
		Source: "sdk-cancel-exit/v1", Checkpoints: checkpointRefs}
	if kind == "group-resume" {
		recovery = nil
	}
	repository := &resumeRenewalReferenceRepository{Store: store, recovery: recovery, resumeInputAbsent: kind == "runtime-recovery"}
	if kind == "runtime-recovery" {
		recovery.ResumeInputHash = stopHash(nil)
	}
	if kind == "group-resume" {
		repository.group = group
	}
	dispatcher := NewDispatcher(repository, "", 1)
	signer := &leaseAwareTestSigner{}
	dispatcher.SetSecurity(signer, func(context.Context, sharedkernel.Scope) error { return nil })
	dispatcher.recoveryCheckpoint = func(_ context.Context, _ sharedkernel.Scope, checkpoint contract.RecoveryCheckpointReference) (map[string]any, error) {
		if value := stateBySchema[checkpoint.SchemaID]; value != nil {
			return value, nil
		}
		return map[string]any{"version": "example/v1"}, nil
	}
	dispatcher.recoveryCheckpointRenewal = dispatcher.recoveryCheckpoint
	if approved {
		dispatcher.approvedResume = func(context.Context, sharedkernel.Scope, json.RawMessage) (map[string]any, error) {
			return map[string]any{"confirmation_token": "transient-signed-confirmation", "checkpoint": map[string]any{"revision": 2}}, nil
		}
		dispatcher.approvedResumeRenewal = func(context.Context, sharedkernel.Scope, json.RawMessage) (map[string]any, error) {
			return map[string]any{"confirmation_token": "transient-signed-confirmation", "checkpoint": map[string]any{"revision": 2}}, nil
		}
	}
	module := NewModuleWithSharedRepository("", repository)
	module.dispatcher = dispatcher
	return resumeRenewalCase{module: module, dispatcher: dispatcher, store: store, repository: repository,
		running: running, approved: approved, group: group != nil, policyHash: policyHash}
}

func (f resumeRenewalCase) expectedDispatchRequest(t *testing.T) contract.ExecuteRequest {
	t.Helper()
	var request contract.ExecuteRequest
	run, err := f.repository.Get(f.running.ID)
	if err != nil || json.Unmarshal(run.RequestJSON, &request) != nil {
		t.Fatal("could not rebuild baseline request", err)
	}
	request.Operation = "resume"
	if len(run.ResumeInputJSON) > 0 {
		if json.Unmarshal(run.ResumeInputJSON, &request.ResumeInput) != nil {
			t.Fatal("could not decode durable resume input")
		}
	}
	return request
}

func TestCapabilityRenewalRebuildsRuntimeRecoveryAndGroupEnvelopes(t *testing.T) {
	for _, kind := range []string{"runtime-recovery", "runtime-recovery-approved", "runtime-recovery-group", "group-resume"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newResumeRenewalCase(t, kind)
			run, err := fixture.repository.Get(fixture.running.ID)
			if err != nil {
				t.Fatal(err)
			}
			dispatchRequest := fixture.expectedDispatchRequest(t)
			if kind == "group-resume" {
				recovered, recoveryErr := fixture.dispatcher.prepareRecoveryDispatch(context.Background(), run, &dispatchRequest)
				if recoveryErr != nil || recovered {
					t.Fatalf("unexpected runtime recovery source: recovered=%t err=%v", recovered, recoveryErr)
				}
				grouped, groupErr := fixture.dispatcher.prepareAgentGroupResume(context.Background(), run, &dispatchRequest)
				if groupErr != nil || !grouped {
					t.Fatalf("group dispatch preparation failed: grouped=%t err=%v", grouped, groupErr)
				}
			} else {
				if fixture.repository.recovery == nil || !fixture.repository.recovery.valid() {
					t.Fatalf("invalid recovery fixture: ref=%+v", fixture.repository.recovery)
				}
				if fixture.repository.recovery.ReadyRevision+1 != run.Revision {
					t.Fatalf("recovery generation mismatch: ready=%d run=%d", fixture.repository.recovery.ReadyRevision, run.Revision)
				}
				recovered, recoveryErr := fixture.dispatcher.prepareRecoveryDispatch(context.Background(), run, &dispatchRequest)
				if recoveryErr != nil || !recovered {
					t.Fatalf("runtime recovery preparation failed: recovered=%t err=%v", recovered, recoveryErr)
				}
			}
			dispatchHash, err := contract.CanonicalExecuteBodyHash(dispatchRequest)
			if err != nil {
				t.Fatal(err)
			}
			command := platformruntime.DispatchCommand{RunID: run.ID, Revision: run.Revision, Operation: "resume", BodyHash: dispatchHash, PolicyHash: fixture.policyHash}
			if err := fixture.store.RecordDispatchCommand(command, run.LeaseToken); err != nil {
				t.Fatal(err)
			}
			ctx := sharedkernel.BindExecutionLease(context.Background(), run.Revision, run.LeaseToken)
			if _, err := fixture.module.RenewCapabilityToken(ctx, run.Scope, "resume", dispatchHash, fixture.policyHash); err != nil {
				t.Fatalf("resume envelope renewal failed: %v", err)
			}
			actualHash, err := contract.CanonicalExecuteBodyHash(fixture.dispatcher.signer.(*leaseAwareTestSigner).request)
			if err != nil || actualHash != dispatchHash {
				t.Fatalf("renewed body differs from the dispatched command: got=%q want=%q err=%v", actualHash, dispatchHash, err)
			}
			latest, err := fixture.store.Get(run.ID)
			if err != nil || strings.Contains(string(latest.ResumeInputJSON), "transient-signed-confirmation") {
				t.Fatal("transient confirmation token was persisted in durable Run data")
			}
		})
	}
}

func TestResumeRenewalRequiresCurrentApprovedResumeResolver(t *testing.T) {
	fixture := newResumeRenewalCase(t, "runtime-recovery-approved")
	run, err := fixture.repository.Get(fixture.running.ID)
	if err != nil {
		t.Fatal(err)
	}
	dispatchRequest := fixture.expectedDispatchRequest(t)
	if recovered, err := fixture.dispatcher.prepareRecoveryDispatch(context.Background(), run, &dispatchRequest); err != nil || !recovered {
		t.Fatalf("approved recovery dispatch preparation failed: recovered=%t err=%v", recovered, err)
	}
	bodyHash, err := contract.CanonicalExecuteBodyHash(dispatchRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: run.ID, Revision: run.Revision, Operation: "resume", BodyHash: bodyHash, PolicyHash: fixture.policyHash}, run.LeaseToken); err != nil {
		t.Fatal(err)
	}
	fixture.dispatcher.approvedResumeRenewal = nil
	ctx := sharedkernel.BindExecutionLease(context.Background(), run.Revision, run.LeaseToken)
	if _, err := fixture.module.RenewCapabilityToken(ctx, run.Scope, "resume", bodyHash, fixture.policyHash); err == nil {
		t.Fatal("renewal reused the dispatch-only approval resolver")
	}
	if fixture.dispatcher.signer.(*leaseAwareTestSigner).calls != 0 {
		t.Fatal("missing renewal approval authority had signing side effects")
	}
}
