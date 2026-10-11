package execution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type recoveryDispatchRepository struct {
	*platformruntime.Store
	ref                *RecoveryStopReference
	reads              int
	changeOnSecondRead bool
}

func (r *recoveryDispatchRepository) CurrentRecoveryStopReference(context.Context, platformruntime.Run) (*RecoveryStopReference, error) {
	r.reads++
	if r.ref == nil {
		return nil, nil
	}
	copy := *r.ref
	if r.changeOnSecondRead && r.reads > 1 {
		copy.BodyHash = strings.Repeat("b", 64)
	}
	return &copy, nil
}

func recoveryDispatchFixture() (*Dispatcher, *recoveryDispatchRepository, platformruntime.Run, contract.ExecuteRequest) {
	scope := testScope("recovery-dispatch").domain()
	digest := strings.Repeat("a", 64)
	ref := &RecoveryStopReference{Version: "runtime-recovery-stop/v1", RunID: scope.RunID,
		StoppedRevision: 3, ReadyRevision: 5, Operation: "invoke", BodyHash: digest,
		PolicyHash: digest, LeaseHash: digest, RequestHash: digest, ResumeInputHash: digest,
		Source: "sdk-cancel-exit/v1", Checkpoints: []contract.RecoveryCheckpointReference{{
			StateKey: digest, Revision: 1, SchemaID: "schema://example/state/v1", ContentHash: digest,
			ExecutionRevision: 3, ExpiresAt: time.Now().UTC().Add(time.Hour),
		}}}
	repo := &recoveryDispatchRepository{Store: platformruntime.NewStore(), ref: ref}
	d := NewDispatcher(repo, "", 1)
	d.SetSecurity(&leaseAwareTestSigner{}, func(context.Context, sharedkernel.Scope) error { return nil })
	d.recoveryCheckpoint = func(context.Context, sharedkernel.Scope, contract.RecoveryCheckpointReference) (map[string]any, error) {
		return map[string]any{"version": "example/v1"}, nil
	}
	run := platformruntime.Run{ID: scope.RunID, Scope: scope, Revision: 6}
	request := contract.ExecuteRequest{Operation: "invoke", Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": digest}}}
	request.Scope.RunID = scope.RunID
	return d, repo, run, request
}

func TestRecoveryDispatchUsesCommittedReferenceWithoutMutatingBusinessInput(t *testing.T) {
	d, repo, run, request := recoveryDispatchFixture()
	ok, err := d.prepareRecoveryDispatch(context.Background(), run, &request)
	if err != nil || !ok || request.Operation != "resume" || repo.reads != 2 {
		t.Fatalf("recovery preparation: %v %v", ok, err)
	}
	if request.ResumeInput["version"] != "runtime-recovery/v1" || request.ResumeInput["origin_operation"] != "invoke" {
		t.Fatal("wrong recovery envelope")
	}
	if _, exists := request.ResumeInput["confirmation_token"]; exists {
		t.Fatal("fabricated approval")
	}
	if request.Input["policy_snapshot"].(map[string]any)["content_hash"] != repo.ref.PolicyHash || len(run.ResumeInputJSON) != 0 {
		t.Fatal("original input changed")
	}
}

func TestRecoveryDispatchRejectsLostStateRevocationAndChangedProvenance(t *testing.T) {
	for _, scenario := range []string{"missing", "expired", "revoked", "changed"} {
		t.Run(scenario, func(t *testing.T) {
			d, repo, run, request := recoveryDispatchFixture()
			switch scenario {
			case "missing":
				d.recoveryCheckpoint = func(context.Context, sharedkernel.Scope, contract.RecoveryCheckpointReference) (map[string]any, error) {
					return nil, errors.New("lost")
				}
			case "expired":
				repo.ref.Checkpoints[0].ExpiresAt = time.Now().UTC().Add(-time.Minute)
			case "revoked":
				d.authorize = func(context.Context, sharedkernel.Scope) error { return errors.New("revoked") }
			case "changed":
				repo.changeOnSecondRead = true
			}
			if ok, err := d.prepareRecoveryDispatch(context.Background(), run, &request); ok || err == nil {
				t.Fatal("unsafe recovery accepted")
			}
			if request.Operation != "invoke" || request.ResumeInput != nil {
				t.Fatal("failed preflight changed request")
			}
		})
	}
}
