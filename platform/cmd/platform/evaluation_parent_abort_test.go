package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type evaluationAbortStore struct {
	evaluationproduct.ExecutionStore
	parent evaluationproduct.Resource
	err    error
}

func (s evaluationAbortStore) Get(context.Context, evaluationproduct.Scope, evaluationproduct.Kind, string) (evaluationproduct.Resource, error) {
	return s.parent, s.err
}

func TestEvaluationParentAbortCheckPreservesWorkerRecoveryAndRejectsForeignOwner(t *testing.T) {
	scope := sharedkernel.Scope{
		TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a",
		AgentInstanceID: "installation-a", InstallationID: "installation-a", AgentID: "agent-a", AgentVersionID: "version-a",
		PrincipalType: "user", PrincipalID: "alice", AuthorizationEpoch: 7,
		SessionID: "evaluation-session", RunID: "evaluation-child", ParentRunID: "evaluation-parent", TraceID: "evaluation-trace",
	}
	parent := evaluationproduct.Resource{ID: scope.ParentRunID, Kind: evaluationproduct.KindRun, Scope: evaluationProductScope(scope), CreatedBy: scope.PrincipalID}
	for _, state := range []string{"queued", "running", "succeeded", "cancelling", "cancelled", "failed"} {
		t.Run(state, func(t *testing.T) {
			p := parent
			p.Status = state
			authority := evaluationExecutionAuthority{products: evaluationAbortStore{parent: p}}
			aborted, err := authority.ParentAborted(context.Background(), scope)
			if err != nil || aborted != (state == "cancelling" || state == "cancelled" || state == "failed") {
				t.Fatalf("state=%s aborted=%v err=%v", state, aborted, err)
			}
		})
	}
	parent.Status = "cancelled"
	for _, mutate := range []func(*evaluationproduct.Resource){
		func(p *evaluationproduct.Resource) { p.CreatedBy = "bob" },
		func(p *evaluationproduct.Resource) { p.Scope.TenantID = "tenant-b" },
		func(p *evaluationproduct.Resource) { p.ID = "foreign-parent" },
	} {
		p := parent
		mutate(&p)
		authority := evaluationExecutionAuthority{products: evaluationAbortStore{parent: p}}
		if aborted, err := authority.ParentAborted(context.Background(), scope); err == nil || aborted {
			t.Fatal("foreign product parent could authorize cancellation")
		}
	}
	authority := evaluationExecutionAuthority{products: evaluationAbortStore{err: errors.New("store unavailable")}}
	if aborted, err := authority.ParentAborted(context.Background(), scope); err == nil || aborted {
		t.Fatal("unknown parent state was treated as explicit abort")
	}
}
