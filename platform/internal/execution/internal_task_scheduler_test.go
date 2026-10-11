package execution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type internalQueueFixture struct {
	Repository
	ids []string
}

func (q internalQueueFixture) ListInternalPending(context.Context, string, int) ([]string, error) {
	return q.ids, nil
}

func TestInternalTaskSchedulerClaimsOnlyOwnedPendingCommands(t *testing.T) {
	for _, mode := range []string{"accepted", "duplicate", "revoked", "revoked-after-claim", "foreign-scope", "remote-agent", "expired-owner", "retained-token", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			base := platformruntime.NewStore()
			scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentID: "indexer", AgentInstanceID: "i", InstallationID: "i", AgentVersionID: "v1", SessionID: mode, RunID: mode, TraceID: "trace", AuthorizationEpoch: 1}
			request := contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, Operation: "invoke", InputSchema: KnowledgeIndexInputSchema, IdempotencyKey: mode, Scope: contract.ScopeKey{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentID: "indexer", AgentInstanceID: "i", InstallationID: "i", AgentVersionID: "v1", SessionID: mode, RunID: mode, TraceID: "trace", AuthorizationEpoch: 1}, Input: map[string]any{"knowledge_id": "docs"}}
			if mode == "foreign-scope" {
				request.Scope.PrincipalID = "foreign"
			}
			if mode == "retained-token" {
				request.ContextToken = "stale"
			}
			raw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := ""
			if mode == "remote-agent" {
				endpoint = "http://agent.invalid"
			}
			if _, err := base.Create(platformruntime.CreateRequest{ID: mode, Scope: scope, AgentVersionID: "v1", IdempotencyKey: mode, Fingerprint: "fixture", RequestJSON: raw, AgentEndpoint: endpoint}); err != nil {
				t.Fatal(err)
			}
			if mode == "expired-owner" {
				lease, err := base.AcquireLease(mode, "old-owner", time.Now(), 50*time.Millisecond)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := base.TransitionLeased(mode, platformruntime.StatusAccepted, platformruntime.StatusRunning, lease.Revision, lease.LeaseToken); err != nil {
					t.Fatal(err)
				}
				time.Sleep(60 * time.Millisecond)
			}
			checks, calls := 0, 0
			denied := errors.New("management revoked")
			authorize := func(context.Context, sharedkernel.Scope) error {
				checks++
				if mode == "revoked" || (mode == "revoked-after-claim" && checks > 1) {
					return denied
				}
				return nil
			}
			queue := internalQueueFixture{Repository: base, ids: []string{mode}}
			scheduler := InternalTaskScheduler{Repository: queue, InputSchema: KnowledgeIndexInputSchema, LeaseTTL: time.Minute, Authorize: authorize, Execute: func(ctx context.Context, run platformruntime.Run) error {
				calls++
				return (InternalTaskSupervisor{Repository: base, LeaseTTL: time.Minute, Authorize: authorize, Execute: func(context.Context, platformruntime.Run) (map[string]any, error) {
					return map[string]any{"receipt": "done"}, nil
				}}).Run(ctx, run)
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			err = scheduler.Dispatch(ctx, mode)
			if mode == "accepted" || mode == "duplicate" {
				if err != nil || calls != 1 {
					t.Fatal("not scheduled", err, calls)
				}
				if mode == "duplicate" {
					if err := scheduler.Dispatch(ctx, mode); !errors.Is(err, platformruntime.ErrLeaseConflict) || calls != 1 {
						t.Fatal("duplicate reexecuted", err, calls)
					}
				}
				finished, err := base.Get(mode)
				if err != nil || finished.Status != platformruntime.StatusSucceeded {
					t.Fatal("missing durable result", err)
				}
			} else if err == nil || calls != 0 {
				t.Fatal("invalid command executed", err, calls)
			}
		})
	}
}
