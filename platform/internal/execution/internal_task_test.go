package execution

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type internalTaskFinalizeFaultRepository struct {
	Repository
	err error
}

func (r internalTaskFinalizeFaultRepository) FinalizeLeased(string, platformruntime.Status, uint64, string, map[string]any, map[string]any) (platformruntime.Run, error) {
	return platformruntime.Run{}, r.err
}

func TestInternalTaskSupervisorReusesLeaseHeartbeatAndOutcome(t *testing.T) {
	for _, mode := range []string{"success", "heartbeat-fault", "revocation", "work-failure", "finalize-failure", "forged-lease"} {
		t.Run(mode, func(t *testing.T) {
			base := platformruntime.NewStore()
			scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentID: "indexer", AgentInstanceID: "instance", InstallationID: "install", AgentVersionID: "v1", SessionID: mode, RunID: mode, TraceID: "trace", AuthorizationEpoch: 1}
			if _, err := base.Create(platformruntime.CreateRequest{ID: mode, Scope: scope, AgentVersionID: "v1", IdempotencyKey: mode, Fingerprint: "fixture"}); err != nil {
				t.Fatal(err)
			}
			claim, err := base.AcquireLease(mode, "private-owner", time.Now().UTC(), 120*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			run, err := base.TransitionLeased(mode, platformruntime.StatusAccepted, platformruntime.StatusRunning, claim.Revision, claim.LeaseToken)
			if err != nil {
				t.Fatal(err)
			}
			heartbeatRepo := &heartbeatFaultRepository{Repository: base}
			var repo Repository = heartbeatRepo
			if mode == "finalize-failure" {
				repo = internalTaskFinalizeFaultRepository{Repository: base, err: errors.New("private finalization detail")}
			}
			var revoked atomic.Bool
			denied := errors.New("revoked")
			workFailure := errors.New("controlled outage")
			calls := 0
			s := InternalTaskSupervisor{Repository: repo, LeaseTTL: 120 * time.Millisecond, Authorize: func(_ context.Context, current sharedkernel.Scope) error {
				if current != scope {
					t.Fatal("changed owner")
				}
				if revoked.Load() {
					return denied
				}
				return nil
			}, Execute: func(ctx context.Context, current platformruntime.Run) (map[string]any, error) {
				calls++
				if current.Revision != run.Revision || current.LeaseToken != run.LeaseToken {
					t.Fatal("lost lease")
				}
				if mode == "work-failure" {
					return nil, workFailure
				}
				if mode == "heartbeat-fault" {
					heartbeatRepo.fail.Store(true)
				}
				if mode == "revocation" {
					revoked.Store(true)
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(180 * time.Millisecond):
					return map[string]any{"schema_version": "fixture/v1", "generation_id": "generation"}, nil
				}
			}}
			if mode == "forged-lease" {
				run.LeaseToken = "foreign"
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = s.Run(ctx, run)
			current, getErr := base.Get(mode)
			if getErr != nil {
				t.Fatal(getErr)
			}
			if mode == "success" {
				outcome, outErr := base.GetOutcome(mode)
				if err != nil || current.Status != platformruntime.StatusSucceeded || outcome.Revision != current.Revision || outErr != nil || calls != 1 {
					t.Fatal("no durable success", current.Status, err, outErr)
				}
			} else {
				if err == nil || current.Status != platformruntime.StatusRunning {
					t.Fatal("failed task finalized", current.Status, err)
				}
				if mode == "work-failure" || mode == "finalize-failure" {
					var phased interface{ InternalTaskPhase() string }
					if !errors.As(err, &phased) {
						t.Fatalf("missing safe phase classification: %T", err)
					}
					wantPhase := "execute"
					if mode == "finalize-failure" {
						wantPhase = "finalize"
						if strings.Contains(err.Error(), "private finalization detail") {
							t.Fatal("phase error exposed its cause")
						}
					}
					if got := phased.InternalTaskPhase(); got != wantPhase {
						t.Fatalf("phase = %q, want %q", got, wantPhase)
					}
				}
				if mode == "forged-lease" && calls != 0 {
					t.Fatal("foreign owner executed")
				}
				if mode == "work-failure" && !errors.Is(err, workFailure) {
					t.Fatal(err)
				}
			}
		})
	}
}
