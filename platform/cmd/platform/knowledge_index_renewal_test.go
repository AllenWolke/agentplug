package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestIndexModelRenewalPinsAuthorityAndWorkerLifetime(t *testing.T) {
	for _, mode := range []string{"renewed", "revoked", "foreign-scope", "changed-policy", "closed", "batch-canceled", "wrong-operation"} {
		t.Run(mode, func(t *testing.T) {
			scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentID: "agent", AgentInstanceID: "i", InstallationID: "i", AgentVersionID: "v", SessionID: "s", RunID: "r", TraceID: "trace", AuthorizationEpoch: 1}
			policy := policyasset.Snapshot{Hash: "immutable", Model: policyasset.ModelPolicy{ModelVersionID: "embedding-v1", Provider: "vectors", Model: "vectors"}}
			opens, closes, calls := 0, 0, 0
			var latestClosed *atomic.Bool
			open := func(ctx context.Context) (capability.TaskEmbeddingSession, error) {
				opens++
				if mode == "revoked" && opens > 1 {
					return capability.TaskEmbeddingSession{}, identity.ErrPermissionDenied
				}
				owner, snapshot := scope, policy
				if opens > 1 && mode == "foreign-scope" {
					owner.RunID = "foreign"
				}
				if opens > 1 && mode == "changed-policy" {
					snapshot.Model.ModelVersionID = "unapproved"
				}
				closed := &atomic.Bool{}
				latestClosed = closed
				check := func(context.Context, string) error {
					if err := ctx.Err(); err != nil {
						return err
					}
					if closed.Load() {
						return context.Canceled
					}
					return nil
				}
				return capability.TaskEmbeddingSession{Scope: owner, Policy: snapshot, Check: check, Call: func(c context.Context, op string, input map[string]any) (map[string]any, error) {
					if err := check(c, op); err != nil {
						return nil, err
					}
					calls++
					return map[string]any{"receipt": opens}, nil
				}, Close: func() {
					if closed.CompareAndSwap(false, true) {
						closes++
					}
				}}, nil
			}
			models, closeModels, err := renewingIndexModels(context.Background(), scope, open)
			if err != nil {
				t.Fatal(err)
			}
			defer closeModels()
			if err := models.request.ModelCheck(context.Background(), "embed"); err != nil || opens != 1 {
				t.Fatal("check issued context", err, opens)
			}
			if mode == "closed" {
				closeModels()
				closeModels()
			}
			batch, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "batch-canceled" {
				cancel()
			}
			op := "embed"
			if mode == "wrong-operation" {
				op = "generate"
			}
			if mode == "renewed" {
				// Expired prior context must be replaced before the next batch.
				latestClosed.Store(true)
			}
			_, err = models.request.ModelCall(batch, op, map[string]any{"texts": []string{"doc"}})
			if mode != "renewed" {
				if err == nil || calls != 0 {
					t.Fatal("invalid renewal sent model", err, calls)
				}
				if mode == "revoked" && !errors.Is(err, identity.ErrPermissionDenied) {
					t.Fatal(err)
				}
				if (mode == "closed" || mode == "batch-canceled" || mode == "wrong-operation") && opens != 1 {
					t.Fatal("invalid operation issued session")
				}
				return
			}
			if err != nil || opens != 2 || calls != 1 {
				t.Fatal("batch did not renew", err, opens, calls)
			}
			cancel()
			// Ending the batch must not end the session used by later SQL guards.
			if err := models.request.ModelCheck(context.Background(), "embed"); err != nil || opens != 2 {
				t.Fatal("batch cancellation invalidated worker session", err)
			}
			if _, err := models.request.ModelCall(context.Background(), "embed", nil); err != nil || opens != 3 || calls != 2 {
				t.Fatal("second renewal", err, opens, calls)
			}
			closeModels()
			closeModels()
			if err := models.request.ModelCheck(context.Background(), "embed"); !errors.Is(err, context.Canceled) {
				t.Fatal("closed worker survived", err)
			}
			if closes != 2 {
				t.Fatal("live replacement sessions leaked", closes)
			}
		})
	}
}
