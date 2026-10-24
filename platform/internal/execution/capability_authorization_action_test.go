package execution

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestCapabilityAuthorizationActionUsesOnlyLeaseVerifiedCommand(t *testing.T) {
	for _, mode := range []string{"internal", "business", "remote-internal-schema", "missing-lease", "wrong-body"} {
		t.Run(mode, func(t *testing.T) {
			scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentID: "indexer", AgentInstanceID: "i", InstallationID: "i", AgentVersionID: "v", SessionID: mode, RunID: mode, TraceID: strings.Repeat("b", 32), AuthorizationEpoch: 1}
			command := contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, Operation: "invoke", InputSchema: KnowledgeIndexInputSchema, IdempotencyKey: "fixture-request", Scope: contract.ScopeKey{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentID: "indexer", AgentInstanceID: "i", InstallationID: "i", AgentVersionID: "v", SessionID: mode, RunID: mode, TraceID: scope.TraceID, AuthorizationEpoch: 1}, Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": strings.Repeat("a", 64)}}}
			endpoint := ""
			if mode == "business" {
				command.InputSchema = "schema://agent/input/v1"
				endpoint = "http://agent.invalid"
			}
			if mode == "remote-internal-schema" {
				endpoint = "http://agent.invalid"
			}
			raw, _ := json.Marshal(command)
			digest, err := contract.CanonicalExecuteBodyHash(command)
			if err != nil {
				t.Fatal(err)
			}
			base := platformruntime.NewStore()
			if _, err := base.Create(platformruntime.CreateRequest{ID: mode, Scope: scope, AgentVersionID: "v", IdempotencyKey: command.IdempotencyKey, Fingerprint: digest, RequestJSON: raw, AgentEndpoint: endpoint}); err != nil {
				t.Fatal(err)
			}
			lease, err := base.AcquireLease(mode, "fixture-owner", time.Now(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			run, err := base.TransitionLeased(mode, platformruntime.StatusAccepted, platformruntime.StatusRunning, lease.Revision, lease.LeaseToken)
			if err != nil {
				t.Fatal(err)
			}
			if err := base.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: mode, Revision: run.Revision, Operation: "invoke", BodyHash: digest, PolicyHash: strings.Repeat("a", 64)}, run.LeaseToken); err != nil {
				t.Fatal(err)
			}
			ctx := sharedkernel.BindExecutionLease(context.Background(), run.Revision, run.LeaseToken)
			if mode == "missing-lease" {
				ctx = context.Background()
			}
			if mode == "wrong-body" {
				digest = strings.Repeat("c", 64)
			}
			module := NewModuleWithRepository("internal", base)
			action, err := module.CapabilityAuthorizationAction(ctx, scope, "invoke", digest, strings.Repeat("a", 64))
			if mode == "missing-lease" || mode == "wrong-body" {
				if err == nil || action != "" {
					t.Fatal("unverified command selected action")
				}
				return
			}
			expected := "run"
			if mode == "internal" {
				expected = "policy.manage"
			}
			if err != nil || action != expected {
				t.Fatal("wrong persisted command classification", err, action)
			}
		})
	}
}

type countedLiveAuthorityStore struct {
	*platformruntime.Store
	reads atomic.Int32
}

func (s *countedLiveAuthorityStore) GetContext(ctx context.Context, id string) (platformruntime.Run, error) {
	s.reads.Add(1)
	if err := ctx.Err(); err != nil {
		return platformruntime.Run{}, err
	}
	return s.Store.Get(id)
}

func TestCombinedLeaseClassificationReadsOnceAndStillDeniesFreshCancellation(t *testing.T) {
	scope := testScope("combined-authority").domain()
	base := platformruntime.NewStore()
	command := contract.ExecuteRequest{Operation: "invoke", InputSchema: KnowledgeIndexInputSchema}
	raw, _ := json.Marshal(command)
	_, err := base.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID,
		IdempotencyKey: "combined", Fingerprint: "fixture", RequestJSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := base.AcquireLease(scope.RunID, "owner", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	run, err := base.TransitionLeased(scope.RunID, platformruntime.StatusAccepted, platformruntime.StatusRunning, lease.Revision, lease.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	body, policy := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := base.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: scope.RunID, Revision: run.Revision,
		Operation: "invoke", BodyHash: body, PolicyHash: policy}, run.LeaseToken); err != nil {
		t.Fatal(err)
	}
	store := &countedLiveAuthorityStore{Store: base}
	module := NewModuleWithRepository("internal", store)
	ctx := sharedkernel.BindExecutionLease(context.Background(), run.Revision, run.LeaseToken)
	for i := 1; i <= 2; i++ {
		action, err := module.ValidateLiveLeaseAndAction(ctx, scope, "invoke", body, policy)
		if err != nil || action != "policy.manage" || store.reads.Load() != int32(i) {
			t.Fatal(action, err, store.reads.Load())
		}
	}
	if _, err := base.Cancel(scope.RunID, run.Revision); err != nil {
		t.Fatal(err)
	}
	if action, err := module.ValidateLiveLeaseAndAction(ctx, scope, "invoke", body, policy); err == nil || action != "" || store.reads.Load() != 3 {
		t.Fatal("later fence reused earlier authorization", action, err, store.reads.Load())
	}
}
