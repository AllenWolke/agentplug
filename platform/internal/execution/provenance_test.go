package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestRunProvenanceIsScopedBoundedAndDurable(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("provenance-run").domain()
	scope.SessionID = "session"
	m := NewModuleWithSharedRepository("test", store)
	if result, err := m.ReadRunProvenance(context.Background(), scope); err != nil || result != nil {
		t.Fatalf("not dispatched yet: %v %v", result, err)
	}
	_, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: "v1", IdempotencyKey: "provenance", Fingerprint: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := m.ReadRunProvenance(context.Background(), scope); err != nil || result != nil {
		t.Fatalf("pending: %v %v", result, err)
	}
	claimed, err := store.AcquireLease(scope.RunID, "owner", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, "owner")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.FinalizeLeased(running.ID, platformruntime.StatusWaiting, running.Revision, running.LeaseToken, map[string]any{"provenance": map[string]any{"synthetic": true, "source_type": "synthetic", "data_source": "demo"}, "private_report": "must-not-leak"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.ReadRunProvenance(context.Background(), scope)
	if err != nil || len(result) != 3 || result["synthetic"] != true || result["data_source"] != "demo" {
		t.Fatalf("result: %v %v", result, err)
	}
	for _, mutate := range []func(*sharedkernel.Scope){
		func(s *sharedkernel.Scope) { s.TenantID = "other" },
		func(s *sharedkernel.Scope) { s.DepartmentID = "other" },
		func(s *sharedkernel.Scope) { s.ApplicationID = "other" },
		func(s *sharedkernel.Scope) { s.PrincipalID = "other" },
		func(s *sharedkernel.Scope) { s.PrincipalType = "service_principal" },
		func(s *sharedkernel.Scope) { s.AgentID = "other" },
		func(s *sharedkernel.Scope) { s.AgentInstanceID = "other" },
		func(s *sharedkernel.Scope) { s.SessionID = "other" },
	} {
		changed := scope
		mutate(&changed)
		if output, err := m.ReadRunProvenance(context.Background(), changed); !errors.Is(err, sharedkernel.ErrInvalidScope) || output != nil {
			t.Fatalf("scope bypass: %v %v", output, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.ReadRunProvenance(ctx, scope); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}
