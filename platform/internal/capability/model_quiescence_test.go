package capability

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestModelQuiescenceRetainsUnsettledCallsWithoutResending(t *testing.T) {
	for _, mode := range []string{"empty", "running", "reconcile", "completed", "failed", "unsupported", "cancelled-context", "invalid-scope", "foreign-session"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "indexer", AgentInstanceID: "instance", InstallationID: "install", AgentVersionID: "v1", PrincipalID: "u", PrincipalType: "user", SessionID: "session", RunID: "run", TraceID: "trace", AuthorizationEpoch: 1}
			store := newMemoryModelInvocationStore()
			module := &Module{modelStore: store}
			hash := capabilityScopeHash(harnessContext{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "indexer", AgentInstanceID: "instance", InstallationID: "install", AgentVersionID: "v1", ActorID: "u", PrincipalType: "user", SessionID: "session"})
			if mode != "empty" {
				if _, _, err := store.Reserve(ctx, hash, "call", "fingerprint", 0, 0); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "reconcile":
				if err := store.MarkReconciliationNeeded(ctx, hash, "call", "fingerprint", nil, 0); err != nil {
					t.Fatal(err)
				}
			case "completed":
				if err := store.Complete(ctx, hash, "call", "fingerprint", map[string]any{}, 0); err != nil {
					t.Fatal(err)
				}
			case "failed":
				if err := store.Fail(ctx, hash, "call", "fingerprint"); err != nil {
					t.Fatal(err)
				}
			case "unsupported":
				module.modelStore = nil
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "invalid-scope":
				scope.AuthorizationEpoch = 0
			case "foreign-session":
				scope.SessionID = "other-session"
			}
			err := module.CheckTaskModelQuiescence(ctx, scope)
			allowed := mode == "empty" || mode == "completed" || mode == "failed" || mode == "foreign-session"
			if (err == nil) != allowed {
				t.Fatal("quiescence did not preserve pending calls", err)
			}
			if mode == "cancelled-context" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}
