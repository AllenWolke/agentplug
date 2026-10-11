package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestChildLifecycleDoesNotWaitOnLiveRunUpdate(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	prefix := fmt.Sprintf("child-life-%d", time.Now().UnixNano())
	parentID, childID := prefix+"-parent", prefix+"-child"
	parentScope := testScope(parentID).domain()
	childScope := parentScope
	childScope.RunID = childID
	childScope.ParentRunID = parentID
	wireScope := contract.ScopeKey{
		TenantID: childScope.TenantID, DepartmentID: childScope.DepartmentID, ApplicationID: childScope.ApplicationID,
		AgentInstanceID: childScope.AgentInstanceID, InstallationID: childScope.InstallationID,
		AgentID: childScope.AgentID, AgentVersionID: childScope.AgentVersionID,
		PrincipalType: childScope.PrincipalType, PrincipalID: childScope.PrincipalID,
		SessionID: childScope.SessionID, RunID: childScope.RunID,
		AuthorizationEpoch: childScope.AuthorizationEpoch, TraceID: childScope.TraceID,
		ParentRunID: parentID, DelegationDepth: 1,
	}
	request, err := json.Marshal(contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion, Scope: wireScope, Operation: "run",
		IdempotencyKey: childID, InputSchema: "schema://fixture/input/v1", Input: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Create(platformruntime.CreateRequest{
		ID: childID, Scope: childScope, AgentVersionID: childScope.AgentVersionID,
		IdempotencyKey: childID, Fingerprint: "fixture-fingerprint", RequestJSON: request,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM platform_execution_run WHERE run_id=$1`, childID)
	})
	holder, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err = store.BudgetRunForUpdateTx(ctx, holder, childID); err != nil {
		t.Fatal(err)
	}
	reader, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	readCtx, readCancel := context.WithTimeout(ctx, time.Second)
	defer readCancel()
	facts, err := store.ChildLifecycleTx(readCtx, reader, parentScope, childScope)
	if err != nil || facts.Scope.RunID != childID || facts.Status != platformruntime.StatusAccepted || facts.TerminalVerified {
		t.Fatalf("live child lifecycle waited or changed state: status=%s verified=%t err=%v", facts.Status, facts.TerminalVerified, err)
	}
	shareCtx, shareCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer shareCancel()
	_, err = store.BudgetRunTx(shareCtx, reader, childID)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("FOR SHARE on the locked child must still wait, got %v", err)
	}
}
