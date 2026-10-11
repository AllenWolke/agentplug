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

func TestSQLCoordinatedChildStopRevisionConflictReturnsLockedFacts(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	ctx := context.Background()
	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal("open isolated coordinated-stop fixture failed")
	}
	defer store.Close()
	prefix := fmt.Sprintf("child-stop-cas-%d", time.Now().UnixNano())
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
		ProtocolVersion: contract.ProtocolVersion,
		Scope:           wireScope,
		Operation:       "run",
		IdempotencyKey:  childID,
		InputSchema:     "schema://fixture/input/v1",
		Input:           map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(platformruntime.CreateRequest{
		ID: childID, Scope: childScope, AgentVersionID: childScope.AgentVersionID,
		IdempotencyKey: childID, Fingerprint: "fixture-fingerprint", RequestJSON: request,
	}); err != nil {
		t.Fatal("create accepted child fixture failed")
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := store.beginRecordedChildStopTx(ctx, tx, parentScope, childScope, 1, 2, "PARENT_CHILD_CANCEL_REQUESTED")
	_ = tx.Rollback()
	if !errors.Is(err, platformruntime.ErrRevisionConflict) {
		t.Fatalf("stale positive revision error = %v, want revision conflict", err)
	}
	if facts.Scope != childScope || facts.Status != platformruntime.StatusAccepted || facts.Revision != 1 || facts.Changed {
		t.Fatalf("conflict did not retain only locked child facts: %#v", facts)
	}
	current, err := store.Get(childID)
	if err != nil || current.Status != platformruntime.StatusAccepted || current.Revision != 1 {
		t.Fatal("stale CAS changed child state")
	}
}
