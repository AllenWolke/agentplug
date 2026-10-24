package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLDispatchRootAuthorityDistinguishesLockedRunFromDeniedGrant(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = execution.MigrateSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	iam := identity.NewSQLStore(db)
	if err = iam.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	runs, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	routes, err := agentcoordination.NewSQLRouteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("dispatch-lock-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: "department", ApplicationID: "application",
		AgentInstanceID: "installation", InstallationID: "installation", AgentID: "agent", AgentVersionID: "v1",
		PrincipalType: "user", PrincipalID: "ungranted-caller", SessionID: id, RunID: id, AuthorizationEpoch: 1,
		TraceID: "0123456789abcdef0123456789abcdef"}
	raw, _ := json.Marshal(stopAuthorityExecuteRequest(scope, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"))
	if _, err = runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: "v1", IdempotencyKey: id,
		Fingerprint: "fixture", RequestJSON: raw}); err != nil {
		t.Fatal(err)
	}
	holder, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err = runs.BudgetRunForUpdateTx(ctx, holder, id); err != nil {
		t.Fatal(err)
	}
	fixture := &dispatchAuthorityFixture{expected: 1, current: 1, allowed: true}
	authority := fixture.authority()
	authority.pinRoot = (agentRouteAuthority{identity: iam, runs: runs, routes: routes}).PinRootMachineAuthority
	waitCtx, stopWait := context.WithTimeout(ctx, 200*time.Millisecond)
	err = authority.Authorize(waitCtx, scope)
	stopWait()
	var stage *dispatchAuthorityFailure
	if err == nil || !errors.As(err, &stage) || stage.stage != "root_machine" || !ancestryLockWait(err) {
		t.Fatalf("locked root lost its bounded wait classification: %T %v", err, err)
	}
	if err = holder.Rollback(); err != nil {
		t.Fatal(err)
	}
	// The same root is now readable, but no current IAM grant exists. That
	// completed rejection must remain a rejection, never a deferred timeout.
	err = authority.Authorize(ctx, scope)
	if err == nil || ancestryLockWait(err) || !errors.Is(err, agentcoordination.ErrDenied) {
		t.Fatalf("readable ungranted root did not fail closed: %T %v", err, err)
	}
}
