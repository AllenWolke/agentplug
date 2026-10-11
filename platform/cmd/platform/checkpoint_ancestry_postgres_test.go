package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLCheckpointAncestryRequiresProvenEvaluationParent(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	runs, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	if err = execution.MigrateSchema(ctx, runs.DB()); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("checkpoint-ancestry-%d", time.Now().UnixNano())
	root := sharedkernel.Scope{TenantID: id, DepartmentID: id, ApplicationID: id, AgentInstanceID: id, InstallationID: id, AgentID: id, AgentVersionID: id, PrincipalType: "user", PrincipalID: id, SessionID: id, RunID: id, TraceID: "0123456789abcdef0123456789abcdef", AuthorizationEpoch: 1}
	create := func(scope sharedkernel.Scope, depth uint32) {
		command := contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, Scope: budgetContractScope(scope), Operation: "run", IdempotencyKey: scope.RunID, InputSchema: "schema://fixture/input/v1", Input: map[string]any{"fixture": true}}
		command.Scope.DelegationDepth = depth
		raw, e := json.Marshal(command)
		if e != nil {
			t.Fatal(e)
		}
		_, e = runs.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: scope.RunID, Fingerprint: scope.RunID, RequestJSON: raw})
		if e != nil {
			t.Fatal(e)
		}
	}
	create(root, 0)
	tx, err := runs.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = lockCheckpointAncestors(ctx, tx, runs, nil, root); err != nil {
		t.Fatal("ordinary root requires no product parent", err)
	}
	tx.Rollback()
	delegated := root
	delegated.RunID = id + "-delegated"
	delegated.ParentRunID = root.RunID
	create(delegated, 1)
	tx, err = runs.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = lockCheckpointAncestors(ctx, tx, runs, nil, delegated); err != nil {
		t.Fatal("actual execution ancestry remains fenced", err)
	}
	tx.Rollback()
	evaluated := root
	evaluated.RunID = id + "-evaluated"
	evaluated.ParentRunID = id + "-product"
	create(evaluated, 0)
	if !evaluationBudgetCandidate(ctx, runs, evaluated) {
		t.Fatal("depth-zero durable product candidate not classified")
	}
	for _, authority := range []*evaluationExecutionAuthority{nil, {route: agentRouteAuthority{runs: runs}}} {
		tx, err = runs.DB().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = lockCheckpointAncestors(ctx, tx, runs, authority, evaluated); err == nil {
			t.Fatal("unproven product parent bypassed checkpoint authority")
		}
		tx.Rollback()
	}
	forged := evaluated
	forged.RunID = id + "-forged"
	tx, err = runs.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = lockCheckpointAncestors(ctx, tx, runs, nil, forged); err == nil {
		t.Fatal("bare parent ID without durable case admitted")
	}
}
