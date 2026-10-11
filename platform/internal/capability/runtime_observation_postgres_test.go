package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestRuntimeObservationPostgresReceiptReopenPrecisionAndIsolation(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLToolInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if runtimeDSN == "" {
		t.Fatal("DML-only runtime fixture required")
	}
	runtimeDB, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeDB.Close()
	db = runtimeDB
	store, err = NewSQLToolInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE runtime_observation_forbidden_ddl(id integer)`); sqlutil.SQLState(err) != "42501" {
		t.Fatal("DML runtime did not reject schema creation")
	}
	scope := scopeFromHarness(capabilityContext())
	scope.RunID = fmt.Sprintf("observation-sql-%d", time.Now().UnixNano())
	scope.SessionID = scope.RunID
	callID := "precision"
	fingerprint, err := ToolCommandFingerprint("fixture.read", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	query := ToolReceiptQuery{Scope: scope, Name: "fixture.read", CallID: callID, Fingerprint: fingerprint}
	ctx = context.WithValue(ctx, toolReceiptContextKey{}, query)
	lease, replay, err := store.AcquireTool(ctx, ToolReceiptScopeHash(scope), callID, fingerprint, "owned-observation-test", time.Minute)
	if err != nil || replay {
		t.Fatalf("lease creation replay=%v err=%v", replay, err)
	}
	if err := store.BeginTool(ctx, lease.Lease); err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	observation, output := newToolObservation(scope, "fixture.read", callID, &started, "succeeded", "completed", "", map[string]any{"sequence": json.Number("9007199254740993"), "password": "private-sql-password-marker"})
	stored := storedToolObservation(observation, output)
	if err := store.FinishTool(ctx, lease.Lease, stored); err != nil {
		t.Fatal(err)
	}
	other, err := NewSQLToolInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	var updatedBefore, updatedAfter time.Time
	if err := db.QueryRowContext(ctx, `SELECT updated_at FROM platform_tool_invocation WHERE scope_hash=$1 AND call_id=$2`, ToolReceiptScopeHash(scope), callID).Scan(&updatedBefore); err != nil {
		t.Fatal(err)
	}
	record, found, err := other.LookupToolInvocation(ctx, ToolReceiptScopeHash(scope), callID)
	if err != nil || !found || record.Status != "completed" || record.Result["data"].(map[string]any)["sequence"] != json.Number("9007199254740993") {
		t.Fatal("read-only SQL lookup lost receipt or precision", err)
	}
	if _, found, err = other.LookupToolInvocation(ctx, "different-scope", callID); err != nil || found {
		t.Fatal("read-only lookup crossed scope", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT updated_at FROM platform_tool_invocation WHERE scope_hash=$1 AND call_id=$2`, ToolReceiptScopeHash(scope), callID).Scan(&updatedAfter); err != nil || !updatedAfter.Equal(updatedBefore) {
		t.Fatal("read-only lookup mutated ledger", err)
	}
	read, replay, err := other.AcquireTool(ctx, ToolReceiptScopeHash(scope), callID, fingerprint, "reopened-reader", time.Minute)
	if err != nil || !replay {
		t.Fatalf("SQL replay=%v err=%v", replay, err)
	}
	before, err := toolObservationResponse(scope, "fixture.read", callID, stored)
	if err != nil {
		t.Fatal(err)
	}
	after, err := toolObservationResponse(scope, "fixture.read", callID, read.Result)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if string(a) != string(b) || read.Result["data"].(map[string]any)["sequence"] != json.Number("9007199254740993") {
		t.Fatal("reopened SQL changed exact result or timing")
	}
	var raw string
	if err := db.QueryRowContext(ctx, `SELECT result_json FROM platform_tool_invocation WHERE scope_hash=$1 AND call_id=$2`, ToolReceiptScopeHash(scope), callID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "private-sql-password-marker") {
		t.Fatal("raw credential reached SQL receipt")
	}
	foreign := scope
	foreign.PrincipalID = "other-user"
	foreignQuery := query
	foreignQuery.Scope = foreign
	foreignCtx := context.WithValue(ctx, toolReceiptContextKey{}, foreignQuery)
	_, replay, err = other.AcquireTool(foreignCtx, ToolReceiptScopeHash(foreign), callID, fingerprint, "foreign-reader", time.Minute)
	if err != nil || replay {
		t.Fatal("foreign scope replayed another user's receipt")
	}
}
