package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/platform/internal/sqlutil"
)

func evaluationEvidenceQuery(t *testing.T, payload map[string]any) ToolReceiptQuery {
	t.Helper()
	fingerprint, err := ToolCommandFingerprint("fixture.read", payload)
	if err != nil {
		t.Fatal(err)
	}
	return ToolReceiptQuery{Scope: scopeFromHarness(capabilityContext()), CallID: "call", Name: "fixture.read", Fingerprint: fingerprint, InputEvidence: toolInputEvidence(payload)}
}

func TestToolEvaluationEvidenceBindsArgumentsAndScope(t *testing.T) {
	q := evaluationEvidenceQuery(t, map[string]any{"batch_id": "agentmodes-v009", "large_number": json.Number("9007199254740993")})
	raw, _ := json.Marshal(q)
	actual, err := decodeToolEvaluationEvidence(q.Scope, q.CallID, q.Fingerprint, string(raw))
	if err != nil || actual.Arguments["batch_id"] != "agentmodes-v009" || fmt.Sprint(actual.Arguments["large_number"]) != "9007199254740993" {
		t.Fatal("exact input evidence was not preserved", err)
	}
	foreign := q.Scope
	foreign.PrincipalID = "other-user"
	if _, err := decodeToolEvaluationEvidence(foreign, q.CallID, q.Fingerprint, string(raw)); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("cross-owner input disclosed", err)
	}
	q.InputEvidence.Arguments = json.RawMessage(`{"batch_id":"foreign"}`)
	tampered, _ := json.Marshal(q)
	if _, err := decodeToolEvaluationEvidence(q.Scope, q.CallID, q.Fingerprint, string(tampered)); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("input not bound to original invocation accepted", err)
	}
}

func TestToolEvaluationEvidenceMissingAndSensitiveParametersStayUnknown(t *testing.T) {
	for name, payload := range map[string]map[string]any{
		"sensitive field": {"password": "private-parameter-marker"},
		"secret in text":  {"note": "Bearer private-parameter-marker"},
		"oversize":        {"body": strings.Repeat("a", toolInputEvidenceMax+1)},
	} {
		t.Run(name, func(t *testing.T) {
			q := evaluationEvidenceQuery(t, payload)
			raw, _ := json.Marshal(q)
			actual, err := decodeToolEvaluationEvidence(q.Scope, q.CallID, q.Fingerprint, string(raw))
			if err != nil || actual.Arguments != nil {
				t.Fatal("sensitive or incomplete parameters were disclosed/scored", err)
			}
		})
	}
	q := evaluationEvidenceQuery(t, map[string]any{"id": "old-call"})
	q.InputEvidence = nil
	raw, _ := json.Marshal(q)
	actual, err := decodeToolEvaluationEvidence(q.Scope, q.CallID, q.Fingerprint, string(raw))
	if err != nil || actual.Arguments != nil || actual.CallID != "call" {
		t.Fatal("historical unknown input was invented", err)
	}
}

func TestSQLToolEvaluationEvidenceReadsExactOwnedInvocation(t *testing.T) {
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
	q := evaluationEvidenceQuery(t, map[string]any{"batch_id": "independent-fixture"})
	q.Scope.RunID = fmt.Sprintf("argument-evidence-%d", time.Now().UnixNano())
	hash := ToolReceiptScopeHash(q.Scope)
	defer func() {
		if _, err := db.Exec(sqlutil.Bind("DELETE FROM platform_tool_invocation WHERE scope_hash=?"), hash); err != nil {
			t.Error("owned input evidence fixture cleanup failed", err)
		}
	}()
	bound := context.WithValue(ctx, toolReceiptContextKey{}, q)
	if _, _, err := store.AcquireTool(bound, hash, q.CallID, q.Fingerprint, "evidence-fixture", 30*time.Second); err != nil {
		t.Fatal(err)
	}
	rows, complete, err := store.EvaluationToolEvidence(ctx, q.Scope)
	if err != nil || !complete || len(rows) != 1 || rows[0].Arguments["batch_id"] != "independent-fixture" {
		t.Fatal("durable invocation arguments missing", complete, rows, err)
	}
	foreign := q.Scope
	foreign.RunID = "another-run"
	rows, complete, err = store.EvaluationToolEvidence(ctx, foreign)
	if err != nil || !complete || len(rows) != 0 {
		t.Fatal("cross-run invocation input disclosed", complete, rows, err)
	}
	q.InputEvidence.Arguments = json.RawMessage(`{"batch_id":"tampered"}`)
	tampered, _ := json.Marshal(q)
	if _, err := db.ExecContext(ctx, sqlutil.Bind("UPDATE platform_tool_invocation SET recovery_query=? WHERE scope_hash=? AND call_id=?"), string(tampered), hash, q.CallID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.EvaluationToolEvidence(ctx, q.Scope); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("tampered persisted argument proof accepted", err)
	}
}

func TestSQLToolEvaluationEvidenceLargeProfileRetainsBoundedProtectedRows(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	if err = store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	q := evaluationEvidenceQuery(t, map[string]any{"batch_id": "owned-large-fixture", "padding": strings.Repeat("x", 6500)})
	q.Scope.RunID = fmt.Sprintf("large-argument-evidence-%d", time.Now().UnixNano())
	hash := ToolReceiptScopeHash(q.Scope)
	defer func() {
		if _, err := db.Exec(sqlutil.Bind("DELETE FROM platform_tool_invocation WHERE scope_hash=?"), hash); err != nil {
			t.Error("owned large fixture cleanup failed", err)
		}
	}()
	insert := func(start, end int) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		stmt, err := tx.PrepareContext(ctx, sqlutil.Bind("INSERT INTO platform_tool_invocation(scope_hash,call_id,fingerprint,status,recovery_query,created_at,updated_at) VALUES(?,?,?,'running',?,clock_timestamp(),clock_timestamp())"))
		if err != nil {
			t.Fatal(err)
		}
		defer stmt.Close()
		for i := start; i < end; i++ {
			q.CallID = fmt.Sprintf("call-%05d", i)
			raw, err := json.Marshal(q)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = stmt.ExecContext(ctx, hash, q.CallID, q.Fingerprint, string(raw)); err != nil {
				t.Fatal(err)
			}
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	insert(0, 1000)
	_, complete, err := store.EvaluationToolEvidence(ctx, q.Scope)
	if err != nil || complete {
		t.Fatal("legacy 2MiB bound changed", complete, err)
	}
	rows, complete, err := store.EvaluationToolEvidenceProfile(ctx, q.Scope, "", agenteval.EvidenceReadProfileLargeV1)
	if err != nil || !complete || len(rows) != 1000 || rows[0].Arguments["batch_id"] != "owned-large-fixture" {
		t.Fatal("protected large input evidence incomplete", len(rows), complete, err)
	}
	foreign := q.Scope
	foreign.PrincipalID = "foreign-owner"
	rows, complete, err = store.EvaluationToolEvidenceProfile(ctx, foreign, "", agenteval.EvidenceReadProfileLargeV1)
	if err != nil || !complete || len(rows) != 0 {
		t.Fatal("large mode disclosed another principal", err)
	}
	insert(1000, 3000)
	rows, complete, err = store.EvaluationToolEvidenceProfile(ctx, q.Scope, "", agenteval.EvidenceReadProfileLargeV1)
	if err != nil || !complete || len(rows) != 3000 {
		t.Fatal("published large profile must retain evidence beyond the former 16MiB limit", len(rows), complete, err)
	}
	insert(3000, 10000)
	_, complete, err = store.EvaluationToolEvidenceProfile(ctx, q.Scope, "", agenteval.EvidenceReadProfileLargeV1)
	if err != nil || complete {
		t.Fatal("64MiB ledger overflow accepted", complete, err)
	}
	if _, _, err = store.EvaluationToolEvidenceProfile(ctx, q.Scope, "", "unlimited"); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("arbitrary read capacity accepted", err)
	}
}
