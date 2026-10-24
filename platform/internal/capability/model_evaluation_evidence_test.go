package capability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestEvaluationModelEvidencePreservesHistoricalSessionHash(t *testing.T) {
	c := capabilityContext()
	legacy, _ := json.Marshal([]string{c.TenantID, c.DepartmentID, c.ApplicationID, c.AgentID, c.AgentInstanceID, c.PrincipalType, c.ActorID, c.InstallationID, c.AgentVersionID, c.SessionID})
	want := fmt.Sprintf("%x", sha256.Sum256(legacy))
	if got := capabilityScopeHash(c); got != want {
		t.Fatal("historical model invocation identity changed")
	}
	other := scopeFromHarness(c)
	other.RunID = "next-run-same-session"
	if modelEvidenceScopeHash(other) != want {
		t.Fatal("historical session identity was silently migrated to run identity")
	}
}

func TestSQLEvaluationNoModelProofRequiresEmptySessionLedger(t *testing.T) {
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
	store, err := NewSQLModelInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	scope := scopeFromHarness(capabilityContext())
	scope.SessionID = fmt.Sprintf("model-proof-%d", time.Now().UnixNano())
	hash := modelEvidenceScopeHash(scope)
	defer func() {
		if _, err := db.Exec(sqlutil.Bind("DELETE FROM platform_model_invocation WHERE scope_hash=?"), hash); err != nil {
			t.Error("owned model proof fixture cleanup failed", err)
		}
	}()
	if yes, err := store.EvaluationNoModelRequests(ctx, scope); err != nil || !yes {
		t.Fatal("empty original session ledger was not established", yes, err)
	}
	if _, _, err := store.Reserve(ctx, hash, "admitted-with-no-usage-event", "fingerprint", 100, 1); err != nil {
		t.Fatal(err)
	}
	if yes, err := store.EvaluationNoModelRequests(ctx, scope); err != nil || yes {
		t.Fatal("admitted request without usage became false zero", yes, err)
	}
	otherRun := scope
	otherRun.RunID = "other-run-same-original-session"
	if yes, err := store.EvaluationNoModelRequests(ctx, otherRun); err != nil || yes {
		t.Fatal("prior session request was mistaken for a clean zero-call proof", yes, err)
	}
	invalid := scope
	invalid.AuthorizationEpoch = 0
	if yes, err := store.EvaluationNoModelRequests(ctx, invalid); err == nil || yes {
		t.Fatal("untrusted model proof query accepted")
	}
}
