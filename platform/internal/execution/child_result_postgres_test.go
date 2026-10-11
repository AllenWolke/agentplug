package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// Cover the real PostgreSQL JSON column, byte boundary and immediate-parent
// isolation through the production repository. No model or dispatcher is used.
func TestPostgresChildResultJSONByteLimitAndOwnerBoundary(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal("open isolated PostgreSQL fixture failed")
	}
	defer store.Close()
	for _, tc := range []struct {
		name, answer string
		omitted      bool
	}{
		{"utf8_output", "教学资料：检查日志和指标", false},
		{"oversized_output", strings.Repeat("资料", 4096), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := fmt.Sprintf("pg-child-output-%s-%d", tc.name, time.Now().UnixNano())
			parent := testScope(id + "-parent").domain()
			parent.SessionID = id + "-session"
			child := parent
			child.RunID, child.ParentRunID = id, parent.RunID
			requestJSON, _ := json.Marshal(map[string]any{"scope": map[string]any{"run_id": id, "parent_run_id": parent.RunID, "delegation_depth": 1}})
			created, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: child, AgentVersionID: "v1", IdempotencyKey: id, Fingerprint: "fixture", RequestJSON: requestJSON})
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := store.AcquireLease(created.Run.ID, id, time.Now(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			running, err := store.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, id)
			if err != nil {
				t.Fatal(err)
			}
			output := map[string]any{"answer": tc.answer}
			if _, err := store.FinalizeLeased(id, platformruntime.StatusSucceeded, running.Revision, id, output, nil); err != nil {
				t.Fatal(err)
			}
			tx, err := store.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			actual, err := store.ChildResultTx(ctx, tx, parent, id)
			if err != nil {
				t.Fatalf("succeeded child JSON could not be read: %v", err)
			}
			raw, _ := json.Marshal(output)
			if actual.OutputBytes != int64(len(raw)) || actual.OutputOmitted != tc.omitted || actual.OutputAvailable == tc.omitted {
				t.Fatalf("incorrect UTF-8 byte boundary: bytes=%d expected=%d available=%v omitted=%v", actual.OutputBytes, len(raw), actual.OutputAvailable, actual.OutputOmitted)
			}
			if !tc.omitted && string(actual.OutputJSON) != string(raw) || tc.omitted && len(actual.OutputJSON) != 0 {
				t.Fatal("output was changed or oversized output was disclosed")
			}
			foreign := parent
			foreign.PrincipalID = "other-user"
			denied, err := store.ChildResultTx(ctx, tx, foreign, id)
			if err == nil || len(denied.OutputJSON) != 0 {
				t.Fatal("foreign owner received child output")
			}
		})
	}
}
