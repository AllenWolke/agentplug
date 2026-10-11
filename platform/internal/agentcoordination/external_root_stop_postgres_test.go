package agentcoordination

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLExternalRootStopRequiresProvenanceAndStillChecksDescendants(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLRouteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("external-stop-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: id, ApplicationID: id,
		AgentID: id, AgentVersionID: "v1", AgentInstanceID: id, InstallationID: id,
		PrincipalType: "user", PrincipalID: id, SessionID: id, RunID: id, ParentRunID: "product-" + id,
		AuthorizationEpoch: 1, TraceID: "0123456789abcdef0123456789abcdef"}
	check := func() error {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		return store.CheckDescendantStopTx(ctx, tx, scope)
	}
	if err = check(); !errors.Is(err, ErrConflict) {
		t.Fatalf("unproven parent accepted: %v", err)
	}
	store.SetExternalRootVerifier(func(context.Context, *sql.Tx, sharedkernel.Scope) error { return ErrDenied })
	if err = check(); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied provenance accepted: %v", err)
	}
	calls := 0
	store.SetExternalRootVerifier(func(c context.Context, tx *sql.Tx, got sharedkernel.Scope) error {
		calls++
		if c != ctx || tx == nil || got != scope {
			return ErrDenied
		}
		var one int
		if e := tx.QueryRowContext(c, "SELECT 1").Scan(&one); e != nil {
			return e
		}
		return nil
	})
	if err = check(); err != nil || calls != 1 {
		t.Fatalf("proven external root rejected: calls=%d err=%v", calls, err)
	}
	// Even a proven root may not bypass an invalid recorded descendant tree.
	key := routeScopeKey(scope)
	defer db.ExecContext(context.Background(), "DELETE FROM platform_agent_route WHERE parent_key=$1", key)
	_, err = db.ExecContext(ctx, `INSERT INTO platform_agent_route(parent_key,operation_key,parent_run_id,fingerprint,policy_hash,task_type,child_depth,reserved_children,plan_json,evidence_digest)
		VALUES($1,'fixture',$2,$3,$3,'documents.read',1,1,'{}',$3)`, key, scope.RunID, digest("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if err = check(); !errors.Is(err, ErrConflict) || calls != 2 {
		t.Fatalf("descendant validation bypassed: calls=%d err=%v", calls, err)
	}
}
