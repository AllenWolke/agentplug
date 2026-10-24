package execution

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLPublishedWindowRetainsFirstClaimAcrossLaterGenerationsAndReopen(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &SQLStore{db: db}
	if err := store.EnsureGenerationJournalSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("window-%d", time.Now().UnixNano())
	scope := sharedkernel.Scope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", AgentID: "check", AgentVersionID: "v1", InstallationID: id, AgentInstanceID: id, PrincipalType: "user", PrincipalID: id, SessionID: id, RunID: id, TraceID: strings.Repeat("c", 32), AuthorizationEpoch: 1}
	run := platformruntime.Run{ID: id, Scope: scope, RequestJSON: []byte(`{"frozen":"command"}`)}
	first := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	for i, at := range []time.Time{first, first.Add(40 * time.Second)} {
		_, err := db.ExecContext(ctx, `INSERT INTO platform_execution_generation_claim_journal
 (run_id,protocol_epoch,protocol_version,prior_status,prior_revision,claim_revision,lease_token_hash,request_hash,resume_input_hash,recorded_at)
 VALUES($1,$2,$3,'accepted',$4,$5,$6,$7,$8,$9)`, id, generationJournalProtocolEpoch, generationJournalProtocolVersion, i, i+1, strings.Repeat("a", 64), generationJournalHash(run.RequestJSON), generationJournalHash(nil), at)
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.OriginalGenerationStart(ctx, run)
	if err != nil || !got.Equal(first) {
		t.Fatal("later generation renewed processing start", got, err)
	}
	reopened, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err = (&SQLStore{db: reopened}).OriginalGenerationStart(ctx, run)
	if err != nil || !got.Equal(first) {
		t.Fatal("reopen renewed processing start", got, err)
	}
	run.RequestJSON = []byte(`{"changed":"command"}`)
	if _, err := store.OriginalGenerationStart(ctx, run); err == nil {
		t.Fatal("different command reused an unrelated start")
	}
}
