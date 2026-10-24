package evaluationproduct

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestEvaluationCaseReusePostgresIntegration(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("requires the isolated PostgreSQL fixture")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid isolated PostgreSQL DSN")
	}
	admin, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	// Generated ASCII identity, independent of all live application databases.
	name := fmt.Sprintf("eval_reuse_test_%d", time.Now().UnixNano())
	if registered := os.Getenv("PUBLIC_TEST_EVALUATION_REUSE_DATABASE"); registered != "" {
		if !regexp.MustCompile(`^eval_reuse_test_[a-z0-9_]{1,40}$`).MatchString(registered) {
			t.Fatal("invalid registered isolated reuse database")
		}
		name = registered
	}
	if _, err = admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec("DROP DATABASE " + name); err != nil {
			t.Error("isolated reuse database cleanup", err)
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	store := NewSQLStore(db)
	if err = store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	verifyCaseReuseMissingOnly(t, store, Scope{TenantID: "reuse-native", DepartmentID: "dept", ApplicationID: "app"})
	var originals, derived int
	if err = db.QueryRow(`SELECT count(*) FROM platform_evaluation_product_output_artifact WHERE run_id='reuse-original'`).Scan(&originals); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM platform_evaluation_product_output_artifact WHERE run_id='reuse-missing-only'`).Scan(&derived); err != nil {
		t.Fatal(err)
	}
	if originals != 1 || derived != 2 {
		t.Fatalf("source artifacts=%d new=%d; reused result must not create model output", originals, derived)
	}
}
