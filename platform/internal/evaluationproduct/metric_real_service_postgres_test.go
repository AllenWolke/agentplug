package evaluationproduct

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLRealFrozenRAGMetricServiceEvidence(t *testing.T) {
	migration, runtime := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if migration == "" || runtime == "" {
		t.Skip("requires owned migration and DML-only PostgreSQL fixture")
	}
	ctx := context.Background()
	admin, err := sqlutil.OpenPostgres(ctx, migration)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := NewSQLStore(admin).EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sqlutil.OpenPostgres(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var database, role string
	var creates bool
	if err := db.QueryRowContext(ctx, `SELECT current_database(),current_user,has_schema_privilege(current_user,'public','CREATE')`).Scan(&database, &role, &creates); err != nil || database != "knowledge_test" || role != "knowledge_test_runtime" || creates {
		t.Fatal("owned DML-only PostgreSQL required", err)
	}
	defer func() {
		for _, table := range []string{"platform_evaluation_product_output_artifact", "platform_evaluation_product_run_lease", "platform_evaluation_product_version", "platform_evaluation_product_head"} {
			if _, err := admin.ExecContext(ctx, "DELETE FROM "+table+" WHERE tenant_id=$1", "rag-frozen-real"); err != nil {
				t.Error(err)
			}
		}
	}()
	exerciseRealFrozenRAGMetricService(t, func() ExecutionStore { return NewSQLStore(db) })
	for _, name := range []string{"supported", "fabricated-source", "unknown-reference", "wrong-revision"} {
		var payload []byte
		var digest string
		var size int64
		err := db.QueryRowContext(ctx, `SELECT payload,sha256,size_bytes FROM platform_evaluation_product_output_artifact WHERE tenant_id=$1 AND run_id=$2`, "rag-frozen-real", "real-rag-"+name).Scan(&payload, &digest, &size)
		sum := sha256.Sum256(payload)
		if err != nil || !json.Valid(payload) || size != int64(len(payload)) || digest != hex.EncodeToString(sum[:]) {
			t.Fatalf("durable actual metric output missing or corrupt %s %v", name, err)
		}
	}
}
