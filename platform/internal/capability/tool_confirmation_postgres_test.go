package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLToolApprovalRevocationAndAuditAtomicity(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	store, _ := NewSQLToolApprovalStore(admin)
	if err = store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	outbox := notification.NewSQLStore(admin)
	if err = outbox.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	recorder := audit.NewSQLStoreWithOutbox(admin, outbox)
	if err = recorder.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if runtimeDSN == "" {
		t.Fatal("DML-only runtime DSN required")
	}
	db, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.ExecContext(ctx, `CREATE TABLE forbidden_tool_approval_ddl(id int)`); sqlutil.SQLState(err) != "42501" {
		t.Fatal("runtime DDL was not rejected")
	}
	store, _ = NewSQLToolApprovalStore(db)
	recorder = audit.NewSQLStoreWithOutbox(db, notification.NewSQLStore(db))
	store.SetAuditRecorder(recorder)
	scope := scopeFromHarness(capabilityContext())
	scope.RunID = fmt.Sprintf("tool-approval-%d", time.Now().UnixNano())
	scope.TraceID = scope.RunID
	// This callback is a controlled authorization fixture, not human step-up.
	store.SetAuthorizer(func(_ context.Context, tx *sql.Tx, s sharedkernel.Scope, c ToolConfirmationClaims, action, proof string) error {
		if tx == nil || proof != "owned-proof" || s.PrincipalID != scope.PrincipalID {
			return ErrToolApprovalDenied
		}
		return nil
	})
	fingerprint, _ := ToolCommandFingerprint("fixture.read", map[string]any{})
	claims := confirmationTestClaims(scope, strings.Repeat("b", 64), "fixture.read", "call", fingerprint, time.Now())
	claims.ApprovalID = scope.RunID
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewToolApprovalSigner(private, store)
	token, err := signer.Issue(ctx, scope, claims, "owned-proof")
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := NewToolConfirmationVerifier(public)
	if err = verifier.Verify(token, scope, claims.PolicyHash, claims.ToolName, claims.CallID, claims.Fingerprint, time.Now()); err != nil {
		t.Fatal("post-commit approval signature invalid", err)
	}
	if err = store.Approve(ctx, scope, claims, "owned-proof"); err != nil {
		t.Fatal("idempotent approval failed", err)
	}
	if err = store.CheckApproval(ctx, claims); err != nil {
		t.Fatal("stored approval rejected")
	}
	reopened, _ := NewSQLToolApprovalStore(db)
	if reopened.CheckApproval(ctx, claims) != nil {
		t.Fatal("reopened approval missing")
	}
	changed := claims
	changed.Fingerprint = "changed"
	if !errors.Is(reopened.CheckApproval(ctx, changed), ErrToolApprovalDenied) {
		t.Fatal("changed operation approved")
	}
	t.Run("revoke-audit-rollback", func(t *testing.T) {
		store.SetAuditRecorder(failingCheckpointAudit{})
		if store.Revoke(ctx, scope, claims, "owned-proof") == nil {
			t.Fatal("audit failure committed revocation")
		}
		store.SetAuditRecorder(recorder)
		if store.CheckApproval(ctx, claims) != nil {
			t.Fatal("revocation escaped rollback")
		}
	})
	t.Run("revoke-outbox-rollback", func(t *testing.T) {
		store.SetAuditRecorder(audit.NewSQLStoreWithOutbox(db, failingCheckpointOutbox{}))
		if store.Revoke(ctx, scope, claims, "owned-proof") == nil {
			t.Fatal("Outbox failure committed revocation")
		}
		store.SetAuditRecorder(recorder)
		if store.CheckApproval(ctx, claims) != nil {
			t.Fatal("Outbox failed but revocation committed")
		}
	})
	if err = store.Revoke(ctx, scope, claims, "owned-proof"); err != nil {
		t.Fatal(err)
	}
	if reopened.CheckApproval(ctx, claims) == nil || store.Approve(ctx, scope, claims, "owned-proof") == nil {
		t.Fatal("revoked approval replay or reinstatement accepted")
	}
	t.Run("approve-audit-rollback", func(t *testing.T) {
		failed := claims
		failed.ApprovalID += "-failed"
		store.SetAuditRecorder(failingCheckpointAudit{})
		issued, issueErr := signer.Issue(ctx, scope, failed, "owned-proof")
		if issueErr == nil || issued != "" {
			t.Fatal("audit failure committed approval")
		}
		store.SetAuditRecorder(recorder)
		if store.CheckApproval(ctx, failed) == nil {
			t.Fatal("approval escaped rollback")
		}
	})
	var count int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE aggregate_type='tool_approval' AND aggregate_id=?`), claims.ApprovalID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("expected one approve and revoke event: count=%d err=%v", count, err)
	}
}
