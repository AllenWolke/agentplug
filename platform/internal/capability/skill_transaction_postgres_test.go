package capability

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/notification"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type skillTransactionFenceFunc func(context.Context, *sql.Tx, sharedkernel.Scope) error

func (f skillTransactionFenceFunc) AcquireTransactionFence(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	return f(ctx, tx, scope)
}

type skillSQLAuthorizationCall struct {
	action string
	skill  string
	target string
}

// Uses the migration-owned PostgreSQL fixture and an actual execution lease.
// The skill rows are seeded as isolated fixtures; the authorizer below models
// explicit grants for these exact actions, not production IAM behavior.
func TestSQLSkillModelValidationCallerTransactionPostgres(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("PUBLIC_TEST_POSTGRES_MIGRATION_DSN is only set by the isolated PostgreSQL fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	runs, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	if err := execution.MigrateSchema(ctx, runs.DB()); err != nil {
		t.Fatal(err)
	}
	db := runs.DB()
	outbox := notification.NewSQLStore(db)
	recorder := audit.NewSQLStoreWithOutbox(db, outbox)
	for _, ensure := range []func(context.Context) error{outbox.EnsureSchema, recorder.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewSQLSkillStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	store.SetAuditRecorder(recorder)

	id := fmt.Sprintf("skill-tx-%d", time.Now().UnixNano())
	scope := mcpTestScope()
	scope.RunID, scope.SessionID, scope.TraceID = id, id+"-session", id
	scope.TenantID, scope.PrincipalID = id+"-tenant", id+"-user"
	if _, err := runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "skill-model-binding-fixture"}); err != nil {
		t.Fatal(err)
	}
	claimed, err := runs.AcquireLease(id, "skill-fixture-worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := runs.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	leaseHash := fmt.Sprintf("%x", sha256.Sum256([]byte(claimed.LeaseToken)))
	binding := sharedkernel.ExecutionLeaseBinding{Revision: running.Revision, TokenHash: leaseHash}
	store.SetTransactionFence(skillTransactionFenceFunc(func(ctx context.Context, tx *sql.Tx, candidate sharedkernel.Scope) error {
		return runs.CheckCapabilityLeaseTx(ctx, tx, candidate, binding)
	}))

	const skillID, versionID = "model-skill-fixture", "approved-v1"
	bundle := SkillBundle{
		Protocol: "skill-bundle/v1", SkillID: skillID, VersionID: versionID,
		Title: "Model binding fixture", Summary: "Required capabilities for validation.",
		Sections:      map[string]string{"instructions": "Fixture content."},
		RequiredTools: []string{"fixture.tool"}, RequiredKnowledge: []string{"fixture.knowledge"},
	}
	_, digest, err := freezeSkillBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	namespace := skillNamespace(scope)
	now := time.Now().UTC()
	for _, fixture := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO platform_skill_version(namespace_key,skill_id,version_id,bundle_json,content_hash,author_id,reviewer_id,status,revision,created_at) VALUES(?,?,?,?,?,? ,?,'approved',1,?)`, []any{namespace, skillID, versionID, string(encoded), digest, "fixture-author", "fixture-reviewer", now}},
		{`INSERT INTO platform_skill_release(namespace_key,skill_id,stable_version,candidate_version,candidate_basis_points,revision) VALUES(?,?,?,NULL,0,1)`, []any{namespace, skillID, versionID}},
		{`INSERT INTO platform_skill_run_pin(run_key,namespace_key,skill_id,version_id,content_hash,release_revision) VALUES(?,?,?,?,?,1)`, []any{skillRunKey(scope, skillID), namespace, skillID, versionID, digest}},
	} {
		if _, err := db.ExecContext(ctx, sqlutil.Bind(fixture.query), fixture.args...); err != nil {
			t.Fatal(err)
		}
	}

	var calls []skillSQLAuthorizationCall
	var authTransactionID int64
	var callerTx *sql.Tx
	store.SetAuthorizer(func(authCtx context.Context, tx *sql.Tx, action string, candidate sharedkernel.Scope, skill, target string) error {
		if tx == nil || candidate != scope || skill != skillID {
			return errors.New("authorization did not use the exact scope and explicit skill grant")
		}
		if callerTx != nil {
			if tx != callerTx {
				return errors.New("authorization did not use the caller transaction")
			}
			var transactionID int64
			if err := tx.QueryRowContext(authCtx, `SELECT txid_current()`).Scan(&transactionID); err != nil {
				return err
			}
			if authTransactionID != 0 && authTransactionID != transactionID {
				return errors.New("skill authorization escaped the caller transaction")
			}
			authTransactionID = transactionID
		}
		calls = append(calls, skillSQLAuthorizationCall{action: action, skill: skill, target: target})
		return nil
	})
	registry, err := NewSkillRegistry(store)
	if err != nil {
		t.Fatal(err)
	}
	bindings := map[string]SkillModelBinding{skillID: {VersionID: versionID, Digest: digest}}
	t.Run("common-continuity-binding-keeps-owner-and-rejects-foreign-pool", func(t *testing.T) {
		outer, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer outer.Rollback()
		callerTx, authTransactionID = outer, 0
		defer func() { callerTx = nil }()
		joined := sqlutil.WithContinuityTransaction(ctx, db, outer)
		if err := registry.ValidateModelBindings(joined, scope, bindings); err != nil {
			t.Fatal("common owner not reused", err)
		}
		if err := outer.QueryRowContext(ctx, `SELECT 1`).Scan(new(int)); err != nil {
			t.Fatal("consumer completed caller transaction", err)
		}
		foreign := sqlutil.WithContinuityTransaction(ctx, new(sql.DB), outer)
		if err := registry.ValidateModelBindings(foreign, scope, bindings); err == nil {
			t.Fatal("foreign common owner silently ignored")
		}
	})

	t.Run("success_reuses_locked_run_transaction_and_outer_rollback", func(t *testing.T) {
		outer, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer outer.Rollback()
		var lockedRun string
		if err := outer.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id FROM platform_execution_run WHERE run_id=? FOR UPDATE`), id).Scan(&lockedRun); err != nil || lockedRun != id {
			t.Fatalf("lock execution run: run=%q error=%v", lockedRun, err)
		}
		if err := outer.QueryRowContext(ctx, `SELECT txid_current()`).Scan(&authTransactionID); err != nil {
			t.Fatal(err)
		}
		calls = nil
		callerTx = outer
		validationCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		validationCtx = WithSQLSkillTransaction(validationCtx, db, outer, scope)
		if err := registry.ValidateModelBindings(validationCtx, scope, bindings); err != nil {
			t.Fatalf("validate bindings while caller owns the execution lock: %v", err)
		}
		if got, want := calls, []skillSQLAuthorizationCall{
			{action: "skill.discover", skill: skillID},
			{action: "skill.load", skill: skillID, target: versionID},
			{action: "skill.require_tool", skill: skillID, target: "fixture.tool"},
			{action: "skill.require_knowledge", skill: skillID, target: "fixture.knowledge"},
			{action: "skill.discover", skill: skillID},
			{action: "skill.load", skill: skillID, target: versionID},
			{action: "skill.require_tool", skill: skillID, target: "fixture.tool"},
			{action: "skill.require_knowledge", skill: skillID, target: "fixture.knowledge"},
		}; !reflect.DeepEqual(got, want) {
			t.Fatalf("authorization checks=%+v, want exact current and pre-commit checks=%+v", got, want)
		}
		var inTransactionAudits int
		if err := outer.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE trace_id=? AND action='skill.model_dependency_checked'`), scope.TraceID).Scan(&inTransactionAudits); err != nil || inTransactionAudits != 1 {
			t.Fatalf("audit not written inside caller transaction: count=%d error=%v", inTransactionAudits, err)
		}
		var stillUsable int
		if err := outer.QueryRowContext(ctx, `SELECT 1`).Scan(&stillUsable); err != nil || stillUsable != 1 {
			t.Fatalf("skill validation committed caller transaction: %v", err)
		}
		callerTx = nil
		if err := outer.Rollback(); err != nil {
			t.Fatal(err)
		}
		var durableAudits int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE trace_id=? AND action='skill.model_dependency_checked'`), scope.TraceID).Scan(&durableAudits); err != nil || durableAudits != 0 {
			t.Fatalf("outer rollback did not undo skill audit: count=%d error=%v", durableAudits, err)
		}
	})

	t.Run("scope_mismatch_rejected", func(t *testing.T) {
		outer, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer outer.Rollback()
		boundCtx := WithSQLSkillTransaction(ctx, db, outer, scope)
		foreign := scope
		foreign.DepartmentID += "-other"
		entered := false
		err = store.Transact(boundCtx, foreign, func(SkillTransaction) error {
			entered = true
			return nil
		})
		if err == nil || entered {
			t.Fatalf("scope-bound caller transaction was accepted: entered=%v error=%v", entered, err)
		}
	})

	t.Run("database_mismatch_rejected", func(t *testing.T) {
		otherDB, err := sqlutil.OpenPostgres(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer otherDB.Close()
		otherStore, err := NewSQLSkillStore(otherDB)
		if err != nil {
			t.Fatal(err)
		}
		otherStore.SetAuditRecorder(audit.NewSQLStoreWithOutbox(otherDB, notification.NewSQLStore(otherDB)))
		otherStore.SetAuthorizer(func(context.Context, *sql.Tx, string, sharedkernel.Scope, string, string) error { return nil })
		otherStore.SetTransactionFence(storeFence(runs, binding))
		outer, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer outer.Rollback()
		boundCtx := WithSQLSkillTransaction(ctx, db, outer, scope)
		entered := false
		err = otherStore.Transact(boundCtx, scope, func(SkillTransaction) error {
			entered = true
			return nil
		})
		if err == nil || entered {
			t.Fatalf("transaction from a different database pool was accepted: entered=%v error=%v", entered, err)
		}
	})

	t.Run("operation_error_rolls_back_owned_transaction", func(t *testing.T) {
		failure := errors.New("injected skill operation failure")
		err := store.Transact(ctx, scope, func(unit SkillTransaction) error {
			if err := unit.Authorize(ctx, "skill.discover", scope, skillID, ""); err != nil {
				return err
			}
			if err := unit.Audit("skill.model_dependency_checked", scope, skillID, versionID, digest); err != nil {
				return err
			}
			return failure
		})
		if !errors.Is(err, failure) {
			t.Fatalf("operation error lost: %v", err)
		}
		var durableAudits int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE trace_id=? AND action='skill.model_dependency_checked'`), scope.TraceID).Scan(&durableAudits); err != nil || durableAudits != 0 {
			t.Fatalf("failed owned transaction committed audit: count=%d error=%v", durableAudits, err)
		}
	})

	t.Run("fence_failure_skips_operation", func(t *testing.T) {
		failure := errors.New("injected transaction fence failure")
		store.SetTransactionFence(skillTransactionFenceFunc(func(context.Context, *sql.Tx, sharedkernel.Scope) error { return failure }))
		defer store.SetTransactionFence(storeFence(runs, binding))
		entered := false
		err := store.Transact(ctx, scope, func(SkillTransaction) error {
			entered = true
			return nil
		})
		if !errors.Is(err, failure) || entered {
			t.Fatalf("fence failure reached operation: entered=%v error=%v", entered, err)
		}
		var durableAudits int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE trace_id=? AND action='skill.model_dependency_checked'`), scope.TraceID).Scan(&durableAudits); err != nil || durableAudits != 0 {
			t.Fatalf("fence failure committed audit: count=%d error=%v", durableAudits, err)
		}
	})

	t.Run("progressive_disclosure_and_current_dependency_revocation", func(t *testing.T) {
		denyDependency := false
		store.SetAuthorizer(func(_ context.Context, _ *sql.Tx, action string, candidate sharedkernel.Scope, skill, _ string) error {
			if candidate != scope || skill != skillID || (denyDependency && action == "skill.require_tool") {
				return ErrSkillDenied
			}
			return nil
		})
		summary, err := registry.Load(ctx, scope, skillID, "")
		if err != nil || summary.Content != "" || summary.Section != "" || summary.InstructionTrust != "untrusted_data" || !reflect.DeepEqual(summary.SectionNames, []string{"instructions"}) {
			t.Fatalf("summary disclosed chapter content or lost trust boundary: %+v error=%v", summary, err)
		}
		chapter, err := registry.Load(ctx, scope, skillID, "instructions")
		if err != nil || chapter.Content != bundle.Sections["instructions"] || chapter.VersionID != summary.VersionID || chapter.Digest != summary.Digest {
			t.Fatalf("explicit chapter differs from pinned approved version: %+v error=%v", chapter, err)
		}
		if result, err := registry.Load(ctx, scope, skillID, "missing"); !errors.Is(err, ErrSkillDenied) || !reflect.DeepEqual(result, SkillDisclosure{}) {
			t.Fatalf("unknown chapter disclosed instructions: error=%v", err)
		}
		denyDependency = true
		if result, err := registry.Load(ctx, scope, skillID, "instructions"); !errors.Is(err, ErrSkillDenied) || !reflect.DeepEqual(result, SkillDisclosure{}) {
			t.Fatalf("existing pin bypassed current dependency denial: error=%v", err)
		}
		if err := registry.ValidateModelBindings(ctx, scope, bindings); !errors.Is(err, ErrSkillDenied) {
			t.Fatalf("model binding bypassed current dependency denial: %v", err)
		}
		denyDependency = false
	})

	t.Run("revoked_version_blocks_existing_pin_without_rewriting_it", func(t *testing.T) {
		if err := registry.Review(ctx, scope, skillID, versionID, digest, 1, "revoked"); err != nil {
			t.Fatal(err)
		}
		if result, err := registry.Load(ctx, scope, skillID, "instructions"); !errors.Is(err, ErrSkillDenied) || !reflect.DeepEqual(result, SkillDisclosure{}) {
			t.Fatalf("revoked pinned instructions were disclosed: error=%v", err)
		}
		if err := registry.ValidateModelBindings(ctx, scope, bindings); !errors.Is(err, ErrSkillDenied) {
			t.Fatalf("model accepted revoked pinned version: %v", err)
		}
		var status, reviewer, pinnedVersion, pinnedDigest string
		var revision, pinnedRelease uint64
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,reviewer_id,revision FROM platform_skill_version WHERE namespace_key=? AND skill_id=? AND version_id=?`), namespace, skillID, versionID).Scan(&status, &reviewer, &revision); err != nil {
			t.Fatal(err)
		}
		if status != "revoked" || reviewer != "fixture-reviewer" || revision != 2 {
			t.Fatalf("revocation rewrote reviewer or wrong revision: %q %q %d", status, reviewer, revision)
		}
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT version_id,content_hash,release_revision FROM platform_skill_run_pin WHERE run_key=?`), skillRunKey(scope, skillID)).Scan(&pinnedVersion, &pinnedDigest, &pinnedRelease); err != nil {
			t.Fatal(err)
		}
		if pinnedVersion != versionID || pinnedDigest != digest || pinnedRelease != 1 {
			t.Fatal("revocation rewrote immutable historical pin")
		}
	})
}

func storeFence(runs *execution.SQLStore, binding sharedkernel.ExecutionLeaseBinding) skillTransactionFenceFunc {
	return func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
		return runs.CheckCapabilityLeaseTx(ctx, tx, scope, binding)
	}
}
