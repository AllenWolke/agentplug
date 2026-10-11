package conversation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
)

func TestSQLDeletionReviewFiltersBeforePaginationAndRollsBackDeniedCommit(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	iam := identity.NewSQLStore(db)
	if err := iam.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	store.SetDeletionContinuityGuard(iam.AcquirePermissionReadContinuity)
	outbox := notification.NewSQLStore(db)
	if err := outbox.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	auditStore := audit.NewSQLStoreWithOutbox(db, outbox)
	if err := auditStore.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	record := func(_ context.Context, tx *sql.Tx, actor Scope, item DeletionRequest) error {
		return auditStore.RecordTx(tx, audit.Event{ID: "deletion-approval-" + item.ID, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, ActorType: actor.PrincipalType, ActorID: actor.PrincipalID, TraceID: actor.TraceID, AggregateType: "conversation_deletion", AggregateID: item.ID, Action: "conversation.deletion.approved", Outcome: "success", Summary: "approved request for " + item.SessionID + " requested by " + item.OwnerID, CreatedAt: item.ApprovedAt})
	}
	store.SetDeletionApprovalRecorder(record)
	store.SetDeletionApprovalReplayChecker(func(ctx context.Context, tx *sql.Tx, actor Scope, item DeletionRequest) (bool, error) {
		return auditStore.MatchesCommittedActorTx(ctx, tx, audit.Event{ID: "deletion-approval-" + item.ID, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, ActorType: actor.PrincipalType, ActorID: actor.PrincipalID, AggregateType: "conversation_deletion", AggregateID: item.ID, Action: "conversation.deletion.approved", Outcome: "success", CreatedAt: item.ApprovedAt})
	})
	scope := Scope{TenantID: fmt.Sprintf("deletion-review-%d", time.Now().UnixNano()), DepartmentID: "department", ApplicationID: "app", PrincipalType: "user", PrincipalID: "owner"}
	requests := map[string]DeletionRequest{}
	for _, item := range []struct{ id, installation, owner string }{{"allowed", "installation-a", "owner"}, {"denied", "installation-a", "owner"}, {"foreign", "installation-b", "owner"}, {"self", "installation-a", "reviewer"}} {
		user := scope
		user.PrincipalID = item.owner
		if err := store.CreateSession(ctx, user, Session{Summary: Summary{ID: scope.TenantID + item.id, Kind: "qa", InstallationID: item.installation, AgentID: "fixture-agent", AgentVersionID: "v1", Status: "active", Title: item.id}}); err != nil {
			t.Fatal(err)
		}
		request, err := store.RequestDeletion(ctx, user, DeleteRequest{SessionIDs: []string{scope.TenantID + item.id}, Reason: "owner deletion request"})
		if err != nil {
			t.Fatal(err)
		}
		requests[item.id] = request
	}
	reviewer := scope
	reviewer.PrincipalID = "reviewer"
	plan := HistoryAccessPlan{Allow: []HistoryDataClause{{InstallationID: "installation-a", Type: "approved_organization"}}, Deny: []HistoryDataClause{{InstallationID: "installation-a", Type: "explicit_set", IDs: []string{requests["denied"].SessionID}}}}
	items, total, err := store.ListDeletionRequestsAuthorized(ctx, reviewer, 1, 1, plan)
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != requests["allowed"].ID {
		t.Fatal("unauthorized request affected count or first page", items, total, err)
	}
	items, total, err = store.ListDeletionRequestsAuthorized(ctx, reviewer, 2, 1, plan)
	if err != nil || total != 1 || len(items) != 0 {
		t.Fatal("unauthorized request leaked on next page", items, total, err)
	}
	if _, err := store.ApproveDeletionAuthorized(ctx, reviewer, requests["self"].ID, func(context.Context, SessionResource) error { return nil }); !errors.Is(err, ErrForbidden) {
		t.Fatal("self approval accepted", err)
	}
	checks := 0
	_, err = store.ApproveDeletionAuthorized(ctx, reviewer, requests["allowed"].ID, func(_ context.Context, resource SessionResource) error {
		checks++
		if resource.ID != requests["allowed"].SessionID || resource.OwnerID != "owner" || resource.InstallationID != "installation-a" {
			return ErrForbidden
		}
		if checks == 2 {
			return ErrForbidden
		}
		return nil
	})
	if !errors.Is(err, ErrForbidden) || checks != 2 {
		t.Fatal("missing current authorization recheck", checks, err)
	}
	var status string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_conversation_deletion WHERE id=?`), requests["allowed"].ID).Scan(&status); err != nil || status != "pending" {
		t.Fatal("denied approval leaked state", status, err)
	}
	if _, err := store.GetSessionResource(ctx, scope, requests["allowed"].SessionID); err != nil {
		t.Fatal("denied approval deleted session", err)
	}
	assertNoRecords := func() {
		t.Helper()
		for _, query := range []string{`SELECT COUNT(*) FROM platform_audit_event WHERE tenant_id=?`, `SELECT COUNT(*) FROM platform_notification_outbox WHERE tenant_id=?`} {
			var count int
			if err := db.QueryRowContext(ctx, sqlutil.Bind(query), scope.TenantID).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed approval leaked audit or outbox", count, err)
			}
		}
	}
	assertNoRecords()
	store.SetDeletionApprovalRecorder(nil)
	if _, err := store.ApproveDeletionAuthorized(ctx, reviewer, requests["allowed"].ID, func(context.Context, SessionResource) error { return nil }); !errors.Is(err, ErrDeletionRecorderUnavailable) {
		t.Fatal("missing recorder accepted", err)
	}
	fault := errors.New("injected failure after audit and outbox")
	store.SetDeletionApprovalRecorder(func(ctx context.Context, tx *sql.Tx, actor Scope, item DeletionRequest) error {
		if err := record(ctx, tx, actor, item); err != nil {
			return err
		}
		return fault
	})
	if _, err := store.ApproveDeletionAuthorized(ctx, reviewer, requests["allowed"].ID, func(context.Context, SessionResource) error { return nil }); !errors.Is(err, fault) {
		t.Fatal("recorder failure ignored", err)
	}
	assertNoRecords()
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_conversation_deletion WHERE id=?`), requests["allowed"].ID).Scan(&status); err != nil || status != "pending" {
		t.Fatal("recorder failure changed approval", status, err)
	}
	if _, err := store.GetSessionResource(ctx, scope, requests["allowed"].SessionID); err != nil {
		t.Fatal("recorder failure disposed session", err)
	}
	store.SetDeletionApprovalRecorder(record)
	governance := scope
	governance.PrincipalType, governance.PrincipalID = "service_principal", "governance"
	hold, err := store.PlaceLegalHold(ctx, governance, LegalHoldRequest{SessionID: requests["allowed"].SessionID, Reason: "preserve"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApproveDeletionAuthorized(ctx, reviewer, requests["allowed"].ID, func(context.Context, SessionResource) error { return nil }); !errors.Is(err, ErrLegalHold) {
		t.Fatal("legal hold bypassed", err)
	}
	if _, err := store.ReleaseLegalHold(ctx, governance, hold.ID); err != nil {
		t.Fatal(err)
	}
	approved, err := store.ApproveDeletionAuthorized(ctx, reviewer, requests["allowed"].ID, func(context.Context, SessionResource) error { return nil })
	if err != nil || approved.Status != "approved" {
		t.Fatal("authorized review failed", approved, err)
	}
	if _, err := store.GetSessionResource(ctx, scope, approved.SessionID); !errors.Is(err, ErrNotFound) {
		t.Fatal("approved soft disposal still visible", err)
	}
	var actorID, requestID string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT actor_id,aggregate_id FROM platform_audit_event WHERE event_id=?`), "deletion-approval-"+approved.ID).Scan(&actorID, &requestID); err != nil || actorID != reviewer.PrincipalID || requestID != approved.ID {
		t.Fatal("approval actor provenance missing", actorID, requestID, err)
	}
	var count int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox WHERE tenant_id=?`), scope.TenantID).Scan(&count); err != nil || count != 1 {
		t.Fatal("approval outbox not atomic", count, err)
	}
	var revision int64
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_conversation_session WHERE id=?`), approved.SessionID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	retry := reviewer
	retry.TraceID = "new-http-trace"
	replayed, err := store.ApproveDeletionAuthorized(ctx, retry, approved.ID, func(context.Context, SessionResource) error { return nil })
	if err != nil || replayed.ID != approved.ID || !replayed.ApprovedAt.Equal(approved.ApprovedAt) {
		t.Fatal("committed approval retry failed", replayed, err)
	}
	other := reviewer
	other.PrincipalID = "other-reviewer"
	if _, err := store.ApproveDeletionAuthorized(ctx, other, approved.ID, func(context.Context, SessionResource) error { return nil }); !errors.Is(err, ErrForbidden) {
		t.Fatal("other actor replay accepted", err)
	}
	if _, err := store.ApproveDeletionAuthorized(ctx, retry, approved.ID, func(context.Context, SessionResource) error { return ErrForbidden }); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked actor replay accepted", err)
	}
	store.SetDeletionApprovalReplayChecker(nil)
	if _, err := store.ApproveDeletionAuthorized(ctx, retry, approved.ID, func(context.Context, SessionResource) error { return nil }); !errors.Is(err, ErrForbidden) {
		t.Fatal("replay without provenance accepted", err)
	}
	var finalRevision int64
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_conversation_session WHERE id=?`), approved.SessionID).Scan(&finalRevision); err != nil || finalRevision != revision {
		t.Fatal("retry changed session revision", finalRevision, err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox WHERE tenant_id=?`), scope.TenantID).Scan(&count); err != nil || count != 1 {
		t.Fatal("retry duplicated notification", count, err)
	}
}
