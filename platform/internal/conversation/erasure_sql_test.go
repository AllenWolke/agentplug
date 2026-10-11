package conversation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/url"
)

func TestSQLConversationErasureRecoveryAndAtomicPayloadDeletion(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required")
	}

	uri, err := url.Parse(dsn)
	if err != nil || uri.Hostname() != "127.0.0.1" || uri.Path != "/knowledge_test" || (uri.Scheme != "postgres" && uri.Scheme != "postgresql") {
		t.Fatal("dedicated loopback PostgreSQL fixture required")
	}
	control, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	name := fmt.Sprintf("erasure_fixture_%d", time.Now().UnixNano())
	if _, err = control.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := control.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
	}()
	uri.Path = "/" + name
	dsn = uri.String()
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	iam := identity.NewSQLStore(db)
	if err := iam.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	outbox := notification.NewSQLStore(db)
	if err := outbox.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	audits := audit.NewSQLStoreWithOutbox(db, outbox)
	if err := audits.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	runs, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	if err := runs.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	store.SetDeletionContinuityGuard(iam.AcquirePermissionReadContinuity)
	store.SetDeletionApprovalRecorder(func(_ context.Context, tx *sql.Tx, s Scope, item DeletionRequest) error {
		return audits.RecordTx(tx, audit.Event{ID: "deletion-approval-" + item.ID, TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, ActorType: s.PrincipalType, ActorID: s.PrincipalID, AggregateType: "conversation_deletion", AggregateID: item.ID, Action: "conversation.deletion.approved", Outcome: "success", Summary: "fixture approval", CreatedAt: item.ApprovedAt})
	})
	store.SetDeletionApprovalReplayChecker(func(ctx context.Context, tx *sql.Tx, s Scope, item DeletionRequest) (bool, error) {
		return audits.MatchesCommittedActorTx(ctx, tx, audit.Event{ID: "deletion-approval-" + item.ID, TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, ActorType: s.PrincipalType, ActorID: s.PrincipalID, AggregateType: "conversation_deletion", AggregateID: item.ID, Action: "conversation.deletion.approved", Outcome: "success", CreatedAt: item.ApprovedAt})
	})
	var denied atomic.Bool
	authorize := func(_ context.Context, s Scope, r SessionResource) error {
		if denied.Load() || s.PrincipalID != "reviewer" || r.OwnerID != "owner" {
			return ErrForbidden
		}
		return nil
	}
	quiescence := func(ctx context.Context, tx *sql.Tx, s Scope, id string) (bool, error) {
		return runs.SessionQuiescentTx(ctx, tx, sharedkernel.Scope{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID}, id)
	}
	var recordFault atomic.Bool
	var denyAfterRecord atomic.Bool
	recorder := func(_ context.Context, tx *sql.Tx, s Scope, r ErasureReceipt) error {
		if err := audits.RecordTx(tx, audit.Event{ID: "conversation-erased-" + r.RequestID, TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, ActorType: "service_principal", ActorID: "platform.conversation.erasure", AggregateType: "conversation_deletion", AggregateID: r.RequestID, Action: "conversation.payload.erased", Outcome: "success", Summary: r.Digest, CreatedAt: r.ErasedAt}); err != nil {
			return err
		}
		if recordFault.Load() {
			return errors.New("injected erasure audit rollback")
		}
		if denyAfterRecord.Load() {
			denied.Store(true)
		}
		return nil
	}
	store.SetErasurePorts(authorize, quiescence, recorder)
	base := time.Now().UTC().Truncate(time.Microsecond)
	var now atomic.Int64
	now.Store(base.UnixNano())
	store.clock = func() time.Time { return time.Unix(0, now.Load()).UTC() }
	owner := Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "app", PrincipalType: "user", PrincipalID: "owner"}
	foreign := owner
	foreign.TenantID = "foreign-tenant"
	for _, s := range []Scope{owner, foreign} {
		id := s.TenantID + "-session"
		if err := store.CreateSession(ctx, s, Session{Summary: Summary{ID: id, Kind: "qa", InstallationID: "installation", AgentID: "agent", AgentVersionID: "version", Title: "private title", Status: "active"}, CreatedAt: base.Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := store.AppendMessage(ctx, s, Message{ID: id + "-message", SessionID: id, Role: "user", Content: "private original"}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ReviseMessage(ctx, s, id, id+"-message", "private revision", "private reason", 0); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CreateExport(ctx, s, ExportRequest{SessionIDs: []string{id}}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CreateShare(ctx, s, ShareRequest{SessionID: id, TTLSeconds: 3600}); err != nil {
			t.Fatal(err)
		}
	}
	id := owner.TenantID + "-session"
	request, err := store.RequestDeletion(ctx, owner, DeleteRequest{SessionIDs: []string{id}, Reason: "private request reason"})
	if err != nil {
		t.Fatal(err)
	}
	reviewer := owner
	reviewer.PrincipalID = "reviewer"
	approved, err := store.ApproveDeletionAuthorized(ctx, reviewer, request.ID, func(context.Context, SessionResource) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	var jobs int
	if err := db.QueryRow(sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_erasure WHERE request_id=?`), request.ID).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal("approval job missing", jobs, err)
	}
	if _, err := store.ClaimErasure(ctx, "too-early", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatal("grace period bypass", err)
	}
	now.Store(base.Add(25 * time.Hour).UnixNano())
	claim, err := store.ClaimErasure(ctx, "crashed-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimErasure(ctx, "competing-worker", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatal("live lease stolen", err)
	}
	now.Store(base.Add(25*time.Hour + 2*time.Minute).UnixNano())
	recovered, err := store.ClaimErasure(ctx, "recovery-worker", time.Minute)
	if err != nil || recovered.Revision <= claim.Revision {
		t.Fatal("expired lease not reclaimed", recovered, err)
	}
	if _, err := store.CompleteErasure(ctx, claim); !errors.Is(err, ErrErasureLease) {
		t.Fatal("stale worker accepted", err)
	}
	denied.Store(true)
	if _, err := store.CompleteErasure(ctx, recovered); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked approver erased payload", err)
	}
	denied.Store(false)
	governance := owner
	governance.PrincipalType = "service_principal"
	governance.PrincipalID = "governance"
	hold, err := store.PlaceLegalHold(ctx, governance, LegalHoldRequest{SessionID: id, Reason: "hold after approval before erasure"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteErasure(ctx, recovered); !errors.Is(err, ErrLegalHold) {
		t.Fatal("post-approval hold ignored", err)
	}
	if _, err := store.ReleaseLegalHold(ctx, governance, hold.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutRetentionPolicy(ctx, governance, RetentionPolicy{Kind: "qa", RetentionDays: 30, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteErasure(ctx, recovered); !errors.Is(err, ErrErasureRetention) {
		t.Fatal("retention ignored", err)
	}
	if _, err := store.PutRetentionPolicy(ctx, governance, RetentionPolicy{Kind: "qa", RetentionDays: 30, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	created, err := runs.Create(platformruntime.CreateRequest{ID: "active-run", Scope: sharedkernel.Scope{TenantID: owner.TenantID, DepartmentID: owner.DepartmentID, ApplicationID: owner.ApplicationID, AgentInstanceID: "instance", AgentID: "agent", AgentVersionID: "version", PrincipalID: "owner", PrincipalType: "user", SessionID: id, TraceID: "trace"}, AgentVersionID: "version", IdempotencyKey: "active-idem", Fingerprint: "fingerprint"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteErasure(ctx, recovered); !errors.Is(err, ErrErasureBusy) {
		t.Fatal("recoverable run ignored", err)
	}
	if _, err := runs.Transition(created.Run.ID, platformruntime.StatusAccepted, platformruntime.StatusCancelled, created.Run.Revision); err != nil {
		t.Fatal(err)
	}
	recordFault.Store(true)
	if _, err := store.CompleteErasure(ctx, recovered); err == nil {
		t.Fatal("audit failure accepted")
	}
	recordFault.Store(false)
	denyAfterRecord.Store(true)
	if _, err := store.CompleteErasure(ctx, recovered); !errors.Is(err, ErrForbidden) {
		t.Fatal("commit-time authorization change accepted", err)
	}
	denyAfterRecord.Store(false)
	denied.Store(false)
	var payloads, events int
	if err := db.QueryRow(sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_message WHERE session_id=?`), id).Scan(&payloads); err != nil || payloads != 1 {
		t.Fatal("rollback lost payload", payloads, err)
	}
	if err := db.QueryRow(sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE event_id=?`), "conversation-erased-"+request.ID).Scan(&events); err != nil || events != 0 {
		t.Fatal("rollback leaked audit", events, err)
	}
	if err := store.RetryErasure(ctx, recovered, errors.New("safe synthetic failure")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteErasure(ctx, recovered); !errors.Is(err, ErrErasureLease) {
		t.Fatal("released lease reused", err)
	}
	now.Store(base.Add(26 * time.Hour).UnixNano())
	final, err := store.ClaimErasure(ctx, "final-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.CompleteErasure(ctx, final)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Digest == "" || receipt.DeletedRows["messages"] != 1 || receipt.DeletedRows["revisions"] < 1 || receipt.DeletedRows["exports"] != 1 || receipt.DeletedRows["shares"] != 1 {
		t.Fatal("incomplete receipt", receipt)
	}
	for _, table := range []string{"platform_conversation_message", "platform_conversation_revision", "platform_conversation_export", "platform_conversation_share"} {
		if err := db.QueryRow(sqlutil.Bind(`SELECT COUNT(*) FROM `+table+` WHERE session_id=?`), id).Scan(&payloads); err != nil || payloads != 0 {
			t.Fatal("target payload remains", table, payloads, err)
		}
		if err := db.QueryRow(sqlutil.Bind(`SELECT COUNT(*) FROM `+table+` WHERE session_id=?`), foreign.TenantID+"-session").Scan(&payloads); err != nil || payloads == 0 {
			t.Fatal("foreign payload erased", table, payloads, err)
		}
	}
	var title, preview, reason, stored string
	if err := db.QueryRow(sqlutil.Bind(`SELECT title,preview FROM platform_conversation_session WHERE id=?`), id).Scan(&title, &preview); err != nil || title != "" || preview != "" {
		t.Fatal("summary payload remains", err)
	}
	if err := db.QueryRow(sqlutil.Bind(`SELECT reason FROM platform_conversation_deletion WHERE id=?`), request.ID).Scan(&reason); err != nil || reason != "" {
		t.Fatal("request payload remains", err)
	}
	if err := db.QueryRow(sqlutil.Bind(`SELECT receipt_json FROM platform_conversation_erasure WHERE request_id=? AND status='completed'`), request.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var persisted ErasureReceipt
	if err := json.Unmarshal([]byte(stored), &persisted); err != nil || persisted.Digest != receipt.Digest {
		t.Fatal("receipt not persisted", err)
	}
	if _, err := store.CompleteErasure(ctx, final); !errors.Is(err, ErrErasureLease) {
		t.Fatal("completed job repeated", err)
	}
	if _, err := store.ApproveDeletionAuthorized(ctx, reviewer, approved.ID, func(context.Context, SessionResource) error { return nil }); err != nil {
		t.Fatal("minimal tombstone cannot replay approval", err)
	}
	if err := db.QueryRow(sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox WHERE tenant_id=?`), owner.TenantID).Scan(&events); err != nil || events != 2 {
		t.Fatal("duplicate or missing completion outbox", events, err)
	}
	if err := store.AppendMessage(ctx, owner, Message{ID: "late", SessionID: id, Role: "user", Content: "resurrection"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("erased payload resurrected", err)
	}
	// Exercise the actual background worker rather than only calling its store port.
	if err := store.CreateSession(ctx, owner, Session{Summary: Summary{ID: "automatic-session", Kind: "qa", InstallationID: "installation", AgentID: "agent", AgentVersionID: "version", Title: "automatic private title", Status: "active"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendMessage(ctx, owner, Message{ID: "automatic-message", SessionID: "automatic-session", Role: "user", Content: "automatic private payload"}); err != nil {
		t.Fatal(err)
	}
	automatic, err := store.RequestDeletion(ctx, owner, DeleteRequest{SessionIDs: []string{"automatic-session"}, Reason: "automatic worker fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApproveDeletionAuthorized(ctx, reviewer, automatic.ID, func(context.Context, SessionResource) error { return nil }); err != nil {
		t.Fatal(err)
	}
	now.Store(base.Add(51 * time.Hour).UnixNano())
	module := NewModule(store, "fixture", false)
	module.SetErasureWorkerEnabled(true)
	if err := module.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var status string
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_conversation_erasure WHERE request_id=?`), automatic.ID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background worker did not finish eligible job", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_message WHERE session_id='automatic-session'`)).Scan(&payloads); err != nil || payloads != 0 {
		t.Fatal("background worker left payload", payloads, err)
	}
	closeCtx, closeCancel := context.WithTimeout(ctx, 2*time.Second)
	defer closeCancel()
	if err := module.Close(closeCtx); err != nil {
		t.Fatal("worker did not stop", err)
	}
}
