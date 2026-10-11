package conversation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLRetentionAndLegalHoldSerializeOnSession(t *testing.T) {
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
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("retention-hold-%d", time.Now().UnixNano())
	user := Scope{TenantID: id, DepartmentID: "department", ApplicationID: "application", PrincipalType: "user", PrincipalID: "owner"}
	governance := user
	governance.PrincipalType, governance.PrincipalID = "service_principal", "governance"
	defer func() {
		for _, table := range []string{"platform_conversation_share", "platform_conversation_export", "platform_conversation_legal_hold", "platform_conversation_deletion", "platform_conversation_retention_policy", "platform_conversation_session"} {
			if _, err := db.Exec(sqlutil.Bind(`DELETE FROM `+table+` WHERE tenant_id=?`), id); err != nil {
				t.Error(err)
			}
		}
	}()
	if err := store.CreateSession(ctx, user, Session{Summary: Summary{ID: id, Kind: "qa", AgentID: "agent", AgentVersionID: "v1", Title: "retention", Status: "active"}, UpdatedAt: time.Now().Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutRetentionPolicy(ctx, governance, RetentionPolicy{Kind: "qa", RetentionDays: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	share, err := store.CreateShare(ctx, user, ShareRequest{SessionID: id})
	if err != nil {
		t.Fatal(err)
	}
	export, err := store.CreateExport(ctx, user, ExportRequest{SessionIDs: []string{id}})
	if err != nil {
		t.Fatal(err)
	}
	hold, err := store.PlaceLegalHold(ctx, governance, LegalHoldRequest{SessionID: id, Reason: "preserve evidence"})
	if err != nil {
		t.Fatal(err)
	}
	sweep, err := store.SweepExpired(ctx, governance, time.Now(), 10)
	if err != nil || sweep.Held != 1 || sweep.Disposed != 0 {
		t.Fatalf("active hold did not prevent disposal: %+v, %v", sweep, err)
	}
	if _, err := store.ReleaseLegalHold(ctx, governance, hold.ID); err != nil {
		t.Fatal(err)
	}
	sweep, err = store.SweepExpired(ctx, governance, time.Now(), 10)
	if err != nil || sweep.Disposed != 1 {
		t.Fatalf("released hold did not permit disposal: %+v, %v", sweep, err)
	}
	if _, err := store.PlaceLegalHold(ctx, governance, LegalHoldRequest{SessionID: id, Reason: "too late"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("hold must not be reported on disposed session: %v", err)
	}
	if _, err := store.Detail(ctx, user, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted conversation detail remains visible: %v", err)
	}
	if page, err := store.List(ctx, user, Query{View: "mine"}); err != nil || page.Total != 0 {
		t.Fatalf("deleted conversation remains in ordinary list: %+v, %v", page, err)
	}
	if _, err := store.ReadPublicShare(ctx, share.Token, 1, 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("public share still exposes deleted conversation: %v", err)
	}
	if _, err := store.GetExport(ctx, user, export.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stored export still exposes deleted conversation: %v", err)
	}
	if err := store.AppendMessage(ctx, user, Message{ID: id + "-late-message", SessionID: id, Role: "user", Content: "late"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted conversation accepted a new message: %v", err)
	}

	// Both operations can begin at once. Either the hold commits first and
	// protects the session, or disposal commits first and rejects the hold.
	other := id + "-race"
	if err := store.CreateSession(ctx, user, Session{Summary: Summary{ID: other, Kind: "qa", AgentID: "agent", AgentVersionID: "v1", Title: "race", Status: "active"}, UpdatedAt: time.Now().Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var holdErr, sweepErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, holdErr = store.PlaceLegalHold(ctx, governance, LegalHoldRequest{SessionID: other, Reason: "concurrent hold"})
	}()
	go func() {
		defer wg.Done()
		<-start
		_, sweepErr = store.SweepExpired(ctx, governance, time.Now(), 10)
	}()
	close(start)
	wg.Wait()
	if sweepErr != nil || (holdErr != nil && !errors.Is(holdErr, ErrNotFound)) {
		t.Fatalf("concurrent hold/sweep failed: hold=%v sweep=%v", holdErr, sweepErr)
	}
	var status string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_conversation_session WHERE id=?`), other).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if holdErr == nil && status == "deleted" {
		t.Fatal("committed legal hold and disposed session coexist")
	}
	approvalSession := id + "-approval"
	if err := store.CreateSession(ctx, user, Session{Summary: Summary{ID: approvalSession, Kind: "qa", AgentID: "agent", AgentVersionID: "v1", Title: "approval", Status: "active"}}); err != nil {
		t.Fatal(err)
	}
	request, err := store.RequestDeletion(ctx, user, DeleteRequest{SessionIDs: []string{approvalSession}, Reason: "owner request"})
	if err != nil {
		t.Fatal(err)
	}
	start = make(chan struct{})
	holdErr, sweepErr = nil, nil
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, holdErr = store.PlaceLegalHold(ctx, governance, LegalHoldRequest{SessionID: approvalSession, Reason: "concurrent approval hold"})
	}()
	go func() {
		defer wg.Done()
		<-start
		_, sweepErr = store.ApproveDeletion(ctx, governance, request.ID)
	}()
	close(start)
	wg.Wait()
	if (holdErr == nil && sweepErr == nil) ||
		(holdErr != nil && !errors.Is(holdErr, ErrNotFound)) ||
		(sweepErr != nil && !errors.Is(sweepErr, ErrLegalHold)) {
		t.Fatalf("hold and deletion approval both succeeded or failed unexpectedly: hold=%v approval=%v", holdErr, sweepErr)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_conversation_session WHERE id=?`), approvalSession).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if holdErr == nil && status == "deleted" {
		t.Fatal("approved deletion bypassed committed legal hold")
	}
}

func TestSQLRetentionSweepLimitSkipsUnexpiredOlderSession(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("retention-limit-%d", time.Now().UnixNano())
	defer func() {
		for _, table := range []string{"platform_conversation_retention_policy", "platform_conversation_session"} {
			if _, err := db.Exec(sqlutil.Bind(`DELETE FROM `+table+` WHERE tenant_id=?`), tenant); err != nil {
				t.Error(err)
			}
		}
	}()
	user := Scope{TenantID: tenant, DepartmentID: "department", ApplicationID: "application", PrincipalType: "user", PrincipalID: "owner"}
	governance := user
	governance.PrincipalType, governance.PrincipalID = "service_principal", "governance"
	for _, policy := range []RetentionPolicy{{Kind: "qa", RetentionDays: 30, Enabled: true}, {Kind: "check", RetentionDays: 1, Enabled: true}} {
		if _, err := store.PutRetentionPolicy(ctx, governance, policy); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		id, kind string
		age      time.Duration
	}{
		{"older-unexpired", "qa", 48 * time.Hour},
		{"newer-expired", "check", 36 * time.Hour},
	} {
		if err := store.CreateSession(ctx, user, Session{
			Summary:   Summary{ID: tenant + "-" + item.id, Kind: item.kind, AgentID: "agent", AgentVersionID: "v1", Title: item.id, Status: "active"},
			UpdatedAt: time.Now().Add(-item.age),
		}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := store.SweepExpired(ctx, governance, time.Now(), 1)
	if err != nil || result.Disposed != 1 {
		t.Fatalf("expired session hidden behind unexpired older session: %+v, %v", result, err)
	}
	for _, item := range []struct{ id, status string }{{"older-unexpired", "active"}, {"newer-expired", "deleted"}} {
		var status string
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_conversation_session WHERE id=?`), tenant+"-"+item.id).Scan(&status); err != nil || status != item.status {
			t.Fatalf("retention sweep %s status=%q want=%q: %v", item.id, status, item.status, err)
		}
	}
}
