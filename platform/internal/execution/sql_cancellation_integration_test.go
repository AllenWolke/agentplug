package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Real transaction failures require a disposable database, never a live KB.
// 真实事务故障只允许使用临时隔离数据库，禁止使用现有知识库数据库。
func TestSQLCancellationIntentAndOutcomeFaultRecovery(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal("open isolated cancellation fixture failed")
	}
	defer store.Close()
	prefix := fmt.Sprintf("cancel-sql-%d", time.Now().UnixNano())
	scope := testScope(prefix).domain()
	scope.SessionID = prefix
	create := func(id string) platformruntime.Run {
		t.Helper()
		scope.RunID = id
		result, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "fixture"})
		if err != nil {
			t.Fatal(err)
		}
		return result.Run
	}
	first, next := create(prefix+"-first"), create(prefix+"-next")
	claimed, err := store.AcquireLease(first.ID, "cancel-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(first.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(query string) {
		t.Helper()
		if _, err := store.db.Exec(sqlutil.Bind(query)); err != nil {
			t.Fatal("fixture statement failed")
		}
	}
	exec(`CREATE FUNCTION cancel_intent_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='cancel_requested' THEN RAISE EXCEPTION 'fixture fault'; END IF; RETURN NEW; END $$`)
	defer store.db.Exec(sqlutil.Bind(`DROP FUNCTION IF EXISTS cancel_intent_fault_fn() CASCADE`))
	exec(`CREATE TRIGGER cancel_intent_fault BEFORE INSERT ON platform_execution_event FOR EACH ROW EXECUTE FUNCTION cancel_intent_fault_fn()`)
	defer store.db.Exec(sqlutil.Bind(`DROP TRIGGER IF EXISTS cancel_intent_fault ON platform_execution_event`))
	if _, err := store.BeginCancellation(first.ID, running.Revision); err == nil {
		t.Fatal("intent event fault falsely succeeded")
	}
	unchanged, err := store.Get(first.ID)
	if err != nil || unchanged.Status != platformruntime.StatusRunning || unchanged.Revision != running.Revision || unchanged.LeaseToken != running.LeaseToken {
		t.Fatal("intent failure committed partial state")
	}
	exec(`DROP TRIGGER cancel_intent_fault ON platform_execution_event`)
	// Multiple cancel requests may replay intent, but must not duplicate events.
	// 并发取消允许回放同一意图，但不得重复创建意图事件。
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := store.BeginCancellationWithReason(first.ID, running.Revision, "AGENT_EXECUTION_TIMEOUT"); err != nil && !errors.Is(err, platformruntime.ErrRevisionConflict) {
				t.Error("concurrent cancel failed unexpectedly")
			}
		}()
	}
	group.Wait()
	pending, err := store.Get(first.ID)
	if err != nil || pending.Status != platformruntime.StatusCancelling || pending.Revision != running.Revision+1 || pending.LeaseToken != running.LeaseToken {
		t.Fatal("cancel intent was not fenced")
	}
	var count int
	if err := store.db.QueryRow(sqlutil.Bind(`SELECT COUNT(*) FROM platform_execution_event WHERE run_id=? AND event_type='cancel_requested'`), first.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("intent audit not exactly once")
	}
	// The failure cause must survive a reconnect, not just a process log.
	// 原始失败原因必须可在重连后查询，不能仅保存在进程日志中。
	var payload []byte
	if err := store.db.QueryRow(sqlutil.Bind(`SELECT payload FROM platform_execution_event WHERE run_id=? AND event_type='cancel_requested'`), first.ID).Scan(&payload); err != nil {
		t.Fatal("persisted cancellation reason unavailable")
	}
	var intent struct {
		Code     string `json:"code"`
		Revision uint64 `json:"revision"`
	}
	if err := json.Unmarshal(payload, &intent); err != nil || intent.Code != "AGENT_EXECUTION_TIMEOUT" || intent.Revision != pending.Revision {
		t.Fatal("cancellation intent lost its original failure cause or generation")
	}
	reopened, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal("reconnect fixture failed")
	}
	defer reopened.Close()
	if rows, err := reopened.PendingCancellations(256); err != nil {
		t.Fatal(err)
	} else {
		found := false
		for _, row := range rows {
			found = found || row.ID == first.ID
		}
		if !found {
			t.Fatal("pending cancellation lost after reconnect")
		}
	}
	assertRetained := func() {
		t.Helper()
		current, err := reopened.Get(first.ID)
		if err != nil || current.Status != platformruntime.StatusCancelling || current.Revision != pending.Revision || current.LeaseToken != pending.LeaseToken {
			t.Fatal("terminal fault committed state")
		}
		if _, err := reopened.GetOutcome(first.ID); !errors.Is(err, platformruntime.ErrRunNotFound) {
			t.Fatal("terminal fault left outcome")
		}
		if _, err := reopened.AcquireLease(next.ID, "next-owner", time.Now().UTC().Add(time.Hour), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
			t.Fatal("pending stop released checkpoint reservation")
		}
	}
	exec(`CREATE FUNCTION cancel_outcome_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture fault'; END $$`)
	defer store.db.Exec(sqlutil.Bind(`DROP FUNCTION IF EXISTS cancel_outcome_fault_fn() CASCADE`))
	exec(`CREATE TRIGGER cancel_outcome_fault BEFORE INSERT ON platform_execution_outcome FOR EACH ROW EXECUTE FUNCTION cancel_outcome_fault_fn()`)
	defer store.db.Exec(sqlutil.Bind(`DROP TRIGGER IF EXISTS cancel_outcome_fault ON platform_execution_outcome`))
	if _, err := reopened.Cancel(first.ID, pending.Revision); err == nil {
		t.Fatal("outcome fault falsely succeeded")
	}
	assertRetained()
	exec(`DROP TRIGGER cancel_outcome_fault ON platform_execution_outcome`)
	exec(`CREATE FUNCTION cancel_event_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='task_cancelled' THEN RAISE EXCEPTION 'fixture fault'; END IF; RETURN NEW; END $$`)
	defer store.db.Exec(sqlutil.Bind(`DROP FUNCTION IF EXISTS cancel_event_fault_fn() CASCADE`))
	exec(`CREATE TRIGGER cancel_event_fault BEFORE INSERT ON platform_execution_event FOR EACH ROW EXECUTE FUNCTION cancel_event_fault_fn()`)
	defer store.db.Exec(sqlutil.Bind(`DROP TRIGGER IF EXISTS cancel_event_fault ON platform_execution_event`))
	if _, err := reopened.Cancel(first.ID, pending.Revision); err == nil {
		t.Fatal("terminal event fault falsely succeeded")
	}
	assertRetained()
	exec(`DROP TRIGGER cancel_event_fault ON platform_execution_event`)
	final, err := reopened.Cancel(first.ID, pending.Revision)
	if err != nil || final.Status != platformruntime.StatusCancelled {
		t.Fatal("cancel compensation failed")
	}
	if outcome, err := reopened.GetOutcome(first.ID); err != nil || outcome.Revision != final.Revision || outcome.EventType != "task_cancelled" {
		t.Fatal("durable cancelled result missing")
	}
	if _, err := reopened.AcquireLease(next.ID, "next-owner", time.Now().UTC(), time.Minute); err != nil {
		t.Fatal("confirmed stop failed to release reservation")
	}
}
