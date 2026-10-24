package execution

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type postgresScopedOutcomeRecorder struct {
	runID  string
	fail   bool
	calls  int
	answer string
}

func (r *postgresScopedOutcomeRecorder) RecordRunResult(_ context.Context, _ sharedkernel.Scope, runID string, output map[string]any) error {
	if runID != r.runID {
		return errors.New("unrelated shared-fixture outcome")
	}
	r.calls++
	if r.fail {
		return errors.New("simulated projection outage")
	}
	r.answer, _ = output["answer"].(string)
	return nil
}

type postgresScopedCreationRecorder struct {
	runID             string
	conversationCalls int
	taskCalls         int
}

func (r *postgresScopedCreationRecorder) RecordRun(ctx context.Context, scope sharedkernel.Scope, body []byte) error {
	return r.RecordRunWithMessage(ctx, scope, body, "")
}

func (r *postgresScopedCreationRecorder) RecordRunWithMessage(_ context.Context, scope sharedkernel.Scope, _ []byte, _ string) error {
	if scope.RunID != r.runID {
		return errors.New("unrelated shared-fixture creation")
	}
	r.conversationCalls++
	return nil
}

func (r *postgresScopedCreationRecorder) RecordRunTask(_ context.Context, scope sharedkernel.Scope) error {
	if scope.RunID != r.runID {
		return errors.New("unrelated shared-fixture creation")
	}
	r.taskCalls++
	return nil
}

// Verify real SQL keyset ordering for both durable projection queues.
// 真实SQL验证两类持久化投影队列都能越过失败首批，不删除失败记录。
func TestSQLProjectionKeysetFairness(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal("isolated fixture open failed")
	}
	defer store.Close()
	prefix := fmt.Sprintf("zz-fairness-%d-", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := 0; i < 65; i++ {
		id := fmt.Sprintf("%s%03d", prefix, i)
		if _, err = store.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_outcome(run_id,revision,output_json,event_type,event_payload,projection_pending) VALUES(?,1,'{}','task_completed','{}',TRUE)`), id); err != nil {
			t.Fatal(err)
		}
		if _, err = store.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_creation_projection(run_id,message_id,conversation_pending,task_pending) VALUES(?,'',TRUE,TRUE)`), id); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.PendingOutcomesAfter(prefix, 64)
	if err != nil || len(first) != 64 {
		t.Fatalf("first outcome page: %d %v", len(first), err)
	}
	next, err := store.PendingOutcomesAfter(first[63].RunID, 64)
	if err != nil || len(next) != 1 || next[0].RunID != prefix+"064" {
		t.Fatalf("outcome cursor did not advance: %+v %v", next, err)
	}
	creations, err := store.PendingCreationsAfter(prefix, 64)
	if err != nil || len(creations) != 64 {
		t.Fatalf("first creation page: %d %v", len(creations), err)
	}
	more, err := store.PendingCreationsAfter(creations[63].RunID, 64)
	if err != nil || len(more) != 1 || more[0].RunID != prefix+"064" {
		t.Fatalf("creation cursor did not advance: %+v %v", more, err)
	}
	// Isolated fixtures must not poison later acceptance scenarios.
	// 精确移除本测试造出的记录，不能污染后续验收场景。
	if _, err = store.db.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_execution_outcome WHERE run_id LIKE ?`), prefix+"%"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_execution_creation_projection WHERE run_id LIKE ?`), prefix+"%"); err != nil {
		t.Fatal(err)
	}
}

// This suite requires an isolated PostgreSQL schema; never use a production DSN.
// 本组测试要求独立 PostgreSQL 库，通过真实触发器注入事务故障，禁止使用生产 DSN。
func TestSQLAtomicCreationAndOutcomeFaultRecovery(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal("open isolated SQL fixture failed")
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	exec := func(statement string) {
		t.Helper()
		if _, err := store.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			t.Fatalf("fixture statement failed: %v", err)
		}
	}
	exec(`CREATE FUNCTION fail_creation_projection_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected creation fault'; END $$`)
	defer store.db.ExecContext(context.Background(), sqlutil.Bind(`DROP FUNCTION IF EXISTS fail_creation_projection_fn() CASCADE`))
	exec(`CREATE TRIGGER fail_creation_projection BEFORE INSERT ON platform_execution_creation_projection FOR EACH ROW EXECUTE FUNCTION fail_creation_projection_fn()`)
	defer store.db.ExecContext(context.Background(), sqlutil.Bind(`DROP TRIGGER IF EXISTS fail_creation_projection ON platform_execution_creation_projection`))
	scope := testScope("sql-atomic-outcome-" + strconv.FormatInt(time.Now().UnixNano(), 10)).domain()
	// The migration acceptance batch runs platform packages concurrently against
	// one disposable PostgreSQL database. Keep the session reservation unique so
	// an unrelated fixture Run cannot legitimately block this lease claim.
	scope.SessionID = scope.RunID + "-session"
	request := platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: "v1", IdempotencyKey: scope.RunID, Fingerprint: "fp", MessageID: "saved-message"}
	if _, err := store.Create(request); err == nil {
		t.Fatal("creation fault falsely succeeded")
	}
	if _, err := store.Get(request.ID); !errors.Is(err, platformruntime.ErrRunNotFound) {
		t.Fatal("creation transaction left orphan Run")
	}
	var count int
	if err := store.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_execution_event WHERE run_id=?`), request.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("creation rollback left event")
	}
	exec(`DROP TRIGGER fail_creation_projection ON platform_execution_creation_projection`)
	created, err := store.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	p, err := store.GetCreation(created.Run.ID)
	if err != nil || !p.ConversationPending || !p.TaskPending || p.MessageID != "saved-message" {
		t.Fatalf("creation intent incomplete: %+v %v", p, err)
	}
	claimed, err := store.AcquireLease(created.Run.ID, "sql-owner", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, "sql-owner")
	if err != nil {
		t.Fatal(err)
	}
	command := platformruntime.DispatchCommand{RunID: running.ID, Revision: running.Revision, Operation: "invoke", BodyHash: strings.Repeat("a", 64), PolicyHash: strings.Repeat("b", 64)}
	if err := store.RecordDispatchCommand(command, "foreign-owner"); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatalf("SQL command owner fence failed: %v", err)
	}
	if err := store.RecordDispatchCommand(command, "sql-owner"); err != nil {
		t.Fatal(err)
	}
	if err := NewModuleWithSharedRepository("", store).ValidateLiveCommand(ctx, running.Scope, command.Operation, command.BodyHash, command.PolicyHash); err != nil {
		t.Fatal(err)
	}
	exec(`CREATE FUNCTION fail_terminal_event_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='task_completed' THEN RAISE EXCEPTION 'injected terminal fault'; END IF; RETURN NEW; END $$`)
	defer store.db.ExecContext(context.Background(), sqlutil.Bind(`DROP FUNCTION IF EXISTS fail_terminal_event_fn() CASCADE`))
	exec(`CREATE TRIGGER fail_terminal_event BEFORE INSERT ON platform_execution_event FOR EACH ROW EXECUTE FUNCTION fail_terminal_event_fn()`)
	defer store.db.ExecContext(context.Background(), sqlutil.Bind(`DROP TRIGGER IF EXISTS fail_terminal_event ON platform_execution_event`))
	output := map[string]any{"answer": "persisted evidence"}
	if _, err := store.FinalizeLeased(running.ID, platformruntime.StatusSucceeded, running.Revision, "sql-owner", output, nil); err == nil {
		t.Fatal("terminal fault falsely succeeded")
	}
	unchanged, err := store.Get(running.ID)
	if err != nil || unchanged.Status != platformruntime.StatusRunning || unchanged.Revision != running.Revision {
		t.Fatal("terminal fault committed partial state")
	}
	_, outcomeErr := store.GetOutcome(running.ID)
	events, eventErr := store.Events(running.ID, 0)
	if !errors.Is(outcomeErr, platformruntime.ErrRunNotFound) || eventErr != nil || len(events) != 2 {
		t.Fatal("terminal rollback retained outcome/event")
	}
	exec(`DROP TRIGGER fail_terminal_event ON platform_execution_event`)
	if _, err := store.FinalizeLeased(running.ID, platformruntime.StatusSucceeded, running.Revision, "foreign-owner", output, nil); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatalf("SQL owner fence failed: %v", err)
	}
	final, err := store.FinalizeLeased(running.ID, platformruntime.StatusSucceeded, running.Revision, "sql-owner", output, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A fresh connection reads durable intents after process restart.
	// 新连接模拟进程重启，仅依赖数据库保存的响应与待办。
	reopened, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal("reopen isolated SQL fixture failed")
	}
	defer reopened.Close()
	savedCommand, err := reopened.GetDispatchCommand(running.ID)
	if err != nil || savedCommand != command {
		t.Fatal("dispatch command lost after reconnection")
	}
	if err := NewModuleWithSharedRepository("", reopened).ValidateLiveCommand(ctx, running.Scope, command.Operation, command.BodyHash, command.PolicyHash); err == nil {
		t.Fatal("completed SQL Run admitted another capability")
	}
	stored, err := reopened.GetOutcome(running.ID)
	if err != nil || !stored.ProjectionPending || string(stored.OutputJSON) != `{"answer": "persisted evidence"}` && string(stored.OutputJSON) != `{"answer":"persisted evidence"}` {
		t.Fatalf("durable outcome lost: stored=%+v err=%v", stored, err)
	}
	if err := reopened.AcknowledgeOutcome(final.ID, final.Revision-1); !errors.Is(err, platformruntime.ErrRevisionConflict) {
		t.Fatal("stale SQL acknowledgment accepted")
	}
	if err := reopened.AcknowledgeOutcome(final.ID, final.Revision); err != nil {
		t.Fatal(err)
	}
	if err := reopened.AcknowledgeCreation(final.ID, "conversation"); err != nil {
		t.Fatal(err)
	}
	p, err = reopened.GetCreation(final.ID)
	if err != nil || p.ConversationPending || !p.TaskPending {
		t.Fatal("independent creation acknowledgment lost")
	}
}

// A fresh dispatcher repairs a persisted answer after projection storage
// recovers; it has no Agent gateway and therefore cannot rerun side effects.
// 新调度器仅凭持久化结果修补历史，不连接 Agent，避免重跑模型或工具。
func TestSQLProjectionOutageRecoversWithoutAgentExecution(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := "sql-projection-outage-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	scope := testScope(id).domain()
	scope.SessionID = id
	created, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: "v1", IdempotencyKey: id, Fingerprint: "fp", MessageID: "durable-first-message"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(id, "projection-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	var outcomeCursor string
	if err := store.db.QueryRowContext(context.Background(), sqlutil.Bind(`SELECT COALESCE(MAX(run_id),'') FROM platform_execution_outcome WHERE projection_pending=TRUE AND run_id<?`), id).Scan(&outcomeCursor); err != nil {
		t.Fatal(err)
	}
	recorder := &postgresScopedOutcomeRecorder{runID: id, fail: true}
	dispatcher := NewDispatcher(store, "", 1)
	dispatcher.outcomeCursor = outcomeCursor
	dispatcher.SetResultRecorder(recorder)
	if err := dispatcher.finish(running, platformruntime.StatusSucceeded, map[string]any{"answer": "durable result"}, nil); err != nil {
		t.Fatal(err)
	}
	firstOutcome, err := store.GetOutcome(id)
	if err != nil || !firstOutcome.ProjectionPending || recorder.calls != 1 || created.Run.ID != id {
		t.Fatal("projection failure did not leave a durable repair intent")
	}
	reopened, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recorder.fail = false
	restarted := NewDispatcher(reopened, "", 1)
	restarted.outcomeCursor = outcomeCursor
	restarted.SetResultRecorder(recorder)
	var creationCursor string
	if err := reopened.db.QueryRowContext(context.Background(), sqlutil.Bind(`SELECT COALESCE(MAX(run_id),'') FROM platform_execution_creation_projection WHERE (conversation_pending=TRUE OR task_pending=TRUE) AND run_id<?`), id).Scan(&creationCursor); err != nil {
		t.Fatal(err)
	}
	restarted.creationCursor = creationCursor
	creationRecorder := &postgresScopedCreationRecorder{runID: id}
	restarted.conversation, restarted.taskRecorder = creationRecorder, creationRecorder
	restarted.reconcile(context.Background())
	for len(restarted.queue) > 0 {
		if queued := <-restarted.queue; queued == id {
			t.Fatal("completed Agent was dispatched during projection repair")
		}
	}
	finalOutcome, err := reopened.GetOutcome(id)
	if err != nil || finalOutcome.ProjectionPending || recorder.calls != 2 || recorder.answer != "durable result" {
		t.Fatalf("reconciliation lost result or replayed Agent: outcome=%+v calls=%d answer=%q err=%v", finalOutcome, recorder.calls, recorder.answer, err)
	}
	creation, err := reopened.GetCreation(id)
	if err != nil || creation.ConversationPending || creation.TaskPending || creationRecorder.conversationCalls != 1 || creationRecorder.taskCalls != 1 {
		t.Fatalf("fresh SQL dispatcher did not repair creation projections: %+v recorder=%+v err=%v", creation, creationRecorder, err)
	}
}

// Concurrent first requests must commit one run and one accepted event, while
// different fingerprints remain conflicts after PostgreSQL's insert race.
func TestSQLConcurrentCreationReplaysSingleWinner(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatalf("open fixture: %T", err)
	}
	defer store.Close()
	scope := testScope(fmt.Sprintf("pg-concurrent-create-%d", time.Now().UnixNano())).domain()
	start := make(chan struct{})
	results := make(chan platformruntime.CreateResult, 20)
	failures := make(chan error, 20)
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			req := platformruntime.CreateRequest{ID: fmt.Sprintf("%s-%d", scope.RunID, i), Scope: scope, AgentVersionID: "v1", IdempotencyKey: scope.RunID, Fingerprint: "same"}
			result, err := store.Create(req)
			if err != nil {
				failures <- err
				return
			}
			results <- result
		}(i)
	}
	close(start)
	workers.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Errorf("concurrent create: %T %v", err, err)
	}
	var winner string
	fresh, total := 0, 0
	for result := range results {
		total++
		if winner == "" {
			winner = result.Run.ID
		}
		if result.Run.ID != winner {
			t.Errorf("multiple winners: %s versus %s", winner, result.Run.ID)
		}
		if !result.Replayed {
			fresh++
		}
	}
	if total != 20 || fresh != 1 {
		t.Fatalf("total=%d fresh=%d", total, fresh)
	}
	events, err := store.Events(winner, 0)
	if err != nil || len(events) != 1 || events[0].Type != "accepted" {
		t.Fatalf("accepted events=%+v err=%v", events, err)
	}
	_, err = store.Create(platformruntime.CreateRequest{ID: winner + "-conflict", Scope: scope, AgentVersionID: "v1", IdempotencyKey: scope.RunID, Fingerprint: "different"})
	if !errors.Is(err, platformruntime.ErrIdempotencyConflict) {
		t.Fatalf("changed fingerprint accepted: %v", err)
	}
}
