package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type blockingSQLGateway struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (g *blockingSQLGateway) Invoke(ctx context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	if g.calls.Add(1) == 1 {
		close(g.started)
	}
	select {
	case <-g.release:
		return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded"}, nil
	case <-ctx.Done():
		return contract.ExecuteResponse{}, ctx.Err()
	}
}

func (g *blockingSQLGateway) Resume(ctx context.Context, target agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return g.Invoke(ctx, target, request)
}

// Two dispatchers race through independent SQL connections while the winner's
// Agent call remains blocked. The loser must never enter the Agent gateway.
// 两个调度器真实并发争用，赢家的 Agent 调用阻塞期间输家不得进入网关。
func TestSQLConcurrentDispatchersOnlyInvokeOnce(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	first, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	id := fmt.Sprintf("sql-concurrent-dispatch-%d", time.Now().UnixNano())
	scope := testScope(id)
	scope.SessionID = id
	created, err := first.Create(platformruntime.CreateRequest{ID: id, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: id, Fingerprint: "fixture", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	gateway := &blockingSQLGateway{started: make(chan struct{}), release: make(chan struct{})}
	newDispatcher := func(store Repository) *Dispatcher {
		d := NewDispatcherWithGateway(store, "secret", gateway, 1)
		d.SetSecurity(machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
			return "fresh-concurrent-context-token-000000000000000000000000", nil
		}), func(context.Context, sharedkernel.Scope) error { return nil })
		return d
	}
	d1, d2 := newDispatcher(first), newDispatcher(second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	firstDone := make(chan error, 1)
	go func() { firstDone <- d1.dispatch(ctx, created.Run) }()
	select {
	case <-gateway.started:
	case <-ctx.Done():
		t.Fatal("first dispatcher did not reach gateway")
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- d2.dispatch(ctx, created.Run) }()
	select {
	case err := <-secondDone:
		if !errors.Is(err, platformruntime.ErrLeaseConflict) {
			t.Fatalf("foreign dispatcher did not honor owner lease: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("foreign dispatcher blocked while winner owned lease")
	}
	if gateway.calls.Load() != 1 {
		t.Fatalf("duplicate Agent side effect before terminal CAS: %d", gateway.calls.Load())
	}
	close(gateway.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	final, err := second.Get(id)
	if err != nil || final.Status != platformruntime.StatusSucceeded || gateway.calls.Load() != 1 {
		t.Fatalf("concurrent dispatch result=%+v calls=%d err=%v", final, gateway.calls.Load(), err)
	}
}

// Use a disposable database to prove recovery state/event/session atomicity.
// 临时数据库验证恢复状态、审计和会话归属原子性，不连接已有业务数据库。
func TestSQLRecoveryStopBarrierRollsBackAndRetainsResume(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	s, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id := fmt.Sprintf("sql-recovery-%d", time.Now().UnixNano())
	scope := testScope(id)
	// Each repeat owns a distinct checkpoint; an earlier running fixture must
	// correctly block another Run in the same session, not this independent case.
	// 每次重复使用独立会话；保留上一用例的运行归属，不能为测试绕过 FIFO。
	scope.SessionID = id
	const durableTrace = `{"traceparent":"00-11111111111111111111111111111111-2222222222222222-01"}`
	created, err := s.Create(platformruntime.CreateRequest{ID: id, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: id, Fingerprint: "fixture", TraceContext: durableTrace, RequestJSON: gatewayRequest(t, scope, "invoke"), AgentEndpoint: "http://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	running, err := s.Transition(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, created.Run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Transition(id, platformruntime.StatusRunning, platformruntime.StatusWaiting, running.Revision); err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"decision":"approve"}`)
	if _, err := s.PrepareResume(id, input); err != nil {
		t.Fatal(err)
	}
	old, err := s.AcquireLease(id, "old-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var dispatched contract.ExecuteRequest
	if err := json.Unmarshal(created.Run.RequestJSON, &dispatched); err != nil {
		t.Fatal(err)
	}
	if err := dispatched.Validate(); err != nil {
		t.Fatal("stored original request is invalid:", err)
	}
	dispatched.Operation = "resume"
	if err := json.Unmarshal(input, &dispatched.ResumeInput); err != nil || dispatched.ResumeInput == nil {
		t.Fatal("stored resume input is not a JSON object", err)
	}
	if err := dispatched.Validate(); err != nil {
		t.Fatal("reconstructed resume request is invalid:", err)
	}
	bodyHash, err := contract.CanonicalExecuteBodyHash(dispatched)
	if err != nil {
		t.Fatal(err)
	}
	policySnapshot, ok := dispatched.Input["policy_snapshot"].(map[string]any)
	if !ok {
		t.Fatal("original command has no policy snapshot")
	}
	policyHash, ok := policySnapshot["content_hash"].(string)
	if !ok || len(policyHash) != 64 {
		t.Fatal("original command has no valid policy hash")
	}
	oldCommand := platformruntime.DispatchCommand{
		RunID: id, Revision: old.Revision, Operation: dispatched.Operation,
		BodyHash: bodyHash, PolicyHash: policyHash,
	}
	if err := s.RecordDispatchCommand(oldCommand, old.LeaseToken); err != nil {
		t.Fatal("record original leased dispatch command:", err)
	}
	recoveryNow := time.Now().UTC()
	expiredAt := recoveryNow.Add(-time.Second)
	leaseTx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	runExpiry, err := leaseTx.ExecContext(context.Background(), sqlutil.Bind(`UPDATE platform_execution_run SET lease_until=? WHERE run_id=? AND lease_token=? AND revision=?`), expiredAt, id, old.LeaseToken, old.Revision)
	if err != nil {
		_ = leaseTx.Rollback()
		t.Fatal(err)
	}
	runRows, err := runExpiry.RowsAffected()
	if err != nil || runRows != 1 {
		_ = leaseTx.Rollback()
		t.Fatal("failed to expire original run lease", err)
	}
	sessionExpiry, err := leaseTx.ExecContext(context.Background(), sqlutil.Bind(`UPDATE platform_execution_session_lease SET lease_until=? WHERE session_key=? AND run_id=? AND lease_token=?`), expiredAt, platformruntime.SessionExecutionKey(old.Scope), id, old.LeaseToken)
	if err != nil {
		_ = leaseTx.Rollback()
		t.Fatal(err)
	}
	sessionRows, err := sessionExpiry.RowsAffected()
	if err != nil || sessionRows != 1 {
		_ = leaseTx.Rollback()
		t.Fatal("failed to expire original session lease", err)
	}
	if err := leaseTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcquireLease(id, "thief", time.Now().UTC(), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("expired run lease was stolen before stop")
	}
	pending, err := s.BeginRecovery(id, old.Revision, recoveryNow)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := s.db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_execution_dispatch_command WHERE run_id=? AND revision=?`), id, oldCommand.Revision)
	if err != nil {
		t.Fatal(err)
	}
	deletedRows, err := deleted.RowsAffected()
	if err != nil || deletedRows != 1 {
		t.Fatal("failed to remove original dispatch command for recovery rejection check", err)
	}
	if _, err := s.CompleteRecovery(id, pending.Revision); err == nil {
		t.Fatal("recovery completed without the original dispatch command")
	}
	withoutDispatch, err := s.Get(id)
	if err != nil || withoutDispatch.Status != platformruntime.StatusRecovering || withoutDispatch.LeaseToken != old.LeaseToken || withoutDispatch.Revision != pending.Revision {
		t.Fatal("missing dispatch rejection changed the old execution generation")
	}
	if _, err := s.db.ExecContext(context.Background(), sqlutil.Bind(`INSERT INTO platform_execution_dispatch_command(run_id,revision,operation,body_hash,policy_hash) VALUES (?,?,?,?,?)`), oldCommand.RunID, oldCommand.Revision, oldCommand.Operation, oldCommand.BodyHash, oldCommand.PolicyHash); err != nil {
		t.Fatal("failed to restore original dispatch command fixture:", err)
	}
	if _, err := s.db.Exec(sqlutil.Bind(`CREATE FUNCTION recovery_ack_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.event_type='recovery_stop_confirmed' THEN RAISE EXCEPTION 'fixture fault' USING ERRCODE='P0001'; END IF; RETURN NEW; END $fault$; CREATE TRIGGER recovery_ack_fault BEFORE INSERT ON platform_execution_event FOR EACH ROW EXECUTE FUNCTION recovery_ack_fault_fn()`)); err != nil {
		t.Fatal(err)
	}
	defer s.db.Exec(sqlutil.Bind(`DROP TRIGGER IF EXISTS recovery_ack_fault ON platform_execution_event; DROP FUNCTION IF EXISTS recovery_ack_fault_fn()`))
	if _, err := s.CompleteRecovery(id, pending.Revision); err == nil {
		t.Fatal("partial recovery committed")
	}
	unchanged, err := s.Get(id)
	if err != nil || unchanged.Status != platformruntime.StatusRecovering || unchanged.LeaseToken != old.LeaseToken || unchanged.Revision != pending.Revision {
		t.Fatal("recovery fault lost old generation")
	}
	if _, err := s.db.Exec(sqlutil.Bind(`DROP TRIGGER recovery_ack_fault ON platform_execution_event; DROP FUNCTION IF EXISTS recovery_ack_fault_fn()`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteRecovery(id, pending.Revision); err != nil {
		t.Fatal(err)
	}
	reopened, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.Get(id)
	if err != nil || recovered.Status != platformruntime.StatusRunning || recovered.LeaseToken != "" || string(recovered.RequestJSON) != string(created.Run.RequestJSON) || string(recovered.ResumeInputJSON) != string(input) || recovered.TraceContext != durableTrace {
		t.Fatal("resume command lost after reconnect")
	}
	var eventPayload []byte
	if err := reopened.db.QueryRowContext(context.Background(), sqlutil.Bind(`SELECT payload FROM platform_execution_event WHERE run_id=? AND event_type='recovery_stop_confirmed' ORDER BY seq DESC LIMIT 1`), id).Scan(&eventPayload); err != nil {
		t.Fatal("recovery stop reference event missing:", err)
	}
	var stopEvent struct {
		Revision          uint64                `json:"revision"`
		RecoveryReference RecoveryStopReference `json:"recovery_reference"`
	}
	if err := json.Unmarshal(eventPayload, &stopEvent); err != nil {
		t.Fatal(err)
	}
	reference := stopEvent.RecoveryReference
	if !reference.valid() || stopEvent.Revision != recovered.Revision || reference.RunID != id ||
		reference.StoppedRevision != oldCommand.Revision || reference.ReadyRevision != recovered.Revision ||
		reference.Operation != oldCommand.Operation || reference.BodyHash != oldCommand.BodyHash ||
		reference.PolicyHash != oldCommand.PolicyHash || reference.LeaseHash != stopHash([]byte(old.LeaseToken)) ||
		reference.RequestHash != stopHash(created.Run.RequestJSON) || reference.ResumeInputHash != stopHash(input) ||
		reference.Source != "sdk-cancel-exit/v1" || reference.ProofDigest != "" || reference.RuntimeID != "" {
		t.Fatal("recovery event did not preserve the non-secret original dispatch reference")
	}
	if bytes.Contains(eventPayload, []byte(old.LeaseToken)) || bytes.Contains(eventPayload, created.Run.RequestJSON) || bytes.Contains(eventPayload, input) {
		t.Fatal("recovery event contains plaintext lease or command input")
	}
	if _, err := reopened.GetOutcome(id); !errors.Is(err, platformruntime.ErrRunNotFound) {
		t.Fatal("recovery fabricated a cancelled outcome")
	}
	rows, err := reopened.ListPending(256)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.ID == id && row.TraceContext != durableTrace {
			t.Fatal("trace context lost in reconciliation query")
		}
		found = found || row.ID == id
	}
	if !found {
		t.Fatal("recovery/resume wakeup lost after reconnect")
	}
	if _, err := reopened.AcquireLease(id, "new-owner", time.Now().UTC(), time.Minute); err != nil {
		t.Fatal("confirmed stop did not permit original command")
	}
}

// Two independently opened stores emulate two dispatchers sharing only SQL.
// 两个独立数据库连接模拟跨进程调度器，旧快照不能转移租约或覆盖恢复命令。
func TestSQLDualDispatcherFencesLeaseAndReadsLatestResume(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	first, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	newRun := func(prefix string) (platformruntime.Run, scopeDTO) {
		id := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
		scope := testScope(id)
		scope.SessionID = id
		created, err := first.Create(platformruntime.CreateRequest{ID: id, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: id, Fingerprint: "fixture", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example"})
		if err != nil {
			t.Fatal(err)
		}
		return created.Run, scope
	}
	stale, _ := newRun("sql-two-owners")
	claimed, err := first.AcquireLease(stale.ID, "first-dispatcher-private-lease", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.TransitionLeased(stale.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken); err != nil {
		t.Fatal(err)
	}
	foreignGateway := &dispatcherGatewayStub{}
	foreign := NewDispatcherWithGateway(second, "secret", foreignGateway, 1)
	if err := foreign.dispatch(context.Background(), stale); !errors.Is(err, platformruntime.ErrLeaseConflict) || foreignGateway.invoked || foreignGateway.resumed {
		t.Fatalf("foreign dispatcher bypassed SQL lease: err=%v gateway=%+v", err, foreignGateway)
	}
	resumeSnapshot, _ := newRun("sql-latest-resume")
	running, err := first.Transition(resumeSnapshot.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, resumeSnapshot.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Transition(resumeSnapshot.ID, platformruntime.StatusRunning, platformruntime.StatusWaiting, running.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := first.PrepareResume(resumeSnapshot.ID, []byte(`{"approved":true}`)); err != nil {
		t.Fatal(err)
	}
	resumeGateway := &dispatcherGatewayStub{}
	resumer := NewDispatcherWithGateway(second, "secret", resumeGateway, 1)
	resumer.SetSecurity(machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
		return "fresh-signed-test-token-00000000000000000000000000", nil
	}), func(context.Context, sharedkernel.Scope) error { return nil })
	if err := resumer.dispatch(context.Background(), resumeSnapshot); err != nil {
		t.Fatal(err)
	}
	if resumeGateway.invoked || !resumeGateway.resumed {
		t.Fatalf("stale Invoke snapshot displaced durable Resume: %+v", resumeGateway)
	}
	outcome, err := second.GetOutcome(resumeSnapshot.ID)
	if err != nil || outcome.EventType != "task_completed" {
		t.Fatalf("latest resume did not complete: outcome=%+v err=%v", outcome, err)
	}
}
