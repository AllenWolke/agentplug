package usagecost

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

var (
	errTreeBudgetTestNoReceipt = errors.New("test authority has no immutable provider receipt")
	errTreeBudgetTestAudit     = errors.New("test transactional audit recorder failed after insert")
)

// treeBudgetSQLTestAuthority is an explicit in-test facts/receipt fixture. It
// does not represent production IAM, Execution, coordination or provider APIs.
type treeBudgetSQLTestAuthority struct {
	mu       sync.RWMutex
	facts    map[string]RunTreeBudgetFacts
	receipts map[string]treeBudgetSQLTestReceipt
}

type treeBudgetSQLTestReceipt struct {
	Action             string
	Fingerprint        string
	ActualMicros       int64
	InputTokens        int64
	OutputTokens       int64
	OutcomeFingerprint string
}

func newTreeBudgetSQLTestAuthority() *treeBudgetSQLTestAuthority {
	return &treeBudgetSQLTestAuthority{
		facts:    make(map[string]RunTreeBudgetFacts),
		receipts: make(map[string]treeBudgetSQLTestReceipt),
	}
}

func (a *treeBudgetSQLTestAuthority) AddScope(scope, root sharedkernel.Scope, policyHash string, limitMicros, limitTokens int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.facts[treeScopeKey(scope)] = RunTreeBudgetFacts{
		ActorScope: scope, RootScope: root, PolicyHash: policyHash,
		LimitMicros: limitMicros, LimitTokens: limitTokens,
	}
}

func (a *treeBudgetSQLTestAuthority) Facts(_ context.Context, _ *sql.Tx, scope sharedkernel.Scope, _ bool) (RunTreeBudgetFacts, error) {
	a.mu.RLock()
	facts, ok := a.facts[treeScopeKey(scope)]
	a.mu.RUnlock()
	if !ok {
		return RunTreeBudgetFacts{}, ErrBudgetScopeMismatch
	}
	return facts, nil
}

func (a *treeBudgetSQLTestAuthority) AddReceipt(scope sharedkernel.Scope, requestID string, receipt treeBudgetSQLTestReceipt) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.receipts[treeBudgetTestReceiptKey(scope, requestID)] = receipt
}

func (a *treeBudgetSQLTestAuthority) VerifyOutcome(_ context.Context, _ *sql.Tx, scope sharedkernel.Scope, command RunTreeBudgetCommand) error {
	a.mu.RLock()
	receipt, ok := a.receipts[treeBudgetTestReceiptKey(scope, command.RequestID)]
	a.mu.RUnlock()
	if !ok {
		return errTreeBudgetTestNoReceipt
	}
	if receipt.Action != command.Action || receipt.Fingerprint != command.Fingerprint ||
		receipt.ActualMicros != command.ActualMicros || receipt.InputTokens != command.InputTokens ||
		receipt.OutputTokens != command.OutputTokens || receipt.OutcomeFingerprint != command.OutcomeFingerprint {
		return ErrBudgetReservationConflict
	}
	return nil
}

func treeBudgetTestReceiptKey(scope sharedkernel.Scope, requestID string) string {
	return treeScopeKey(scope) + ":" + requestID
}

// treeBudgetTestAuditRecorder writes into a dedicated fixture table using the
// caller's SQL transaction. Failure after INSERT proves both writes roll back.
type treeBudgetTestAuditRecorder struct {
	failAfterInsert bool
}

func (r *treeBudgetTestAuditRecorder) EnsureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_run_tree_budget_test_audit (
		event_id VARCHAR(128) PRIMARY KEY,
		tenant_id VARCHAR(128) NOT NULL,
		action VARCHAR(128) NOT NULL,
		aggregate_id VARCHAR(128) NOT NULL
	)`)
	return err
}

func (r *treeBudgetTestAuditRecorder) RecordTx(tx *sql.Tx, event audit.Event) error {
	if tx == nil {
		return errors.New("test audit transaction is required")
	}
	if _, err := tx.Exec(sqlutil.Bind(`INSERT INTO platform_run_tree_budget_test_audit(event_id,tenant_id,action,aggregate_id) VALUES(?,?,?,?)`), event.ID, event.TenantID, event.Action, event.AggregateID); err != nil {
		return err
	}
	if r.failAfterInsert {
		return errTreeBudgetTestAudit
	}
	return nil
}

var _ audit.TxRecorder = (*treeBudgetTestAuditRecorder)(nil)
var _ RunTreeBudgetAuthority = (*treeBudgetSQLTestAuthority)(nil)

func TestRunTreeBudgetDenialDiagnosticAllowlistAndDimensions(t *testing.T) {
	scope := sharedkernel.Scope{PrincipalID: "user-data-sentinel", SessionID: "private-session-data-sentinel", RunID: "trusted-run", TraceID: "trusted-trace"}
	tests := []struct {
		name      string
		current   RunTreeBudgetCounters
		hold      RunTreeBudgetHold
		dimension string
	}{
		{name: "cost", current: RunTreeBudgetCounters{LimitMicros: 100, LimitTokens: 1000, UsedMicros: 20, HeldMicros: 30, UsedTokens: 100}, hold: RunTreeBudgetHold{Micros: 51, Tokens: 10}, dimension: "cost"},
		{name: "tokens", current: RunTreeBudgetCounters{LimitMicros: 1000, LimitTokens: 100, UsedMicros: 100, HeldMicros: 100, UsedTokens: 20, HeldTokens: 30}, hold: RunTreeBudgetHold{Micros: 10, Tokens: 51}, dimension: "tokens"},
		{name: "both", current: RunTreeBudgetCounters{LimitMicros: 100, LimitTokens: 100, UsedMicros: 20, HeldMicros: 30, UsedTokens: 10, HeldTokens: 20}, hold: RunTreeBudgetHold{Micros: 51, Tokens: 71}, dimension: "cost_and_tokens"},
	}
	allowedFields := map[string]bool{
		"event": true, "stage": true, "run_id": true, "trace_id": true, "dimension": true,
		"limit_micros": true, "used_micros": true, "held_micros": true, "attempt_micros": true,
		"limit_tokens": true, "used_tokens": true, "held_tokens": true, "attempt_tokens": true,
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.current
			next, err := ReserveRunTreeBudget(tc.current, tc.hold)
			if !errors.Is(err, ErrBudgetExceeded) || next != before {
				t.Fatalf("rejected pure reservation changed counters or error identity: before=%+v next=%+v err=%v", before, next, err)
			}
			fields := strings.Fields(formatRunTreeBudgetDenied(scope, tc.current, tc.hold))
			parsed := make(map[string]string, len(fields))
			for _, field := range fields {
				key, value, ok := strings.Cut(field, "=")
				if !ok || !allowedFields[key] {
					t.Fatalf("diagnostic contains unapproved field %q", field)
				}
				parsed[key] = strings.Trim(value, `"`)
			}
			if len(parsed) != len(allowedFields) || parsed["event"] != "run_tree_budget_denied" || parsed["stage"] != "root_reserve" ||
				parsed["run_id"] != scope.RunID || parsed["trace_id"] != scope.TraceID || parsed["dimension"] != tc.dimension {
				t.Fatalf("diagnostic fields or rejection dimension mismatch: %#v", parsed)
			}
		})
	}
}

func newTreeBudgetSQLTestFixture(t *testing.T) (*SQLRunTreeBudgetStore, *SQLStore, *treeBudgetSQLTestAuthority, *treeBudgetTestAuditRecorder, context.Context) {
	t.Helper()
	windowStore := openModelBudgetSQLStore(t)
	db := windowStore.db
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	tree := NewSQLRunTreeBudgetStore(db)
	if err := tree.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure isolated Run-tree SQL test schema: %v", err)
	}
	authority := newTreeBudgetSQLTestAuthority()
	settingsAudit := &treeBudgetTestAuditRecorder{}
	if err := settingsAudit.EnsureSchema(ctx, db); err != nil {
		t.Fatalf("ensure isolated SQL transaction-audit fixture: %v", err)
	}
	tree.SetAuthority(authority)
	tree.SetAuditRecorder(settingsAudit)
	return tree, windowStore, authority, settingsAudit, ctx
}

func newTreeBudgetTestRoot(t *testing.T) sharedkernel.Scope {
	t.Helper()
	suffix := uniqueBudgetSuffix(t)
	return sharedkernel.Scope{
		TenantID: "tree-budget-test-" + suffix, DepartmentID: "dept-" + suffix, ApplicationID: "app-" + suffix,
		AgentInstanceID: "instance-" + suffix, AgentID: "agent-fixture", PrincipalID: "user-" + suffix,
		PrincipalType: "user", InstallationID: "installation-" + suffix, AgentVersionID: "agent-v1",
		SessionID: "session-" + suffix, RunID: "root-" + suffix, AuthorizationEpoch: 1,
		TraceID: fingerprintFor("root-trace-" + suffix),
	}
}

func newTreeBudgetTestChild(root sharedkernel.Scope, label string) sharedkernel.Scope {
	child := root
	child.RunID = "child-" + label
	child.ParentRunID = root.RunID
	child.TraceID = fingerprintFor("child-trace-" + label)
	return child
}

func treeBudgetTestPolicyHash(root sharedkernel.Scope) string {
	return fingerprintFor("immutable-test-policy-" + root.RunID)
}

func TestValidTreeFactsAdmitsExactEvaluationCaseBudgetRootOnly(t *testing.T) {
	parent := newTreeBudgetTestRoot(t)
	child := parent
	child.RunID = "evaluation-case-" + parent.RunID
	child.ParentRunID = "evaluation-product-" + parent.RunID
	child.TraceID = fingerprintFor("evaluation-case-trace-" + child.RunID)
	facts := RunTreeBudgetFacts{
		ActorScope: child, RootScope: child, PolicyHash: treeBudgetTestPolicyHash(child),
		LimitMicros: 1_600_000, LimitTokens: 16_000, EvaluationRoot: true,
	}
	if !validTreeFacts(facts, child) {
		t.Fatal("exact depth-zero Evaluation case root should retain its product parent and use its finite own budget")
	}

	bad := facts
	bad.RootScope.ParentRunID = "another-product-run"
	if validTreeFacts(bad, child) {
		t.Fatal("Evaluation root accepted a different product parent")
	}
	bad = facts
	bad.RootScope.RunID += "-foreign"
	if validTreeFacts(bad, child) {
		t.Fatal("Evaluation root accepted a different execution Run")
	}
	bad = facts
	bad.ActorScope.PrincipalID += "-foreign"
	if validTreeFacts(bad, child) {
		t.Fatal("Evaluation root accepted a different actor")
	}
	bad = facts
	bad.EvaluationRoot = false
	if validTreeFacts(bad, child) {
		t.Fatal("ordinary root path accepted a depth-zero Evaluation parent")
	}
	delegated := child
	delegated.RunID += "-delegated"
	delegated.ParentRunID = child.RunID
	bad = facts
	bad.ActorScope = delegated
	if validTreeFacts(bad, delegated) {
		t.Fatal("Evaluation root flag authorized a positive-depth child")
	}

	ordinary := newTreeBudgetTestRoot(t)
	ordinaryFacts := RunTreeBudgetFacts{ActorScope: ordinary, RootScope: ordinary, PolicyHash: treeBudgetTestPolicyHash(ordinary), LimitMicros: 5, LimitTokens: 6}
	if !validTreeFacts(ordinaryFacts, ordinary) {
		t.Fatal("ordinary parentless root behavior changed")
	}
}

func registerTreeBudgetTestScopes(authority *treeBudgetSQLTestAuthority, root sharedkernel.Scope, scopes []sharedkernel.Scope, policyHash string, limitMicros, limitTokens int64) {
	for _, scope := range scopes {
		authority.AddScope(scope, root, policyHash, limitMicros, limitTokens)
	}
}

func treeBudgetTestCommand(action, requestID, fingerprint string, hold RunTreeBudgetHold) RunTreeBudgetCommand {
	return RunTreeBudgetCommand{Action: action, RequestID: requestID, Fingerprint: fingerprint, Hold: hold}
}

func TestSQLRunTreeBudgetConcurrentRootAndChildReservationsShareLimitAndReplay(t *testing.T) {
	tree, windowStore, authority, _, ctx := newTreeBudgetSQLTestFixture(t)
	root := newTreeBudgetTestRoot(t)
	policyHash := treeBudgetTestPolicyHash(root)
	scopes := make([]sharedkernel.Scope, 20)
	scopes[0] = root
	for i := 1; i < len(scopes); i++ {
		scopes[i] = newTreeBudgetTestChild(root, fmt.Sprintf("%s-%02d", root.RunID, i))
	}
	registerTreeBudgetTestScopes(authority, root, scopes, policyHash, 5, 20)

	start := make(chan struct{})
	type result struct {
		accepted bool
		err      error
	}
	results := make(chan result, len(scopes))
	var workers sync.WaitGroup
	for i, scope := range scopes {
		workers.Add(1)
		go func(i int, scope sharedkernel.Scope) {
			defer workers.Done()
			<-start
			requestID := fmt.Sprintf("request-%02d", i)
			command := treeBudgetTestCommand("reserve", requestID, fingerprintFor(root.RunID+"-"+requestID), RunTreeBudgetHold{Micros: 1, Tokens: 1})
			receipt, err := tree.Apply(ctx, scope, command)
			if errors.Is(err, ErrBudgetExceeded) {
				results <- result{}
				return
			}
			if err != nil {
				results <- result{err: fmt.Errorf("reserve %s: %w", scope.RunID, err)}
				return
			}
			if receipt.Status != "held" {
				results <- result{err: fmt.Errorf("reserve %s returned status %q", scope.RunID, receipt.Status)}
				return
			}
			replayed, replayErr := tree.Apply(ctx, scope, command)
			if replayErr != nil || replayed.Status != "held" {
				results <- result{err: fmt.Errorf("same-request replay for %s: status=%q error=%w", scope.RunID, replayed.Status, replayErr)}
				return
			}
			results <- result{accepted: true}
		}(i, scope)
	}
	close(start)
	workers.Wait()
	close(results)

	accepted := 0
	for item := range results {
		if item.err != nil {
			t.Fatal(item.err)
		}
		if item.accepted {
			accepted++
		}
	}
	if accepted != 5 {
		t.Fatalf("concurrent unified limit admitted %d reservations, want 5", accepted)
	}
	var counters RunTreeBudgetCounters
	err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT limit_micros,limit_tokens,used_micros,used_tokens,held_micros,held_tokens FROM platform_run_tree_budget WHERE root_key=?`), treeScopeKey(root)).Scan(
		&counters.LimitMicros, &counters.LimitTokens, &counters.UsedMicros, &counters.UsedTokens, &counters.HeldMicros, &counters.HeldTokens)
	if err != nil {
		t.Fatalf("read unified root budget counters: %v", err)
	}
	if counters.LimitMicros != 5 || counters.HeldMicros != 5 || counters.HeldTokens != 5 || counters.UsedMicros != 0 || counters.UsedTokens != 0 {
		t.Fatalf("root/child holds or same-request replay changed counters: %+v", counters)
	}
	var heldRequests int
	if err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_run_tree_budget_request WHERE root_key=? AND status='held'`), treeScopeKey(root)).Scan(&heldRequests); err != nil {
		t.Fatalf("count durable holds: %v", err)
	}
	if heldRequests != 5 {
		t.Fatalf("same-request replay created extra holds: got %d want 5", heldRequests)
	}
}

func TestSQLRunTreeBudgetUnknownKeepsHoldAndRejectsReleaseWithoutProviderReceipt(t *testing.T) {
	tree, windowStore, authority, _, ctx := newTreeBudgetSQLTestFixture(t)
	root := newTreeBudgetTestRoot(t)
	policyHash := treeBudgetTestPolicyHash(root)
	authority.AddScope(root, root, policyHash, 100, 100)
	requestID := "unknown-provider-request"
	fingerprint := fingerprintFor(root.RunID + "-unknown")
	hold := RunTreeBudgetHold{Micros: 25, Tokens: 30}
	reserve := treeBudgetTestCommand("reserve", requestID, fingerprint, hold)
	if _, err := tree.Apply(ctx, root, reserve); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	unknown := reserve
	unknown.Action = "unknown"
	uncertain, err := tree.Apply(ctx, root, unknown)
	if err != nil || uncertain.Status != "uncertain" {
		t.Fatalf("unknown receipt transition: status=%q error=%v", uncertain.Status, err)
	}
	release := reserve
	release.Action = "release_unbilled"
	release.OutcomeFingerprint = fingerprintFor("no-provider-proof-" + root.RunID)
	if _, err := tree.Apply(ctx, root, release); !errors.Is(err, errTreeBudgetTestNoReceipt) {
		t.Fatalf("release without immutable provider receipt should fail closed, got %v", err)
	}

	var counters RunTreeBudgetCounters
	if err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT limit_micros,limit_tokens,used_micros,used_tokens,held_micros,held_tokens FROM platform_run_tree_budget WHERE root_key=?`), treeScopeKey(root)).Scan(
		&counters.LimitMicros, &counters.LimitTokens, &counters.UsedMicros, &counters.UsedTokens, &counters.HeldMicros, &counters.HeldTokens); err != nil {
		t.Fatalf("read counters after rejected release: %v", err)
	}
	if counters.HeldMicros != hold.Micros || counters.HeldTokens != hold.Tokens || counters.UsedMicros != 0 || counters.UsedTokens != 0 {
		t.Fatalf("unknown provider outcome released or billed the hold: %+v", counters)
	}
	var status string
	if err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_run_tree_budget_request WHERE root_key=? AND actor_key=? AND request_id=?`), treeScopeKey(root), treeScopeKey(root), requestID).Scan(&status); err != nil {
		t.Fatalf("read request status: %v", err)
	}
	if status != "uncertain" {
		t.Fatalf("request status after unsupported release is %q, want uncertain", status)
	}
}

func TestSQLRunTreeBudgetSettlesActualOverestimateOnceAndBlocksAdmission(t *testing.T) {
	tree, windowStore, authority, _, ctx := newTreeBudgetSQLTestFixture(t)
	root := newTreeBudgetTestRoot(t)
	policyHash := treeBudgetTestPolicyHash(root)
	authority.AddScope(root, root, policyHash, 10, 10)
	requestID := "over-estimate-request"
	fingerprint := fingerprintFor(root.RunID + "-estimate")
	hold := RunTreeBudgetHold{Micros: 3, Tokens: 4}
	reserve := treeBudgetTestCommand("reserve", requestID, fingerprint, hold)
	if _, err := tree.Apply(ctx, root, reserve); err != nil {
		t.Fatalf("reserve estimated amount: %v", err)
	}
	settle := reserve
	settle.Action = "settle"
	settle.OutcomeFingerprint = fingerprintFor("trusted-billed-result-" + root.RunID)
	settle.ActualMicros, settle.InputTokens, settle.OutputTokens = 15, 7, 5
	authority.AddReceipt(root, requestID, treeBudgetSQLTestReceipt{
		Action: settle.Action, Fingerprint: settle.Fingerprint, ActualMicros: settle.ActualMicros,
		InputTokens: settle.InputTokens, OutputTokens: settle.OutputTokens,
		OutcomeFingerprint: settle.OutcomeFingerprint,
	})
	first, err := tree.Apply(ctx, root, settle)
	if err != nil {
		t.Fatalf("settle actual provider charge above estimate/limit: %v", err)
	}
	if first.Status != "settled" || !first.Exceeded || first.Counters.UsedMicros != 15 || first.Counters.UsedTokens != 12 || first.Counters.HeldMicros != 0 || first.Counters.HeldTokens != 0 {
		t.Fatalf("actual over-limit charge was not recorded/exhausting: %+v", first)
	}
	replayed, err := tree.Apply(ctx, root, settle)
	if err != nil {
		t.Fatalf("settlement replay: %v", err)
	}
	if replayed.Counters != first.Counters || !replayed.Exceeded {
		t.Fatalf("settlement replay double-counted actual cost: first=%+v replay=%+v", first.Counters, replayed.Counters)
	}
	if _, err := tree.Apply(ctx, root, treeBudgetTestCommand("reserve", "after-overrun", fingerprintFor(root.RunID+"-after-overrun"), RunTreeBudgetHold{Micros: 1, Tokens: 1})); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("admission after actual budget overrun should be blocked, got %v", err)
	}

	var usedMicros, usedTokens, heldMicros, heldTokens int64
	if err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT used_micros,used_tokens,held_micros,held_tokens FROM platform_run_tree_budget WHERE root_key=?`), treeScopeKey(root)).Scan(&usedMicros, &usedTokens, &heldMicros, &heldTokens); err != nil {
		t.Fatalf("read settled counters: %v", err)
	}
	if usedMicros != 15 || usedTokens != 12 || heldMicros != 0 || heldTokens != 0 {
		t.Fatalf("stored charge was lost, doubled, or left held: micros=%d tokens=%d heldMicros=%d heldTokens=%d", usedMicros, usedTokens, heldMicros, heldTokens)
	}
}

func TestSQLRunTreeBudgetAuditFailureRollsBackReservationAndRejectsMissingAudit(t *testing.T) {
	tree, windowStore, authority, recorder, ctx := newTreeBudgetSQLTestFixture(t)
	root := newTreeBudgetTestRoot(t)
	authority.AddScope(root, root, treeBudgetTestPolicyHash(root), 50, 50)
	command := treeBudgetTestCommand("reserve", "audit-rollback-request", fingerprintFor(root.RunID+"-audit"), RunTreeBudgetHold{Micros: 5, Tokens: 6})

	tree.SetAuditRecorder(nil)
	if _, err := tree.Apply(ctx, root, command); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("missing audit recorder should fail closed, got %v", err)
	}
	recorder.failAfterInsert = true
	tree.SetAuditRecorder(recorder)
	if _, err := tree.Apply(ctx, root, command); !errors.Is(err, errTreeBudgetTestAudit) {
		t.Fatalf("transactional audit failure should abort reserve, got %v", err)
	}

	for table, query := range map[string]string{
		"budget root":     `SELECT COUNT(*) FROM platform_run_tree_budget WHERE root_key=?`,
		"request receipt": `SELECT COUNT(*) FROM platform_run_tree_budget_request WHERE root_key=?`,
		"audit row":       `SELECT COUNT(*) FROM platform_run_tree_budget_test_audit WHERE aggregate_id=?`,
	} {
		key := treeScopeKey(root)
		if table == "audit row" {
			key = root.RunID
		}
		var count int
		if err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(query), key).Scan(&count); err != nil {
			t.Fatalf("query %s after rollback: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s leaked despite audit transaction failure: %d rows", table, count)
		}
	}
}

func TestSQLRunTreeBudgetRejectsCrossUserAndWrongRootFacts(t *testing.T) {
	tests := []struct {
		name       string
		mutateRoot func(sharedkernel.Scope) sharedkernel.Scope
	}{
		{name: "cross-user root", mutateRoot: func(root sharedkernel.Scope) sharedkernel.Scope { root.PrincipalID += "-other-user"; return root }},
		{name: "wrong tenant/root", mutateRoot: func(root sharedkernel.Scope) sharedkernel.Scope { root.TenantID += "-other-tenant"; return root }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, windowStore, authority, _, ctx := newTreeBudgetSQLTestFixture(t)
			expectedRoot := newTreeBudgetTestRoot(t)
			child := newTreeBudgetTestChild(expectedRoot, tc.name+"-child")
			badRoot := tc.mutateRoot(expectedRoot)
			// This deliberately inconsistent adapter fact is only a negative
			// fixture. Production Facts comes from trusted identity/execution data.
			authority.AddScope(child, badRoot, treeBudgetTestPolicyHash(expectedRoot), 10, 10)
			cmd := treeBudgetTestCommand("reserve", "reject-bad-facts", fingerprintFor(child.RunID+"-bad-facts"), RunTreeBudgetHold{Micros: 1, Tokens: 1})
			if _, err := tree.Apply(ctx, child, cmd); !errors.Is(err, ErrBudgetScopeMismatch) {
				t.Fatalf("inconsistent cross-user/root authority facts should be rejected, got %v", err)
			}
			var roots, requests int
			if err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_run_tree_budget WHERE root_key=?`), treeScopeKey(expectedRoot)).Scan(&roots); err != nil {
				t.Fatalf("check rejected root row: %v", err)
			}
			if err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_run_tree_budget_request WHERE run_id=?`), child.RunID).Scan(&requests); err != nil {
				t.Fatalf("check rejected request row: %v", err)
			}
			if roots != 0 || requests != 0 {
				t.Fatalf("inconsistent authority facts wrote state: roots=%d requests=%d", roots, requests)
			}
		})
	}
}

func TestSQLRunTreeBudgetDenialDiagnosticIsSafeAndNonMutating(t *testing.T) {
	tree, windowStore, authority, _, ctx := newTreeBudgetSQLTestFixture(t)
	tests := []struct {
		name      string
		seed      RunTreeBudgetHold
		attempt   RunTreeBudgetHold
		dimension string
	}{
		{name: "cost", seed: RunTreeBudgetHold{Micros: 9, Tokens: 1}, attempt: RunTreeBudgetHold{Micros: 2, Tokens: 1}, dimension: "cost"},
		{name: "tokens", seed: RunTreeBudgetHold{Micros: 1, Tokens: 9}, attempt: RunTreeBudgetHold{Micros: 1, Tokens: 2}, dimension: "tokens"},
		{name: "both", seed: RunTreeBudgetHold{Micros: 9, Tokens: 9}, attempt: RunTreeBudgetHold{Micros: 2, Tokens: 2}, dimension: "cost_and_tokens"},
	}
	allowedFields := map[string]bool{
		"event": true, "stage": true, "run_id": true, "trace_id": true, "dimension": true,
		"limit_micros": true, "used_micros": true, "held_micros": true, "attempt_micros": true,
		"limit_tokens": true, "used_tokens": true, "held_tokens": true, "attempt_tokens": true,
	}
	oldWriter := log.Writer()
	defer log.SetOutput(oldWriter)
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			root := newTreeBudgetTestRoot(t)
			root.PrincipalID = "user-data-sentinel"
			root.SessionID = "private-session-data-sentinel"
			authority.AddScope(root, root, treeBudgetTestPolicyHash(root), 10, 10)
			if _, err := tree.Apply(ctx, root, treeBudgetTestCommand("reserve", "safe-seed-"+tc.name, fingerprintFor(root.RunID+"-seed"), tc.seed)); err != nil {
				t.Fatalf("seed root counters: %v", err)
			}
			var before RunTreeBudgetCounters
			if err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT limit_micros,limit_tokens,used_micros,used_tokens,held_micros,held_tokens FROM platform_run_tree_budget WHERE root_key=?`), treeScopeKey(root)).Scan(
				&before.LimitMicros, &before.LimitTokens, &before.UsedMicros, &before.UsedTokens, &before.HeldMicros, &before.HeldTokens); err != nil {
				t.Fatalf("read counters before denied attempt: %v", err)
			}

			requestID := "sensitive-request-id-" + tc.name
			fingerprint := fingerprintFor("private-request-fingerprint-" + tc.name)
			var captured bytes.Buffer
			log.SetOutput(&captured)
			_, reserveErr := tree.Apply(ctx, root, treeBudgetTestCommand("reserve", requestID, fingerprint, tc.attempt))
			log.SetOutput(oldWriter)
			if !errors.Is(reserveErr, ErrBudgetExceeded) {
				t.Fatalf("denied reservation error identity changed: %v", reserveErr)
			}

			marker := strings.Index(captured.String(), "event=run_tree_budget_denied ")
			if marker < 0 {
				t.Fatalf("root reservation denial was not logged: %q", captured.String())
			}
			fields := strings.Fields(strings.TrimSpace(captured.String()[marker:]))
			parsed := make(map[string]string, len(fields))
			for _, field := range fields {
				key, value, ok := strings.Cut(field, "=")
				if !ok || !allowedFields[key] {
					t.Fatalf("diagnostic contains an unapproved field %q", field)
				}
				parsed[key] = strings.Trim(value, `"`)
			}
			if len(parsed) != len(allowedFields) || parsed["event"] != "run_tree_budget_denied" || parsed["stage"] != "root_reserve" ||
				parsed["run_id"] != root.RunID || parsed["trace_id"] != root.TraceID || parsed["dimension"] != tc.dimension {
				t.Fatalf("diagnostic identity or dimension mismatch: %#v", parsed)
			}
			if strings.Contains(captured.String(), requestID) || strings.Contains(captured.String(), fingerprint) ||
				strings.Contains(captured.String(), "user-data-sentinel") || strings.Contains(captured.String(), "private-session-data-sentinel") {
				t.Fatal("diagnostic exposed request identifiers, fingerprints, or user data")
			}
			wantNumerics := map[string]string{
				"limit_micros": "10", "used_micros": "0", "held_micros": fmt.Sprint(tc.seed.Micros), "attempt_micros": fmt.Sprint(tc.attempt.Micros),
				"limit_tokens": "10", "used_tokens": "0", "held_tokens": fmt.Sprint(tc.seed.Tokens), "attempt_tokens": fmt.Sprint(tc.attempt.Tokens),
			}
			for key, want := range wantNumerics {
				if parsed[key] != want {
					t.Fatalf("diagnostic %s=%q, want %q", key, parsed[key], want)
				}
			}

			var after RunTreeBudgetCounters
			if err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT limit_micros,limit_tokens,used_micros,used_tokens,held_micros,held_tokens FROM platform_run_tree_budget WHERE root_key=?`), treeScopeKey(root)).Scan(
				&after.LimitMicros, &after.LimitTokens, &after.UsedMicros, &after.UsedTokens, &after.HeldMicros, &after.HeldTokens); err != nil {
				t.Fatalf("read counters after denied attempt: %v", err)
			}
			if after != before {
				t.Fatalf("denied reservation changed counters: before=%+v after=%+v", before, after)
			}
			var deniedRequests int
			if err := windowStore.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_run_tree_budget_request WHERE root_key=? AND actor_key=? AND request_id=?`), treeScopeKey(root), treeScopeKey(root), requestID).Scan(&deniedRequests); err != nil {
				t.Fatalf("check denied request persistence: %v", err)
			}
			if deniedRequests != 0 {
				t.Fatalf("denied attempt unexpectedly persisted %d request rows", deniedRequests)
			}
		})
	}
}
