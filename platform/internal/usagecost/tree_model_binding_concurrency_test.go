package usagecost

import (
	"database/sql"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

// Both foreground settlement and recovery resolve the committed binding before
// acquiring the root. Synchronize that exact interleaving: with the former
// request SHARE locks, neither transaction could settle without a deadlock.
func TestSQLRunTreeBudgetModelBindingConcurrentSettlement(t *testing.T) {
	tree, window, authority, _, ctx := newTreeBudgetSQLTestFixture(t)
	root := newTreeBudgetTestRoot(t)
	authority.AddScope(root, root, treeBudgetTestPolicyHash(root), 1000, 1000)
	req := validBudgetTestRequest(time.Now().UTC(), "model-request", root.AgentID, 1000, 60)
	req.Scope = ModelBudgetScope{TenantID: root.TenantID, DepartmentID: root.DepartmentID, ApplicationID: root.ApplicationID, AgentID: root.AgentID, AgentVersionID: root.AgentVersionID}
	req.RunID = root.RunID
	hold := RunTreeBudgetHold{Micros: req.ReserveMicros, Tokens: 30}
	command := treeBudgetTestCommand("reserve", req.RequestID, req.Fingerprint, hold)
	tx, err := window.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	receipt, err := tree.ApplyTx(ctx, tx, root, command)
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.SaveModelBindingTx(ctx, tx, receipt.rootKey, root, req, hold.Tokens); err != nil {
		t.Fatal(err)
	}
	reservation, err := window.ReserveTx(ctx, tx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.SaveModelReservationTx(ctx, tx, reservation); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	command.Action = "settle"
	command.OutcomeFingerprint = fingerprintFor(root.RunID + "-provider-proof")
	command.ActualMicros, command.InputTokens, command.OutputTokens = 45, 10, 5
	authority.AddReceipt(root, req.RequestID, treeBudgetSQLTestReceipt{Action: command.Action, Fingerprint: command.Fingerprint, ActualMicros: command.ActualMicros, InputTokens: command.InputTokens, OutputTokens: command.OutputTokens, OutcomeFingerprint: command.OutcomeFingerprint})
	event := Event{ID: "binding-event-" + reservation.ReservationID, Scope: budgetUsageScope(req), Provider: "fixture", Model: "fixture", CostMicros: 45, InputTokens: 10, OutputTokens: 5}

	ready := make(chan error, 2)
	start := make(chan struct{})
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			tx, err := window.db.BeginTx(ctx, nil)
			if err != nil {
				ready <- err
				done <- err
				return
			}
			defer tx.Rollback()
			_, err = tree.ModelBindingTx(ctx, tx, reservation)
			ready <- err
			<-start
			if err == nil {
				_, err = tree.ApplyTx(ctx, tx, root, command)
			}
			if err == nil {
				_, err = window.SettleTx(ctx, tx, reservation, event, req.PriceVersionID)
			}
			if err == nil {
				err = tx.Commit()
			}
			done <- err
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-ready; err != nil {
			close(start)
			t.Fatal(err)
		}
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent foreground/recovery settlement: %v", err)
		}
	}
	var usedMicros, usedTokens, heldMicros, heldTokens int64
	if err := window.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT used_micros,used_tokens,held_micros,held_tokens FROM platform_run_tree_budget WHERE root_key=?`), treeScopeKey(root)).Scan(&usedMicros, &usedTokens, &heldMicros, &heldTokens); err != nil {
		t.Fatal(err)
	}
	if usedMicros != 45 || usedTokens != 15 || heldMicros != 0 || heldTokens != 0 {
		t.Fatalf("lost/double root accounting: %d %d %d %d", usedMicros, usedTokens, heldMicros, heldTokens)
	}
	var usageCount int
	if err := window.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_usage_event WHERE event_id=?`), event.ID).Scan(&usageCount); err != nil {
		t.Fatal(err)
	}
	if usageCount != 1 {
		t.Fatalf("expected one usage event, got %d", usageCount)
	}

	// Immutable lookup still rejects a foreign reservation; it is not authority
	// to bypass the existing mutable root/outcome checks.
	bad := reservation
	bad.ReservationID += "-foreign"
	check, err := window.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer check.Rollback()
	if _, err = tree.ModelBindingTx(ctx, check, bad); err == nil {
		t.Fatal("foreign reservation accepted")
	}
}
