package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

// This wrapper loses only the repository response, after the real transaction
// committed. A restarted dispatcher must discover that receipt, not resend.
type lostCancellationAckResponse struct {
	*SQLStore
}

// The dispatcher, execution receipt, invocation record and money hold use real
// stores. Only the remote Agent stop transport is a fixture. This intentionally
// leaves unknown supplier usage unresolved; an exit acknowledgement cannot
// manufacture a no-charge decision or free the retained budget.
func TestSQLCancellationAcknowledgementRetainsRealModelHold(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL migration fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runs, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	models, err := capability.NewSQLModelInvocationStore(runs.DB())
	if err != nil {
		t.Fatal(err)
	}
	window := usagecost.NewSQLStore(runs.DB())
	for _, ensure := range []func(context.Context) error{models.EnsureSchema, window.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := models.SetModelBudgetClosureReader(window); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("stop-real-hold-%d", time.Now().UnixNano())
	pending, executed := cancellationGenerationFixture(t, runs, id, false, false, true)
	hash, fp := stopHash([]byte(id)), strings.Repeat("b", 64)
	now := time.Now().UTC()
	r := usagecost.ModelBudgetRequest{Scope: usagecost.ModelBudgetScope{
		TenantID: pending.Scope.TenantID, DepartmentID: pending.Scope.DepartmentID,
		ApplicationID: pending.Scope.ApplicationID, AgentID: pending.Scope.AgentID, AgentVersionID: pending.Scope.AgentVersionID},
		RunID: id, RequestID: id, Fingerprint: fp, PriceVersionID: "fixture-price", BudgetLimitMicros: 1000, ReserveMicros: 80,
		Window: usagecost.ModelBudgetWindow{Start: now.Add(-time.Minute), End: now.Add(time.Hour)}, ExpiresAt: now.Add(time.Minute)}
	reservation, err := window.Reserve(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	attempt, _, err := models.ReserveGoverned(ctx, hash, id, fp)
	if err != nil {
		t.Fatal(err)
	}
	if err := models.SaveBillingRecovery(ctx, hash, id, fp, nil, 0, capability.BillingRecovery{
		Reservation: reservation, PriceID: r.PriceVersionID, AttemptToken: attempt.AttemptToken}); err != nil {
		t.Fatal(err)
	}
	if err := window.MarkReconciliationNeeded(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	gateway := &cancelTestGateway{}
	for restart := 0; restart < 3; restart++ {
		reopened, err := OpenSQLStore(ctx, "pgx", dsn)
		if err != nil {
			t.Fatal(err)
		}
		freshModels, err := capability.NewSQLModelInvocationStore(reopened.DB())
		if err != nil {
			t.Fatal(err)
		}
		if err := freshModels.SetModelBudgetClosureReader(usagecost.NewSQLStore(reopened.DB())); err != nil {
			t.Fatal(err)
		}
		d := NewDispatcherWithGateway(reopened, "", gateway, 1)
		d.SetSecurity(machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
			return "signed-stop-only", nil
		}), nil)
		d.stopQuiescence = func(ctx context.Context, owner sharedkernel.Scope) error {
			if owner != pending.Scope {
				t.Fatal("ledger owner changed")
			}
			return freshModels.CheckModelQuiescence(ctx, hash)
		}
		if err := d.confirmCancellation(ctx, pending); !errors.Is(err, capability.ErrModelInvocationReconciliationNeeded) {
			t.Fatal("real unknown model ledger was bypassed", err)
		}
		revision, found, err := reopened.ReadCancellationAgentAcknowledgement(ctx, pending)
		if err != nil || !found || revision != executed || gateway.calls != 1 {
			t.Fatal("durable stop was lost or resent", err)
		}
		actual, err := reopened.Get(id)
		if err != nil || !sameCancellationGeneration(actual, pending) {
			t.Fatal("unknown charge released execution", err)
		}
		var state string
		var held int64
		if err := reopened.DB().QueryRowContext(ctx, `SELECT status,reserve_micros FROM platform_model_budget_reservation WHERE reservation_id=$1`, reservation.ReservationID).Scan(&state, &held); err != nil || state != "reconcile" || held != 80 {
			t.Fatal("stop altered unknown financial hold", state, held, err)
		}
		if _, err := reopened.GetOutcome(id); !errors.Is(err, platformruntime.ErrRunNotFound) {
			t.Fatal("stop fabricated terminal outcome", err)
		}
		reopened.Close()
	}
}

func (s lostCancellationAckResponse) RecordCancellationAgentAcknowledgement(ctx context.Context, run platformruntime.Run, revision uint64) error {
	if err := s.SQLStore.RecordCancellationAgentAcknowledgement(ctx, run, revision); err != nil {
		return err
	}
	return errors.New("fixture: acknowledgement commit response lost")
}

func TestSQLCancellationAcknowledgementSurvivesSettlementWait(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("requires owned PostgreSQL migration fixture")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, loseResponse := range []bool{false, true} {
		t.Run(fmt.Sprintf("lost_commit_response_%t", loseResponse), func(t *testing.T) {
			id := fmt.Sprintf("stop-ack-restart-%t-%d", loseResponse, time.Now().UnixNano())
			pending, executed := cancellationGenerationFixture(t, store, id, false, false, true)
			gateway := &cancelTestGateway{}
			settled := false
			newDispatcher := func(repository Repository) *Dispatcher {
				d := NewDispatcherWithGateway(repository, "", gateway, 1)
				d.SetSecurity(machineRunContextSignerFunc(func(ctx context.Context, scope sharedkernel.Scope, request contract.ExecuteRequest) (string, error) {
					binding, ok := sharedkernel.ExecutionLeaseFromContext(ctx)
					if !ok || binding.Revision != executed || scope != pending.Scope || request.Operation != "cancel" {
						t.Fatal("stop acknowledgement used a different generation")
					}
					return "signed-stop-only", nil
				}), nil)
				d.stopQuiescence = func(_ context.Context, scope sharedkernel.Scope) error {
					if scope != pending.Scope {
						t.Fatal("financial check changed owner")
					}
					if !settled {
						return ErrExecutionOutcomeUnconfirmed
					}
					return nil
				}
				return d
			}
			var firstStore Repository = store
			if loseResponse {
				firstStore = lostCancellationAckResponse{store}
			}
			first := newDispatcher(firstStore)
			if err := first.confirmCancellation(context.Background(), pending); err == nil {
				t.Fatal("unsettled request was reported complete")
			}
			revision, found, err := store.ReadCancellationAgentAcknowledgement(context.Background(), pending)
			if err != nil || !found || revision != executed || gateway.calls != 1 {
				t.Fatal("remote exit was not durably retained", revision, found, err, gateway.calls)
			}
			// Use a fresh repository and dispatcher, not the previous Go object.
			reopened, err := OpenSQLStore(context.Background(), "pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			restarted := newDispatcher(reopened)
			for i := 0; i < 3; i++ {
				if err := restarted.confirmCancellation(context.Background(), pending); !errors.Is(err, ErrExecutionOutcomeUnconfirmed) {
					t.Fatal("ledger barrier was bypassed", err)
				}
			}
			actual, err := reopened.Get(id)
			if err != nil || !sameCancellationGeneration(actual, pending) || gateway.calls != 1 {
				t.Fatal("settlement wait released FIFO or resent remote stop", err, gateway.calls)
			}
			if _, err := reopened.GetOutcome(id); !errors.Is(err, platformruntime.ErrRunNotFound) {
				t.Fatal("remote exit fabricated a terminal result", err)
			}
			settled = true
			if err := restarted.confirmCancellation(context.Background(), pending); err != nil {
				t.Fatal("settled cancellation did not finalize", err)
			}
			actual, err = reopened.Get(id)
			if err != nil || actual.Status != platformruntime.StatusCancelled || actual.LeaseToken != "" || gateway.calls != 1 {
				t.Fatal("final cancellation did not preserve one stop acknowledgement", err, gateway.calls)
			}
		})
	}
}

func TestSQLCancellationAcknowledgementBindingAndConcurrentCommit(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("requires owned PostgreSQL migration fixture")
	}
	ctx := context.Background()
	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := fmt.Sprintf("stop-ack-binding-%d", time.Now().UnixNano())
	pending, executed := cancellationGenerationFixture(t, store, id, false, false, true)
	if _, found, err := store.ReadCancellationAgentAcknowledgement(ctx, pending); err != nil || found {
		t.Fatal("missing acknowledgement was invented", found, err)
	}
	if err := store.RecordCancellationAgentAcknowledgement(ctx, pending, executed+1); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("wrong execution revision was accepted", err)
	}
	if _, err := store.AppendEvent(id, cancellationAcknowledgementEvent, map[string]any{"version": "forged"}); !errors.Is(err, platformruntime.ErrInvalidTransition) {
		t.Fatal("generic event API could manufacture stop acknowledgement", err)
	}
	var writers sync.WaitGroup
	errorsSeen := make(chan error, 8)
	for i := 0; i < 8; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			errorsSeen <- store.RecordCancellationAgentAcknowledgement(ctx, pending, executed)
		}()
	}
	writers.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal("concurrent receipt commit failed", err)
		}
	}
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM platform_execution_event WHERE run_id=$1 AND event_type=$2`, id, cancellationAcknowledgementEvent).Scan(&count); err != nil || count != 1 {
		t.Fatal("acknowledgement was not idempotent", count, err)
	}
	for _, change := range []string{"scope", "revision", "lease", "request", "resume", "endpoint", "idempotency"} {
		t.Run(change, func(t *testing.T) {
			foreign := pending
			switch change {
			case "scope":
				foreign.Scope.TenantID = "foreign-tenant"
			case "revision":
				foreign.Revision++
			case "lease":
				foreign.LeaseToken = "foreign-lease"
			case "request":
				foreign.RequestJSON = []byte(`{}`)
			case "resume":
				foreign.ResumeInputJSON = []byte(`{}`)
			case "endpoint":
				foreign.AgentEndpoint = "http://foreign.invalid"
			case "idempotency":
				foreign.IdempotencyKey = "foreign"
			}
			if _, _, err := store.ReadCancellationAgentAcknowledgement(ctx, foreign); !errors.Is(err, platformruntime.ErrRevisionConflict) {
				t.Fatal("foreign binding read stop proof", err)
			}
			if err := store.RecordCancellationAgentAcknowledgement(ctx, foreign, executed); !errors.Is(err, platformruntime.ErrRevisionConflict) {
				t.Fatal("foreign binding wrote stop proof", err)
			}
		})
	}
	proof, _ := json.Marshal(cancellationAcknowledgement(pending, executed))
	for _, raw := range []string{`{}`, string(proof[:len(proof)-1]) + `,"version":"forged"}`, string(proof) + `{}`} {
		_, err := store.db.Exec(`UPDATE platform_execution_event SET payload=$1 WHERE run_id=$2 AND event_type=$3`, []byte(raw), id, cancellationAcknowledgementEvent)
		if !json.Valid([]byte(raw)) {
			var invalid interface{ SQLState() string }
			if !errors.As(err, &invalid) || invalid.SQLState() != "22P02" {
				t.Fatal("native JSON column accepted malformed bytes", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.ReadCancellationAgentAcknowledgement(ctx, pending); !errors.Is(err, ErrStopEvidenceInvalid) {
			t.Fatal("malformed stored proof was trusted", err)
		}
	}
}
