package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func cancellationGenerationFixture(t *testing.T, store Repository, id string, waiting, resumed, record bool) (platformruntime.Run, uint64) {
	t.Helper()
	dto := testScope(id)
	dto.SessionID = id
	scope := dto.domain()
	raw := gatewayRequest(t, dto, "invoke")
	created, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: id, RequestJSON: raw, AgentEndpoint: "http://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	claim := func(from platformruntime.Status) platformruntime.Run {
		leased, err := store.AcquireLease(id, "generation-worker", time.Now().UTC(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if from == platformruntime.StatusRunning {
			return leased
		}
		run, err := store.TransitionLeased(id, from, platformruntime.StatusRunning, leased.Revision, leased.LeaseToken)
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	running := claim(created.Run.Status)
	if resumed {
		paused, err := store.FinalizeLeased(id, platformruntime.StatusWaiting, running.Revision, running.LeaseToken, map[string]any{"stage": "review"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PrepareResume(paused.ID, []byte(`{"decision":"approve"}`)); err != nil {
			t.Fatal(err)
		}
		running = claim(platformruntime.StatusRunning)
	}
	if record {
		var request contract.ExecuteRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Fatal(err)
		}
		if resumed {
			request.Operation = "resume"
			request.ResumeInput = map[string]any{"decision": "approve"}
		}
		hash, err := contract.CanonicalExecuteBodyHash(request)
		if err != nil {
			t.Fatal(err)
		}
		policy := request.Input["policy_snapshot"].(map[string]any)["content_hash"].(string)
		if err := store.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: id, Revision: running.Revision, Operation: request.Operation, BodyHash: hash, PolicyHash: policy}, running.LeaseToken); err != nil {
			t.Fatal(err)
		}
	}
	if waiting {
		paused, err := store.FinalizeLeased(id, platformruntime.StatusWaiting, running.Revision, running.LeaseToken, map[string]any{"stage": "review"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		running = paused
	}
	cancellable, ok := store.(cancellationRepository)
	if !ok {
		t.Fatal("fixture has no cancellation port")
	}
	pending, err := cancellable.BeginCancellation(id, running.Revision)
	if err != nil {
		t.Fatal(err)
	}
	executed := running.Revision
	if waiting {
		executed--
	}
	return pending, executed
}

func TestSignedCancellationUsesRecordedExecutionGeneration(t *testing.T) {
	for _, mode := range []string{"running", "waiting", "resumed_waiting", "missing_dispatch"} {
		t.Run(mode, func(t *testing.T) {
			store := platformruntime.NewStore()
			pending, executed := cancellationGenerationFixture(t, store, "cancel-generation-"+mode, mode != "running", mode == "resumed_waiting", mode != "missing_dispatch")
			gateway := &cancelTestGateway{}
			dispatcher := NewDispatcherWithGateway(store, "", gateway, 1)
			signs := 0
			dispatcher.SetSecurity(machineRunContextSignerFunc(func(ctx context.Context, scope sharedkernel.Scope, request contract.ExecuteRequest) (string, error) {
				signs++
				binding, ok := sharedkernel.ExecutionLeaseFromContext(ctx)
				if !ok || binding.Revision != executed || scope != pending.Scope || request.Operation != "cancel" || request.ResumeInput != nil {
					t.Fatal("stop command did not bind the recorded execution generation")
				}
				return "signed-stop-only", nil
			}), func(context.Context, sharedkernel.Scope) error {
				t.Fatal("stop control attempted business admission")
				return nil
			})
			err := dispatcher.confirmCancellation(context.Background(), pending)
			if mode == "missing_dispatch" {
				if err == nil || signs != 0 || gateway.calls != 0 {
					t.Fatal("missing dispatch identity was guessed", err, signs, gateway.calls)
				}
				return
			}
			if err != nil || signs != 1 || gateway.calls != 1 {
				t.Fatal("recorded generation was not cancelled", err, signs, gateway.calls)
			}
			terminal, err := store.Get(pending.ID)
			if err != nil || terminal.Status != platformruntime.StatusCancelled {
				t.Fatal("matching stop acknowledgement was not committed", err)
			}
		})
	}
}

func TestSQLCancellationExecutionGenerationJournal(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("requires owned PostgreSQL migration fixture")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, mode := range []string{"running", "waiting", "resumed_waiting"} {
		t.Run(mode, func(t *testing.T) {
			id := fmt.Sprintf("sql-stop-generation-%s-%d", mode, time.Now().UnixNano())
			pending, executed := cancellationGenerationFixture(t, store, id, mode != "running", mode == "resumed_waiting", true)
			revision, err := store.CancellationExecutionRevision(context.Background(), pending)
			if err != nil || revision != executed {
				t.Fatal("actual journal generation was not resolved", revision, executed, err)
			}
			for _, change := range []string{"scope", "head", "lease", "request", "resume"} {
				foreign := pending
				switch change {
				case "scope":
					foreign.Scope.TenantID = "foreign-tenant"
				case "head":
					foreign.Revision++
				case "lease":
					foreign.LeaseToken = "foreign-lease"
				case "request":
					foreign.RequestJSON = []byte(`{}`)
				case "resume":
					foreign.ResumeInputJSON = []byte(`{"decision":"reject"}`)
				}
				if _, err := store.CancellationExecutionRevision(context.Background(), foreign); !errors.Is(err, platformruntime.ErrRevisionConflict) {
					t.Fatal("foreign stop binding accepted", change, err)
				}
			}
			// A plausible mutable projection cannot replace the append-only proof.
			// 可变投影被改为其他摘要时，缺少只追加账本匹配，必须拒绝。
			if _, err := store.db.Exec(`UPDATE platform_execution_dispatch_command SET body_hash=$1 WHERE run_id=$2`, strings.Repeat("f", 64), id); err != nil {
				t.Fatal(err)
			}
			if _, err := store.CancellationExecutionRevision(context.Background(), pending); !errors.Is(err, platformruntime.ErrLeaseConflict) {
				t.Fatal("unrecorded command projection was trusted", err)
			}
		})
	}
}
