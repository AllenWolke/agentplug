package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLLiveCapabilityCommandKeepsLargeRecoveryOffHotPath(t *testing.T) {
	admin, runtime := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if admin == "" || runtime == "" {
		t.Skip("owned migration and DML-only PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := openMigratedSQLFixture(ctx, "pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	store, err := ConnectSQLStore(ctx, "pgx", runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	body, policy := strings.Repeat("b", 64), strings.Repeat("c", 64)
	fixture := func(t *testing.T) (sharedkernel.Scope, platformruntime.Run) {
		t.Helper()
		id := fmt.Sprintf("live-capability-%d", time.Now().UnixNano())
		scope := testScope(id).domain()
		scope.SessionID = id
		raw := []byte(`{"operation":"invoke","input_schema":"schema://fixture/input/v1"}`)
		if _, err = store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "fixture", RequestJSON: raw, AgentEndpoint: "http://agent.invalid"}); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.AcquireLease(id, "worker", time.Now().UTC(), 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		run, err := store.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: id, Revision: run.Revision, Operation: "invoke", BodyHash: body, PolicyHash: policy}, run.LeaseToken); err != nil {
			t.Fatal(err)
		}
		return scope, run
	}
	t.Run("large-recovery-excluded-and-fresh-cancel-observed", func(t *testing.T) {
		scope, run := fixture(t)
		recovery, _ := json.Marshal(map[string]any{"fixture": strings.Repeat("x", 2<<20)})
		if _, err = store.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET resume_input_json=? WHERE run_id=?`), recovery, run.ID); err != nil {
			t.Fatal(err)
		}
		full, err := store.GetContext(ctx, run.ID)
		if err != nil || len(full.ResumeInputJSON) < 2<<20 {
			t.Fatal("large fixture not persisted", err)
		}
		lean, err := store.ReadLiveCapabilityCommand(ctx, scope, "invoke", body, policy)
		if err != nil || lean.Scope != full.Scope || lean.Revision != full.Revision || lean.LeaseToken != full.LeaseToken || lean.AgentEndpoint != full.AgentEndpoint || string(lean.RequestJSON) != string(full.RequestJSON) || len(lean.ResumeInputJSON) != 0 {
			t.Fatal("narrow read changed authority facts or copied recovery", err)
		}
		module := NewModuleWithRepository("internal", store)
		bound := sharedkernel.BindExecutionLease(ctx, run.Revision, run.LeaseToken)
		if action, err := module.ValidateLiveLeaseAndAction(bound, scope, "invoke", body, policy); err != nil || action != "run" {
			t.Fatal("production selection failed", action, err)
		}
		if _, err = store.Cancel(run.ID, run.Revision); err != nil {
			t.Fatal(err)
		}
		if _, err = module.ValidateLiveLeaseAndAction(bound, scope, "invoke", body, policy); err == nil {
			t.Fatal("later fence reused pre-cancel authority")
		}
	})
	for _, mutation := range []struct{ name, query string }{
		{"expired-run", `UPDATE platform_execution_run SET lease_until=clock_timestamp()-interval '1 second' WHERE run_id=?`},
		{"expired-session", `UPDATE platform_execution_session_lease SET lease_until=clock_timestamp()-interval '1 second' WHERE run_id=?`},
		{"wrong-session-token", `UPDATE platform_execution_session_lease SET lease_token='synthetic-wrong-token' WHERE run_id=?`},
		{"stale-command", `UPDATE platform_execution_dispatch_command SET revision=revision+1 WHERE run_id=?`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			scope, run := fixture(t)
			if _, err = store.db.ExecContext(ctx, sqlutil.Bind(mutation.query), run.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = store.ReadLiveCapabilityCommand(ctx, scope, "invoke", body, policy); err == nil {
				t.Fatal("changed authority admitted")
			}
		})
	}
	t.Run("scope-command-cancellation-and-lease-digest-still-required", func(t *testing.T) {
		scope, run := fixture(t)
		foreign := scope
		foreign.PrincipalID += "-foreign"
		for _, candidate := range []struct {
			scope                   sharedkernel.Scope
			operation, body, policy string
		}{
			{foreign, "invoke", body, policy}, {scope, "resume", body, policy}, {scope, "invoke", policy, policy}, {scope, "invoke", body, body},
		} {
			if _, err = store.ReadLiveCapabilityCommand(ctx, candidate.scope, candidate.operation, candidate.body, candidate.policy); err == nil {
				t.Fatal("foreign command accepted")
			}
		}
		cancelled, stop := context.WithCancel(ctx)
		stop()
		if _, err = store.ReadLiveCapabilityCommand(cancelled, scope, "invoke", body, policy); err == nil {
			t.Fatal("caller cancellation ignored")
		}
		wrong := sharedkernel.BindExecutionLease(ctx, run.Revision, "wrong-synthetic-token")
		if _, err = NewModuleWithRepository("internal", store).ValidateLiveLeaseAndAction(wrong, scope, "invoke", body, policy); err == nil {
			t.Fatal("signed lease digest ignored")
		}
	})
}
