package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/evaluationproduct"
)

// Runs the opt-in seed in the actual platform's owned database while the
// process is down, then verifies its real lifecycle worker recovers the lease.
// The intentionally incomplete published suite must terminate SNAPSHOT_INVALID;
// this proves recovery and safe rejection, not successful business evaluation.
func verifyRuntimeEvaluationSeedRestart(t *testing.T, ctx context.Context, binary, runtimeDSN, adminDSN string, db *sql.DB) {
	t.Helper()
	var firstProcessStopped bool
	launchPlatformFixtureWithControl(t, ctx, binary, runtimeDSN, true, nil, func(_ *http.Client, _ string, crash func()) {
		crash()
		firstProcessStopped = true
	})
	if !firstProcessStopped {
		t.Fatal("first owned platform process did not exit")
	}
	store := evaluationproduct.NewSQLStore(db)
	scope := evaluationproduct.Scope{TenantID: "tenant-demo", DepartmentID: "dept-demo", ApplicationID: "app-demo"}
	const suiteID = "restart-process-suite"
	data, err := json.Marshal(evaluationproduct.SuiteData{Name: "Restart fixture", Version: "1", AgentID: "restart-fixture-agent", AgentVersionID: "restart-fixture-agent-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, evaluationproduct.Resource{ID: suiteID, Kind: evaluationproduct.KindSuite, Scope: scope, Status: "published", Revision: 1, CreatedBy: "restart.fixture.operator", Data: data}); err != nil {
		t.Fatal(err)
	}
	// Invoke the original test, rather than recreating its seed and claiming that
	// the previously skipped case ran. Inspect its final JSON test action.
	seed := exec.CommandContext(ctx, "go", "test", "-json", "-p=1", "-count=1", "-timeout=60s", "-run", "^TestSeedPlatformProcessRestartRun$", "./internal/evaluationproduct")
	seed.Dir = "../.."
	seed.Env = append(os.Environ(), "PUBLIC_TEST_POSTGRES_MIGRATION_DSN="+adminDSN, "LEXAGENT_E2E_PLATFORM_RESTART_SEED=1", "LEXAGENT_E2E_EVALUATION_SUITE_ID="+suiteID)
	output, err := seed.CombinedOutput()
	if err != nil {
		t.Fatal("original restart seed subprocess failed; credential-bearing diagnostics suppressed")
	}
	state := "missing"
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		var event struct{ Action, Test string }
		if json.Unmarshal(line, &event) == nil && event.Test == "TestSeedPlatformProcessRestartRun" && (event.Action == "pass" || event.Action == "skip" || event.Action == "fail") {
			state = event.Action
		}
	}
	if state != "pass" {
		t.Fatal("original restart seed did not finish PASS")
	}
	t.Log("original_restart_seed_test=PASS")
	var runID string
	if err := db.QueryRowContext(ctx, `SELECT resource_id FROM platform_evaluation_product_head WHERE resource_kind='run' AND tenant_id='tenant-demo' AND department_id='dept-demo' AND application_id='app-demo'`).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	before, err := store.Get(ctx, scope, evaluationproduct.KindRun, runID)
	if err != nil {
		t.Fatal(err)
	}
	var prior evaluationproduct.RunData
	if json.Unmarshal(before.Data, &prior) != nil || before.Status != "running" || prior.Attempt != 1 || prior.LeaseOwner != "process-before-restart" || prior.LeaseUntil.After(time.Now().UTC()) {
		t.Fatal("original seed did not persist an expired first-attempt lease")
	}
	launchPlatformFixtureWithOptions(t, ctx, binary, runtimeDSN, true, nil, func(_ *http.Client, _ string) {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			current, err := store.Get(ctx, scope, evaluationproduct.KindRun, runID)
			if err != nil {
				t.Fatal(err)
			}
			var recovered evaluationproduct.RunData
			if json.Unmarshal(current.Data, &recovered) != nil {
				t.Fatal("recovered run data is invalid")
			}
			if current.Status == "failed" {
				if recovered.Attempt != 2 || current.Revision != before.Revision+2 || recovered.ErrorCode != "SNAPSHOT_INVALID" || recovered.ExecutionState != "failed" || recovered.LeaseOwner != "" || recovered.LeaseToken != "" {
					t.Fatal("new process did not recover and safely reject the exact original seed")
				}
				var leases int
				if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_evaluation_product_run_lease WHERE run_id=$1`, runID).Scan(&leases); err != nil || leases != 0 {
					t.Fatal("completed recovery retained a stale lease")
				}
				t.Log("actual_platform_restart_recovered_original_seed=PASS attempts=2 terminal=SNAPSHOT_INVALID")
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("actual restarted platform did not recover the original seed")
	})
}
