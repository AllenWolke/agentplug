package usagecost

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestEvaluationModelUsageLinksRemainExactAndLegacyMissingPostgres(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	now := time.Now().UTC()
	suffix := uniqueBudgetSuffix(t)
	for _, name := range []string{"linked", "legacy", "duplicate", "invalid", "foreign-run"} {
		t.Run(name, func(t *testing.T) {
			q := validBudgetTestRequest(now, "perf-"+name+"-"+suffix, "perf-"+name+"-"+suffix, 100, 1)
			scope := budgetUsageScope(q)
			step := StableModelUsageStepID(scope, "logical-request")
			if name == "legacy" {
				step = nil
			}
			e := Event{ID: q.RequestID, Scope: scope, Provider: "fixture", Model: "fixture", InputTokens: 1, CostMicros: 1, StepID: step}
			if _, err := store.Apply(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			if name == "duplicate" {
				e.ID += "-another"
				if _, err := store.Apply(context.Background(), e); err != nil {
					t.Fatal(err)
				}
			}
			if name == "invalid" {
				if _, err := store.db.Exec(sqlutil.Bind(`UPDATE platform_usage_event SET step_id=? WHERE event_id=?`), "PRIVATE INVALID STEP", e.ID); err != nil {
					t.Fatal(err)
				}
			}
			if name == "foreign-run" {
				scope.RunID += "-foreign"
			}
			result, err := store.EvaluationUsage(context.Background(), scope, now.Add(-time.Minute), now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if name == "foreign-run" {
				if result.EventCount != 0 || len(result.ModelUsageStepIDs) != 0 {
					t.Fatal("foreign Run links disclosed")
				}
				return
			}
			want := name == "linked"
			if result.ModelUsageLinksComplete != want || (len(result.ModelUsageStepIDs) > 0) != want {
				t.Fatal("missing/duplicate/untrusted step became exact model link", result)
			}
			raw, _ := json.Marshal(result)
			if strings.Contains(string(raw), "model-step-") || strings.Contains(string(raw), "ModelUsage") {
				t.Fatal("internal step links changed the public usage contract")
			}
		})
	}
}
