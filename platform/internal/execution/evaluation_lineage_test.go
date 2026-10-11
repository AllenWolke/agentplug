package execution

import (
	"testing"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestRestoreEvaluationParentFromDurableRequest(t *testing.T) {
	run := platformruntime.Run{ID: "case-run"}
	run.Scope.RunID = run.ID
	run.RequestJSON = []byte(`{"scope":{"run_id":"case-run","parent_run_id":"evaluation-run"}}`)
	restoreParentRunID(&run)
	if run.Scope.RunID != "case-run" || run.Scope.ParentRunID != "evaluation-run" {
		t.Fatalf("evaluation lineage lost after persistence: %+v", run.Scope)
	}
	// A malformed persisted envelope never invents a parent attribution.
	// 损坏的持久化信封不能凭空生成父 Run 归属。
	run.Scope.ParentRunID = ""
	run.RequestJSON = []byte(`not-json`)
	restoreParentRunID(&run)
	if run.Scope.ParentRunID != "" {
		t.Fatalf("invalid request invented billing lineage: %+v", run.Scope)
	}
}
