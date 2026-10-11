package capability

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/agentcoordination"
)

func TestChildStopControlConflictResponseIsNarrowAndRequiresTypedConflict(t *testing.T) {
	conflict := &agentcoordination.ChildStopRevisionConflict{Status: "running", ExecutionRevision: 9}
	response, ok := childStopControlConflictResponse(errors.Join(errors.New("wrapped"), conflict), "trace-safe")
	if !ok || response.Code != 1 || response.ErrorCode != "AGENT_STOP_REVISION_CONFLICT" || response.TraceID != "trace-safe" {
		t.Fatalf("unexpected stop conflict response: %#v %v", response, ok)
	}
	data, ok := response.Data.(map[string]any)
	if !ok || len(data) != 1 {
		t.Fatalf("stop conflict data is not allowlisted: %#v", response.Data)
	}
	control, ok := data["stop_control"].(map[string]any)
	if !ok || len(control) != 3 || control["version"] != agentcoordination.ChildStopControlConflictVersion || control["status"] != "running" || control["execution_revision"] != uint64(9) {
		t.Fatalf("invalid stop control metadata: %#v", data)
	}
	wire, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if containsAny(string(wire), "output", "history", "request", "child_run_id", "private-sentinel") {
		t.Fatalf("stop conflict response disclosed unrelated facts: %s", wire)
	}

	for name, invalid := range map[string]*agentcoordination.ChildStopRevisionConflict{
		"zero revision":      {Status: "running"},
		"unknown status":     {Status: "cancelled", ExecutionRevision: 9},
		"too-large revision": {Status: "running", ExecutionRevision: 1 << 63},
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := childStopControlConflictResponse(invalid, ""); ok {
				t.Fatal("invalid conflict produced control metadata")
			}
		})
	}
	if _, ok := childStopControlConflictResponse(agentcoordination.ErrConflict, ""); ok {
		t.Fatal("ordinary route conflict produced stop-control metadata")
	}
}

func containsAny(value string, parts ...string) bool {
	for _, part := range parts {
		if strings.Contains(value, part) {
			return true
		}
	}
	return false
}
