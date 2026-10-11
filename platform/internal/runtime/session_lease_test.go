package runtime

import (
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSessionExecutionKeyIsUnambiguousAndStableAcrossRuns(t *testing.T) {
	one := sharedkernel.Scope{TenantID: "a:b", DepartmentID: "c", ApplicationID: "app", InstallationID: "install", AgentInstanceID: "instance", AgentID: "agent", PrincipalType: "user", PrincipalID: "user", SessionID: "session", AgentVersionID: "v1", RunID: "run-1", TraceID: "trace-1", AuthorizationEpoch: 1}
	two := one
	two.TenantID = "a"
	two.DepartmentID = "b:c"
	if SessionExecutionKey(one) == SessionExecutionKey(two) {
		t.Fatal("scope delimiter collision")
	}
	same := one
	same.RunID = "run-2"
	same.TraceID = "trace-2"
	same.AuthorizationEpoch = 2
	if SessionExecutionKey(one) != SessionExecutionKey(same) {
		t.Fatal("Run or authorization epoch broke session continuity")
	}
}
