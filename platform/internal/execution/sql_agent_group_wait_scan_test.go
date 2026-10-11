package execution

import (
	"strings"
	"testing"
)

func TestAgentGroupWaitingCandidateSQLCastsJSON(t *testing.T) {
	if !strings.Contains(agentGroupWaitingCandidateSQL, "event_payload::text") || !strings.Contains(agentGroupWaitingCandidateSQL, "group_wait_reference") {
		t.Fatal("waiting-group scan must cast JSON event_payload before strpos")
	}
	if strings.Contains(agentGroupWaitingCandidateSQL, "strpos(o.event_payload,'") {
		t.Fatal("strpos on the json column has no PostgreSQL overload")
	}
}
