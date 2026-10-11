package contract

import (
	"errors"
	"strings"
	"testing"
)

func TestAgentEventCursorSafeIntegerBoundary(t *testing.T) {
	request := EventRequest{
		ProtocolVersion: ProtocolVersion, ContextToken: strings.Repeat("x", 32),
		PolicySnapshotHash: strings.Repeat("a", 64),
		Scope: ScopeKey{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application",
			AgentInstanceID: "instance", AgentID: "example", AgentVersionID: "v2", InstallationID: "installation",
			PrincipalType: "user", PrincipalID: "owner", SessionID: "session", RunID: "run",
			AuthorizationEpoch: 1, TraceID: strings.Repeat("a", 32)},
	}
	seen := make(map[string]bool)
	for _, cursor := range []uint64{0, MaxAgentEventSequence - 1, MaxAgentEventSequence} {
		request.AfterSeq = cursor
		if err := request.Validate(); err != nil {
			t.Fatalf("valid boundary cursor rejected: %v", err)
		}
		hash, err := CanonicalEventBodyHash(request)
		if err != nil || hash == "" || seen[hash] {
			t.Fatal("valid distinct cursors did not preserve exact signature input")
		}
		seen[hash] = true
	}
	for _, cursor := range []uint64{MaxAgentEventSequence + 1, ^uint64(0)} {
		request.AfterSeq = cursor
		if err := request.Validate(); !errors.Is(err, ErrSchemaValidation) {
			t.Fatal("out-of-range cursor was not rejected by contract validation")
		}
		if _, err := CanonicalEventBodyHash(request); !errors.Is(err, ErrSchemaValidation) {
			t.Fatal("out-of-range cursor could still be signed")
		}
	}
}
