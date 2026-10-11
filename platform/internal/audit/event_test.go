package audit

import (
	"testing"
	"time"
)

func TestEventJSONContractAndDigestStable(t *testing.T) {
	event := Event{ID: "event-1", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", ActorID: "actor", AggregateType: "run", AggregateID: "run-1", Action: "completed", CreatedAt: time.Unix(1, 0).UTC()}
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	one, err := event.Digest()
	if err != nil {
		t.Fatal(err)
	}
	two, err := event.Digest()
	if err != nil || one != two {
		t.Fatalf("digest is not stable: %q %q %v", one, two, err)
	}
}

func TestDigestIsStableAndRejectsIncompleteScope(t *testing.T) {
	e := Event{ID: "event", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", ActorType: "user", ActorID: "alice", TraceID: "0123456789abcdef0123456789abcdef", AggregateType: "run", AggregateID: "run-1", Action: "run.create", Outcome: "accepted", Summary: "hash-only", CreatedAt: time.Unix(1, 0).UTC()}
	one, err := e.Digest()
	if err != nil {
		t.Fatal(err)
	}
	two, err := e.Digest()
	if err != nil || one != two {
		t.Fatalf("digest not stable: %q %q err=%v", one, two, err)
	}
	e.TenantID = ""
	if _, err = e.Digest(); err == nil {
		t.Fatal("incomplete scope must be rejected")
	}
}
