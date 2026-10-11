package execution

import (
	"context"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestLiveCommandBindsScopeDigestAndCancellation(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("live-command").domain()
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: "v1", IdempotencyKey: "live-command-key", Fingerprint: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(created.Run.ID, "owner", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, "owner")
	if err != nil {
		t.Fatal(err)
	}
	command := platformruntime.DispatchCommand{RunID: scope.RunID, Revision: running.Revision, Operation: "invoke", BodyHash: strings.Repeat("a", 64), PolicyHash: strings.Repeat("b", 64)}
	m := NewModuleWithSharedRepository("", store)
	if err := m.ValidateLiveCommand(context.Background(), scope, command.Operation, command.BodyHash, command.PolicyHash); err == nil {
		t.Fatal("missing current command admitted")
	}
	if err := store.RecordDispatchCommand(command, "foreign-owner"); err == nil {
		t.Fatal("foreign command writer admitted")
	}
	if err := store.RecordDispatchCommand(command, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateLiveCommand(context.Background(), scope, command.Operation, command.BodyHash, command.PolicyHash); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"operation", "body", "policy", "scope"} {
		s, op, body, policy := scope, command.Operation, command.BodyHash, command.PolicyHash
		switch field {
		case "operation":
			op = "resume"
		case "body":
			body = strings.Repeat("c", 64)
		case "policy":
			policy = strings.Repeat("d", 64)
		case "scope":
			s.SessionID = "another-session"
		}
		if err := m.ValidateLiveCommand(context.Background(), s, op, body, policy); err == nil {
			t.Fatalf("tampered %s admitted", field)
		}
	}
	if _, err := store.Cancel(scope.RunID, running.Revision); err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateLiveCommand(context.Background(), scope, command.Operation, command.BodyHash, command.PolicyHash); err == nil {
		t.Fatal("cancelled Run admitted new capability")
	}
	if err := store.RecordDispatchCommand(command, "owner"); err == nil {
		t.Fatal("cancelled Run accepted new signed command")
	}
}
